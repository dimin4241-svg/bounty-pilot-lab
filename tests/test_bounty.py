import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shlex
import subprocess
import stat
import urllib.error
import urllib.parse
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bounty = load('bounty', 'skills/bounty-pilot/scripts/bounty.py')
keccak = load('bp_keccak', 'skills/bounty-pilot/scripts/keccak.py')


class FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode('utf-8')

    def read(self):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeNode:
    """Answers JSON-RPC from a dict, and records what was asked."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, request, timeout=None):
        body = json.loads(request.data.decode('utf-8'))
        self.calls.append((body['method'], body['params']))
        key = body['method']
        if key not in self.answers:
            # What a node says to a call it cannot satisfy, e.g. a getter the contract lacks.
            return FakeResponse({'jsonrpc': '2.0', 'id': body['id'],
                                 'error': {'code': 3, 'message': 'execution reverted'}})
        value = self.answers[key]
        if callable(value):
            value = value(body['params'])
        return FakeResponse({'jsonrpc': '2.0', 'id': body['id'], 'result': value})


def git(repo, *args):
    subprocess.run(['git', '-C', str(repo), *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def commit(repo, message):
    git(repo, 'add', '-A')
    git(repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
        'commit', '-qm', message)


class KeccakTests(unittest.TestCase):
    def test_known_digests(self):
        self.assertEqual(keccak.keccak256('').hex(),
                         'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(keccak.keccak256('abc').hex(),
                         '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')

    def test_digest_crosses_the_rate_boundary(self):
        # 200 bytes needs two absorb blocks at a 136-byte rate
        self.assertEqual(len(keccak.keccak256(b'a' * 200)), 32)
        self.assertNotEqual(keccak.keccak256(b'a' * 200), keccak.keccak256(b'a' * 136))

    def test_selectors(self):
        self.assertEqual(keccak.selector('transfer(address,uint256)'), '0xa9059cbb')
        self.assertEqual(keccak.selector('balanceOf(address)'), '0x70a08231')
        self.assertEqual(keccak.selector('totalSupply()'), '0x18160ddd')

    def test_selector_rejects_non_signature(self):
        with self.assertRaises(ValueError):
            keccak.selector('not a signature')

    def test_proxy_slots_match_the_published_constants(self):
        slots = bounty.proxy_slots()
        self.assertEqual(slots['eip1967-implementation'],
                         '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc')
        self.assertEqual(slots['eip1967-beacon'],
                         '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50')
        self.assertEqual(slots['eip1967-admin'],
                         '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103')


class BytecodeTests(unittest.TestCase):
    def setUp(self):
        self.code = bytes.fromhex('6080604052') + b'\xab' * 20
        blob = b'\xa2dipfsX"\x12 ' + b'\x11' * 32 + b'dsolcC\x00\x08\x14'
        self.trailer = blob + len(blob).to_bytes(2, 'big')
        self.live = '0x' + (self.code + self.trailer).hex()

    def test_a_trailing_length_alone_is_not_stripped(self):
        # Reported case: two unrelated runtimes both ending in 0x0002 compared as exact,
        # because the tail length was trusted without checking the tail is solc metadata.
        left, right = '0x6001aabb0002', '0x6001ccdd0002'
        self.assertEqual(bounty.strip_metadata(left)[1], 0)
        result = bounty.compare_bytecode(left, right)
        self.assertNotEqual(result['status'], 'exact')
        self.assertEqual(result['differing_bytes'], 2)

    def test_a_cbor_sized_tail_without_a_solc_marker_is_not_stripped(self):
        blob = b'\xa2' + b'\x41' * 40          # CBOR map header, no solc/ipfs/bzzr marker
        raw = b'\x60\x01' + blob + len(blob).to_bytes(2, 'big')
        self.assertEqual(bounty.strip_metadata('0x' + raw.hex())[1], 0)

    def test_a_tail_that_is_not_a_cbor_map_is_not_stripped(self):
        blob = b'\x01solc' + b'\x00' * 40       # right size and marker, wrong header byte
        raw = b'\x60\x01' + blob + len(blob).to_bytes(2, 'big')
        self.assertEqual(bounty.strip_metadata('0x' + raw.hex())[1], 0)

    def test_metadata_is_stripped(self):
        body, stripped = bounty.strip_metadata(self.live)
        self.assertEqual(body, self.code)
        self.assertEqual(stripped, len(self.trailer))

    def test_identical_builds_are_exact(self):
        self.assertEqual(bounty.compare_bytecode(self.live, self.live)['status'], 'exact')

    def test_differing_metadata_only_is_still_exact(self):
        other_blob = b'\xa2dipfsX"\x12 ' + b'\x22' * 32 + b'dsolcC\x00\x08\x14'
        other = '0x' + (self.code + other_blob + len(other_blob).to_bytes(2, 'big')).hex()
        self.assertEqual(bounty.compare_bytecode(self.live, other)['status'], 'exact')

    def test_same_length_different_body_is_partial_not_exact(self):
        mutated = bytearray(self.code)
        mutated[3] ^= 0xFF
        other = '0x' + (bytes(mutated) + self.trailer).hex()
        result = bounty.compare_bytecode(self.live, other)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['differing_bytes'], 1)

    def test_different_length_is_mismatch(self):
        other = '0x' + (self.code[:-4] + self.trailer).hex()
        self.assertEqual(bounty.compare_bytecode(self.live, other)['status'], 'mismatch')

    def test_no_code_is_mismatch(self):
        self.assertEqual(bounty.compare_bytecode('0x', self.live)['status'], 'mismatch')

    def test_artifact_reading_supports_foundry_and_hardhat(self):
        with tempfile.TemporaryDirectory() as temp:
            foundry = Path(temp) / 'f.json'
            foundry.write_text(json.dumps({'deployedBytecode': {'object': '0xdead'}}))
            self.assertEqual(bounty.read_artifact(foundry), ('0xdead', 'deployedBytecode'))
            hardhat = Path(temp) / 'h.json'
            hardhat.write_text(json.dumps({'deployedBytecode': '0xbeef'}))
            self.assertEqual(bounty.read_artifact(hardhat), ('0xbeef', 'deployedBytecode'))
            empty = Path(temp) / 'e.json'
            empty.write_text(json.dumps({'abi': []}))
            with self.assertRaises(ValueError):
                bounty.read_artifact(empty)


class EncodingTests(unittest.TestCase):
    def test_static_types(self):
        self.assertEqual(bounty.encode_static(['uint32'], ['4']).hex(), '00' * 31 + '04')
        self.assertEqual(
            bounty.encode_static(['address'], ['0x' + '55' * 20]).hex(),
            '00' * 12 + '55' * 20)
        self.assertEqual(bounty.encode_static(['bool'], ['true']).hex(), '00' * 31 + '01')
        self.assertEqual(bounty.encode_static(['int256'], ['-1']).hex(), 'ff' * 32)

    def test_out_of_range_integers_are_refused(self):
        for type_name, value in (('uint8', '256'), ('uint8', '-1'), ('int8', '128'),
                                 ('int8', '-129'), ('uint256', str(1 << 256))):
            with self.assertRaises(ValueError, msg=f'{type_name} {value}'):
                bounty.encode_static([type_name], [value])
        self.assertTrue(bounty.encode_static(['uint8'], ['255']).endswith(b'\xff'))
        bounty.encode_static(['int8'], ['-128'])

    def test_non_boolean_words_are_refused_not_read_as_false(self):
        with self.assertRaises(ValueError):
            bounty.encode_static(['bool'], ['banana'])
        self.assertEqual(bounty.encode_static(['bool'], ['no']), b'\x00' * 32)
        self.assertEqual(bounty.encode_static(['bool'], ['TRUE']), b'\x00' * 31 + b'\x01')

    def test_malformed_address_and_bytes_are_refused(self):
        for type_name, value in (('address', '0x1234'), ('address', 'not-hex'),
                                 ('bytes32', '0xaa'), ('bytes32', '0xzz'), ('bytes33', '0x00')):
            with self.assertRaises(ValueError, msg=f'{type_name} {value}'):
                bounty.encode_static([type_name], [value])

    def test_invalid_integer_widths_are_refused(self):
        for type_name in ('uint7', 'uint512', 'int0'):
            with self.assertRaises(ValueError, msg=type_name):
                bounty.encode_static([type_name], ['1'])

    def test_dynamic_types_are_refused_rather_than_mis_encoded(self):
        with self.assertRaises(ValueError):
            bounty.encode_static(['string'], ['hello'])
        with self.assertRaises(ValueError):
            bounty.encode_static(['uint256[]'], ['1'])

    def test_argument_count_is_checked(self):
        with self.assertRaises(ValueError):
            bounty.encode_static(['uint256', 'uint256'], ['1'])


class RpcTests(unittest.TestCase):
    def test_beacon_proxy_is_compared_to_the_beacon_implementation(self):
        proxy = '0x' + '22' * 20
        beacon = '0x' + '44' * 20
        impl = '0x' + '33' * 20
        proxy_code, impl_code = '0x' + '60' * 30, '0x' + '61' * 60
        beacon_slot = bounty.proxy_slots()['eip1967-beacon']
        padded = '0x' + '00' * 12 + beacon[2:]
        node = FakeNode({
            'eth_chainId': '0x1', 'eth_blockNumber': '0x100',
            'eth_getCode': lambda params: impl_code if params[0] == impl else proxy_code,
            'eth_getStorageAt': lambda params: padded if params[1] == beacon_slot else '0x' + '00' * 32,
            'eth_call': lambda params: '0x' + '00' * 12 + impl[2:],
        })
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / 'impl.json'
            artifact.write_text(json.dumps({'deployedBytecode': {'object': impl_code}}))
            result = bounty.verify_deployment('http://node.invalid', proxy,
                                              str(artifact), 'latest', opener=node)
        self.assertEqual(result['deployment_status'], 'exact')
        self.assertEqual(result['compared'], 'implementation')
        self.assertEqual(result['proxy']['beacon-implementation'], impl)
        self.assertTrue(all(params[-1] == '0x100' for method, params in node.calls
                            if method in ('eth_getCode', 'eth_getStorageAt', 'eth_call')))

    def test_unresolved_beacon_never_accepts_a_matching_proxy_artifact_as_exact(self):
        proxy = '0x' + '22' * 20
        beacon = '0x' + '44' * 20
        proxy_code = '0x' + '60' * 30
        beacon_slot = bounty.proxy_slots()['eip1967-beacon']
        padded = '0x' + '00' * 12 + beacon[2:]
        def fail_call(_params):
            raise ValueError('beacon call failed')
        node = FakeNode({
            'eth_chainId': '0x1', 'eth_blockNumber': '0x100',
            'eth_getCode': proxy_code,
            'eth_getStorageAt': lambda params: padded if params[1] == beacon_slot else '0x' + '00' * 32,
            'eth_call': fail_call,
        })
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / 'proxy.json'
            artifact.write_text(json.dumps({'deployedBytecode': {'object': proxy_code}}))
            result = bounty.verify_deployment('http://node.invalid', proxy,
                                              str(artifact), 'latest', opener=node)
        self.assertEqual(result['deployment_status'], 'partial')
        self.assertEqual(result['proxy_resolution'], 'unresolved')

    def test_eip1167_clone_is_compared_to_its_implementation(self):
        proxy, impl = '0x' + '22' * 20, '0x' + '33' * 20
        clone_code = '0x363d3d373d3d3d363d73' + impl[2:] + '5af43d82803e903d91602b57fd5bf3'
        impl_code = '0x' + '61' * 60
        node = FakeNode({
            'eth_chainId': '0x1', 'eth_blockNumber': '0x100',
            'eth_getCode': lambda params: impl_code if params[0] == impl else clone_code,
            'eth_getStorageAt': '0x' + '00' * 32,
        })
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / 'impl.json'
            artifact.write_text(json.dumps({'deployedBytecode': {'object': impl_code}}))
            result = bounty.verify_deployment('http://node.invalid', proxy,
                                              str(artifact), 'latest', opener=node)
        self.assertEqual(result['deployment_status'], 'exact')
        self.assertEqual(result['proxy']['eip1167-minimal-clone'], impl)

    def test_eip1822_proxy_is_compared_to_its_proxiable_slot_implementation(self):
        proxy, impl = '0x' + '22' * 20, '0x' + '33' * 20
        impl_code = '0x' + '61' * 60
        slot = bounty.proxy_slots()['eip1822-proxiable']
        padded = '0x' + '00' * 12 + impl[2:]
        node = FakeNode({
            'eth_chainId': '0x1', 'eth_blockNumber': '0x100',
            'eth_getCode': lambda params: impl_code if params[0] == impl else '0x' + '60' * 30,
            'eth_getStorageAt': lambda params: padded if params[1] == slot else '0x' + '00' * 32,
        })
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / 'impl.json'
            artifact.write_text(json.dumps({'deployedBytecode': {'object': impl_code}}))
            result = bounty.verify_deployment('http://node.invalid', proxy,
                                              str(artifact), 'latest', opener=node)
        self.assertEqual(result['deployment_status'], 'exact')
        self.assertEqual(result['proxy_implementation']['address'], impl)

    def test_unrecognized_clone_variant_is_never_exact_against_its_own_runtime(self):
        proxy = '0x' + '22' * 20
        # The ERC-1167 prefix with a forwarder tail no library emits. (Bytes appended after the
        # canonical tail are immutable args, a recognised form: see test_evidence_hardening.)
        code = '0x363d3d373d3d3d363d73' + '33' * 20 + '5af43d82803e903d91602b57fd5bf4'
        node = FakeNode({
            'eth_chainId': '0x1', 'eth_blockNumber': '0x100', 'eth_getCode': code,
            'eth_getStorageAt': '0x' + '00' * 32,
        })
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / 'clone.json'
            artifact.write_text(json.dumps({'deployedBytecode': {'object': code}}))
            result = bounty.verify_deployment('http://node.invalid', proxy,
                                              str(artifact), 'latest', opener=node)
        self.assertEqual(result['deployment_status'], 'partial')
        self.assertEqual(result['proxy_resolution'], 'unresolved')

    def test_verify_deployment_reports_exact_and_pins_one_block(self):
        code = '0x' + ('60' * 40)
        node = FakeNode({'eth_chainId': '0x3e7', 'eth_blockNumber': '0x1e240',
                         'eth_getCode': code, 'eth_getStorageAt': '0x' + '00' * 32})
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / 'a.json'
            artifact.write_text(json.dumps({'deployedBytecode': {'object': code}}))
            result = bounty.verify_deployment('http://node.invalid', '0x' + '11' * 20,
                                              str(artifact), 'latest', opener=node)
        self.assertEqual(result['deployment_status'], 'exact')
        self.assertEqual(result['chain_id'], 999)
        self.assertEqual(result['block'], 123456)
        blocks = {params[-1] for method, params in node.calls
                  if method in ('eth_getCode', 'eth_getStorageAt')}
        self.assertEqual(blocks, {'0x1e240'}, 'every read must use the one pinned block')

    def test_verify_deployment_flags_an_address_with_no_code(self):
        node = FakeNode({'eth_chainId': '0x1', 'eth_blockNumber': '0x10', 'eth_getCode': '0x'})
        result = bounty.verify_deployment('http://node.invalid', '0x' + '22' * 20, None,
                                          'latest', opener=node)
        self.assertEqual(result['deployment_status'], 'mismatch')
        self.assertIn('no code', result['reason'])

    def test_verify_deployment_detects_a_proxy_and_stays_unknown_without_an_artifact(self):
        impl = '0x' + '00' * 12 + '33' * 20
        node = FakeNode({
            'eth_chainId': '0x1', 'eth_blockNumber': '0x10', 'eth_getCode': '0xdeadbeef',
            'eth_getStorageAt': lambda params: impl if params[1] == bounty.proxy_slots()[
                'eip1967-implementation'] else '0x' + '00' * 32})
        result = bounty.verify_deployment('http://node.invalid', '0x' + '22' * 20, None,
                                          'latest', opener=node)
        self.assertEqual(result['proxy']['eip1967-implementation'], '0x' + '33' * 20)
        self.assertEqual(result['deployment_status'], 'unknown')

    def _proxy_node(self, proxy_code, impl_code, impl_address):
        slot = bounty.proxy_slots()['eip1967-implementation']
        padded = '0x' + '00' * 12 + impl_address[2:]
        return FakeNode({
            'eth_chainId': '0x1', 'eth_blockNumber': '0x100',
            'eth_getCode': lambda params: impl_code if params[0] == impl_address else proxy_code,
            'eth_getStorageAt': lambda params: padded if params[1] == slot else '0x' + '00' * 32})

    def test_a_proxy_is_compared_against_its_implementation(self):
        impl_address = '0x' + '33' * 20
        impl_code = '0x' + '61' * 60
        node = self._proxy_node('0x' + '60' * 30, impl_code, impl_address)
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / 'impl.json'
            artifact.write_text(json.dumps({'deployedBytecode': {'object': impl_code}}))
            result = bounty.verify_deployment('http://node.invalid', '0x' + '22' * 20,
                                              str(artifact), 'latest', opener=node)
        self.assertEqual(result['deployment_status'], 'exact')
        self.assertEqual(result['compared'], 'implementation')
        self.assertEqual(result['proxy_implementation']['address'], impl_address)

    def test_a_matching_proxy_runtime_never_reads_as_exact(self):
        # The logic lives behind the proxy; matching the proxy's own runtime proves nothing,
        # and the submission gate accepts exact, so this must not be exact.
        impl_address = '0x' + '33' * 20
        proxy_code = '0x' + '60' * 30
        node = self._proxy_node(proxy_code, '0x' + '61' * 60, impl_address)
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / 'proxy.json'
            artifact.write_text(json.dumps({'deployedBytecode': {'object': proxy_code}}))
            result = bounty.verify_deployment('http://node.invalid', '0x' + '22' * 20,
                                              str(artifact), 'latest', opener=node)
        self.assertEqual(result['deployment_status'], 'partial')
        self.assertIn('not the implementation', result['comparison']['reason'])

    def test_implementation_code_is_read_at_the_same_pinned_block(self):
        impl_address = '0x' + '33' * 20
        node = self._proxy_node('0x' + '60' * 30, '0x' + '61' * 60, impl_address)
        bounty.verify_deployment('http://node.invalid', '0x' + '22' * 20, None, 'latest',
                                 opener=node)
        blocks = {params[-1] for method, params in node.calls if method == 'eth_getCode'}
        self.assertEqual(blocks, {'0x100'})

    def test_decimal_block_is_converted_before_it_reaches_the_node(self):
        node = FakeNode({'eth_chainId': '0x1', 'eth_blockNumber': '0x10',
                         'eth_getCode': '0xdead', 'eth_getStorageAt': '0x' + '00' * 32})
        bounty.verify_deployment('http://node.invalid', '0x' + '22' * 20, None, '4096',
                                 opener=node)
        codes = [params[-1] for method, params in node.calls if method == 'eth_getCode']
        self.assertEqual(codes, ['0x1000'])

    def test_bad_address_is_refused_before_any_network_call(self):
        node = FakeNode({})
        with self.assertRaises(ValueError):
            bounty.verify_deployment('http://node.invalid', 'not-an-address', None,
                                     'latest', opener=node)
        self.assertEqual(node.calls, [])

    def test_eth_call_builds_the_selector_and_decodes_words(self):
        node = FakeNode({'eth_call': '0x' + '00' * 31 + '2a'})
        result = bounty.eth_call('http://node.invalid', '0x' + '44' * 20, 'markPx(uint32)',
                                 ['4'], 'latest', opener=node)
        self.assertEqual(result['selector'], keccak.selector('markPx(uint32)'))
        self.assertEqual(result['words'][0]['uint'], '42')
        self.assertEqual(node.calls[0][1][0]['data'][10:], '00' * 31 + '04')

    def test_eth_call_does_not_read_a_small_number_as_an_address(self):
        node = FakeNode({'eth_call': '0x' + '00' * 31 + '06'})
        result = bounty.eth_call('http://node.invalid', '0x' + '44' * 20, 'decimals()', [],
                                 'latest', opener=node)
        self.assertEqual(result['words'][0]['uint'], '6')
        self.assertIsNone(result['words'][0]['address'])

    def test_eth_call_offers_an_address_reading_for_a_padded_address(self):
        node = FakeNode({'eth_call': '0x' + '00' * 12 + '33' * 20})
        result = bounty.eth_call('http://node.invalid', '0x' + '44' * 20, 'owner()', [],
                                 'latest', opener=node)
        self.assertEqual(result['words'][0]['address'], '0x' + '33' * 20)

    def test_rpc_error_is_raised_not_swallowed(self):
        class Failing(FakeNode):
            def __call__(self, request, timeout=None):
                return FakeResponse({'jsonrpc': '2.0', 'id': 1,
                                     'error': {'code': -32000, 'message': 'nope'}})
        with self.assertRaises(ValueError):
            bounty.rpc_call('http://node.invalid', 'eth_chainId', [], Failing({}))


class ImmutableMaskingTests(unittest.TestCase):
    """Review 0.9.1, item 4: immutables made every such contract `partial` forever."""

    def setUp(self):
        self.prefix = bytes.fromhex('608060405234') + b'\x5b' * 40
        self.suffix = b'\x5b' * 40 + bytes.fromhex('00')
        self.value = bytes.fromhex('00' * 12 + '33' * 20)     # e.g. OZ UUPS __self
        self.start = len(self.prefix)
        self.live = '0x' + (self.prefix + self.value + self.suffix).hex()
        self.built = '0x' + (self.prefix + b'\0' * 32 + self.suffix).hex()
        self.refs = {'812': [{'start': self.start, 'length': 32}]}

    def test_without_references_immutables_stay_partial(self):
        self.assertEqual(bounty.compare_bytecode(self.live, self.built)['status'], 'partial')

    def test_declared_immutables_are_masked_and_reported(self):
        result = bounty.compare_bytecode(self.live, self.built, immutable_references=self.refs)
        self.assertEqual(result['status'], 'exact')
        self.assertEqual(result['masked_ranges'], [{
            'kind': 'immutable', 'start': self.start, 'length': 32,
            'onchain_value': '0x' + self.value.hex()}])

    def test_masking_does_not_hide_a_difference_outside_the_ranges(self):
        mutated = bytearray(bytes.fromhex(self.live[2:]))
        mutated[2] ^= 0xFF
        result = bounty.compare_bytecode('0x' + mutated.hex(), self.built,
                                         immutable_references=self.refs)
        self.assertEqual(result['status'], 'partial')

    def test_a_range_wider_than_the_compiler_emits_is_not_trusted(self):
        # An artifact claiming one giant "immutable" would otherwise mask its way to exact.
        refs = {'1': [{'start': 0, 'length': len(self.prefix) + 32}]}
        result = bounty.compare_bytecode(self.live, self.built, immutable_references=refs)
        self.assertEqual(result['status'], 'partial')
        self.assertTrue(result['masking_skipped'])

    def test_library_placeholders_are_masked_with_link_references(self):
        address = bytes.fromhex('44' * 20)
        live = '0x' + (self.prefix + address + self.suffix).hex()
        placeholder = '__$' + 'ab' * 17 + '$__'
        built = '0x' + self.prefix.hex() + placeholder + self.suffix.hex()
        links = {'src/Lib.sol': {'Lib': [{'start': self.start, 'length': 20}]}}
        result = bounty.compare_bytecode(live, built, link_references=links)
        self.assertEqual(result['status'], 'exact')
        self.assertEqual(result['masked_ranges'][0]['onchain_value'], '0x' + address.hex())
        with self.assertRaisesRegex(ValueError, 'not hex'):
            bounty.compare_bytecode(live, built)

    def test_verify_deployment_reads_foundry_immutable_references(self):
        impl = '0x' + '33' * 20
        slot = bounty.proxy_slots()['eip1967-implementation']
        node = FakeNode({
            'eth_chainId': '0x1', 'eth_blockNumber': '0x100',
            'eth_getCode': lambda p: self.live if p[0] == impl else '0x' + '60' * 30,
            'eth_getStorageAt': lambda p: ('0x' + '00' * 12 + impl[2:]) if p[1] == slot
                                          else '0x' + '00' * 32})
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / 'impl.json'
            artifact.write_text(json.dumps({'deployedBytecode': {
                'object': self.built, 'immutableReferences': self.refs, 'linkReferences': {}}}))
            result = bounty.verify_deployment('http://node.invalid', '0x' + '22' * 20,
                                              str(artifact), 'latest', opener=node)
        self.assertEqual(result['deployment_status'], 'exact')
        self.assertEqual(result['comparison']['masked_ranges'][0]['onchain_value'],
                         '0x' + self.value.hex())


class ProxyDetectionTests(unittest.TestCase):
    """Review 0.9.1, item 5: unrecognized proxies verified as exact against their own runtime."""

    proxy = '0x' + '22' * 20
    impl = '0x' + '33' * 20
    impl_code = '0x' + '61' * 60

    def verify(self, proxy_code, artifact_code, storage=None, calls=None):
        storage = storage or {}
        calls = calls or {}

        def get_code(params):
            return self.impl_code if params[0] == self.impl else proxy_code

        def get_storage(params):
            return storage.get(params[1], '0x' + '00' * 32)

        def call(params):
            selector = params[0]['data'][:10]
            if selector not in calls:
                raise ValueError('execution reverted')
            return calls[selector]
        node = FakeNode({'eth_chainId': '0x1', 'eth_blockNumber': '0x100',
                         'eth_getCode': get_code, 'eth_getStorageAt': get_storage,
                         'eth_call': call})
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / 'a.json'
            artifact.write_text(json.dumps({'deployedBytecode': {'object': artifact_code}}))
            return bounty.verify_deployment('http://node.invalid', self.proxy, str(artifact),
                                            'latest', opener=FakeNodeErrors(node))

    def padded(self, address):
        return '0x' + '00' * 12 + address[2:]

    def test_zeppelinos_slot_is_derived_and_resolved(self):
        slot = bounty.proxy_slots()['zeppelinos-implementation']
        self.assertEqual(slot, '0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3')
        result = self.verify('0x' + '60' * 30, self.impl_code, storage={slot: self.padded(self.impl)})
        self.assertEqual(result['proxy_kind'], 'zeppelinos-implementation')
        self.assertEqual(result['compared'], 'implementation')
        self.assertEqual(result['deployment_status'], 'exact')

    def test_safe_proxy_is_compared_to_its_singleton(self):
        selector = keccak.selector('masterCopy()')
        # GnosisSafeProxy compares calldata against the selector left-aligned in a PUSH32.
        code = '0x7f' + selector[2:] + '00' * 28 + '35' + '14' + '5af4' + '00'
        result = self.verify(code, self.impl_code, calls={selector: self.padded(self.impl)})
        self.assertEqual(result['proxy']['gnosis-safe-mastercopy'], self.impl)
        self.assertEqual(result['deployment_status'], 'exact')
        matching_proxy = self.verify(code, code, calls={selector: self.padded(self.impl)})
        self.assertEqual(matching_proxy['deployment_status'], 'partial')

    def test_compound_unitroller_is_compared_to_its_comptroller(self):
        selector = keccak.selector('comptrollerImplementation()')
        code = '0x63' + selector[2:] + '14' + '5af4' + '00'
        result = self.verify(code, self.impl_code, calls={selector: self.padded(self.impl)})
        self.assertEqual(result['proxy_kind'], 'compound-unitroller')
        self.assertEqual(result['proxy_implementation']['address'], self.impl)
        self.assertEqual(result['deployment_status'], 'exact')

    def test_getter_is_not_probed_when_the_runtime_lacks_the_selector(self):
        # A contract whose fallback returns an address-shaped word is not a Safe.
        selector = keccak.selector('masterCopy()')
        code = '0x' + '60' * 40
        result = self.verify(code, code, calls={selector: self.padded(self.impl)})
        self.assertEqual(result['proxy'], {})
        self.assertEqual(result['deployment_status'], 'exact')

    def test_diamond_is_reported_partial_with_its_facets(self):
        facet_a, facet_b = '0x' + 'a1' * 20, '0x' + 'b2' * 20
        words = [0x20, 2, 0x40, 0xc0,
                 int(facet_a, 16), 0x40, 1, int('1f931c1c' + '00' * 28, 16),
                 int(facet_b, 16), 0x40, 1, int('cdffacc6' + '00' * 28, 16)]
        encoded = '0x' + ''.join(format(w, '064x') for w in words)
        code = '0x' + '6000' + '5af4' + '60' * 30
        result = self.verify(code, code, calls={keccak.selector('facets()'): encoded})
        self.assertEqual(result['proxy']['eip2535-diamond'], [facet_a, facet_b])
        self.assertEqual(result['proxy_kind'], 'eip2535-diamond')
        self.assertEqual(result['deployment_status'], 'partial')
        self.assertIn('facet', result['comparison']['reason'])

    def test_slot0_singleton_forwarder_is_compared_to_the_singleton(self):
        code = '0x' + '6000' + '54' + '5af4' + '60' * 20
        result = self.verify(code, self.impl_code, storage={'0x0': self.padded(self.impl)})
        self.assertEqual(result['proxy_kind'], 'slot0-singleton')
        self.assertEqual(result['deployment_status'], 'exact')

    def test_small_unrecognized_delegating_runtime_is_never_exact(self):
        code = '0x' + '6000' + '5af4' + '60' * 30
        result = self.verify(code, code)
        self.assertEqual(result['proxy'], {})
        self.assertEqual(result['deployment_status'], 'partial')
        self.assertIn('unrecognized proxy', result['comparison']['reason'])

    def test_a_delegatecall_byte_inside_push_data_is_not_an_opcode(self):
        code = '0x' + '60f4' * 30        # PUSH1 0xf4, never DELEGATECALL
        self.assertFalse(bounty.has_delegatecall(bytes.fromhex(code[2:])))
        self.assertEqual(self.verify(code, code)['deployment_status'], 'exact')


class FakeNodeErrors:
    """Adapts FakeNode so a callable answer can raise to signal a JSON-RPC error (a revert)."""

    def __init__(self, node):
        self.node = node
        self.calls = node.calls

    def __call__(self, request, timeout=None):
        try:
            return self.node(request, timeout)
        except ValueError as exc:
            body = json.loads(request.data.decode('utf-8'))
            return FakeResponse({'jsonrpc': '2.0', 'id': body['id'],
                                 'error': {'code': 3, 'message': str(exc)}})


class RunTests(unittest.TestCase):
    def test_inventory_recognizes_more_contract_and_service_languages(self):
        self.assertTrue({'.fc', '.tolk', '.move', '.cairo', '.rs', '.java', '.kt', '.php',
                         '.cs', '.tf', '.graphql', '.proto'}.issubset(bounty.SOURCE_SUFFIXES))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        (self.repo / 'src/Vault.sol').write_text('contract Vault {}\n')
        commit(self.repo, 'fixture')
        self.run = self.base / 'run'
        bounty.initialize(self.repo, self.run)
        meta = bounty.read_json(self.run / 'run.json')
        meta['project_key'] = 'example.invalid/test'
        bounty.dump(self.run / 'run.json', meta)
        self.commit = meta['commit']
        # history check refuses a clean no-match against a ledger that does not exist.
        self.ledger = self.base / 'private' / 'history.jsonl'
        self.ledger.parent.mkdir()
        self.ledger.write_text('')

    def candidate(self):
        row = bounty.template()
        row.update(title='Example', root_cause='Example mechanism',
                   affected_paths=['src/Vault.sol'], bug_class='aggregate-not-decremented',
                   revision=self.commit, attacker_capabilities='Unprivileged caller',
                   preconditions='Example state', impact='Demonstrated property change',
                   next_experiment={'question': 'Can an unprivileged user trigger the mismatch?',
                                    'method': 'Run the local test with two actors and compare totals',
                                    'expected_evidence': 'Assertion shows the user gain exceeds the ledger',
                                    'blocker': ''})
        return row

    def check(self, row, submission=False):
        bounty.dump(self.run / 'findings.json', [row])
        if submission:
            bounty.history_check(self.run, self.ledger, project='example.invalid/test')
            self.harvest([])
            self.dup_check()
        return bounty.validate(self.run, submission=submission)

    def dup_check(self):
        """dup-check as this fixture needs it before a submission gate.

        The fixture's map is the empty scaffold, so the reason is recorded with the join; and
        the review-artifact inventory every submission requires is taken when absent.
        """
        if not (self.run / 'audit-inventory.json').exists():
            bounty.audit_inventory(self.repo, self.run)
        return bounty.dup_check(self.run, empty_map_reason='Fixture: no known-issues list, '
                                                           'audit or contest to read')

    def paired(self, row):
        """Record the executed candidate and negative-control run a verified record stands on."""
        argv = shlex.split(row['evidence']['command'])

        def case(role, command):
            return {'id': role, 'pair_id': 'p1', 'role': role, 'argv': command, 'cwd': '.',
                    'executed': True, 'tests_ran': True, 'timed_out': False, 'status': 'ran',
                    'exit_code': 0, 'expected_exit': 0, 'matched_expected_exit': True}
        name = 'native-' + row['id'] + '.json'
        bounty.dump(self.run / name, {
            'schema': 1, 'finding_id': row['id'], 'source_revision': self.commit,
            'source_status': 'clean', 'mode': 'executed', 'result': 'experiments-conformed',
            'cases': [case('candidate', argv), case('negative-control', argv + ['--control'])]})
        ledger = bounty.read_json(self.run / 'experiments.json')
        ledger['experiments'] = [entry for entry in ledger['experiments']
                                 if entry.get('finding_id') != row['id']]
        ledger['experiments'].append({
            'finding_id': row['id'], 'status': 'executed', 'revision': self.commit,
            'result_path': name,
            'observation': 'The candidate passed and the negative control failed as expected.'})
        bounty.dump(self.run / 'experiments.json', ledger)
        return row

    def harvest(self, items, triage=None, labels=('wontfix',)):
        """Record a dup-harvest result from a saved search, without touching the network."""
        source = self.base / 'harvest-input.json'
        source.write_text(json.dumps({'items': items}))
        result = bounty.dup_harvest(self.run, repo='example.invalid/test',
                                    labels=list(labels), from_file=str(source))
        if triage is not None:
            data = bounty.read_json(self.run / 'dup-harvest.json')
            data['triage'] = triage
            bounty.dump(self.run / 'dup-harvest.json', data)
        return result

    def verified(self):
        row = self.candidate()
        row['status'] = 'verified'
        (self.run / 'poc.py').write_text('assert True\n')
        (self.run / 'log.txt').write_text('example test output\n')
        row['evidence'] = dict(command='python3 poc.py', exit_code=0, poc_path='poc.py',
                               log_path='log.txt', assertion='Example assertion',
                               negative_control='Observed control',
                               source_integrity='Original source')
        return row

    def objection(self, outcome='answered'):
        item = {'gate': 'interruption',
                'claim': 'the nonReentrant modifier on redeem() stops the second entry',
                'anchor': 'code: src/Vault.sol:142 modifier nonReentrant on redeem()',
                'outcome': outcome}
        if outcome == 'withdrawn':
            # Withdrawn means no anchor could be produced; an anchored one is not withdrawn.
            del item['anchor']
            item['withdrawn_because'] = 'no guard found on the redeemFor() path'
        if outcome == 'answered':
            item['answer'] = 'redeemFor() reaches _redeem() directly and carries no guard'
            item['answer_anchor'] = 'code: src/Vault.sol:188-204 redeemFor -> _redeem'
        return item

    def deployment_evidence(self, address='0x' + '11' * 20, onchain=None, built=None):
        """Run verify-deployment against a fake node, saving its result into the run."""
        code = '0x' + '60' * 40
        node = FakeNode({'eth_chainId': '0x1', 'eth_blockNumber': '0x100',
                         'eth_getCode': onchain or code, 'eth_getStorageAt': '0x' + '00' * 32})
        artifact = self.base / ('artifact-' + address[-6:] + '.json')
        artifact.write_text(json.dumps({'deployedBytecode': {'object': built or code}}))
        result = bounty.verify_deployment('http://node.invalid', address, str(artifact),
                                          'latest', opener=node, run=self.run)
        return str(Path(result['evidence_file']).relative_to(self.run.resolve()))

    def escalation(self, **overrides):
        """A completed ladder: every amplifier tried exactly once, every result anchored."""
        record = {'attempted': [{'amplifier': amplifier, 'result': 'blocked',
                                 'anchor': 'code: src/Vault.sol:144 bounds ' + amplifier}
                                for amplifier in bounty.ESCALATION_AMPLIFIERS],
                  'ceiling': 'informational',
                  'ceiling_evidence': 'Self-harm only; every amplifier came back blocked.'}
        record.update(overrides)
        return record

    def submittable(self):
        row = self.verified()
        row['escalation'] = self.escalation()
        row['objections'] = [self.objection()]
        row.update(severity='high', scope_status='in-scope', deployment_status='exact',
                   deployment_evidence=[self.deployment_evidence()],
                   severity_rationale='Program rubric: permanent loss of core function')
        row['novelty'] = {'status': 'no-public-match-found',
                          'sources': ['https://example.invalid/known-issues (read 2026-10-08)',
                                      'https://example.invalid/audit.pdf (no match on mechanism)']}
        row['evidence']['impact_quantification'] = '12,400 USDC of debt accounting, cost 0.002 ETH'
        row['history_review'] = {'status': 'no-match', 'case_ids': [],
                                 'rationale': 'Private history check returned no matches on 2026-10-09'}
        row['dup_review'] = {'status': 'no-match', 'entry_ids': [],
                             'rationale': 'dup-check clean on 2026-10-09 against the known-issues '
                                          'list and the published audit'}
        return self.paired(row)

    # ---- init ----
    def test_inventory_and_empty_run(self):
        data = json.loads((self.run / 'run.json').read_text())
        self.assertEqual(data['source_candidates'], ['src/Vault.sol'])
        self.assertFalse(data['dirty'])
        self.assertEqual(data['schema_version'], bounty.SCHEMA_VERSION)
        self.assertEqual(bounty.validate(self.run), [])

    def test_init_writes_the_funnel_scaffolding(self):
        for name in ('dup-map.json', 'known-hypotheses.md', 'coverage.md', 'scope.md', 'model.md'):
            self.assertTrue((self.run / name).exists(), name)
        self.assertEqual(json.loads((self.run / 'dup-map.json').read_text()), [])

    def test_never_overwrite(self):
        with self.assertRaises(ValueError):
            bounty.initialize(self.repo, self.run)

    def test_no_output_in_target(self):
        with self.assertRaises(ValueError):
            bounty.initialize(self.repo, self.repo / 'inside')

    def test_stale_schema_is_reported(self):
        meta = json.loads((self.run / 'run.json').read_text())
        meta['schema_version'] = 1
        bounty.dump(self.run / 'run.json', meta)
        errors = bounty.validate(self.run)
        self.assertTrue(any('schema_version' in e for e in errors))

    # ---- structural gate ----
    def test_complete_record_is_structurally_valid_even_with_unknown_scope(self):
        self.assertEqual(self.check(self.candidate()), [])

    def test_duplicate_id_rejected(self):
        row = self.candidate()
        bounty.dump(self.run / 'findings.json', [row, dict(row)])
        self.assertTrue(any('duplicate id' in e for e in bounty.validate(self.run)))

    def test_bug_class_must_be_kebab_case(self):
        row = self.candidate()
        row['bug_class'] = 'Not Kebab Case'
        self.assertTrue(any('bug_class' in e for e in self.check(row)))

    def test_revision_is_required(self):
        row = self.candidate()
        row['revision'] = ''
        self.assertTrue(any('revision' in e for e in self.check(row)))

    def test_wrong_types_reported(self):
        row = self.candidate()
        row['affected_paths'] = 'src/Vault.sol'
        row['severity'] = 'catastrophic'
        errors = self.check(row)
        self.assertTrue(any('affected_paths' in e for e in errors))
        self.assertTrue(any('severity' in e for e in errors))

    def test_refutation_needs_reason(self):
        row = self.candidate()
        row['status'] = 'refuted'
        self.assertTrue(any('refutation' in e for e in self.check(row)))

    def test_open_candidate_requires_a_decisive_next_experiment(self):
        row = self.candidate()
        row['next_experiment'] = {'question': '', 'method': '', 'expected_evidence': ''}
        errors = self.check(row)
        for field in ('question', 'method', 'expected_evidence'):
            self.assertTrue(any('next_experiment.' + field in error for error in errors))

    def test_queue_lists_every_open_candidate_with_its_experiment(self):
        row = self.candidate()
        row['status'] = 'needs-evidence'
        bounty.dump(self.run / 'findings.json', [row])
        result = bounty.lead_queue(self.run)
        self.assertEqual(result['open_count'], 1)
        self.assertEqual(result['leads'][0]['next_experiment']['question'],
                         row['next_experiment']['question'])

    def test_queue_refuses_to_hide_a_lead_without_a_next_step(self):
        row = self.candidate()
        row['next_experiment']['method'] = ''
        bounty.dump(self.run / 'findings.json', [row])
        result = bounty.lead_queue(self.run)
        self.assertEqual(result['state'], 'invalid')
        self.assertTrue(any('next_experiment.method' in e for e in result['errors']))

    # ---- blockers ----
    def blocked(self, blocker, status='needs-evidence'):
        row = self.candidate()
        row['status'] = status
        row['next_experiment']['blocker'] = blocker
        bounty.dump(self.run / 'findings.json', [row])
        return row

    def reproduced_blocker(self, **overrides):
        record = {'claim': 'forge build fails: unresolved import of a sibling workspace package',
                  'command': 'forge build --build-info',
                  'exit_code': 1,
                  'output_excerpt': 'Error: failed to resolve import @royco/periphery',
                  'recorded_at': '2026-10-16T09:14:00Z',
                  'attempted_alternative': 'installed from the monorepo root instead of the '
                                           'copied subproject'}
        record.update(overrides)
        return record

    def test_a_bare_string_blocker_still_validates_and_is_reported_as_unverified(self):
        # The wording that deleted three passes of coverage: a sentence nobody could check.
        self.blocked('cannot be installed - no root package.json, no workspaces')
        self.assertEqual(bounty.validate(self.run), [])
        result = bounty.lead_queue(self.run)
        self.assertEqual([row['id'] for row in result['unverified_blockers']], ['BP-001'])
        self.assertEqual(result['unverified_blockers'][0]['surface'], 'src/Vault.sol')
        self.assertIn('no root package.json', result['unverified_blockers'][0]['claim'])

    def test_a_reproduced_blocker_is_not_reported(self):
        self.blocked(self.reproduced_blocker())
        self.assertEqual(bounty.validate(self.run), [])
        self.assertEqual(bounty.lead_queue(self.run)['unverified_blockers'], [])
        self.assertEqual(bounty.blocker_state(self.reproduced_blocker()), 'reproduced')

    def test_an_object_blocker_without_its_output_is_only_unverified(self):
        row = self.blocked(self.reproduced_blocker(output_excerpt=''))
        self.assertEqual(bounty.validate(self.run), [])
        self.assertEqual(bounty.blocker_state(row['next_experiment']['blocker']), 'unverified')
        self.assertEqual([r['id'] for r in bounty.lead_queue(self.run)['unverified_blockers']],
                         ['BP-001'])

    def test_no_blocker_at_all_is_absent_not_unverified(self):
        self.blocked('')
        self.assertEqual(bounty.lead_queue(self.run)['unverified_blockers'], [])
        self.assertEqual(bounty.blocker_state({}), 'absent')
        self.assertEqual(bounty.blocker_state(None), 'absent')

    def test_a_malformed_blocker_object_is_an_error_and_never_a_crash(self):
        row = self.blocked({'command': 'forge build'})
        self.assertTrue(any('blocker.claim is required' in e
                            for e in bounty.validate(self.run)))
        row = self.blocked(self.reproduced_blocker(exit_code='1', command=['forge', 'build']))
        errors = bounty.validate(self.run)
        self.assertTrue(any('blocker.exit_code must be an integer' in e for e in errors))
        self.assertTrue(any('blocker.command must be a string' in e for e in errors))
        for wrong in ([], 17, True, None):
            self.blocked(wrong)
            self.assertTrue(any('blocker must be a string, or an object' in e
                                for e in bounty.validate(self.run)), wrong)
        # A record whose blocker cannot be read is an invalid queue, not a traceback.
        self.assertEqual(bounty.lead_queue(self.run)['state'], 'invalid')
        self.assertEqual(row['id'], 'BP-001')

    def test_a_blocker_on_a_terminal_record_is_left_alone(self):
        row = self.candidate()
        row.update(status='refuted', rejection_reason='The caller is checked against the owner.')
        row['next_experiment']['blocker'] = 'no archive RPC'
        bounty.dump(self.run / 'findings.json', [row])
        self.assertEqual(bounty.validate(self.run), [])
        self.assertEqual(bounty.lead_queue(self.run)['unverified_blockers'], [])

    def test_submission_is_blocked_while_a_needed_experiment_rests_on_an_unproven_blocker(self):
        blocked = self.candidate()
        blocked.update(id='BP-002', status='needs-evidence')
        blocked['next_experiment']['blocker'] = 'cannot be installed - no root package.json'
        bounty.dump(self.run / 'findings.json', [self.submittable(), blocked])
        bounty.history_check(self.run, self.ledger, project='example.invalid/test')
        self.harvest([])
        self.dup_check()
        errors = bounty.validate(self.run, submission=True)
        self.assertTrue(any('unverified blocker' in e for e in errors), errors)

    def test_a_reproduced_blocker_does_not_block_submission(self):
        blocked = self.candidate()
        blocked.update(id='BP-002', status='needs-evidence')
        blocked['next_experiment']['blocker'] = self.reproduced_blocker()
        bounty.dump(self.run / 'findings.json', [self.submittable(), blocked])
        bounty.history_check(self.run, self.ledger, project='example.invalid/test')
        self.harvest([])
        self.dup_check()
        self.assertEqual(bounty.validate(self.run, submission=True), [])

    def test_a_hypothesis_is_not_held_to_the_blocker_gate(self):
        # A hypothesis has not yet claimed its experiment is the one that must run.
        blocked = self.candidate()
        blocked.update(id='BP-002', status='hypothesis')
        blocked['next_experiment']['blocker'] = 'needs a paid archive key'
        bounty.dump(self.run / 'findings.json', [self.submittable(), blocked])
        bounty.history_check(self.run, self.ledger, project='example.invalid/test')
        self.harvest([])
        self.dup_check()
        self.assertEqual(bounty.validate(self.run, submission=True), [])

    def test_queue_flags_a_blocker_the_probe_contradicts(self):
        self.capabilities({'source-build': {'state': 'available',
                                            'reason': '`forge build` exited 0 in this checkout'}})
        self.blocked('the project cannot be built: no root manifest resolves the imports')
        result = bounty.lead_queue(self.run)
        self.assertEqual([row['capability'] for row in result['contradicted_blockers']],
                         ['source-build'])
        self.assertEqual(result['contradicted_blockers'][0]['id'], 'BP-001')
        self.assertIn('exited 0', result['contradicted_blockers'][0]['probe_reason'])

    def test_a_capability_the_probe_could_not_measure_never_accuses_a_blocker(self):
        self.capabilities({'source-build': {'state': 'unknown',
                                            'reason': 'the build was NOT executed'}})
        self.blocked('the project cannot be built: no root manifest resolves the imports')
        self.assertEqual(bounty.lead_queue(self.run)['contradicted_blockers'], [])

    def test_an_unrelated_blocker_is_not_accused_by_an_available_build(self):
        self.capabilities({'source-build': {'state': 'available', 'reason': 'exited 0'}})
        self.blocked('the owner key is held by a multisig we cannot impersonate')
        self.assertEqual(bounty.lead_queue(self.run)['contradicted_blockers'], [])

    def test_queue_reports_the_coverage_floor_once_it_was_measured(self):
        self.assertIsNone(bounty.lead_queue(self.run)['coverage_floor'])
        bounty.dump(self.run / 'coverage-floor.json',
                    {'state': 'below-floor', 'files_in_scope': 40, 'files_examined': 8,
                     'examined_fraction': 0.2, 'min_fraction': 0.8, 'unexamined_count': 32})
        floor = bounty.lead_queue(self.run)['coverage_floor']
        self.assertEqual(floor['examined_fraction'], 0.2)
        self.assertEqual(floor['unexamined_count'], 32)

    def capabilities(self, evidence):
        bounty.dump(self.run / 'capabilities.json', {'evidence': evidence})

    def test_unreadable_probe_or_floor_output_leaves_the_queue_working(self):
        (self.run / 'capabilities.json').write_text('{not json', encoding='utf-8')
        (self.run / 'coverage-floor.json').write_text('[]', encoding='utf-8')
        self.blocked('the project cannot be built')
        result = bounty.lead_queue(self.run)
        self.assertEqual(result['state'], 'open-leads')
        self.assertEqual(result['contradicted_blockers'], [])
        self.assertIsNone(result['coverage_floor'])
        self.assertEqual([row['id'] for row in result['unverified_blockers']], ['BP-001'])

    def test_a_blocker_is_classified_only_as_one_of_the_declared_states(self):
        # Downstream code compares these strings; a typo would silently mean nothing.
        for blocker in ('', 'a sentence', {}, {'claim': 'x'}, self.reproduced_blocker(),
                        None, [], 7):
            self.assertIn(bounty.blocker_state(blocker), bounty.BLOCKER_STATES, blocker)

    def test_terminal_candidate_does_not_need_a_next_experiment(self):
        row = self.candidate()
        row['next_experiment'] = {}
        row['status'] = 'refuted'
        row['rejection_reason'] = 'The caller is checked against the recorded owner.'
        self.assertEqual(self.check(row), [])

    def test_public_novelty_claim_requires_sources(self):
        row = self.candidate()
        row['novelty'] = {'status': 'no-public-match-found', 'sources': []}
        self.assertTrue(any('novelty' in e for e in self.check(row)))

    def test_verified_needs_artifacts(self):
        row = self.candidate()
        row['status'] = 'verified'
        errors = self.check(row)
        for field in ('command', 'assertion', 'negative_control', 'source_integrity',
                      'exit_code', 'log_path', 'poc_path'):
            self.assertTrue(any(field in e for e in errors), field)
        self.assertEqual(self.check(self.verified()), [])

    def test_boolean_exit_code_rejected(self):
        row = self.verified()
        row['evidence']['exit_code'] = True
        self.assertTrue(any('exit_code' in e for e in self.check(row)))

    def test_traversal_rejected(self):
        row = self.verified()
        row['evidence']['log_path'] = '../outside.txt'
        (self.base / 'outside.txt').write_text('x')
        self.assertTrue(any('inside the run' in e for e in self.check(row)))

    def test_symlink_escape_rejected(self):
        row = self.verified()
        (self.base / 'outside.txt').write_text('x')
        (self.run / 'link.txt').symlink_to(self.base / 'outside.txt')
        row['evidence']['log_path'] = 'link.txt'
        self.assertTrue(any('inside the run' in e for e in self.check(row)))

    def test_empty_evidence_file_rejected(self):
        row = self.verified()
        (self.run / 'log.txt').write_text('')
        self.assertTrue(any('must not be empty' in e for e in self.check(row)))

    # ---- submission gate ----
    def test_submission_gate_passes_a_complete_record(self):
        self.assertEqual(self.check(self.submittable(), submission=True), [])

    def test_submission_gate_requires_a_fresh_personal_history_result(self):
        row = self.submittable()
        self.assertEqual(self.check(row, submission=True), [])
        meta = bounty.read_json(self.run / 'run.json')
        meta['history_project_key'] = 'example.invalid/other-project'
        bounty.dump(self.run / 'run.json', meta)
        errors = bounty.validate(self.run, submission=True)
        self.assertTrue(any('project key changed' in error for error in errors))
        meta['history_project_key'] = 'example.invalid/test'
        bounty.dump(self.run / 'run.json', meta)
        records = bounty.read_json(self.run / 'findings.json')
        records[0]['root_cause'] = 'Changed after personal history comparison'
        bounty.dump(self.run / 'findings.json', records)
        errors = bounty.validate(self.run, submission=True)
        self.assertTrue(any('candidate mechanisms changed' in error for error in errors))
        (self.run / 'history-matches.json').unlink()
        errors = bounty.validate(self.run, submission=True)
        self.assertTrue(any('run history check before submission' in error for error in errors))

    def test_submission_gate_cannot_ignore_a_detected_personal_history_match(self):
        row = self.submittable()
        prior = bounty.history_import(
            'example.invalid/test', 'OLD-001', row['bug_class'], row['affected_paths'],
            row['root_cause'], 'duplicate', self.ledger, reason='private-duplicate')
        errors = self.check(row, submission=True)
        self.assertTrue(any('matching cases; review them' in error for error in errors))
        row['history_review'] = {
            'status': 'different-root-cause', 'case_ids': [prior['case_id']],
            'rationale': 'Same file, but the earlier report is a separate accounting path.'}
        self.assertEqual(self.check(row, submission=True), [])
        row['history_review'] = {
            'status': 'regression', 'case_ids': [prior['case_id']],
            'rationale': 'The patch to the accounting write was later removed.',
            'evidence': 'Current deployed bytecode matches commit f00ba4; the local PoC reproduces at the pinned block.'}
        self.assertEqual(self.check(row, submission=True), [])
        row['history_review']['case_ids'] = []
        errors = self.check(row, submission=True)
        self.assertTrue(any('cover every match' in error for error in errors))

    def test_submission_gate_blocks_undeployed_revision(self):
        row = self.submittable()
        row['deployment_status'] = 'unknown'
        errors = self.check(row, submission=True)
        self.assertTrue(any('deployment_status' in e for e in errors))

    def test_submission_gate_blocks_partial_bytecode_match(self):
        row = self.submittable()
        row['deployment_status'] = 'partial'
        self.assertTrue(any('deployment_status' in e for e in self.check(row, submission=True)))

    def test_submission_gate_blocks_unverified_and_out_of_scope(self):
        row = self.submittable()
        row['scope_status'] = 'unknown'
        self.assertTrue(any('scope_status' in e for e in self.check(row, submission=True)))
        row = self.submittable()
        row['status'] = 'needs-evidence'
        errors = self.check(row, submission=True)
        self.assertTrue(any('no verified records to submit' in e for e in errors))

    def test_submission_gate_requires_rubric_and_two_novelty_sources(self):
        row = self.submittable()
        del row['severity_rationale']
        row['novelty']['sources'] = ['https://example.invalid/only-one']
        errors = self.check(row, submission=True)
        self.assertTrue(any('severity_rationale' in e for e in errors))
        self.assertTrue(any('two checked novelty sources' in e for e in errors))

    def test_submission_gate_requires_quantified_impact(self):
        row = self.submittable()
        del row['evidence']['impact_quantification']
        self.assertTrue(any('impact_quantification' in e
                            for e in self.check(row, submission=True)))

    def test_submission_gate_requires_personal_history_review(self):
        row = self.submittable()
        row['history_review'] = {'status': 'unchecked', 'case_ids': [], 'rationale': ''}
        self.assertTrue(any('personal history was not checked' in e
                            for e in self.check(row, submission=True)))
        row['history_review'] = {'status': 'same-mechanism', 'case_ids': ['H-123'],
                                 'rationale': 'Same root cause as an earlier report'}
        self.assertTrue(any('same mechanism' in e
                            for e in self.check(row, submission=True)))

    def test_submission_gate_requires_reasoned_history_collision_review(self):
        row = self.submittable()
        row['history_review'] = {'status': 'different-root-cause', 'case_ids': [],
                                 'rationale': 'different function'}
        self.assertTrue(any('requires case_ids' in e
                            for e in self.check(row, submission=True)))
        row['history_review'] = {'status': 'regression', 'case_ids': ['H-123'],
                                 'rationale': ''}
        errors = self.check(row, submission=True)
        self.assertTrue(any('mechanism comparison' in e for e in errors))
        self.assertTrue(any('regression requires evidence' in e for e in errors))

    def test_submission_gate_refuses_an_empty_file(self):
        self.assertTrue(any('no verified records' in e
                            for e in bounty.validate(self.run, submission=True)))

    # ---- escalation ladder ----
    def test_the_template_carries_the_amplifier_ladder_shape(self):
        self.assertEqual(bounty.template()['escalation'],
                         {'attempted': [], 'ceiling': '', 'ceiling_evidence': ''})
        self.assertEqual(bounty.ESCALATION_AMPLIFIERS,
                         ('repetition', 'other-parties-funds', 'composition',
                          'become-the-trusted-party', 'timing', 'freeze-instead-of-theft'))

    def test_escalation_is_optional_for_an_open_candidate(self):
        # A hypothesis has not been escalated yet; only submission demands the completed ladder.
        row = self.candidate()
        del row['escalation']
        self.assertEqual(self.check(row), [])
        row['escalation'] = {'attempted': [], 'ceiling': '', 'ceiling_evidence': ''}
        self.assertEqual(self.check(row), [])

    def test_a_misshapen_escalation_is_an_error_not_a_crash(self):
        row = self.candidate()
        row['escalation'] = 'tried everything'
        self.assertTrue(any('escalation must be an object' in e for e in self.check(row)))
        row['escalation'] = {'attempted': 'repetition'}
        self.assertTrue(any('escalation.attempted must be an array' in e for e in self.check(row)))
        row['escalation'] = {'attempted': ['repetition']}
        self.assertTrue(any('attempted[0]: must be an object' in e for e in self.check(row)))
        row['escalation'] = {'attempted': [], 'ceiling': ['critical']}
        self.assertTrue(any('escalation.ceiling must be a string' in e for e in self.check(row)))
        row['escalation'] = {'attempted': [{'amplifier': 'repetition', 'result': 'not-applicable',
                                            'anchor': 7}]}
        self.assertTrue(any('anchor must be a string' in e for e in self.check(row)))

    def test_amplifier_and_result_come_from_the_fixed_sets(self):
        row = self.candidate()
        row['escalation'] = {'attempted': [{'amplifier': 'flash-loan', 'result': 'maybe'}]}
        errors = self.check(row)
        self.assertTrue(any('amplifier must be one of' in e for e in errors))
        self.assertTrue(any('result must be one of' in e for e in errors))

    def test_a_reached_or_blocked_amplifier_needs_an_anchor(self):
        # An unanchored `blocked` is an assumption, and the assumption is what files a record
        # one impact class too low.
        row = self.candidate()
        for result in ('reached', 'blocked'):
            row['escalation'] = {'attempted': [{'amplifier': 'repetition', 'result': result}]}
            self.assertTrue(any('requires an anchor' in e for e in self.check(row)), result)
        row['escalation'] = {'attempted': [{'amplifier': 'repetition',
                                            'result': 'not-applicable'}]}
        self.assertEqual(self.check(row), [])

    def test_submission_requires_every_amplifier_to_have_been_tried(self):
        row = self.submittable()
        row['escalation'] = self.escalation(
            attempted=[{'amplifier': 'repetition', 'result': 'reached',
                        'anchor': 'code: src/Vault.sol:214 no bound on deposit()'}])
        errors = self.check(row, submission=True)
        for amplifier in bounty.ESCALATION_AMPLIFIERS[1:]:
            self.assertTrue(any(amplifier in e for e in errors), amplifier)
        self.assertFalse(any('missing repetition' in e for e in errors))

    def test_submission_accepts_a_completed_ladder_of_blocked_amplifiers(self):
        # The point is a completed checklist, not a long one: blocked with an anchor is a pass.
        self.assertEqual(self.check(self.submittable(), submission=True), [])

    def test_submission_requires_an_escalation_record_at_all(self):
        row = self.submittable()
        del row['escalation']
        self.assertTrue(any('requires an escalation record' in e
                            for e in self.check(row, submission=True)))

    def test_an_amplifier_carries_exactly_one_result(self):
        row = self.submittable()
        ladder = self.escalation()
        ladder['attempted'].append(dict(ladder['attempted'][0], result='reached'))
        row['escalation'] = ladder
        errors = self.check(row, submission=True)
        self.assertTrue(any('more than once' in e and 'repetition' in e for e in errors))

    def test_queue_reports_the_amplifiers_nobody_has_tried(self):
        row = self.candidate()
        row['escalation'] = {'attempted': [{'amplifier': 'repetition', 'result': 'reached',
                                            'anchor': 'code: src/Vault.sol:214 unbounded loop'}],
                             'ceiling': '', 'ceiling_evidence': ''}
        bounty.dump(self.run / 'findings.json', [row])
        result = bounty.lead_queue(self.run)
        self.assertEqual(result['state'], 'open-leads')          # still a report, never a gate
        self.assertEqual(result['leads'][0]['escalation_gaps'],
                         list(bounty.ESCALATION_AMPLIFIERS[1:]))

    def test_queue_reports_a_refusal_made_without_one_amplifier_tried(self):
        weak = self.candidate()
        weak.update(id='BP-001', status='refuted',
                    rejection_reason='The caller is checked against the recorded owner.')
        strong = self.candidate()
        strong.update(id='BP-002', status='refuted', escalation=self.escalation(),
                      rejection_reason='Quoted guard on every writer of the aggregate.')
        bounty.dump(self.run / 'findings.json', [weak, strong])
        result = bounty.lead_queue(self.run)
        self.assertEqual([r['id'] for r in result['weak_refusals']], ['BP-001'])
        self.assertEqual(result['state'], 'all-leads-closed')     # reported, not failed
        self.assertEqual(bounty.validate(self.run), [])

    # ---- objection exchange ----
    def test_objections_must_be_an_array_of_anchored_objects(self):
        row = self.candidate()
        row['objections'] = 'none'
        self.assertTrue(any('objections must be an array' in e for e in self.check(row)))
        row['objections'] = [{'gate': 'nonsense', 'claim': '', 'outcome': 'answered'}]
        errors = self.check(row)
        self.assertTrue(any('gate must be one of' in e for e in errors))
        self.assertTrue(any('claim is required' in e for e in errors))
        self.assertTrue(any('anchor is required' in e for e in errors))

    def test_a_withdrawn_objection_needs_no_anchor(self):
        # Withdrawn means triage could not anchor it. Demanding an anchor would make the
        # outcome unrecordable, and unrecorded withdrawals are how bad objections get reused.
        row = self.candidate()
        row['objections'] = [{'gate': 'eligibility', 'outcome': 'withdrawn',
                              'claim': 'probably intended behaviour',
                              'withdrawn_because': 'no spec or code supports it'}]
        self.assertEqual(self.check(row), [])

    def test_a_sustained_objection_still_needs_an_anchor(self):
        row = self.candidate()
        row['objections'] = [{'gate': 'harm', 'claim': 'dust only', 'outcome': 'sustained'}]
        self.assertTrue(any('anchor is required' in e for e in self.check(row)))

    def test_an_answered_objection_needs_its_own_anchor(self):
        # The symmetry is the point: an unanchored answer must not defeat an anchored objection.
        row = self.candidate()
        item = self.objection()
        del item['answer_anchor']
        row['objections'] = [item]
        self.assertTrue(any('answered objection requires answer_anchor' in e
                            for e in self.check(row)))

    def test_withdrawn_and_sustained_objections_need_no_answer(self):
        for outcome in ('withdrawn', 'sustained'):
            row = self.candidate()
            row['objections'] = [self.objection(outcome)]
            self.assertEqual(self.check(row), [], outcome)

    def test_submission_requires_a_triage_exchange(self):
        row = self.submittable()
        row['objections'] = []
        self.assertTrue(any('triage exchange' in e for e in self.check(row, submission=True)))

    def test_submission_is_blocked_by_a_sustained_objection(self):
        row = self.submittable()
        row['objections'] = [self.objection(), self.objection('sustained')]
        errors = self.check(row, submission=True)
        self.assertTrue(any('sustained objection' in e for e in errors))
        self.assertTrue(any('interruption' in e for e in errors))

    def test_withdrawn_objections_do_not_block_submission(self):
        row = self.submittable()
        row['objections'] = [self.objection(), self.objection('withdrawn')]
        self.assertEqual(self.check(row, submission=True), [])

    # ---- submission targets (review 0.9.1, item 1) ----
    def test_submission_gate_applies_only_to_verified_records(self):
        # Records are never deleted: a refuted sibling and an open lead must not block the
        # verified record that is actually being submitted.
        target = self.submittable()
        refuted = self.candidate()
        refuted.update(id='BP-002', status='refuted',
                       rejection_reason='redeem() is guarded by nonReentrant on every path')
        open_lead = self.candidate()
        open_lead.update(id='BP-003', status='hypothesis')
        bounty.dump(self.run / 'findings.json', [target, refuted, open_lead])
        bounty.history_check(self.run, self.ledger, project='example.invalid/test')
        self.harvest([])
        self.dup_check()
        self.assertEqual(bounty.validate(self.run, submission=True), [])
        self.assertEqual(bounty.submission_targets(self.run), ['BP-001'])

    def test_non_target_records_still_get_structural_validation(self):
        target = self.submittable()
        broken = self.candidate()
        broken.update(id='BP-002')
        broken['next_experiment']['method'] = ''
        bounty.dump(self.run / 'findings.json', [target, broken])
        bounty.history_check(self.run, self.ledger, project='example.invalid/test')
        self.harvest([])
        self.dup_check()
        errors = bounty.validate(self.run, submission=True)
        self.assertEqual(errors, ['finding[1]: open candidate requires next_experiment.method'])

    def test_submission_with_no_verified_record_is_refused(self):
        bounty.dump(self.run / 'findings.json', [self.candidate()])
        bounty.history_check(self.run, self.ledger, project='example.invalid/test')
        errors = bounty.validate(self.run, submission=True)
        self.assertIn('findings.json: no verified records to submit', errors)

    # ---- withdrawn objections and concessions (item 2) ----
    def test_an_anchored_objection_cannot_be_withdrawn(self):
        # The bypass: an anchored (i.e. sustained) objection relabelled withdrawn passed the gate.
        row = self.submittable()
        item = self.objection('sustained')
        item['outcome'] = 'withdrawn'
        row['objections'] = [self.objection(), item]
        self.assertTrue(any('anchored objection cannot be withdrawn' in e for e in self.check(row)))
        self.assertTrue(any('anchored objection cannot be withdrawn' in e
                            for e in self.check(row, submission=True)))

    def test_withdrawn_objections_alone_are_not_a_triage_exchange(self):
        row = self.submittable()
        row['objections'] = [self.objection('withdrawn')]
        self.assertTrue(any('triage exchange' in e for e in self.check(row, submission=True)))
        row['concessions'] = [{'gate': 'harm', 'reason': 'searched for a fee cap and found none; '
                                                         'the loss is uncapped'}]
        self.assertEqual(self.check(row, submission=True), [])

    def test_concessions_are_validated(self):
        row = self.candidate()
        row['concessions'] = [{'gate': 'nonsense', 'reason': ''}, 'conceded']
        errors = self.check(row)
        self.assertTrue(any('concessions[0]: gate must be one of' in e for e in errors))
        self.assertTrue(any('concessions[0]: reason is required' in e for e in errors))
        self.assertTrue(any('concessions[1]: must be an object' in e for e in errors))
        row['concessions'] = 'all of them'
        self.assertTrue(any('concessions must be an array' in e for e in self.check(row)))

    # ---- deployment evidence (item 3) ----
    def test_hand_typed_exact_deployment_is_refused(self):
        row = self.submittable()
        del row['deployment_evidence']
        errors = self.check(row, submission=True)
        self.assertTrue(any('requires deployment_evidence' in e for e in errors))

    def test_deployment_evidence_must_report_exact_for_its_own_address(self):
        row = self.submittable()
        partial = self.deployment_evidence('0x' + '22' * 20, onchain='0x' + '60' * 40,
                                           built='0x' + '60' * 39 + '61')
        row['deployment_evidence'] = [row['deployment_evidence'][0], partial]
        errors = self.check(row, submission=True)
        self.assertTrue(any('reports partial, not exact' in e for e in errors))
        # A renamed file no longer names the address it was recorded for.
        renamed = self.run / 'deployments' / ('0x' + '33' * 20 + '.json')
        (self.run / row['deployment_evidence'][0]).rename(renamed)
        row['deployment_evidence'] = ['deployments/' + renamed.name]
        self.assertTrue(any('does not name the address' in e
                            for e in self.check(row, submission=True)))

    def test_deployment_evidence_must_live_in_the_runs_deployments_folder(self):
        row = self.submittable()
        (self.run / 'stray.json').write_text((self.run / row['deployment_evidence'][0]).read_text())
        for bad in ('stray.json', '../outside.json', '/etc/hosts', 'deployments/missing.json'):
            row['deployment_evidence'] = [bad]
            self.assertTrue(any("deployments/ folder" in e
                                for e in self.check(row, submission=True)), bad)
        row['deployment_evidence'] = 42
        self.assertTrue(any('deployment_evidence must be a string' in e for e in self.check(row)))

    def test_deployment_evidence_goes_stale_when_the_artifact_changes(self):
        row = self.submittable()
        record = json.loads((self.run / row['deployment_evidence'][0]).read_text())
        Path(record['artifact']['path']).write_text(json.dumps({'deployedBytecode': '0x00'}))
        errors = self.check(row, submission=True)
        self.assertTrue(any('artifact changed after it was compared' in e for e in errors))

    def test_not_applicable_needs_a_rationale_and_no_contract_source(self):
        row = self.submittable()
        row['deployment_status'] = 'not-applicable'
        row['deployment_evidence'] = []
        errors = self.check(row, submission=True)
        self.assertTrue(any('requires deployment_rationale' in e for e in errors))
        self.assertTrue(any('refused for deployed contract source' in e for e in errors))
        row['deployment_rationale'] = 'Off-chain keeper service; no contract code involved.'
        row['affected_paths'] = ['services/keeper/main.go:submitBatch']
        self.assertEqual(self.check(row, submission=True), [])
        row['affected_paths'] = ['contracts/Pool.vy:withdraw']
        self.assertTrue(any('refused for deployed contract source' in e
                            for e in self.check(row, submission=True)))

    def test_verify_deployment_run_must_be_an_init_run(self):
        node = FakeNode({})
        with self.assertRaisesRegex(ValueError, 'created by init'):
            bounty.verify_deployment('http://node.invalid', '0x' + '11' * 20, None, 'latest',
                                     opener=node, run=self.base)
        self.assertEqual(node.calls, [])

    def test_verify_deployment_saves_the_full_result_into_the_run(self):
        rel = self.deployment_evidence('0x' + 'AB' * 20)
        self.assertEqual(rel, 'deployments/0x' + 'ab' * 20 + '.json')
        record = json.loads((self.run / rel).read_text())
        self.assertEqual(record['address'], '0x' + 'AB' * 20)
        self.assertEqual(record['deployment_status'], 'exact')
        self.assertEqual((record['chain_id'], record['block']), (1, 256))
        self.assertEqual(record['proxy_kind'], 'none')
        self.assertIsNone(record['implementation_address'])
        self.assertEqual(record['artifact']['sha256'],
                         bounty._sha256_file(record['artifact']['path']))
        self.assertIn('reason', record['comparison'])
        self.assertNotIn('node.invalid', json.dumps(record))   # the RPC URL may carry a key

    # ---- wrong JSON types (item 12) ----
    def test_wrong_types_are_errors_not_crashes(self):
        row = self.submittable()
        row['novelty'] = {'status': ['no-public-match-found'], 'sources': ['a', 'b']}
        row['history_review'] = {'status': {'no': 'match'}, 'case_ids': [], 'rationale': 'x'}
        row['objections'] = [{'gate': ['harm'], 'claim': 'c', 'anchor': 'a',
                              'outcome': {'answered': True}}]
        errors = self.check(row, submission=True)
        for expected in ('invalid novelty.status', 'invalid history_review.status',
                         'gate must be one of', 'outcome must be one of'):
            self.assertTrue(any(expected in e for e in errors), expected)
        row['novelty'] = 'checked'
        row['id'] = ['BP-001']
        errors = self.check(row, submission=True)
        self.assertTrue(any('novelty must be an object' in e for e in errors))

    def test_dup_map_with_wrong_types_is_reported(self):
        bounty.dump(self.run / 'findings.json', [self.candidate()])
        bounty.dump(self.run / 'dup-map.json', [{'id': 'KI-000', 'kind': ['past-audit'],
                                                 'source': 's',
                                                 'surfaces': ['src/Vault.sol'],
                                                 'bug_classes': 'aggregate-not-decremented'}])
        errors, _ = bounty.check_dup_map(self.run)
        self.assertTrue(any('kind must be one of' in e for e in errors))
        self.assertTrue(any('bug_classes must be a string array' in e for e in errors))

    # ---- small ones (item 15) ----
    def test_dup_check_treats_a_string_path_as_one_path(self):
        row = self.candidate()
        row['affected_paths'] = 'src/Vault.sol'
        bounty.dump(self.run / 'findings.json', [row])
        bounty.dump(self.run / 'dup-map.json', [{
            'id': 'KI-006', 'kind': 'past-audit', 'source': 'https://example.invalid/a',
            'surfaces': ['lib/Other.sol']}])
        self.assertEqual(bounty.check_dup_map(self.run), ([], []))   # was: matched on 'l'
        bounty.dump(self.run / 'dup-map.json', [{
            'id': 'KI-006', 'kind': 'past-audit', 'source': 'https://example.invalid/a',
            'surfaces': ['src/Vault.sol']}])
        self.assertEqual(len(bounty.check_dup_map(self.run)[1]), 1)

    def test_an_invalid_project_is_an_error_not_a_fallback(self):
        bounty.dump(self.run / 'findings.json', [self.verified()])
        with self.assertRaisesRegex(ValueError, '--project must be'):
            bounty.history_check(self.run, self.ledger, project='not a project')
        with self.assertRaisesRegex(ValueError, '--project must be'):
            bounty.history_record(self.run, 'BP-001', 'submitted', self.ledger,
                                  project='nonsense')

    # ---- duplicate map ----
    def test_dup_check_is_clean_on_an_empty_map(self):
        bounty.dump(self.run / 'findings.json', [self.candidate()])
        self.assertEqual(bounty.check_dup_map(self.run), ([], []))

    def test_dup_check_matches_surface_and_class(self):
        bounty.dump(self.run / 'findings.json', [self.candidate()])
        bounty.dump(self.run / 'dup-map.json', [{
            'id': 'KI-001', 'kind': 'program-known-issue',
            'source': 'https://example.invalid/known-issues',
            'surfaces': ['src/Vault.sol'],
            'bug_classes': ['aggregate-not-decremented'], 'note': 'acknowledged'}])
        errors, collisions = bounty.check_dup_map(self.run)
        self.assertEqual(errors, [])
        self.assertEqual(collisions[0]['confidence'], 'class-match')

    def test_dup_check_reports_surface_only_when_the_class_differs(self):
        bounty.dump(self.run / 'findings.json', [self.candidate()])
        bounty.dump(self.run / 'dup-map.json', [{
            'id': 'KI-002', 'kind': 'past-audit', 'source': 'https://example.invalid/audit',
            'surfaces': ['src/Vault.sol'], 'bug_classes': ['oracle-staleness']}])
        errors, collisions = bounty.check_dup_map(self.run)
        self.assertEqual(errors, [])
        self.assertEqual([(c['entry'], c['confidence']) for c in collisions],
                         [('KI-002', 'surface-only')])
        bounty.dump(self.run / 'dup-map.json', [{
            'id': 'KI-003', 'kind': 'past-audit', 'source': 'https://example.invalid/audit',
            'surfaces': ['src/Vault.sol']}])
        _, collisions = bounty.check_dup_map(self.run)
        self.assertEqual(collisions[0]['confidence'], 'surface-only')

    def test_dup_check_ignores_refuted_findings_and_validates_the_map(self):
        row = self.candidate()
        row['status'] = 'refuted'
        row['rejection_reason'] = 'guarded'
        bounty.dump(self.run / 'findings.json', [row])
        bounty.dump(self.run / 'dup-map.json', [{
            'id': 'KI-004', 'kind': 'program-known-issue', 'source': 'https://x.invalid',
            'surfaces': ['src/Vault.sol']}])
        self.assertEqual(bounty.check_dup_map(self.run), ([], []))
        bounty.dump(self.run / 'dup-map.json', [{'id': 'KI-005', 'kind': 'invented'}])
        errors, _ = bounty.check_dup_map(self.run)
        self.assertTrue(any('kind' in e for e in errors))
        self.assertTrue(any('source' in e for e in errors))

    def test_dup_map_entries_need_an_id_the_gate_can_cite(self):
        bounty.dump(self.run / 'findings.json', [self.candidate()])
        bounty.dump(self.run / 'dup-map.json', [
            {'kind': 'past-audit', 'source': 'https://x.invalid/a', 'surfaces': ['src/Vault.sol']},
            {'id': 'KI-010', 'kind': 'past-audit', 'source': 'https://x.invalid/b',
             'surfaces': ['src/Vault.sol']},
            {'id': 'KI-010', 'kind': 'past-audit', 'source': 'https://x.invalid/c',
             'surfaces': ['src/Vault.sol']}])
        errors, _ = bounty.check_dup_map(self.run)
        self.assertTrue(any('dup-map[0]: id is required' in e for e in errors))
        self.assertTrue(any('duplicate id KI-010' in e for e in errors))

    # ---- the duplicate gate ----
    def judged_issue(self, number=506):
        return {'number': number, 'html_url': f'https://example.invalid/i/{number}',
                'title': 'CS Note 8.12: Zapper remove manager requires increased trust',
                'labels': [{'name': 'ChainSecurity'}, {'name': 'wontfix'}],
                'closed_at': '2025-02-01T00:00:00Z',
                'body': 'The removeManager can decide the swap parameters. Accepted risk.'}

    def ready_for_submission(self, row):
        """Everything the gate needs except the duplicate artifacts under test."""
        bounty.dump(self.run / 'findings.json', [row])
        bounty.history_check(self.run, self.ledger, project='example.invalid/test')

    def test_submission_requires_the_closed_issue_harvest(self):
        row = self.submittable()
        self.ready_for_submission(row)
        self.dup_check()
        errors = bounty.validate(self.run, submission=True)
        self.assertTrue(any('requires the closed-issue harvest' in e for e in errors))
        self.harvest([])
        self.assertEqual(bounty.validate(self.run, submission=True), [])

    def test_an_untriaged_harvested_issue_blocks_submission(self):
        row = self.submittable()
        self.ready_for_submission(row)
        self.harvest([self.judged_issue()])
        self.dup_check()
        errors = bounty.validate(self.run, submission=True)
        self.assertTrue(any('untriaged' in e and '#506' in e for e in errors))
        self.harvest([self.judged_issue()],
                     triage={'#506': {'disposition': 'irrelevant',
                                      'note': 'other contract, no shared surface'}})
        self.assertEqual(bounty.validate(self.run, submission=True), [])

    def test_in_map_triage_must_name_an_entry_the_map_holds(self):
        row = self.submittable()
        self.ready_for_submission(row)
        self.harvest([self.judged_issue()],
                     triage={'#506': {'disposition': 'in-map', 'entry_id': 'KI-404'}})
        self.dup_check()
        errors = bounty.validate(self.run, submission=True)
        self.assertTrue(any('untriaged' in e and '#506' in e for e in errors))
        bounty.dump(self.run / 'dup-map.json', [{
            'id': 'KI-404', 'kind': 'program-known-issue',
            'source': 'https://example.invalid/i/506 (read 2026-10-12)',
            'surfaces': ['src/Zappers/LeverageWETHZapper.sol'],
            'bug_classes': ['caller-supplied-swap-floor'], 'note': 'wontfix'}])
        self.dup_check()
        self.assertEqual(bounty.validate(self.run, submission=True), [])

    def test_a_harvest_stopped_at_the_limit_blocks_submission(self):
        row = self.submittable()
        self.ready_for_submission(row)
        self.harvest([])
        data = bounty.read_json(self.run / 'dup-harvest.json')
        data['truncated'] = True
        bounty.dump(self.run / 'dup-harvest.json', data)
        self.dup_check()
        errors = bounty.validate(self.run, submission=True)
        self.assertTrue(any('stopped at --limit' in e for e in errors))

    def collided(self):
        """A submittable record whose surface and class the map already holds."""
        row = self.submittable()
        bounty.dump(self.run / 'dup-map.json', [{
            'id': 'KI-001', 'kind': 'program-known-issue',
            'source': 'https://example.invalid/known-issues (read 2026-10-12)',
            'surfaces': ['src/Vault.sol'], 'bug_classes': ['aggregate-not-decremented'],
            'note': 'team states the mismatch is accepted'}])
        return row

    def test_a_collision_cannot_be_filed_as_no_match(self):
        row = self.collided()
        self.ready_for_submission(row)
        self.harvest([])
        self.dup_check()
        errors = bounty.validate(self.run, submission=True)
        self.assertTrue(any('collided with KI-001' in e for e in errors))

    def test_a_surface_only_collision_must_be_reviewed_before_submission(self):
        # Same surface, different consequence label: one root cause is often filed under another
        # class, so the entry must still be compared rather than slip through as no-match.
        row = self.submittable()
        bounty.dump(self.run / 'dup-map.json', [{
            'id': 'C4-QA-01', 'kind': 'contest-finding',
            'source': 'https://example.invalid/report (read 2026-10-14)',
            'surfaces': ['src/Vault.sol'], 'bug_classes': ['donation-inflates-measured-yield']}])
        self.ready_for_submission(row)
        self.harvest([])
        self.dup_check()
        errors = bounty.validate(self.run, submission=True)
        self.assertTrue(any('collided with C4-QA-01' in e for e in errors))
        row['dup_review'] = {'status': 'different-mechanism', 'entry_ids': ['C4-QA-01'],
                             'rationale': 'The QA note reports the yield reading only; this one '
                                          'moves funds between depositors'}
        self.ready_for_submission(row)
        self.dup_check()
        self.assertEqual(bounty.validate(self.run, submission=True), [])

    def test_a_reviewed_collision_must_cover_every_entry_and_say_why(self):
        row = self.collided()
        row['dup_review'] = {'status': 'different-mechanism', 'entry_ids': [], 'rationale': ''}
        self.ready_for_submission(row)
        self.harvest([])
        self.dup_check()
        errors = bounty.validate(self.run, submission=True)
        self.assertTrue(any('requires the entry_ids' in e for e in errors))
        self.assertTrue(any('requires the mechanism comparison' in e for e in errors))
        row['dup_review'] = {'status': 'different-mechanism', 'entry_ids': ['KI-999'],
                             'rationale': 'The known issue is about the owner oversizing the loan; '
                                          'this one needs no owner action at all'}
        self.ready_for_submission(row)
        self.dup_check()
        errors = bounty.validate(self.run, submission=True)
        self.assertTrue(any('must cover every dup-check collision; missing KI-001' in e
                            for e in errors))
        row['dup_review']['entry_ids'] = ['KI-001', 'KI-999']
        self.ready_for_submission(row)
        self.dup_check()
        self.assertEqual(bounty.validate(self.run, submission=True), [])

    def test_same_mechanism_blocks_submission_and_keeps_the_record(self):
        row = self.collided()
        row['dup_review'] = {'status': 'same-mechanism', 'entry_ids': ['KI-001'],
                             'rationale': 'Same actor, same swap floor, same victim'}
        self.ready_for_submission(row)
        self.harvest([])
        self.dup_check()
        errors = bounty.validate(self.run, submission=True)
        self.assertTrue(any('do not submit' in e and 'rejection_reason' in e for e in errors))

    def test_an_unchecked_dup_review_blocks_submission(self):
        row = self.submittable()
        row['dup_review'] = {'status': 'unchecked', 'entry_ids': [], 'rationale': ''}
        errors = self.check(row, submission=True)
        self.assertTrue(any('duplicate map was not reviewed' in e for e in errors))
        row.pop('dup_review')
        errors = self.check(row, submission=True)
        self.assertTrue(any('submission requires a dup_review' in e for e in errors))

    def test_a_map_that_grows_after_the_join_invalidates_it(self):
        row = self.submittable()
        self.assertEqual(self.check(row, submission=True), [])
        bounty.dump(self.run / 'dup-map.json', [{
            'id': 'KI-007', 'kind': 'public-disclosure', 'source': 'https://x.invalid/post',
            'surfaces': ['src/Vault.sol'], 'bug_classes': ['aggregate-not-decremented']}])
        errors = bounty.validate(self.run, submission=True)
        self.assertTrue(any('duplicate map changed after the join' in e for e in errors))
        self.dup_check()
        errors = bounty.validate(self.run, submission=True)
        self.assertTrue(any('collided with KI-007' in e for e in errors))

    def test_a_join_from_another_run_or_stale_findings_is_refused(self):
        row = self.submittable()
        self.assertEqual(self.check(row, submission=True), [])
        data = bounty.read_json(self.run / 'dup-matches.json')
        data['run_id'] = 'other'
        bounty.dump(self.run / 'dup-matches.json', data)
        self.assertTrue(any('belongs to a different run' in e
                            for e in bounty.validate(self.run, submission=True)))
        self.dup_check()
        row['root_cause'] = 'Changed after the duplicate join'
        bounty.dump(self.run / 'findings.json', [row])
        self.assertTrue(any('dup-matches.json: candidate mechanisms changed' in e
                            for e in bounty.validate(self.run, submission=True)))
        (self.run / 'dup-matches.json').unlink()
        self.assertTrue(any('run dup-check before submission' in e
                            for e in bounty.validate(self.run, submission=True)))

    def test_an_invalid_map_is_not_certified_by_a_join(self):
        bounty.dump(self.run / 'dup-map.json', [{'id': 'KI-008', 'kind': 'invented',
                                                 'surfaces': ['src/Vault.sol']}])
        bounty.dump(self.run / 'findings.json', [self.candidate()])
        result = self.dup_check()
        self.assertEqual(result['state'], 'invalid-map')
        self.assertFalse((self.run / 'dup-matches.json').is_file())

    # ---- the closed-issue harvest ----
    def test_dup_harvest_searches_the_labels_that_say_already_judged(self):
        seen = []

        def opener(request, timeout=None):
            seen.append(request.full_url)
            if '/labels' in request.full_url:
                return FakeResponse([{'name': 'wontfix'}, {'name': 'ChainSecurity'},
                                     {'name': 'enhancement'}])
            return FakeResponse({'total_count': 1, 'items': [self.judged_issue()]})

        result = bounty.dup_harvest(self.run, repo='https://github.com/liquity/bold',
                                    opener=opener)
        self.assertEqual(result['repo'], 'liquity/bold')
        self.assertEqual(result['labels'], ['ChainSecurity', 'wontfix'])
        self.assertEqual(result['untriaged'], ['#506'])
        self.assertEqual(result['candidates'][0]['url'], 'https://example.invalid/i/506')
        query = urllib.parse.unquote([url for url in seen if '/search/' in url][0])
        self.assertIn('repo:liquity/bold is:closed label:"ChainSecurity","wontfix"', query)
        self.assertTrue(all('enhancement' not in url for url in seen))

    def test_dup_harvest_keeps_triage_for_issues_still_present(self):
        self.harvest([self.judged_issue(506), self.judged_issue(777)],
                     triage={'#506': {'disposition': 'irrelevant', 'note': 'other contract'},
                             '#777': {'disposition': 'irrelevant', 'note': 'docs only'}})
        result = self.harvest([self.judged_issue(506)])
        self.assertEqual(sorted(result['triage']), ['#506'])
        self.assertEqual(result['untriaged'], [])

    def test_dup_harvest_never_writes_the_duplicate_map_itself(self):
        self.harvest([self.judged_issue()])
        self.assertEqual(bounty.read_json(self.run / 'dup-map.json'), [])

    def test_dup_labels_match_whole_words_and_cover_more_firms(self):
        names = ['Recon', 'reconciliation', 'Coinspect', 'status:wontfix', 'Zappers',
                 'Known Issues', 'unknown issue tracker']
        self.assertEqual(bounty._dup_label_candidates(names),
                         ['Coinspect', 'Known Issues', 'Recon', 'status:wontfix'])

    def test_dup_harvest_reports_the_labels_it_did_not_select(self):
        def opener(request, timeout=None):
            if '/labels' in request.full_url:
                return FakeResponse([{'name': 'wontfix'}, {'name': 'Recon'},
                                     {'name': 'Obscure Audit Co'}, {'name': 'bug'}])
            return FakeResponse({'total_count': 0, 'items': []})

        result = bounty.dup_harvest(self.run, repo='liquity/bold', opener=opener)
        self.assertEqual(result['labels'], ['Recon', 'wontfix'])
        self.assertEqual(result['labels_skipped'], ['bug', 'Obscure Audit Co'])

    def test_a_harvest_that_searched_nothing_blocks_submission(self):
        def opener(request, timeout=None):
            if '/labels' in request.full_url:
                return FakeResponse([{'name': 'type:bug'}, {'name': 'rpc'}])
            raise AssertionError('nothing should be searched without a judged label')

        row = self.submittable()
        self.ready_for_submission(row)
        result = bounty.dup_harvest(self.run, repo='ethereum/go-ethereum', opener=opener)
        self.assertTrue(result['vacuous'])
        self.assertIn('warning', result)
        self.dup_check()
        errors = bounty.validate(self.run, submission=True)
        self.assertTrue(any('searched nothing and certifies nothing' in e for e in errors))
        bounty.dup_harvest(self.run, repo='ethereum/go-ethereum', opener=opener,
                           empty_reason='security reports go through GHSA advisories; '
                                        'checked https://github.com/ethereum/go-ethereum/security')
        self.assertEqual(bounty.validate(self.run, submission=True), [])
        # The reason survives a rerun that does not repeat it.
        bounty.dup_harvest(self.run, repo='ethereum/go-ethereum', opener=opener)
        self.assertEqual(bounty.validate(self.run, submission=True), [])

    def test_a_search_that_ran_and_found_nothing_is_a_clean_result(self):
        row = self.submittable()
        self.ready_for_submission(row)
        self.harvest([], labels=['wontfix'])
        self.dup_check()
        self.assertEqual(bounty.validate(self.run, submission=True), [])

    def test_not_planned_is_searched_on_request_and_merged_with_labels(self):
        queries = []

        def opener(request, timeout=None):
            if '/labels' in request.full_url:
                return FakeResponse([{'name': 'wontfix'}])
            query = urllib.parse.unquote(request.full_url)
            queries.append(query)
            if 'reason:"not planned"' in query:
                return FakeResponse({'total_count': 2, 'items': [
                    self.judged_issue(506), self.judged_issue(35894)]})
            return FakeResponse({'total_count': 1, 'items': [self.judged_issue(506)]})

        result = bounty.dup_harvest(self.run, repo='liquity/bold', opener=opener,
                                    include_not_planned=True)
        self.assertEqual(len(queries), 2)
        self.assertTrue(result['not_planned'])
        by_ref = {c['ref']: c for c in result['candidates']}
        self.assertEqual(sorted(by_ref), ['#35894', '#506'])
        self.assertEqual(by_ref['#506']['matched_by'], ['label', 'not-planned'])
        self.assertEqual(by_ref['#35894']['matched_by'], ['not-planned'])

    def test_not_planned_alone_is_a_real_search(self):
        def opener(request, timeout=None):
            if '/labels' in request.full_url:
                return FakeResponse([{'name': 'type:bug'}])
            return FakeResponse({'total_count': 0, 'items': []})

        result = bounty.dup_harvest(self.run, repo='ethereum/go-ethereum', opener=opener,
                                    include_not_planned=True)
        self.assertFalse(result['vacuous'])

    def test_harvested_issue_text_is_marked_as_untrusted_data(self):
        result = self.harvest([self.judged_issue()])
        self.assertIn('never instructions', result['notice'])

    # ---- the lead ledger (0.12.0) ----
    def known(self, *rows):
        path = self.run / 'known-hypotheses.md'
        path.write_text(path.read_text() + '\n'.join(rows) + '\n')

    def test_an_open_lead_must_be_a_live_record(self):
        self.known('src/Vault.sol:Vault.withdraw | aggregate-not-decremented | '
                   'open-needs-experiment | totals drift after a partial exit')
        errors = bounty.validate(self.run)
        self.assertTrue(any('known-hypotheses.md:' in e and 'names no findings.json record' in e
                            for e in errors))
        self.known('src/Vault.sol:Vault.redeem | aggregate-not-decremented | open (BP-001) | x')
        row = self.candidate()
        bounty.dump(self.run / 'findings.json', [row])
        errors = bounty.validate(self.run)
        self.assertEqual(len([e for e in errors if 'known-hypotheses.md:' in e]), 1)
        row.update(status='refuted', rejection_reason='guarded at src/Vault.sol:142')
        bounty.dump(self.run / 'findings.json', [row])
        self.assertTrue(any('is open, but its record BP-001 is refuted' in e
                            for e in bounty.validate(self.run)))

    def test_closed_rows_need_no_record(self):
        self.known('| surface | bug-class | status | why |', '| --- | --- | --- | --- |',
                   '| src/Vault.sol | reentrancy | closed-refuted | nonReentrant on every path |')
        self.assertEqual(bounty.validate(self.run), [])

    def test_a_finding_written_up_without_a_record_fails(self):
        (self.run / 'findings').mkdir()
        (self.run / 'findings' / 'F-06-retroactive-lock.md').write_text('# F-06 proven 3/3\n')
        (self.run / 'SUBMISSION-DRAFT-F06.md').write_text('Subject: [BOUNTY] lock\n')
        errors = bounty.validate(self.run)
        self.assertTrue(any(e.startswith('findings/F-06-retroactive-lock.md:') for e in errors))
        self.assertTrue(any(e.startswith('SUBMISSION-DRAFT-F06.md:') for e in errors))
        bounty.dump(self.run / 'findings.json', [self.candidate()])
        (self.run / 'findings' / 'F-06-retroactive-lock.md').write_text('# F-06 = BP-001\n')
        (self.run / 'SUBMISSION-DRAFT-F06.md').write_text('Record BP-001\n')
        self.assertEqual(bounty.validate(self.run), [])

    def parked(self, **park):
        row = self.candidate()
        row['status'] = 'parked'
        row['park'] = dict({'reason': 'uneconomic-now',
                            'revive_if': 'deposits above 2M MOR, at which the window pays',
                            'evidence': 'test/LumpCredit.t.sol passes at block 52400000'}, **park)
        return row

    def test_parked_needs_a_reason_a_revive_condition_and_evidence(self):
        row = self.parked()
        self.assertEqual(self.check(row), [])
        row['park'] = {'reason': 'boring', 'revive_if': '', 'evidence': ''}
        errors = self.check(row)
        self.assertTrue(any('park.reason must be one of' in e for e in errors))
        self.assertTrue(any('park.revive_if' in e for e in errors))
        self.assertTrue(any('park.evidence' in e for e in errors))
        row.pop('park')
        self.assertTrue(any('parked requires a park object' in e for e in self.check(row)))

    def test_parked_stays_in_the_duplicate_join_and_is_never_submitted(self):
        bounty.dump(self.run / 'dup-map.json', [{
            'id': 'KI-020', 'kind': 'past-audit', 'source': 'https://x.invalid/a',
            'surfaces': ['src/Vault.sol'], 'bug_classes': ['aggregate-not-decremented']}])
        bounty.dump(self.run / 'findings.json', [self.parked()])
        self.assertEqual(len(bounty.check_dup_map(self.run)[1]), 1)
        self.assertEqual(bounty.submission_targets(self.run), [])
        refuted = self.candidate()
        refuted.update(status='refuted', rejection_reason='guarded at src/Vault.sol:142')
        bounty.dump(self.run / 'findings.json', [refuted])
        self.assertEqual(bounty.check_dup_map(self.run)[1], [])

    def test_queue_shows_what_would_otherwise_be_lost(self):
        open_lead = self.candidate()
        parked = self.parked()
        parked['id'] = 'BP-002'
        buried = self.candidate()
        buried.update(id='BP-003', status='refuted',
                      rejection_reason='The mechanism is real, reproduced three times, but the '
                                       'finding is ineligible under the program rules')
        bounty.dump(self.run / 'findings.json', [open_lead, parked, buried])
        self.known('src/Vault.sol:Vault.sweep | stale-index | open-blocked | needs an RPC key')
        result = bounty.lead_queue(self.run)
        self.assertEqual(result['state'], 'open-leads')
        self.assertEqual([lead['id'] for lead in result['leads']], ['BP-001'])
        self.assertEqual(result['untracked_leads'][0]['bug_class'], 'stale-index')
        self.assertEqual(result['parked'][0]['revive_if'],
                         'deposits above 2M MOR, at which the window pays')
        self.assertEqual([row['id'] for row in result['possibly_parked']], ['BP-003'])

    def test_an_untracked_lead_alone_keeps_the_queue_open(self):
        self.known('src/Vault.sol | stale-index | open-needs-experiment | x')
        result = bounty.lead_queue(self.run)
        self.assertEqual(result['state'], 'open-leads')
        self.assertEqual(len(result['untracked_leads']), 1)

    def test_dup_harvest_explains_a_rate_limited_github(self):
        def opener(request, timeout=None):
            # A real body: on Python 3.9 an HTTPError built without one cannot be closed.
            error = urllib.error.HTTPError(request.full_url, 403, 'rate limited', {},
                                           io.BytesIO(b''))
            self.addCleanup(error.close)
            raise error

        with self.assertRaisesRegex(ValueError, '--from-file'):
            bounty.dup_harvest(self.run, repo='liquity/bold', opener=opener)

    # ---- review artifacts the repository ships ----
    def inventory(self, *artifacts):
        """Record an audit-inventory result without walking a checkout."""
        bounty.dump(self.run / 'audit-inventory.json',
                    {'repo': str(self.repo), 'artifact_count': len(artifacts),
                     'artifacts': list(artifacts)})

    def artifact(self, path='audits/report.pdf', triage='unreviewed', note=''):
        return {'path': path, 'bytes': 10, 'sha256': 'ab' * 32, 'firm': 'spearbit',
                'matched_by': 'review directory', 'triage': triage, 'note': note}

    def test_an_unreviewed_audit_artifact_blocks_submission(self):
        self.inventory(self.artifact(), self.artifact('audits/second.pdf', 'read'))
        errors = self.check(self.submittable(), submission=True)
        self.assertTrue(any('audits/report.pdf' in error for error in errors), errors)
        self.assertTrue(any('not-applicable' in error for error in errors), errors)
        self.assertFalse(any('audits/second.pdf' in error for error in errors), errors)

    def test_a_triaged_audit_artifact_does_not_block_submission(self):
        self.inventory(self.artifact(triage='read'),
                       self.artifact('audits/old.pdf', 'not-applicable',
                                     note='covers v1, out of this scope'),
                       self.artifact('audits/named.pdf', 'unavailable'))
        self.assertEqual(self.check(self.submittable(), submission=True), [])

    def test_a_run_with_no_inventory_is_blocked_and_an_empty_one_is_not(self):
        # Stage 1 requires the inventory; a target that ships no review writes an empty one.
        self.assertEqual(self.check(self.submittable(), submission=True), [])
        self.assertEqual(bounty.read_json(self.run / 'audit-inventory.json')['artifacts'], [])
        (self.run / 'audit-inventory.json').unlink()
        errors = bounty.validate(self.run, submission=True)
        self.assertTrue(any(e.startswith('audit-inventory.json: missing') for e in errors), errors)

    def test_not_applicable_without_a_reason_is_still_unreviewed(self):
        self.inventory(self.artifact(triage='not-applicable'))
        errors = self.check(self.submittable(), submission=True)
        self.assertTrue(any('audits/report.pdf' in error for error in errors), errors)

    def test_an_unknown_triage_word_is_never_read_as_accounted_for(self):
        self.inventory(self.artifact(triage='probably fine'))
        errors = self.check(self.submittable(), submission=True)
        self.assertTrue(any('audits/report.pdf' in error for error in errors), errors)

    def test_a_hand_broken_inventory_is_an_error_not_a_crash(self):
        for payload in ('{not json', '[]', '{"artifacts": {}}', '{"artifacts": [7]}'):
            (self.run / 'audit-inventory.json').write_text(payload, encoding='utf-8')
            errors = self.check(self.submittable(), submission=True)
            self.assertTrue(any('audit-inventory.json' in error for error in errors), payload)

    def test_queue_reports_the_shipped_review_artifacts(self):
        self.assertIsNone(bounty.lead_queue(self.run)['audit_inventory'])
        self.inventory(self.artifact(), self.artifact('audits/second.pdf', 'read'))
        reported = bounty.lead_queue(self.run)['audit_inventory']
        self.assertEqual(reported['artifacts'], 2)
        self.assertEqual(reported['unreviewed_count'], 1)
        self.assertEqual(reported['unreviewed'], ['audits/report.pdf'])
        self.assertEqual(reported['triage'], {'unreviewed': 1, 'read': 1})

    def test_an_invalid_run_still_reports_the_inventory_field(self):
        self.inventory(self.artifact())
        bounty.dump(self.run / 'findings.json', [{'id': 'BP-001'}])
        result = bounty.lead_queue(self.run)
        self.assertEqual(result['state'], 'invalid')
        self.assertEqual(result['audit_inventory']['unreviewed_count'], 1)


class AuditInventoryTests(unittest.TestCase):
    """Royco, Squads and marginfi all ship their reviews in the checkout; nothing listed them."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        (self.repo / 'audits').mkdir()
        (self.repo / 'docs').mkdir()
        git(self.repo, 'init', '-q')
        (self.repo / 'src/Vault.sol').write_text('contract Vault {}\n')
        # A PDF is bytes, not text: the inventory must still list and hash it.
        (self.repo / 'audits/2023-03-ChainSecurity.pdf').write_bytes(b'%PDF-1.4\x00\xff report')
        (self.repo / 'audits/notes.md').write_text('findings\n')
        (self.repo / 'docs/2024-trail-of-bits-assessment.md').write_text('assessment\n')
        (self.repo / 'docs/reconciliation.md').write_text('how settlement reconciles\n')
        (self.repo / 'SECURITY.md').write_text('# Security\n\nAudited by Spearbit in 2024.\n')
        (self.repo / 'README.md').write_text('readme\n')
        commit(self.repo, 'fixture')
        self.run = self.base / 'run'
        bounty.initialize(self.repo, self.run)

    def paths(self, result):
        return [row['path'] for row in result['artifacts']]

    def test_artifacts_are_found_in_every_location_shape(self):
        result = bounty.audit_inventory(self.repo, self.run)
        self.assertEqual(self.paths(result),
                         ['SECURITY.md', 'audits/2023-03-ChainSecurity.pdf', 'audits/notes.md',
                          'docs/2024-trail-of-bits-assessment.md'])
        by_path = {row['path']: row for row in result['artifacts']}
        self.assertEqual(by_path['audits/notes.md']['matched_by'], 'review directory')
        self.assertEqual(by_path['docs/2024-trail-of-bits-assessment.md']['matched_by'],
                         'review-shaped name')
        self.assertEqual(by_path['SECURITY.md']['matched_by'],
                         'security policy naming a review')
        self.assertNotIn('src/Vault.sol', self.paths(result))
        self.assertNotIn('README.md', self.paths(result))

    def test_a_firm_is_attributed_from_the_name_and_a_pdf_is_hashed_not_read(self):
        result = bounty.audit_inventory(self.repo, self.run)
        by_path = {row['path']: row for row in result['artifacts']}
        self.assertEqual(by_path['audits/2023-03-ChainSecurity.pdf']['firm'], 'chainsecurity')
        self.assertEqual(by_path['docs/2024-trail-of-bits-assessment.md']['firm'],
                         'trail of bits')
        self.assertIsNone(by_path['audits/notes.md']['firm'])
        self.assertEqual(result['firms'], ['chainsecurity', 'trail of bits'])
        blob = (self.repo / 'audits/2023-03-ChainSecurity.pdf').read_bytes()
        self.assertEqual(by_path['audits/2023-03-ChainSecurity.pdf']['sha256'],
                         hashlib.sha256(blob).hexdigest())
        self.assertEqual(by_path['audits/2023-03-ChainSecurity.pdf']['bytes'], len(blob))

    def test_the_firm_list_is_the_one_dup_harvest_maintains(self):
        # One list, two callers: a firm added for the label search is attributable here too.
        self.assertTrue(set(bounty.AUDIT_FIRM_HINTS).issubset(bounty.AUDITOR_LABEL_HINTS))
        self.assertNotIn('audit report', bounty.AUDIT_FIRM_HINTS)

    def test_a_short_firm_name_is_not_matched_inside_a_longer_word(self):
        # `recon` is a firm and also the first five letters of reconciliation.
        self.assertIsNone(bounty._audit_firm('docs/reconciliation-review.md'))
        self.assertEqual(bounty._audit_firm('audits/recon-2024.pdf'), 'recon')

    def test_a_security_policy_that_names_no_review_is_not_an_artifact(self):
        (self.repo / 'SECURITY.md').write_text('# Security\n\nMail security@example.invalid.\n')
        commit(self.repo, 'plain policy')
        self.assertNotIn('SECURITY.md', self.paths(bounty.audit_inventory(self.repo, self.run)))

    def test_a_symlinked_artifact_is_never_followed(self):
        outside = self.base / 'outside.pdf'
        outside.write_bytes(b'%PDF secret')
        os.symlink(outside, self.repo / 'audits/linked-audit.pdf')
        commit(self.repo, 'symlink')
        result = bounty.audit_inventory(self.repo, self.run)
        self.assertNotIn('audits/linked-audit.pdf', self.paths(result))
        self.assertIn({'path': 'audits/linked-audit.pdf',
                       'reason': 'not a regular file in the checkout'}, result['skipped_files'])

    def test_an_oversize_report_is_listed_without_a_hash_and_disclosed(self):
        with mock.patch.object(bounty, 'AUDIT_ARTIFACT_MAX_BYTES', 4):
            result = bounty.audit_inventory(self.repo, self.run)
        by_path = {row['path']: row for row in result['artifacts']}
        self.assertIsNone(by_path['audits/2023-03-ChainSecurity.pdf']['sha256'])
        self.assertTrue(any(row['path'] == 'audits/2023-03-ChainSecurity.pdf'
                            and 'larger than' in row['reason']
                            for row in result['skipped_files']), result['skipped_files'])
        # Unhashable is not the same as absent: it still has to be accounted for.
        self.assertIn('audits/2023-03-ChainSecurity.pdf', result['unreviewed'])

    def test_every_artifact_starts_unreviewed(self):
        result = bounty.audit_inventory(self.repo, self.run)
        self.assertEqual(result['unreviewed_count'], 4)
        self.assertTrue(all(row['triage'] == 'unreviewed' for row in result['artifacts']))
        self.assertEqual(bounty.read_json(self.run / 'audit-inventory.json')['artifact_count'], 4)

    def test_triage_survives_a_rerun_while_the_bytes_hold(self):
        bounty.audit_inventory(self.repo, self.run)
        data = bounty.read_json(self.run / 'audit-inventory.json')
        for row in data['artifacts']:
            row['triage'] = 'read'
        data['artifacts'][0]['triage'] = 'not-applicable'
        data['artifacts'][0]['note'] = 'covers the v1 deployment'
        bounty.dump(self.run / 'audit-inventory.json', data)
        again = bounty.audit_inventory(self.repo, self.run)
        self.assertEqual(again['unreviewed'], [])
        self.assertEqual(again['artifacts'][0]['note'], 'covers the v1 deployment')

    def test_a_replaced_report_is_a_report_nobody_has_read(self):
        bounty.audit_inventory(self.repo, self.run)
        data = bounty.read_json(self.run / 'audit-inventory.json')
        for row in data['artifacts']:
            row['triage'] = 'read'
        bounty.dump(self.run / 'audit-inventory.json', data)
        (self.repo / 'audits/notes.md').write_text('findings, revision two\n')
        commit(self.repo, 'new revision of the report')
        again = bounty.audit_inventory(self.repo, self.run)
        self.assertEqual(again['unreviewed'], ['audits/notes.md'])

    def test_the_gate_fails_while_an_artifact_is_unreviewed(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = bounty.main(['audit-inventory', '--repo', str(self.repo),
                                '--run', str(self.run), '--gate'])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out.getvalue())['unreviewed_count'], 4)
        data = bounty.read_json(self.run / 'audit-inventory.json')
        for row in data['artifacts']:
            row['triage'] = 'read'
        bounty.dump(self.run / 'audit-inventory.json', data)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(bounty.main(['audit-inventory', '--repo', str(self.repo),
                                          '--run', str(self.run), '--gate']), 0)

    def test_without_the_gate_an_unreviewed_artifact_is_reported_not_failed(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(bounty.main(['audit-inventory', '--repo', str(self.repo),
                                          '--run', str(self.run)]), 0)

    def test_a_repository_shipping_no_review_writes_an_empty_inventory(self):
        for name in ('SECURITY.md', 'audits/notes.md', 'audits/2023-03-ChainSecurity.pdf',
                     'docs/2024-trail-of-bits-assessment.md'):
            (self.repo / name).unlink()
        commit(self.repo, 'no reviews')
        result = bounty.audit_inventory(self.repo, self.run)
        self.assertEqual(result['artifact_count'], 0)
        self.assertEqual(result['unreviewed'], [])

    def test_a_hand_broken_inventory_does_not_block_the_rerun_that_replaces_it(self):
        (self.run / 'audit-inventory.json').write_text('{not json', encoding='utf-8')
        result = bounty.audit_inventory(self.repo, self.run)
        self.assertEqual(result['artifact_count'], 4)
        self.assertEqual(result['unreviewed_count'], 4)

    def test_the_inventory_is_never_written_through_a_symlink(self):
        os.symlink(self.base / 'elsewhere.json', self.run / 'audit-inventory.json')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            bounty.audit_inventory(self.repo, self.run)

    def test_the_inventory_is_refused_outside_a_run_directory(self):
        with self.assertRaisesRegex(ValueError, 'run directory created by init'):
            bounty.audit_inventory(self.repo, self.base / 'not-a-run')

    def test_the_inventory_is_never_written_into_the_target(self):
        (self.repo / 'inside').mkdir()
        (self.repo / 'inside' / 'run.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'outside the target'):
            bounty.audit_inventory(self.repo, self.repo / 'inside')


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        git(self.repo, 'remote', 'add', 'origin',
            'https://user:secret@example.invalid/org/vault.git')
        (self.repo / 'src/Vault.sol').write_text('contract Vault {}\n')
        commit(self.repo, 'fixture')
        self.run = self.base / 'run'
        bounty.initialize(self.repo, self.run)
        row = bounty.template()
        row.update(title='Fee accounting can be withdrawn twice', status='verified',
                   severity='medium', root_cause='Withdraw does not decrement accrued fee',
                   affected_paths=['src/Vault.sol:Vault.withdraw'],
                   bug_class='fee-accounting-not-decremented',
                   revision=bounty.read_json(self.run / 'run.json')['commit'],
                   attacker_capabilities='Unprivileged depositor',
                   preconditions='A fee has accrued', impact='Fee can be claimed twice')
        (self.run / 'poc.py').write_text('assert True\n')
        (self.run / 'log.txt').write_text('reproduced\n')
        row['evidence'] = {'command': 'python3 poc.py', 'exit_code': 0,
                           'log_path': 'log.txt', 'poc_path': 'poc.py',
                           'assertion': 'Fee total increases twice',
                           'negative_control': 'control did not increase total',
                           'source_integrity': 'Original checkout; no storage edits'}
        bounty.dump(self.run / 'findings.json', [row])
        self.ledger = self.base / 'private' / 'history.jsonl'

    def test_project_key_strips_credentials_and_git_suffix(self):
        self.assertEqual(bounty.canonical_project(
            'https://researcher:token@example.invalid/org/vault.git'),
            'example.invalid/org/vault')
        self.assertEqual(bounty.read_json(self.run / 'run.json')['project_key'],
                         'example.invalid/org/vault')

    def test_history_record_is_private_and_contains_no_report_artifacts(self):
        result = bounty.history_record(self.run, 'BP-001', 'duplicate', self.ledger,
                                       program='Cantina', reason='private-duplicate', hours=3.5)
        self.assertTrue(result['case_id'].startswith('H-'))
        self.assertEqual(stat.S_IMODE(self.ledger.stat().st_mode), 0o600)
        stored = json.loads(self.ledger.read_text().splitlines()[0])
        self.assertEqual(stored['project_key'], 'example.invalid/org/vault')
        self.assertEqual(stored['disposition'], 'duplicate')
        for private_key in ('report_text', 'source', 'poc_path', 'wallet', 'credentials'):
            self.assertNotIn(private_key, stored)

    def test_history_record_recovers_project_key_from_target_remote(self):
        meta = bounty.read_json(self.run / 'run.json')
        meta['project_key'] = None
        bounty.dump(self.run / 'run.json', meta)
        result = bounty.history_record(self.run, 'BP-001', 'submitted', self.ledger)
        stored = json.loads(self.ledger.read_text().splitlines()[0])
        self.assertEqual(stored['project_key'], 'example.invalid/org/vault')
        self.assertEqual(result['disposition'], 'submitted')

    def test_explicit_project_key_is_reused_by_later_history_commands(self):
        git(self.repo, 'remote', 'remove', 'origin')
        meta = bounty.read_json(self.run / 'run.json')
        meta['project_key'] = None
        bounty.dump(self.run / 'run.json', meta)
        first = bounty.history_check(self.run, self.ledger, project='example.invalid/org/vault')
        self.assertEqual(first['project_key'], 'example.invalid/org/vault')
        second = bounty.history_check(self.run, self.ledger)
        self.assertEqual(second['project_key'], 'example.invalid/org/vault')
        recorded = bounty.history_record(self.run, 'BP-001', 'submitted', self.ledger)
        stored = json.loads(self.ledger.read_text().splitlines()[0])
        self.assertEqual(recorded['disposition'], 'submitted')
        self.assertEqual(stored['project_key'], 'example.invalid/org/vault')

    def test_history_record_reports_missing_project_instead_of_crashing(self):
        git(self.repo, 'remote', 'remove', 'origin')
        meta = bounty.read_json(self.run / 'run.json')
        meta['project_key'] = None
        bounty.dump(self.run / 'run.json', meta)
        with self.assertRaisesRegex(ValueError, 'No canonical repository remote'):
            bounty.history_record(self.run, 'BP-001', 'submitted', self.ledger)

    def test_history_permissions_have_a_portable_fallback(self):
        with mock.patch.object(bounty.os, 'fchmod', None, create=True):
            bounty.history_record(self.run, 'BP-001', 'submitted', self.ledger)
        self.assertEqual(stat.S_IMODE(self.ledger.stat().st_mode), 0o600)

    def test_history_check_surfaces_same_project_matches_without_calling_them_duplicates(self):
        recorded = bounty.history_record(self.run, 'BP-001', 'submitted', self.ledger)
        next_run = self.base / 'run-again'
        bounty.initialize(self.repo, next_run)
        bounty.dump(next_run / 'findings.json', json.loads((self.run / 'findings.json').read_text()))
        result = bounty.history_check(next_run, self.ledger)
        self.assertEqual(result['state'], 'review-required')
        match = result['matches'][0]
        self.assertEqual(match['case_id'], recorded['case_id'])
        self.assertIn('same-project', match['relationship'])
        self.assertIn('not an automatic duplicate', match['relationship'])
        self.assertTrue((next_run / 'history-matches.json').is_file())

    def test_history_check_seeds_the_first_pass_with_own_prior_cases(self):
        recorded = bounty.history_record(self.run, 'BP-001', 'paid', self.ledger)
        empty_run = self.base / 'empty-run'
        bounty.initialize(self.repo, empty_run)
        result = bounty.history_check(empty_run, self.ledger)
        self.assertEqual(result['matches'], [])
        self.assertEqual(result['prior_cases_total'], 1)
        self.assertEqual(result['prior_cases'][0]['case_id'], recorded['case_id'])
        self.assertIn('Withdraw does not decrement',
                      result['prior_cases'][0]['root_cause_summary'])

    def test_old_report_can_be_imported_without_copying_its_report_text(self):
        imported = bounty.history_import(
            'https://example.invalid/org/vault.git', 'C4-123',
            'fee-accounting-not-decremented', ['src/Vault.sol:Vault.withdraw'],
            'Withdraw fails to decrement the accrued fee', 'duplicate', self.ledger,
            program='Code4rena', reason='private-duplicate', lens='accounting')
        self.assertEqual(imported['disposition'], 'duplicate')
        stored = json.loads(self.ledger.read_text().splitlines()[0])
        self.assertEqual(stored['finding_id'], 'C4-123')
        self.assertNotIn('report_text', stored)
        self.assertNotIn('poc_path', stored)
        result = bounty.history_check(self.run, self.ledger)
        self.assertEqual(result['matches'][0]['case_id'], imported['case_id'])

    def test_same_run_report_does_not_match_itself(self):
        bounty.history_record(self.run, 'BP-001', 'submitted', self.ledger)
        result = bounty.history_check(self.run, self.ledger)
        self.assertEqual(result['matches'], [])

    def test_cross_project_match_is_only_a_related_pattern(self):
        bounty.history_record(self.run, 'BP-001', 'accepted', self.ledger)
        next_run = self.base / 'fork-run'
        bounty.initialize(self.repo, next_run)
        bounty.dump(next_run / 'findings.json', json.loads((self.run / 'findings.json').read_text()))
        result = bounty.history_check(next_run, self.ledger, project='example.invalid/forked-vault')
        self.assertEqual(result['matches'][0]['relationship'],
                         'other project: related pattern, not a duplicate')

    def test_history_summary_uses_latest_event_per_case(self):
        first = bounty.history_record(self.run, 'BP-001', 'duplicate', self.ledger)
        bounty.history_record(self.run, 'BP-001', 'paid', self.ledger, case_id=first['case_id'])
        summary = bounty.history_summary(self.ledger)
        self.assertEqual(summary['reports'], 1)
        self.assertEqual(summary['dispositions']['paid'], 1)
        self.assertEqual(summary['dispositions']['duplicate'], 0)
        self.assertEqual(summary['duplicate_of_decided'], '0 of 1')

    def test_case_id_cannot_be_reused_for_a_different_report(self):
        first = bounty.history_record(self.run, 'BP-001', 'submitted', self.ledger)
        second_run = self.base / 'run-other-finding'
        bounty.initialize(self.repo, second_run)
        (second_run / 'poc.py').write_text('assert True\n')
        (second_run / 'log.txt').write_text('reproduced\n')
        first_finding = json.loads((self.run / 'findings.json').read_text())[0]
        first_finding['id'] = 'BP-002'
        bounty.dump(second_run / 'findings.json', [first_finding])
        with self.assertRaisesRegex(ValueError, 'different report'):
            bounty.history_record(second_run, 'BP-002', 'paid', self.ledger,
                                  case_id=first['case_id'])

    def test_history_file_inside_target_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'outside the target'):
            bounty.history_check(self.run, self.repo / 'history.jsonl')

    def test_corrupt_history_is_an_error_not_a_clean_result(self):
        self.ledger.parent.mkdir()
        self.ledger.write_text('{not-json}\n')
        with self.assertRaisesRegex(ValueError, 'line 1'):
            bounty.history_check(self.run, self.ledger)

    def test_structurally_corrupt_history_fields_are_reported(self):
        self.ledger.parent.mkdir()
        self.ledger.write_text(json.dumps({
            'schema_version': 1, 'case_id': 'H-bad', 'recorded_at': 'today',
            'project_key': 'example.invalid/repo', 'finding_id': 'old',
            'bug_class': 'unsafe-math', 'affected_paths': [],
            'root_cause_summary': 'root cause', 'disposition': 'paid'}) + '\n')
        with self.assertRaisesRegex(ValueError, 'invalid affected_paths'):
            bounty.history_check(self.run, self.ledger)


class BulkHistoryImportTests(unittest.TestCase):
    """A report went out duplicating the hunter's own earlier one, because importing an
    account's submissions one twelve-flag command at a time never happened."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.ledger = self.base / 'private' / 'history.jsonl'
        self.records = [
            {'finding_id': 'C4-123', 'bug_class': 'fee-accounting-not-decremented',
             'surface': 'src/Vault.sol:Vault.withdraw',
             'root_cause': 'Withdraw does not decrement the accrued fee',
             'outcome': 'duplicate', 'reason': 'private-duplicate', 'hours': 4},
            {'finding_id': 'C4-124', 'bug_class': 'oracle-staleness',
             'affected_paths': ['src/Oracle.sol', 'src/Feed.sol'],
             'root_cause': 'A stale round is accepted as fresh', 'outcome': 'paid'},
        ]

    def write(self, name, text):
        path = self.base / name
        path.write_text(text, encoding='utf-8')
        return path

    def rows(self):
        return bounty._history_rows(self.ledger.resolve())

    def test_a_json_array_export_imports_every_record(self):
        source = self.write('export.json', json.dumps(self.records))
        result = bounty.history_bulk_import(source, self.ledger,
                                            project='https://example.invalid/org/vault.git')
        self.assertEqual(result['shape'], 'json-array')
        self.assertEqual((result['added'], result['already_present'], result['updated'],
                          result['rejected']), (2, 0, 0, 0))
        stored = self.rows()
        self.assertEqual([row['finding_id'] for row in stored], ['C4-123', 'C4-124'])
        self.assertEqual({row['project_key'] for row in stored}, {'example.invalid/org/vault'})
        self.assertEqual(stored[0]['effort_hours'], 4.0)
        self.assertEqual(stored[1]['affected_paths'], ['src/Oracle.sol', 'src/Feed.sol'])

    def test_an_object_holding_the_list_is_read(self):
        source = self.write('export.json', json.dumps({'total': 2, 'reports': self.records}))
        result = bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')
        self.assertEqual(result['shape'], 'json-object')
        self.assertEqual(result['added'], 2)

    def test_a_sole_unnamed_list_in_an_object_is_read(self):
        source = self.write('export.json', json.dumps({'anything': self.records}))
        self.assertEqual(bounty.history_bulk_import(source, self.ledger,
                                                    project='example.invalid/org/v')['added'], 2)

    def test_an_object_with_two_lists_is_refused_rather_than_guessed(self):
        source = self.write('export.json', json.dumps({'a': self.records, 'b': [1]}))
        with self.assertRaisesRegex(ValueError, 'no single list of records'):
            bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')

    def test_json_lines_are_read(self):
        source = self.write('export.jsonl',
                            '\n'.join(json.dumps(row) for row in self.records) + '\n')
        result = bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')
        self.assertEqual(result['shape'], 'json-lines')
        self.assertEqual(result['added'], 2)

    def test_a_csv_export_is_read(self):
        source = self.write('export.csv',
                            'ID,Bug Class,Surface,Root Cause,Status,Hours\n'
                            'C4-123,Fee Accounting,"src/Vault.sol:withdraw",'
                            'Withdraw keeps the fee,Duplicate,4\n'
                            'C4-124,oracle-staleness,"src/Oracle.sol;src/Feed.sol",'
                            'Stale round accepted,Paid,\n')
        result = bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')
        self.assertEqual(result['shape'], 'csv')
        self.assertEqual((result['added'], result['rejected']), (2, 0))
        stored = self.rows()
        self.assertEqual(stored[0]['bug_class'], 'fee-accounting')
        self.assertEqual(stored[1]['affected_paths'], ['src/Oracle.sol', 'src/Feed.sol'])
        self.assertIsNone(stored[1]['effort_hours'])

    def test_the_spellings_an_export_uses_all_map_onto_the_ledger(self):
        source = self.write('export.json', json.dumps([{
            'id': 'IMM-7', 'title': 'ignored once id is present', 'category': 'Access Control',
            'paths': 'programs/vault/src/lib.rs:handler', 'summary': 'Missing signer check',
            'status': 'Out of Scope', 'program_name': 'Immunefi / Vault',
            'repository': 'example.invalid/org/vault', 'effort': '2.5',
            'reason_category': 'out-of-scope', 'lens': 'Privileged Path',
            'platform_url': 'https://example.invalid/report/7'}]))
        result = bounty.history_bulk_import(source, self.ledger)
        self.assertEqual(result['added'], 1)
        self.assertEqual(result['unmapped_keys'], ['platform_url'])
        row = self.rows()[0]
        self.assertEqual(row['finding_id'], 'IMM-7')
        self.assertEqual(row['bug_class'], 'access-control')
        self.assertEqual(row['disposition'], 'out-of-scope')
        self.assertEqual(row['program'], 'Immunefi / Vault')
        self.assertEqual(row['lens'], 'privileged-path')
        self.assertEqual(row['effort_hours'], 2.5)
        self.assertEqual(row['affected_paths'], ['programs/vault/src/lib.rs:handler'])

    def test_reimporting_the_same_export_adds_nothing(self):
        source = self.write('export.json', json.dumps(self.records))
        bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')
        again = bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')
        self.assertEqual((again['added'], again['already_present'], again['updated']), (0, 2, 0))
        self.assertEqual(len(self.ledger.read_text().splitlines()), 2)

    def test_a_refreshed_export_updates_the_same_case(self):
        source = self.write('export.json', json.dumps(self.records))
        first = bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')
        decided = [dict(self.records[0], outcome='paid'), self.records[1]]
        source.write_text(json.dumps(decided), encoding='utf-8')
        again = bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')
        self.assertEqual((again['added'], again['already_present'], again['updated']), (0, 1, 1))
        self.assertEqual(again['cases_updated'][0]['was'], 'duplicate')
        self.assertEqual(again['cases_updated'][0]['case_id'],
                         first['cases_added'][0]['case_id'])
        summary = bounty.history_summary(self.ledger)
        self.assertEqual(summary['reports'], 2)
        self.assertEqual(summary['dispositions']['paid'], 2)
        self.assertEqual(summary['dispositions']['duplicate'], 0)

    def test_a_malformed_record_is_rejected_with_its_reason_while_the_rest_import(self):
        bad = [{'finding_id': 'X-1', 'bug_class': '', 'surface': 'src/A.sol',
                'root_cause': 'no class', 'outcome': 'paid'},
               {'finding_id': 'X-2', 'bug_class': 'ok-class', 'surface': 'src/A.sol',
                'root_cause': 'bad outcome', 'outcome': 'maybe-someday'},
               {'finding_id': 'X-3', 'bug_class': 'ok-class', 'surface': '',
                'root_cause': 'no surface', 'outcome': 'paid'},
               'not even an object']
        source = self.write('export.json', json.dumps(self.records + bad))
        result = bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')
        self.assertEqual((result['added'], result['rejected']), (2, 4))
        reasons = [row['reason'] for row in result['rejected_records']]
        self.assertTrue(any('bug_class' in reason for reason in reasons), reasons)
        self.assertTrue(any('outcome must be one of' in reason for reason in reasons), reasons)
        self.assertTrue(any('surface' in reason for reason in reasons), reasons)
        self.assertIn('not a JSON object', reasons)
        self.assertEqual([row['record'] for row in result['rejected_records']],
                         ['record 3', 'record 4', 'record 5', 'record 6'])
        self.assertEqual(len(self.rows()), 2)

    def test_one_unparseable_line_does_not_lose_the_others(self):
        source = self.write('export.jsonl',
                            json.dumps(self.records[0]) + '\n{broken\n'
                            + json.dumps(self.records[1]) + '\n')
        result = bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')
        self.assertEqual((result['added'], result['rejected']), (2, 1))
        self.assertEqual(result['rejected_records'],
                         [{'record': 'line 2', 'reason': 'not valid JSON'}])

    def test_a_record_with_no_project_and_no_default_is_rejected(self):
        source = self.write('export.json', json.dumps(self.records))
        result = bounty.history_bulk_import(source, self.ledger)
        self.assertEqual((result['added'], result['rejected']), (0, 2))
        self.assertTrue(all('no project' in row['reason']
                            for row in result['rejected_records']))
        self.assertFalse(self.ledger.exists())

    def test_a_record_names_its_own_project_over_the_default(self):
        source = self.write('export.json', json.dumps(
            [dict(self.records[0], project='example.invalid/org/other')]))
        bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/vault')
        self.assertEqual(self.rows()[0]['project_key'], 'example.invalid/org/other')

    def test_a_project_url_with_credentials_is_stored_without_them(self):
        source = self.write('export.json', json.dumps(
            [dict(self.records[0], project='https://user:token@example.invalid/org/vault.git')]))
        bounty.history_bulk_import(source, self.ledger)
        self.assertEqual(self.rows()[0]['project_key'], 'example.invalid/org/vault')
        self.assertNotIn('token', self.ledger.read_text())

    def test_dry_run_reports_the_same_counts_and_writes_nothing(self):
        source = self.write('export.json', json.dumps(self.records))
        dry = bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v',
                                         dry_run=True)
        self.assertTrue(dry['dry_run'])
        self.assertEqual(dry['added'], 2)
        self.assertFalse(self.ledger.exists())
        wet = bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')
        self.assertEqual((wet['added'], wet['already_present']), (dry['added'], 0))
        self.assertEqual(len(self.rows()), 2)

    def test_dry_run_on_a_second_pass_reports_what_is_already_there(self):
        source = self.write('export.json', json.dumps(self.records))
        bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')
        dry = bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v',
                                         dry_run=True)
        self.assertEqual((dry['added'], dry['already_present']), (0, 2))
        self.assertEqual(len(self.ledger.read_text().splitlines()), 2)

    def test_the_bulk_ledger_keeps_the_single_record_invariants(self):
        source = self.write('export.json', json.dumps(self.records))
        bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v',
                                   program='Cantina / Vault')
        self.assertEqual(stat.S_IMODE(self.ledger.stat().st_mode), 0o600)
        stored = json.loads(self.ledger.read_text().splitlines()[0])
        self.assertEqual(stored['schema_version'], bounty.HISTORY_SCHEMA)
        self.assertEqual(stored['program'], 'Cantina / Vault')
        self.assertTrue(stored['case_id'].startswith('H-'))
        for private_key in ('report_text', 'source', 'poc_path', 'wallet', 'credentials',
                            'platform_url', 'nonsense_key'):
            self.assertNotIn(private_key, stored)

    def test_the_ledger_is_never_written_through_a_symlink(self):
        self.ledger.parent.mkdir()
        os.symlink(self.base / 'elsewhere.jsonl', self.ledger)
        source = self.write('export.json', json.dumps(self.records))
        with self.assertRaisesRegex(ValueError, 'symlink'):
            bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')

    def test_a_ledger_inside_the_target_checkout_is_refused(self):
        repo = self.base / 'repo'
        repo.mkdir()
        git(repo, 'init', '-q')
        (repo / 'src.sol').write_text('contract A {}\n')
        commit(repo, 'fixture')
        source = self.write('export.json', json.dumps(self.records))
        with mock.patch.object(bounty, 'git', return_value=str(repo)):
            with self.assertRaisesRegex(ValueError, 'outside the target'):
                bounty.history_bulk_import(source, repo / 'history.jsonl',
                                           project='example.invalid/org/v')

    def test_a_corrupt_ledger_is_an_error_before_anything_is_appended(self):
        self.ledger.parent.mkdir()
        self.ledger.write_text('{not-json}\n')
        source = self.write('export.json', json.dumps(self.records))
        with self.assertRaisesRegex(ValueError, 'line 1'):
            bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')

    def test_a_bad_program_default_is_refused_before_the_file_is_read(self):
        with self.assertRaisesRegex(ValueError, '--program'):
            bounty.history_bulk_import(self.base / 'missing.json', self.ledger,
                                       project='example.invalid/org/v', program='x' * 121)

    def test_a_file_that_is_no_export_is_an_error_not_a_clean_result(self):
        source = self.write('export.json', 'this is prose, not an export\n')
        with self.assertRaisesRegex(ValueError, 'JSON Lines'):
            bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')
        source = self.write('number.json', '42')
        with self.assertRaisesRegex(ValueError, 'list of exported reports'):
            bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')

    def test_an_unknown_case_id_in_the_export_is_rejected_not_invented(self):
        source = self.write('export.json', json.dumps(
            [dict(self.records[0], case_id='H-neverseen')]))
        result = bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')
        self.assertEqual((result['added'], result['rejected']), (0, 1))
        self.assertIn('unknown case_id', result['rejected_records'][0]['reason'])

    def test_a_case_id_from_another_report_is_rejected(self):
        source = self.write('export.json', json.dumps(self.records))
        first = bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')
        stolen = dict(self.records[1], case_id=first['cases_added'][0]['case_id'])
        source.write_text(json.dumps([stolen]), encoding='utf-8')
        result = bounty.history_bulk_import(source, self.ledger, project='example.invalid/org/v')
        self.assertEqual((result['added'], result['rejected']), (0, 1))
        self.assertIn('different report', result['rejected_records'][0]['reason'])

    def test_what_was_imported_is_what_history_check_joins_against(self):
        repo = self.base / 'repo'
        (repo / 'src').mkdir(parents=True)
        git(repo, 'init', '-q')
        git(repo, 'remote', 'add', 'origin', 'https://example.invalid/org/vault.git')
        (repo / 'src/Vault.sol').write_text('contract Vault {}\n')
        commit(repo, 'fixture')
        run = self.base / 'run'
        bounty.initialize(repo, run)
        row = bounty.template()
        row.update(title='Fee can be withdrawn twice', root_cause='Withdraw does not decrement '
                   'the accrued fee', affected_paths=['src/Vault.sol:Vault.withdraw'],
                   bug_class='fee-accounting-not-decremented', revision='abc1234',
                   attacker_capabilities='Depositor', preconditions='A fee accrued',
                   impact='Fee claimed twice',
                   next_experiment={'question': 'q', 'method': 'm', 'expected_evidence': 'e',
                                    'blocker': ''})
        bounty.dump(run / 'findings.json', [row])
        source = self.write('export.json', json.dumps(self.records))
        bounty.history_bulk_import(source, self.ledger,
                                   project='https://example.invalid/org/vault.git')
        result = bounty.history_check(run, self.ledger)
        self.assertEqual(result['state'], 'review-required')
        self.assertEqual(result['prior_cases_total'], 2)
        self.assertEqual(result['matches'][0]['disposition'], 'duplicate')

    def test_the_single_record_form_still_asks_for_its_flags(self):
        with self.assertRaisesRegex(ValueError, '--finding-id.*--from-file'):
            bounty.history_import('example.invalid/org/v', None, 'fee-accounting',
                                  ['src/A.sol'], 'cause', 'paid', self.ledger)

    def test_the_cli_wires_both_import_forms(self):
        source = self.write('export.json', json.dumps(self.records))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = bounty.main(['history', 'import', '--from-file', str(source),
                                '--ledger', str(self.ledger), '--project',
                                'example.invalid/org/vault', '--dry-run'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())['added'], 2)
        self.assertFalse(self.ledger.exists())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = bounty.main(['history', 'import', '--ledger', str(self.ledger),
                                '--project', 'example.invalid/org/vault', '--dry-run'])
        self.assertEqual(code, 2)
        self.assertIn('--dry-run', err.getvalue())


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.repo = base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        (self.repo / 'test').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        (self.repo / 'src/Vault.sol').write_text('contract Vault { uint256 totalDebt; }\n')
        (self.repo / 'test/Vault.t.sol').write_text('contract VaultTest { Vault v; }\n')
        commit(self.repo, 'fixture')
        self.run = base / 'run'
        bounty.initialize(self.repo, self.run)

    def test_one_bundle_per_lens_with_source_and_lens_text(self):
        result = bounty.bundle(self.repo, self.run, ['accounting', 'liveness'])
        self.assertEqual([b['lens'] for b in result['bundles']], ['accounting', 'liveness'])
        text = (self.run / 'bundles/accounting-bundle.md').read_text()
        self.assertIn('contract Vault', text)                      # source bundled
        self.assertIn('every writer of every aggregate', text)     # the lens procedure
        self.assertIn('Shared hunt rules', text)                   # the shared stance
        self.assertIn('plain words', text)                         # the SOP
        self.assertIn('Lens: **accounting**', text)                # restated task footer

    def test_bundles_include_relevant_configs_but_exclude_secret_files(self):
        (self.repo / 'foundry.toml').write_text(
            '[profile.default]\nsolc_version = "0.8.24"\napi_key = "do-not-bundle"\n')
        (self.repo / 'deployments').mkdir()
        (self.repo / 'deployments/mainnet.json').write_text('{"proxy":"0x1234"}\n')
        (self.repo / '.env.local').write_text('PRIVATE_KEY=do-not-bundle\n')
        (self.repo / 'configs').mkdir()
        (self.repo / 'configs/prod-secrets.yaml').write_text('api_key: do-not-bundle\n')
        commit(self.repo, 'add config fixtures')
        result = bounty.bundle(self.repo, self.run, ['accounting'])
        text = (self.run / 'bundles/accounting-bundle.md').read_text()
        self.assertIn('solc_version', text)
        self.assertIn('mainnet.json', text)
        self.assertNotIn('do-not-bundle', text)
        self.assertGreaterEqual(result['config_files_bundled'], 2)
        self.assertIn('<redacted>', text)

    def test_groups_expand_and_duplicates_collapse(self):
        result = bounty.bundle(self.repo, self.run, ['attack', 'accounting'])
        lenses = [b['lens'] for b in result['bundles']]
        self.assertEqual(lenses, list(bounty.ATTACK_LENSES))

    def test_every_registered_lens_has_an_instruction_file(self):
        for lens in bounty.LENSES:
            path = (bounty.SKILL_ROOT / 'references/hunt-agents' / f'{lens}-agent.md')
            self.assertTrue(path.is_file(), lens)
        result = bounty.bundle(self.repo, self.run, ['all'])
        self.assertEqual([b['lens'] for b in result['bundles']], list(bounty.LENSES))

    def test_privileged_path_leads_the_attack_group(self):
        # Access control and initialization are the categories automated reviewers miss most.
        self.assertEqual(bounty.ATTACK_LENSES[0], 'privileged-path')

    def test_lens_attribution_is_validated_against_the_registry(self):
        row = bounty.template()
        row.update(title='t', root_cause='r', affected_paths=['src/Vault.sol'],
                   bug_class='x-y', revision='abc', attacker_capabilities='a',
                   preconditions='p', impact='i',
                   next_experiment={'question': 'q', 'method': 'm',
                                    'expected_evidence': 'e', 'blocker': ''})
        run = self.run
        row['lens'] = 'accounting'
        bounty.dump(run / 'findings.json', [row])
        self.assertEqual(bounty.validate(run), [])
        row['lens'] = 'not-a-lens'
        bounty.dump(run / 'findings.json', [row])
        self.assertTrue(any('lens must be one of' in e for e in bounty.validate(run)))

    def test_bundles_carry_the_impact_ladder_and_the_precedents(self):
        bounty.bundle(self.repo, self.run, ['economics'])
        text = (self.run / 'bundles/economics-bundle.md').read_text()
        self.assertIn('Direct theft of funds', text)
        self.assertIn('What has actually been exploited', text)

    def test_unknown_lens_is_refused(self):
        with self.assertRaises(ValueError):
            bounty.bundle(self.repo, self.run, ['reentrancy'])

    def test_only_the_coverage_gap_lens_receives_the_tests(self):
        bounty.bundle(self.repo, self.run, ['coverage-gap', 'accounting'])
        gap = (self.run / 'bundles/coverage-gap-bundle.md').read_text()
        acc = (self.run / 'bundles/accounting-bundle.md').read_text()
        self.assertIn('contract VaultTest', gap)
        self.assertNotIn('contract VaultTest', acc)

    def test_scoped_bundles_only_carry_the_relevant_tests(self):
        # Bundling every test file in the repo defeats --scope: a real target with 105 test files
        # produced a 1.7 MB coverage-gap bundle, too large for a lens to read.
        (self.repo / 'test/Unrelated.t.sol').write_text('contract UnrelatedTest { Other o; }\n')
        (self.repo / 'test/Mentions.t.sol').write_text('// exercises Vault indirectly\ncontract M {}\n')
        commit(self.repo, 'more tests')
        result = bounty.bundle(self.repo, self.run, ['coverage-gap'],
                               scope_prefixes=['src/'])
        text = (self.run / 'bundles/coverage-gap-bundle.md').read_text()
        self.assertIn('contract VaultTest', text)          # filename matches src/Vault.sol
        self.assertIn('exercises Vault indirectly', text)  # mentions an in-scope stem
        self.assertNotIn('contract UnrelatedTest', text)   # neither -> omitted
        self.assertEqual(result['test_files_omitted'], 1)
        self.assertIn('omitted', text)                     # the omission is disclosed in the bundle

    def test_unscoped_bundles_still_carry_every_test(self):
        (self.repo / 'test/Unrelated.t.sol').write_text('contract UnrelatedTest { Other o; }\n')
        commit(self.repo, 'more tests')
        result = bounty.bundle(self.repo, self.run, ['coverage-gap'])
        self.assertEqual(result['test_files_omitted'], 0)
        self.assertIn('contract UnrelatedTest',
                      (self.run / 'bundles/coverage-gap-bundle.md').read_text())

    def test_test_files_are_never_in_the_in_scope_source(self):
        bounty.bundle(self.repo, self.run, ['accounting'])
        source = (self.run / 'bundles/source.md').read_text()
        self.assertIn('src/Vault.sol', source)
        self.assertNotIn('test/Vault.t.sol', source)

    def test_triage_bundle_carries_records_and_not_the_hunt_stance(self):
        row = bounty.template()
        row.update(title='t', root_cause='r', affected_paths=['src/Vault.sol'],
                   bug_class='aggregate-not-decremented', revision='abc1234',
                   attacker_capabilities='a', preconditions='p', impact='i')
        bounty.dump(self.run / 'findings.json', [row])
        bounty.bundle(self.repo, self.run, ['triage'])
        text = (self.run / 'bundles/triage-bundle.md').read_text()
        self.assertIn('records under review', text)
        self.assertIn('aggregate-not-decremented', text)
        self.assertIn('OBJECTION', text)
        self.assertIn('Direct theft of funds', text)      # the impact ladder
        self.assertNotIn('Shared hunt rules', text)       # never the no-self-refutation stance

    def test_seam_bundle_carries_the_earlier_records_to_cross(self):
        bounty.dump(self.run / 'findings.json', [])
        bounty.bundle(self.repo, self.run, ['seam'])
        text = (self.run / 'bundles/seam-bundle.md').read_text()
        self.assertIn('Cross them', text)

    def test_context_files_are_included_when_present(self):
        (self.run / 'known-hypotheses.md').write_text('surface | bug-class | closed-refuted | x\n')
        extra = Path(self.temp.name) / 'delta.json'
        extra.write_text('{"ranked": []}')
        result = bounty.bundle(self.repo, self.run, ['accounting'], includes=[str(extra)])
        text = (self.run / 'bundles/accounting-bundle.md').read_text()
        self.assertIn('known-hypotheses.md', text)
        self.assertIn('delta.json', text)
        self.assertGreaterEqual(result['context_sections'], 2)

    def test_saturated_ground_travels_with_every_later_bundle(self):
        (self.run / 'saturated.md').write_text(
            '# Saturated ground\n\n'
            'src/Vault.sol | aggregate-not-decremented | reported by 9 readings '
            '(8 claims, 1 leads)\n')
        result = bounty.bundle(self.repo, self.run, ['accounting'])
        text = (self.run / 'bundles/accounting-bundle.md').read_text()
        self.assertIn('saturated.md', text)                    # named as run context
        self.assertIn('reported by 9 readings', text)          # and its content carried
        self.assertIn(bounty.SATURATED_NOTICE, text)           # with the instruction to skip it
        self.assertGreaterEqual(result['context_sections'], 2)

    def test_the_bundle_header_is_unchanged_while_nothing_is_saturated(self):
        bounty.bundle(self.repo, self.run, ['accounting'])
        self.assertNotIn(bounty.SATURATED_NOTICE,
                         (self.run / 'bundles/accounting-bundle.md').read_text())
        (self.run / 'saturated.md').write_text('')             # written but empty: still nothing
        bounty.bundle(self.repo, self.run, ['accounting'])
        self.assertNotIn(bounty.SATURATED_NOTICE,
                         (self.run / 'bundles/accounting-bundle.md').read_text())

    def test_spec_divergence_is_a_dispatchable_aiming_lens(self):
        self.assertIn('spec-divergence', bounty.LENSES)
        self.assertIn('spec-divergence', bounty.AIM_LENSES)
        result = bounty.bundle(self.repo, self.run, ['spec-divergence'])
        self.assertEqual([b['lens'] for b in result['bundles']], ['spec-divergence'])
        self.assertIn('spec-divergence',
                      [b['lens'] for b in bounty.bundle(self.repo, self.run, ['aim'])['bundles']])

    def test_only_the_spec_divergence_lens_receives_the_documentation(self):
        # Markdown is in no other bundle: the promise a project published is this lens's raw
        # material, and NatSpec already travels with the source for everyone else.
        (self.repo / 'docs').mkdir()
        (self.repo / 'README.md').write_text('# Vault\n\nWithdrawals are always honoured.\n')
        (self.repo / 'docs/spec.md').write_text('The index is checkpointed before every read.\n')
        (self.repo / 'docs/secrets.md').write_text('PRIVATE_KEY=do-not-bundle\n')
        commit(self.repo, 'docs')
        result = bounty.bundle(self.repo, self.run, ['spec-divergence', 'accounting'])
        spec = (self.run / 'bundles/spec-divergence-bundle.md').read_text()
        accounting = (self.run / 'bundles/accounting-bundle.md').read_text()
        self.assertIn('Withdrawals are always honoured', spec)
        self.assertIn('checkpointed before every read', spec)
        self.assertNotIn('do-not-bundle', spec)            # a secrets file is not documentation
        self.assertNotIn('Withdrawals are always honoured', accounting)
        self.assertEqual(result['doc_files_bundled_for_spec_divergence'], 2)
        self.assertTrue((self.run / 'bundles/docs.md').is_file())

    def test_an_oversize_documentation_file_is_omitted_and_disclosed(self):
        (self.repo / 'README.md').write_text('# Vault\n' + 'a promise. ' * 100)
        commit(self.repo, 'big docs')
        with mock.patch.object(bounty, 'DOCS_MAX_FILE_BYTES', 100):
            result = bounty.bundle(self.repo, self.run, ['spec-divergence'])
        self.assertEqual(result['doc_files_omitted'], 1)
        self.assertIn('omitted by path or size budget',
                      (self.run / 'bundles/docs.md').read_text())

    def test_a_symlinked_documentation_file_is_never_followed(self):
        outside = Path(self.temp.name) / 'secret-notes.md'
        outside.write_text('TOP-SECRET promise\n')
        os.symlink(outside, self.repo / 'NOTES.md')
        commit(self.repo, 'symlinked docs')
        result = bounty.bundle(self.repo, self.run, ['spec-divergence'])
        self.assertNotIn('TOP-SECRET',
                         (self.run / 'bundles/spec-divergence-bundle.md').read_text())
        self.assertIn({'path': 'NOTES.md', 'reason': 'symlink'}, result['skipped_files'])

    def test_missing_include_is_refused(self):
        with self.assertRaises(ValueError):
            bounty.bundle(self.repo, self.run, ['accounting'], includes=['/nonexistent.json'])

    def test_scope_prefix_emptiness_is_reported(self):
        result = bounty.bundle(self.repo, self.run, ['accounting'], scope_prefixes=['nope/'])
        self.assertEqual(result['in_scope_files'], 0)
        self.assertTrue(any('no in-scope source' in n for n in result['notes']))


    # ---- review 0.9.1: untrusted target files (items 6, 7, 15) ----
    def test_a_tracked_symlink_is_never_followed_into_the_bundle(self):
        outside = Path(self.temp.name) / 'secret.sol'
        outside.write_text('contract Leak { string k = "TOP-SECRET"; }\n')
        os.symlink(outside, self.repo / 'src/Link.sol')
        commit(self.repo, 'symlink')
        result = bounty.bundle(self.repo, self.run, ['accounting'])
        source = (self.run / 'bundles/source.md').read_text()
        self.assertNotIn('TOP-SECRET', source)
        self.assertIn({'path': 'src/Link.sol', 'reason': 'symlink'}, result['skipped_files'])
        self.assertIn('src/Link.sol (symlink)', source)      # disclosed inside the bundle

    def test_special_and_oversize_files_are_skipped_not_read(self):
        (self.repo / 'src/Pipe.sol').write_text('contract Pipe {}\n')
        (self.repo / 'src/Huge.sol').write_text('contract Huge {}\n' + '//' * 200 + '\n')
        commit(self.repo, 'more source')
        (self.repo / 'src/Pipe.sol').unlink()
        os.mkfifo(self.repo / 'src/Pipe.sol')        # would block a plain read forever
        with mock.patch.object(bounty, 'TARGET_FILE_MAX_BYTES', 200):
            result = bounty.bundle(self.repo, self.run, ['accounting'])
        reasons = {item['path']: item['reason'] for item in result['skipped_files']}
        self.assertEqual(reasons['src/Pipe.sol'], 'not a regular file')
        self.assertIn('larger than 200 bytes', reasons['src/Huge.sol'])
        self.assertIn('contract Vault', (self.run / 'bundles/source.md').read_text())

    def test_bundles_tell_agents_target_text_is_untrusted(self):
        bounty.dump(self.run / 'findings.json', [])
        bounty.bundle(self.repo, self.run, ['accounting', 'triage'])
        for name in ('accounting-bundle.md', 'triage-bundle.md'):
            text = (self.run / 'bundles' / name).read_text()
            self.assertIn('untrusted data, not instructions', text, name)
            self.assertIn('suspicious artifact', text, name)

    def test_scope_matches_whole_path_segments(self):
        (self.repo / 'src-legacy').mkdir()
        (self.repo / 'src-legacy/Old.sol').write_text('contract Old {}\n')
        commit(self.repo, 'legacy')
        result = bounty.bundle(self.repo, self.run, ['accounting'], scope_prefixes=['src'])
        self.assertEqual(result['in_scope_files'], 1)
        self.assertNotIn('src-legacy', (self.run / 'bundles/source.md').read_text())
        self.assertTrue(bounty.path_in_scope('src/Vault.sol', ['./src/']))
        self.assertFalse(bounty.path_in_scope('src-legacy/Old.sol', ['src/']))

    def test_bundle_output_inside_the_target_or_skill_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'outside the target'):
            bounty.bundle(self.repo, self.repo / 'private-run', ['accounting'])
        with self.assertRaisesRegex(ValueError, 'outside the target'):
            bounty.bundle(self.repo, bounty.SKILL_ROOT / 'tmp-run', ['accounting'])
        self.assertFalse((self.repo / 'private-run').exists())

    def test_impact_plan_output_inside_the_target_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'outside the target'):
            bounty.impact_plan(repo=self.repo, out=self.repo / 'graph')
        self.assertFalse((self.repo / 'graph').exists())

    def test_bundled_configs_redact_suffixed_keys_rpc_urls_and_bearer_tokens(self):
        text = '\n'.join([
            'DEPLOYER_PRIVATE_KEY=0xabc123def456',
            'ETHERSCAN_API_KEY: ZZTOPSECRETZZ',
            '"privateKey": "0xfeedface"',
            'mainnet = "https://eth-mainnet.g.alchemy.com/v2/AlchemyKey0123456789abcdef"',
            'url: https://mainnet.infura.io/v3/0123456789abcdef0123456789abcdef',
            'ws = "wss://mainnet.infura.io/ws/v3/fedcba9876543210fedcba9876543210"',
            'q = "https://falling-cool-sun.quiknode.pro/abcdef0123456789abcdef0123456789/"',
            'a = "https://rpc.ankr.com/eth/0a1b2c3d4e5f60718293a4b5c6d7e8f9"',
            'other = "https://rpc.example.org/v2/GenericProviderKey12345678"',
            'auth = "https://user:hunter2@rpc.example.org"',
            'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig',
            'headers = { Authorization = "Bearer tok_live_ABCDEFGH12345" }',
            'solc_version = "0.8.24"',
        ])
        redacted = bounty._redact_context_secrets(text)
        for secret in ('0xabc123def456', 'ZZTOPSECRETZZ', '0xfeedface', 'AlchemyKey0123',
                       '0123456789abcdef0123456789abcdef', 'fedcba9876543210',
                       'abcdef0123456789abcdef0123456789', '0a1b2c3d4e5f6071',
                       'GenericProviderKey', 'hunter2', 'eyJhbGciOiJIUzI1NiJ9',
                       'tok_live_ABCDEFGH'):
            self.assertNotIn(secret, redacted)
        self.assertIn('solc_version = "0.8.24"', redacted)
        self.assertIn('https://eth-mainnet.g.alchemy.com/v2/<redacted>', redacted)


class ConvergeTests(unittest.TestCase):
    """Repeated readings are bought for recall. In a backtest 9 of 12 readings reported one
    mechanism, so the budget bought duplicates; converge is how a later pass is told which
    ground is already covered."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        (self.repo / 'src/Vault.sol').write_text('contract Vault {}\n')
        commit(self.repo, 'fixture')
        self.run = self.base / 'run'
        bounty.initialize(self.repo, self.run)
        self.readings = self.base / 'readings'
        self.readings.mkdir()

    def reading(self, name, *lines):
        path = self.readings / name
        path.write_text('\n'.join(lines) + '\n')
        return path

    def saturated_lines(self, with_record=False):
        body = (self.run / 'saturated.md').read_text()
        lines = [line for line in body.splitlines()
                 if ' | reported by ' in line and not line.startswith('`')]   # skip the shape
        # The last column names the record that carries the mechanism; most tests are about
        # the grouping, so they compare without it.
        return lines if with_record else [line.rsplit(' | ', 1)[0] for line in lines]

    def test_the_same_class_at_neighbouring_functions_stays_two_groups(self):
        # Keyed on the file alone, a second instance in `redeem` became closed ground the
        # moment `withdraw` saturated. Splitting costs a duplicate; merging hides a bug.
        self.reading('pass1.md', 'CANDIDATE | lens: accounting | surface: '
                                 'src/Vault.sol:Vault.withdraw | bug_class: aggregate-not-decremented')
        self.reading('pass2.md', 'CANDIDATE | lens: seam | surface: '
                                 'src/Vault.sol:Vault.redeem | bug_class: aggregate-not-decremented')
        result = bounty.converge([str(self.readings)], self.run)
        self.assertEqual(result['readings_parsed'], 2)
        self.assertEqual(result['distinct_groups'], 2)
        self.assertEqual(result['saturated_groups'], 0)
        # Arguments are not part of the function: `withdraw(uint256)` is `withdraw`.
        self.reading('pass3.md', 'CANDIDATE | lens: seam | surface: '
                                 'src/Vault.sol:Vault.withdraw(uint256) | '
                                 'bug_class: aggregate-not-decremented')
        result = bounty.converge([str(self.readings)], self.run)
        self.assertEqual(result['saturated_groups'], 1)
        self.assertEqual(self.saturated_lines(),
                         ['src/Vault.sol:Vault.withdraw | aggregate-not-decremented | reported by '
                          '2 readings (2 claims, 0 leads)'])

    def test_saturated_ground_without_a_record_is_not_closed(self):
        # Byte-identical files are one reading copied twice, so the two lenses differ here.
        for name, lens in (('pass1.md', 'accounting'), ('pass2.md', 'seam')):
            self.reading(name, f'CANDIDATE | lens: {lens} | surface: src/Vault.sol:Vault.withdraw '
                               '| bug_class: aggregate-not-decremented')
        result = bounty.converge([str(self.readings)], self.run)
        self.assertEqual(len(result['saturated_unrecorded']), 1)
        self.assertTrue(self.saturated_lines(with_record=True)[0]
                        .endswith('UNRECORDED - record it before treating it as closed'))
        row = bounty.template()
        row.update(affected_paths=['src/Vault.sol:Vault.withdraw'],
                   bug_class='aggregate-not-decremented')
        bounty.dump(self.run / 'findings.json', [row])
        result = bounty.converge([str(self.readings)], self.run)
        self.assertEqual(result['saturated_unrecorded'], [])
        self.assertTrue(self.saturated_lines(with_record=True)[0]
                        .endswith('record BP-001 (hypothesis)'))

    def test_findings_and_leads_count_into_the_same_group(self):
        # FINDING is what the sibling solidity-auditor skill emits, and labels are normalised,
        # so `Aggregate Not Decremented` is the same ground as `aggregate-not-decremented`.
        self.reading('pass1.md', 'CANDIDATE | surface: src/Vault.sol:Vault.withdraw | '
                                 'bug_class: aggregate-not-decremented')
        self.reading('pass2.md', 'FINDING | surface: ./src/Vault.sol:Vault.withdraw | '
                                 'bug_class: Aggregate Not Decremented')
        self.reading('pass3.txt', '  LEAD | bug_class: aggregate-not-decremented | lens: seam '
                                  '| surface: src/Vault.sol:Vault.withdraw()')
        bounty.converge([str(self.readings)], self.run)
        report = bounty.read_json(self.run / 'convergence.json')
        self.assertEqual(report['blocks_parsed'], 3)
        group = report['saturated'][0]
        self.assertEqual((group['readings'], group['claims'], group['leads']), (3, 2, 1))
        self.assertEqual(len(group['sources']), 3)
        self.assertEqual(group['surfaces'], ['src/Vault.sol:Vault.withdraw'])
        self.assertEqual(self.saturated_lines(),
                         ['src/Vault.sol:Vault.withdraw | aggregate-not-decremented | reported by '
                          '3 readings (2 claims, 1 leads)'])

    def test_format_examples_are_never_counted_as_reports(self):
        # Every reading quotes the output format from _shared.md; counting those placeholders
        # would make every reading look like it reported the same mechanism.
        # Byte-identical files are one reading copied twice, so each names its own pass.
        for name in ('pass1.md', 'pass2.md'):
            self.reading(name,
                         f'Reading {name}',
                         '```',
                         'CANDIDATE | lens: <lens-name> | surface: <path:Contract.function> | '
                         'bug_class: <kebab-case>',
                         '```',
                         'LEAD | lens: liveness | surface: src/Vault.sol:Vault.pause | '
                         'bug_class: pause-blocks-exit')
        result = bounty.converge([str(self.readings)], self.run)
        self.assertEqual(result['blocks_parsed'], 2)
        self.assertEqual(result['blocks_skipped'], 2)
        self.assertEqual(result['distinct_groups'], 1)
        self.assertEqual(self.saturated_lines(),
                         ['src/Vault.sol:Vault.pause | pause-blocks-exit | reported by 2 readings '
                          '(0 claims, 2 leads)'])

    def test_the_singletons_are_what_the_next_pass_needs(self):
        self.reading('pass1.md', 'CANDIDATE | surface: src/Vault.sol:Vault.withdraw | '
                                 'bug_class: aggregate-not-decremented')
        self.reading('pass2.md', 'CANDIDATE | surface: src/Vault.sol:Vault.withdraw | '
                                 'bug_class: aggregate-not-decremented',
                     'LEAD | surface: src/Oracle.sol:Oracle.peek | bug_class: stale-price-accepted')
        result = bounty.converge([str(self.readings)], self.run)
        self.assertEqual(result['singletons'], 1)
        report = bounty.read_json(self.run / 'convergence.json')
        self.assertEqual([g['bug_class'] for g in report['singletons']], ['stale-price-accepted'])
        self.assertNotIn('stale-price-accepted', (self.run / 'saturated.md').read_text())

    def test_the_threshold_decides_what_counts_as_saturated(self):
        self.reading('pass1.md', 'CANDIDATE | surface: src/Vault.sol:Vault.withdraw | '
                                 'bug_class: aggregate-not-decremented')
        self.reading('pass2.md', 'CANDIDATE | surface: src/Vault.sol:Vault.redeem | '
                                 'bug_class: aggregate-not-decremented')
        result = bounty.converge([str(self.readings)], self.run, threshold=3)
        self.assertEqual(result['saturated_groups'], 0)
        self.assertEqual(self.saturated_lines(), [])
        self.assertIn('No mechanism reached 3 independent readings',
                      (self.run / 'saturated.md').read_text())
        with self.assertRaises(ValueError):
            bounty.converge([str(self.readings)], self.run, threshold=0)

    def test_a_single_file_is_a_reading_and_directories_combine(self):
        first = self.reading('pass1.md', 'CANDIDATE | surface: src/Vault.sol:Vault.withdraw | '
                                         'bug_class: aggregate-not-decremented')
        second = self.base / 'other'
        second.mkdir()
        (second / 'pass2.md').write_text('LEAD | surface: src/Vault.sol:Vault.withdraw | '
                                         'bug_class: aggregate-not-decremented\n')
        result = bounty.converge([str(first), str(second)], self.run)
        self.assertEqual(result['readings_parsed'], 2)
        self.assertEqual(result['saturated_groups'], 1)

    def test_missing_fields_and_stray_shapes_are_tolerated(self):
        self.reading('pass1.md',
                     '## **CANDIDATE** | surface: src/Vault.sol:Vault.withdraw',  # no bug_class
                     '- CANDIDATE | bug_class: unvalidated-compose-sender',       # no surface
                     'LEAD without any fields',                            # not a record header
                     'candidate | surface: src/Vault.sol | bug_class: lowercase-word')
        (self.readings / 'notes.json').write_text('{"not": "a reading"}\n')
        result = bounty.converge([str(self.readings)], self.run)
        self.assertEqual(result['readings_parsed'], 1)       # the .json file is not a reading
        # A lower-case kind word is the same header: it used to be dropped without a trace.
        self.assertEqual(result['blocks_parsed'], 3)
        self.assertEqual(result['distinct_groups'], 3)
        self.assertEqual(result['saturated_groups'], 0)

    def test_converge_refuses_a_directory_that_init_did_not_create(self):
        self.reading('pass1.md', 'CANDIDATE | surface: src/Vault.sol | bug_class: x-y')
        plain = self.base / 'not-a-run'
        plain.mkdir()
        with self.assertRaisesRegex(ValueError, 'run.json'):
            bounty.converge([str(self.readings)], plain)
        inside = self.repo / 'private-run'
        inside.mkdir()
        (inside / 'run.json').write_text((self.run / 'run.json').read_text())
        with self.assertRaisesRegex(ValueError, 'outside the target'):
            bounty.converge([str(self.readings)], inside)
        with self.assertRaisesRegex(ValueError, 'not a file or a directory'):
            bounty.converge([str(self.base / 'nowhere')], self.run)

    def test_converge_reports_what_it_could_not_read(self):
        self.reading('pass1.md', 'CANDIDATE | surface: src/Vault.sol:Vault.withdraw | '
                                 'bug_class: aggregate-not-decremented')
        big = self.reading('pass2.md', 'CANDIDATE | surface: src/Vault.sol | bug_class: x-y')
        with mock.patch.object(bounty, 'READING_MAX_BYTES', 10):
            result = bounty.converge([str(self.readings)], self.run)
        self.assertEqual(result['readings_parsed'], 0)
        self.assertEqual(sorted(result['unreadable_files']),
                         sorted([str(self.readings / 'pass1.md'), str(big)]))

    def test_converge_output_is_the_input_of_the_next_bundle(self):
        self.reading('pass1.md', 'CANDIDATE | surface: src/Vault.sol:Vault.withdraw | '
                                 'bug_class: aggregate-not-decremented')
        self.reading('pass2.md', 'CANDIDATE | surface: src/Vault.sol:Vault.withdraw | '
                                 'bug_class: aggregate-not-decremented')
        bounty.converge([str(self.readings)], self.run)
        bounty.bundle(self.repo, self.run, ['accounting'])
        text = (self.run / 'bundles/accounting-bundle.md').read_text()
        self.assertIn('aggregate-not-decremented', text)
        self.assertIn(bounty.SATURATED_NOTICE, text)


class DispatchTests(unittest.TestCase):
    """`bundle` writes the bundles; until now nothing checked that a reading came back.

    runs/lifi-20261016 is the measured case: eight lens bundles on disk, coverage.md still the
    empty template, no record from any of them - a hunt that never happened, and no gate said
    so. Every other load-bearing rule in this skill became a gate with a script behind it.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        (self.repo / 'test').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        (self.repo / 'src/Vault.sol').write_text('contract Vault { uint256 totalDebt; }\n')
        (self.repo / 'test/Vault.t.sol').write_text('contract VaultTest { Vault v; }\n')
        commit(self.repo, 'fixture')
        self.run = self.base / 'run'
        bounty.initialize(self.repo, self.run)

    def meta(self, key):
        return bounty.read_json(self.run / 'run.json')[key]

    def unread(self):
        return [row['lens'] for row in bounty._dispatch_state(self.run)['unread']]

    def dispatch_errors(self, submission=False):
        """Only the errors this gate raises; the fixture is not otherwise submittable."""
        return [e for e in bounty.validate(self.run, submission=submission)
                if e.startswith(bounty.BUNDLE_MANIFEST + ':')]

    def readings(self, **files):
        """Raw hunt-agent output, one file per reading; the keyword `pass1_md` is `pass1.md`."""
        directory = self.base / 'readings'
        directory.mkdir(exist_ok=True)
        for name, body in files.items():
            (directory / name.replace('_', '.')).write_text(body + '\n')
        return str(directory)

    # ---- 1. bundle records what it emitted ----
    def test_the_manifest_is_a_log_and_not_a_snapshot(self):
        # bundle legitimately runs several times per run (aim, attack, logic, seam, triage),
        # so a later bundling must never erase a lens still waiting to be read.
        bounty.bundle(self.repo, self.run, ['accounting'], scope_prefixes=['src/'])
        bounty.bundle(self.repo, self.run, ['triage'])
        data = bounty.read_json(self.run / 'bundles/manifest.json')
        self.assertEqual(data['schema_version'], bounty.SCHEMA_VERSION)
        self.assertEqual(data['run_id'], self.meta('run_id'))
        self.assertEqual(len(data['dispatches']), 2)
        self.assertEqual([d['commit'] for d in data['dispatches']],
                         [self.meta('commit')] * 2)
        self.assertEqual([d['scope_prefixes'] for d in data['dispatches']], [['src/'], []])
        self.assertTrue(data['dispatches'][0]['generated_at'])
        entry = data['dispatches'][0]['bundles'][0]
        path = self.run / entry['bundle']
        self.assertEqual(entry['lens'], 'accounting')
        self.assertEqual(entry['bundle'], 'bundles/accounting-bundle.md')
        self.assertEqual(entry['bytes'], path.stat().st_size)
        self.assertEqual(entry['sha256'], bounty._sha256_file(path))
        bounty.bundle(self.repo, self.run, ['accounting'])
        self.assertEqual(bounty._dispatch_state(self.run)['manifested'],
                         ['accounting', 'triage'])

    def test_bundle_still_returns_what_it_did_and_names_the_manifest(self):
        result = bounty.bundle(self.repo, self.run, ['accounting'])
        self.assertEqual([b['lens'] for b in result['bundles']], ['accounting'])
        self.assertEqual(result['manifest'], 'bundles/manifest.json')
        self.assertTrue((self.run / result['manifest']).is_file())
        self.assertIn('check --submission blocks', result['dispatch'])

    # ---- 2. a bundle counts as read when a reading left a trace ----
    def test_a_parsed_reading_clears_its_lens(self):
        bounty.bundle(self.repo, self.run, ['accounting', 'liveness'])
        self.assertEqual(self.unread(), ['accounting', 'liveness'])
        directory = self.readings(pass1_md='CANDIDATE | lens: accounting | surface: '
                                           'src/Vault.sol:Vault.withdraw | bug_class: '
                                           'aggregate-not-decremented')
        bounty.converge([directory], self.run)
        self.assertEqual(self.unread(), ['liveness'])
        # A lens that read its bundle and reported nothing names itself only in its file name.
        self.readings(liveness_md='No mechanism survived this lens.')
        bounty.converge([directory], self.run)
        self.assertEqual(self.unread(), [])

    def test_a_coverage_row_clears_its_lens(self):
        bounty.bundle(self.repo, self.run, ['accounting', 'liveness'])
        with (self.run / 'coverage.md').open('a', encoding='utf-8') as handle:
            handle.write('| src/Vault.sol:Vault.withdraw | accounting | 2 | replayed the '
                         'mismatch | totalDebt decremented, no gap |\n')
        self.assertEqual(self.unread(), ['liveness'])
        self.assertEqual(bounty._dispatch_state(self.run)['read'],
                         [{'lens': 'accounting', 'evidence': ['coverage.md']}])

    def test_a_record_carrying_the_lens_clears_it(self):
        bounty.bundle(self.repo, self.run, ['accounting', 'liveness'])
        row = bounty.template()
        row['lens'] = 'liveness'
        bounty.dump(self.run / 'findings.json', [row])
        self.assertEqual(self.unread(), ['accounting'])

    def test_triage_is_cleared_by_the_objections_it_produced(self):
        # Triage is not a lens and never writes a coverage row or a record of its own: its
        # product is objections on other agents' records, so that is what shows it read.
        bounty.bundle(self.repo, self.run, ['triage'])
        self.assertEqual(self.unread(), ['triage'])
        row = bounty.template()
        row['objections'] = [{'gate': 'reachability',
                              'claim': 'no unprivileged path reaches the decrement',
                              'anchor': 'code: src/Vault.sol:12 onlyOwner on withdraw()',
                              'outcome': 'sustained'}]
        bounty.dump(self.run / 'findings.json', [row])
        self.assertEqual(bounty._dispatch_state(self.run)['read'],
                         [{'lens': 'triage', 'evidence': ['objections']}])

    # ---- 3 and 4. queue reports it, submission blocks on it ----
    def test_a_run_shaped_like_the_lifi_hunt_is_reported_and_blocked(self):
        lenses = ['business-logic', 'composition', 'coverage-gap', 'delta', 'economics',
                  'impact-first', 'privileged-path', 'spec-divergence']
        bounty.bundle(self.repo, self.run, lenses)
        self.assertEqual((self.run / 'coverage.md').read_text().count('|'), 12)  # header only
        self.assertEqual(bounty.read_json(self.run / 'findings.json'), [])
        report = bounty.lead_queue(self.run)
        self.assertEqual([row['lens'] for row in report['unread_bundles']], lenses)
        self.assertEqual(report['unread_bundles'][0]['bundle'],
                         'bundles/business-logic-bundle.md')
        self.assertTrue(report['unread_bundles'][0]['built_at'])
        # queue is a report: it still runs, and the state it would have had is unchanged.
        self.assertEqual(report['state'], 'all-leads-closed')
        self.assertIn('unread_bundles are lenses', report['notice'])
        errors = self.dispatch_errors(submission=True)
        self.assertEqual(len(errors), 1)
        for lens in lenses:
            self.assertIn(lens, errors[0])
        self.assertIn('converge --readings', errors[0])
        self.assertEqual(self.dispatch_errors(), [])   # structural check does not block

    def test_a_run_with_no_manifest_is_blocked_by_nothing_here(self):
        # An older run, or one that never bundled, claims nothing about what was read.
        state = bounty._dispatch_state(self.run)
        self.assertFalse(state['present'])
        self.assertEqual(state['unread'], [])
        self.assertEqual(bounty.lead_queue(self.run)['unread_bundles'], [])
        self.assertEqual(self.dispatch_errors(submission=True), [])
        self.assertEqual(self.dispatch_errors(), [])

    def test_submission_clears_once_the_readings_are_converged(self):
        bounty.bundle(self.repo, self.run, ['accounting', 'liveness'])
        self.assertEqual(len(self.dispatch_errors(submission=True)), 1)
        directory = self.readings(
            accounting_md='LEAD | lens: accounting | surface: src/Vault.sol:Vault.withdraw | '
                          'bug_class: aggregate-not-decremented',
            liveness_md='LEAD | lens: liveness | surface: src/Vault.sol:Vault.pause | '
                        'bug_class: pause-blocks-exit')
        bounty.converge([directory], self.run)
        self.assertEqual(self.dispatch_errors(submission=True), [])

    # ---- the log is never a new way to fail ----
    def test_an_unreadable_manifest_gates_nothing_and_is_rewritten(self):
        (self.run / 'bundles').mkdir()
        (self.run / 'bundles/manifest.json').write_text('not json at all\n')
        self.assertEqual(self.dispatch_errors(submission=True), [])
        self.assertEqual(bounty.lead_queue(self.run)['unread_bundles'], [])
        result = bounty.bundle(self.repo, self.run, ['accounting'])
        self.assertTrue(any('was not a dispatch log' in note for note in result['notes']))
        self.assertEqual(self.unread(), ['accounting'])

    def test_a_manifest_from_another_run_does_not_speak_for_this_one(self):
        bounty.bundle(self.repo, self.run, ['accounting'])
        meta = bounty.read_json(self.run / 'run.json')
        meta['run_id'] = 'f' * 32
        bounty.dump(self.run / 'run.json', meta)
        result = bounty.bundle(self.repo, self.run, ['liveness'])
        self.assertTrue(any('different run' in note for note in result['notes']))
        self.assertEqual(self.unread(), ['liveness'])


class CompilerBugTests(unittest.TestCase):
    BY_VERSION = {'0.6.12': {'released': '2020-06-03', 'bugs': ['BadBug', 'TinyBug']},
                  '0.8.19': {'released': '2023-02-22', 'bugs': ['TinyBug']}}
    CATALOGUE = [{'name': 'BadBug', 'uid': 'SOL-2020-1', 'severity': 'medium/high',
                  'summary': 'storage write removed', 'fixed': '0.8.17',
                  'link': 'https://example.invalid/bad'},
                 {'name': 'TinyBug', 'uid': 'SOL-2021-9', 'severity': 'very low',
                  'summary': 'cosmetic', 'fixed': '0.8.20'}]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        (self.repo / 'src/Old.sol').write_text('pragma solidity 0.6.12;\ncontract Old {}\n')
        (self.repo / 'src/New.sol').write_text('pragma solidity ^0.8.20;\ncontract New {}\n')
        (self.repo / 'src/pool.vy').write_text('# @version 0.2.15\n')
        (self.repo / 'foundry.toml').write_text('[profile.default]\nsolc_version = "0.8.19"\n')
        commit(self.repo, 'fixture')

    def opener(self):
        payloads = {bounty.SOLC_BUGS_BY_VERSION: self.BY_VERSION, bounty.SOLC_BUGS: self.CATALOGUE}

        def open_fn(request, timeout=None):
            return FakeResponse(payloads[request.full_url])
        return open_fn

    def test_versions_come_from_config_pragma_and_arguments(self):
        found = bounty.collect_compiler_versions(self.repo)
        self.assertIn('0.6.12', found['exact'])          # exact pragma
        self.assertIn('0.8.19', found['exact'])          # foundry.toml
        self.assertIn('^0.8.20', found['ranges'])        # range kept separate
        self.assertEqual(found['vyper_sources'], ['src/pool.vy'])

    def test_only_compiler_keys_count_as_compiler_versions(self):
        # A key called `version` names a compiler only inside a compiler block. Reading it
        # anywhere reports bugs for a compiler nobody used.
        cases = [
            ('foundry.toml', '[profile.default]\nsolc_version = "0.8.26"\n[docs]\n'
                             'version = "9.9.9"\n', {'0.8.26'}),
            ('hardhat.config.js', 'module.exports={solidity:{version:"0.8.19"},'
                                  'plug:{version:"1.2.3"}}', {'0.8.19'}),
            ('hardhat.config.js', 'solidity: "0.8.17", other: { version: "9.9.9" }', {'0.8.17'}),
            ('hardhat.config.js', 'solidity:{compilers:[{version:"0.8.20"},{version:"0.7.6"}]},'
                                  'x:{version:"4.4.4"}', {'0.8.20', '0.7.6'}),
            ('truffle-config.js', 'compilers:{solc:{version:"0.8.4"}},plugins:{version:"2.0.0"}',
             {'0.8.4'}),
            # A caret is a range: reading it as exact 0.8.24 reports another compiler's bugs.
            ('package.json', '{"name":"p","version":"1.2.3",'
                             '"devDependencies":{"solc":"^0.8.24"}}', {'^0.8.24'}),
            ('package.json', '{"name":"p","version":"1.2.3"}', set()),
            ('package.json', 'not json at all', set()),
        ]
        for name, text, expected in cases:
            self.assertEqual(set(bounty._versions_from_config(name, text)), expected,
                             f'{name}: {text[:50]}')

    def test_an_unrelated_package_version_never_reaches_the_report(self):
        (self.repo / 'package.json').write_text(
            '{"name":"p","version":"1.2.3","devDependencies":{"solc":"0.8.24"}}')
        commit(self.repo, 'add package.json')
        found = bounty.collect_compiler_versions(self.repo)
        self.assertNotIn('1.2.3', found['exact'])
        self.assertIn('0.8.24', found['exact'])

    def test_known_bugs_are_reported_with_severity(self):
        result = bounty.solc_bugs(self.repo, None, self.opener())
        by_version = {c['version']: c for c in result['checked']}
        self.assertEqual(by_version['0.6.12']['bug_count'], 2)
        notable = by_version['0.6.12']['medium_or_higher']
        self.assertEqual([b['name'] for b in notable], ['BadBug'])
        self.assertEqual(notable[0]['fixed_in'], '0.8.17')
        self.assertEqual(by_version['0.8.19']['medium_or_higher'], [])

    def test_ranges_and_vyper_are_flagged_as_unresolved(self):
        result = bounty.solc_bugs(self.repo, None, self.opener())
        self.assertTrue(any('pragma ranges do not determine' in n for n in result['notes']))
        self.assertTrue(any('Vyper' in n for n in result['notes']))
        self.assertTrue(any(a['toolchain'] == 'vyper'
                            for a in result['other_toolchain_advisories']))

    def test_explicit_version_needs_no_repo(self):
        result = bounty.solc_bugs(None, ['0.6.12'], self.opener())
        self.assertEqual(result['checked'][0]['version'], '0.6.12')

    def test_no_version_found_is_said_not_guessed(self):
        bare = Path(self.temp.name) / 'bare'
        bare.mkdir()
        git(bare, 'init', '-q')
        (bare / 'README.md').write_text('nothing\n')
        commit(bare, 'bare')
        result = bounty.solc_bugs(bare, None, self.opener())
        self.assertEqual(result['checked'], [])
        self.assertTrue(any('no compiler version found' in n for n in result['notes']))

    def test_a_fetch_failure_is_reported_not_silently_empty(self):
        def failing(request, timeout=None):
            raise urllib.error.URLError('offline')
        result = bounty.solc_bugs(self.repo, None, failing)
        self.assertTrue(any('could not fetch' in n for n in result['notes']))
        self.assertIn('0.6.12', result['checked'])


    # ---- review 0.9.1, item 10 ----
    def test_caret_in_package_json_is_a_range_not_an_exact_version(self):
        (self.repo / 'package.json').write_text('{"devDependencies":{"solc":"^0.8.0"}}')
        commit(self.repo, 'package')
        found = bounty.collect_compiler_versions(self.repo)
        self.assertNotIn('0.8.0', found['exact'])
        self.assertIn('^0.8.0', found['ranges'])

    def test_commented_pragmas_are_ignored_and_equals_pins_exactly(self):
        (self.repo / 'src/Commented.sol').write_text(
            '// pragma solidity 0.4.24;\n'
            '/* pragma solidity 0.5.0;\n   still a comment */\n'
            'pragma solidity =0.7.6;\n'
            'contract C { string u = "http://example.invalid/*"; }\n'
            '/* unterminated pragma solidity 0.4.11;\n')
        commit(self.repo, 'commented')
        found = bounty.collect_compiler_versions(self.repo)
        self.assertIn('0.7.6', found['exact'])
        for ghost in ('0.4.24', '0.5.0', '0.4.11'):
            self.assertNotIn(ghost, found['exact'])
            self.assertFalse(any(ghost in spec for spec in found['ranges']), ghost)

    def test_pragma_ranges_are_matched_against_released_versions(self):
        (self.repo / 'src/Range.sol').write_text('pragma solidity >=0.6.0 <0.8.20;\n')
        commit(self.repo, 'range')
        result = bounty.solc_bugs(self.repo, None, self.opener())
        by_range = {m['range']: m for m in result['range_matches']}
        wide = by_range['>=0.6.0 <0.8.20']
        self.assertEqual(wide['released_versions_in_range'], 2)
        self.assertEqual(sorted(wide['possible_bugs']), ['BadBug', 'TinyBug'])
        self.assertEqual([b['name'] for b in wide['possible_medium_or_higher']], ['BadBug'])
        self.assertEqual(by_range['^0.8.20']['possible_bugs'], [])   # no listed release admits it
        self.assertTrue(any("no released version" in n for n in result['notes']))

    def test_version_range_semantics(self):
        cases = [('^0.8.0', '0.8.19', True), ('^0.8.0', '0.9.0', False),
                 ('^0.8.0', '0.7.6', False), ('~0.8.1', '0.8.30', True),
                 ('~0.8.1', '0.8.0', False), ('0.8', '0.8.4', True), ('0.8', '0.9.0', False),
                 ('>=0.4.22 <0.9.0', '0.8.30', True), ('>=0.4.22 <0.9.0', '0.9.0', False),
                 ('0.4.0 - 0.5.0', '0.5.0', True), ('0.4.0 - 0.5.0', '0.5.1', False),
                 ('^0.5.0 || ^0.8.0', '0.8.3', True), ('^0.5.0 || ^0.8.0', '0.6.0', False),
                 ('>0.8.4', '0.8.4', False), ('<=0.8', '0.8.99', True), ('*', '0.1.0', True)]
        for spec, version, expected in cases:
            parsed = bounty.parse_version_range(spec)
            self.assertIsNotNone(parsed, spec)
            self.assertEqual(bounty.version_satisfies(parsed, bounty._version_tuple(version)),
                             expected, f'{spec} vs {version}')
        self.assertIsNone(bounty.parse_version_range('latest'))

    def test_a_json_array_under_out_does_not_crash(self):
        (self.repo / 'out').mkdir()
        (self.repo / 'out/list.json').write_text('[1, 2, 3]')
        (self.repo / 'out/str-meta.json').write_text(json.dumps(
            {'metadata': json.dumps({'compiler': {'version': '0.8.21+commit.d9974bed'}})}))
        found = bounty.collect_compiler_versions(self.repo)
        self.assertEqual(found['artifacts_read'], 1)
        self.assertIn('0.8.21', found['exact'])

    def test_a_symlinked_config_is_not_read(self):
        outside = Path(self.temp.name) / 'foundry.toml'
        outside.write_text('[profile.default]\nsolc_version = "0.4.11"\n')
        (self.repo / 'foundry.toml').unlink()
        os.symlink(outside, self.repo / 'foundry.toml')
        found = bounty.collect_compiler_versions(self.repo)
        self.assertNotIn('0.4.11', found['exact'])
        self.assertIn({'path': 'foundry.toml', 'reason': 'symlink'}, found['skipped_files'])


class BacktestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        (self.repo / 'src/Vault.sol').write_text('contract Vault { uint256 totalDebt; }\n')
        commit(self.repo, 'fixture')
        self.run = self.base / 'run'
        bounty.initialize(self.repo, self.run)
        self.case = self.base / 'case'

    def finding(self, ident='BP-001', title='redeem never decrements totalDebt',
                paths=('src/Vault.sol:Vault.redeem',), lens='accounting'):
        row = bounty.template()
        row.update(id=ident, title=title, root_cause='redeem omits the totalDebt decrement',
                   affected_paths=list(paths), bug_class='aggregate-not-decremented',
                   revision='abc1234', lens=lens, attacker_capabilities='any caller',
                   preconditions='an open vault', impact='mint cap bricked', status='verified')
        return row

    def seal_with(self, findings):
        bounty.backtest_init('case', self.repo, self.case)
        bounty.dump(self.run / 'findings.json', findings)
        return bounty.backtest_seal(self.case, self.run)

    def test_the_case_starts_blind_and_records_the_pinned_commit(self):
        result = bounty.backtest_init('c', self.repo, self.case, commit='HEAD')
        self.assertEqual(json.loads((self.case / 'truth.json').read_text()), [])
        self.assertTrue((self.case / 'truth-template.json').is_file())
        self.assertEqual(result['warnings'], [])

    def test_sealing_is_refused_once_truth_exists(self):
        bounty.backtest_init('c', self.repo, self.case)
        bounty.dump(self.case / 'truth.json', [{'id': 'TRUTH-001', 'severity': 'high'}])
        bounty.dump(self.run / 'findings.json', [self.finding()])
        with self.assertRaises(ValueError) as caught:
            bounty.backtest_seal(self.case, self.run)
        self.assertIn('not blind', str(caught.exception))

    def test_a_case_cannot_be_sealed_twice(self):
        self.seal_with([self.finding()])
        with self.assertRaises(ValueError) as caught:
            bounty.backtest_seal(self.case, self.run)
        self.assertIn('already sealed', str(caught.exception))

    def test_scoring_before_sealing_is_refused(self):
        bounty.backtest_init('c', self.repo, self.case)
        with self.assertRaises(ValueError):
            bounty.backtest_score(self.case)

    def test_tampering_with_the_sealed_file_voids_the_case(self):
        self.seal_with([self.finding()])
        bounty.dump(self.case / 'sealed-findings.json',
                    [self.finding(), self.finding('BP-002', 'a convenient extra')])
        bounty.dump(self.case / 'truth.json',
                    [{'id': 'T1', 'severity': 'high', 'title': 'x', 'paths': []}])
        with self.assertRaises(ValueError) as caught:
            bounty.backtest_score(self.case)
        self.assertIn('void', str(caught.exception))

    def test_awaiting_truth_then_awaiting_decisions_then_scored(self):
        self.seal_with([self.finding()])
        self.assertEqual(bounty.backtest_score(self.case)['state'], 'awaiting-truth')

        bounty.dump(self.case / 'truth.json', [
            {'id': 'T1', 'severity': 'high', 'title': 'redeem does not decrement totalDebt',
             'root_cause': 'the redeem path omits the totalDebt decrement',
             'paths': ['src/Vault.sol:Vault.redeem'], 'source': 'https://example.invalid/1'},
            {'id': 'T2', 'severity': 'medium', 'title': 'oracle staleness unchecked',
             'root_cause': 'latestAnswer used without a staleness check',
             'paths': ['src/Oracle.sol:Oracle.price'], 'source': 'https://example.invalid/2'}])

        pending = bounty.backtest_score(self.case)
        self.assertEqual(pending['state'], 'awaiting-decisions')
        self.assertEqual(pending['undecided'], 1)        # only T1 overlaps BP-001

        rows = json.loads((self.case / 'matches.json').read_text())
        rows[0]['decision'] = 'same-mechanism'
        rows[0]['decision_reason'] = 'same omitted decrement on the same function'
        bounty.dump(self.case / 'matches.json', rows)

        scored = bounty.backtest_score(self.case)
        self.assertEqual(scored['state'], 'scored')
        self.assertEqual([r['id'] for r in scored['rediscovered']], ['T1'])
        self.assertEqual([r['id'] for r in scored['missed']], ['T2'])
        self.assertEqual(scored['serious_rediscovered'], '1 of 2')
        self.assertEqual(scored['credited_lenses'], {'accounting': 1})
        self.assertEqual(scored['unmatched_hunt_findings'], [])

    def test_a_rejected_pair_leaves_the_truth_entry_missed(self):
        self.seal_with([self.finding()])
        bounty.dump(self.case / 'truth.json', [
            {'id': 'T1', 'severity': 'high', 'title': 'redeem totalDebt accounting',
             'root_cause': 'different mechanism on the same function',
             'paths': ['src/Vault.sol:Vault.redeem']}])
        bounty.backtest_score(self.case)
        rows = json.loads((self.case / 'matches.json').read_text())
        rows[0]['decision'] = 'related-not-same'
        rows[0]['decision_reason'] = 'same function, different root cause'
        bounty.dump(self.case / 'matches.json', rows)
        scored = bounty.backtest_score(self.case)
        self.assertEqual([r['id'] for r in scored['missed']], ['T1'])
        self.assertEqual([f['id'] for f in scored['unmatched_hunt_findings']], ['BP-001'])

    def test_unmatched_findings_are_reported_without_being_called_false(self):
        self.seal_with([self.finding()])
        bounty.dump(self.case / 'truth.json', [
            {'id': 'T9', 'severity': 'low', 'title': 'unrelated typo',
             'root_cause': 'docs', 'paths': ['docs/README.md']}])
        scored = bounty.backtest_score(self.case)
        self.assertEqual(scored['state'], 'scored')        # no pairs proposed, nothing to decide
        self.assertEqual([f['id'] for f in scored['unmatched_hunt_findings']], ['BP-001'])
        self.assertIn('NOT', scored['notice'])

    def test_truth_entries_are_validated(self):
        self.seal_with([self.finding()])
        bounty.dump(self.case / 'truth.json', [{'id': 'T1', 'severity': 'catastrophic'}])
        with self.assertRaises(ValueError):
            bounty.backtest_score(self.case)


    def test_refuted_records_earn_no_rediscovery_credit(self):
        refuted = self.finding('BP-002', lens='economics')
        refuted.update(status='refuted', rejection_reason='guarded by nonReentrant')
        self.seal_with([refuted])
        bounty.dump(self.case / 'truth.json', [
            {'id': 'T1', 'severity': 'high', 'title': 'redeem does not decrement totalDebt',
             'root_cause': 'the redeem path omits the totalDebt decrement',
             'paths': ['src/Vault.sol:Vault.redeem']}])
        # Even a pair decided by hand cannot credit a record that withdrew its claim.
        bounty.dump(self.case / 'matches.json', [{
            'truth_id': 'T1', 'finding_id': 'BP-002', 'overlap_score': 4.0,
            'decision': 'same-mechanism', 'decision_reason': 'same decrement'}])
        scored = bounty.backtest_score(self.case)
        self.assertEqual(scored['state'], 'scored')
        self.assertEqual(scored['rediscovered'], [])
        self.assertEqual([r['id'] for r in scored['missed']], ['T1'])
        self.assertEqual(scored['credited_lenses'], {})
        self.assertEqual([f['id'] for f in scored['refuted_hunt_findings']], ['BP-002'])
        self.assertEqual(scored['refuted_matches'], [{'truth_id': 'T1', 'finding_id': 'BP-002'}])
        self.assertEqual(scored['unmatched_hunt_findings'], [])
        self.assertEqual(scored['hunt_findings'], 0)

    def test_refuted_records_are_not_proposed_for_matching(self):
        refuted = self.finding('BP-002')
        refuted.update(status='refuted', rejection_reason='guarded')
        self.seal_with([self.finding(), refuted])
        bounty.dump(self.case / 'truth.json', [
            {'id': 'T1', 'severity': 'high', 'title': 'redeem does not decrement totalDebt',
             'root_cause': 'the redeem path omits the totalDebt decrement',
             'paths': ['src/Vault.sol:Vault.redeem']}])
        pending = bounty.backtest_score(self.case)
        self.assertEqual(pending['undecided'], 1)
        rows = json.loads((self.case / 'matches.json').read_text())
        self.assertEqual([r['finding_id'] for r in rows], ['BP-001'])


class ValueTests(unittest.TestCase):
    def test_balances_are_read_and_ranked_per_token(self):
        token = '0x' + 'aa' * 20
        rich, poor = '0x' + '11' * 20, '0x' + '22' * 20
        calls = []

        def node(request, timeout=None):
            body = json.loads(request.data.decode('utf-8'))
            method, params = body['method'], body['params']
            calls.append(method)
            if method == 'eth_chainId':
                result = '0x1'
            elif method == 'eth_blockNumber':
                result = '0x200'
            elif method == 'eth_getBalance':
                result = '0xde0b6b3a7640000' if params[0] == rich else '0x0'
            elif method == 'eth_getCode':
                result = '0x6001'
            elif method == 'eth_call':
                data = params[0]['data']
                if data.startswith(keccak.selector('decimals()')):
                    result = '0x' + '00' * 31 + '06'
                else:
                    result = ('0x' + '00' * 28 + '3b9aca00' if rich[2:].lower() in data.lower()
                              else '0x' + '00' * 32)
            else:
                result = None
            return FakeResponse({'jsonrpc': '2.0', 'id': body['id'], 'result': result})

        out = bounty.value_at_risk('http://node.invalid', [rich, poor], [token], 'latest', node)
        self.assertEqual(out['chain_id'], 1)
        self.assertEqual(out['block'], 512)
        self.assertEqual(out['holdings'][0]['native'], 1.0)
        held = out['holdings'][0]['tokens'][0]
        self.assertEqual(held['decimals'], 6)
        self.assertEqual(held['scaled'], 1000.0)
        self.assertEqual(out['ranked_per_token'][token][0]['address'], rich)

    def test_bad_address_is_refused_before_any_call(self):
        with self.assertRaises(ValueError):
            bounty.value_at_risk('http://node.invalid', ['nope'], None, 'latest', lambda *a: None)


    def test_one_bad_token_is_reported_without_aborting_the_rest(self):
        good, zero_dec, broken, empty = ('0x' + 'aa' * 20, '0x' + 'bb' * 20,
                                         '0x' + 'cc' * 20, '0x' + 'dd' * 20)
        holder = '0x' + '11' * 20

        def answer(method, params):
            if method == 'eth_chainId':
                return '0x1'
            if method == 'eth_blockNumber':
                return '0x10'
            if method == 'eth_getBalance':
                return '0x0'
            if method == 'eth_getCode':
                return '0x' if params[0] == empty else '0x6001'
            token, data = params[0]['to'], params[0]['data']
            if token == broken:
                raise ValueError('execution reverted')
            if data.startswith(keccak.selector('decimals()')):
                return '0x' + format(0 if token == zero_dec else 6, '064x')
            return '0x' + format(5_000_000, '064x')

        def node(request, timeout=None):
            body = json.loads(request.data.decode('utf-8'))
            try:
                payload = {'result': answer(body['method'], body['params'])}
            except ValueError as exc:
                payload = {'error': {'code': 3, 'message': str(exc)}}
            return FakeResponse(dict(payload, jsonrpc='2.0', id=body['id']))

        out = bounty.value_at_risk('http://node.invalid', [holder],
                                   [good, zero_dec, broken, empty], 'latest', node)
        held = {h['token']: h for h in out['holdings'][0]['tokens']}
        self.assertEqual(held[good]['scaled'], 5.0)
        self.assertEqual(held[zero_dec]['decimals'], 0)
        self.assertEqual(held[zero_dec]['scaled'], 5_000_000)      # was None for decimals 0
        self.assertIn('decimals() failed', out['token_errors'][broken])
        self.assertIn('balanceOf() failed', held[broken]['error'])
        self.assertIn('no code', out['token_errors'][empty])
        self.assertIsNone(held[empty]['raw'])                      # not a false zero balance
        self.assertEqual(out['ranked_per_token'][empty], [])


class DeltaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        (self.repo / 'test').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        (self.repo / 'src/Audited.sol').write_text('contract Audited { uint256 x; }\n')
        (self.repo / 'README.md').write_text('docs\n')
        commit(self.repo, 'audited state')
        self.audited = subprocess.run(['git', '-C', str(self.repo), 'rev-parse', 'HEAD'],
                                      check=True, stdout=subprocess.PIPE
                                      ).stdout.decode().strip()
        (self.repo / 'src/Risky.sol').write_text(
            'contract Risky {\n'
            '  uint256 public totalDebt;\n'
            '  function redeem(uint256 a) external {\n'
            '    (bool ok,) = msg.sender.call("");\n'
            '    require(ok);\n'
            '    token.safeTransfer(msg.sender, a);\n'
            '  }\n'
            '}\n')
        (self.repo / 'src/Quiet.sol').write_text('contract Quiet { uint256 y; }\n')
        (self.repo / 'test/Quiet.t.sol').write_text('contract QuietTest { Quiet q; }\n')
        (self.repo / 'README.md').write_text('docs changed\n')
        commit(self.repo, 'post-audit work')

    def test_ranking_prefers_value_bearing_untested_code(self):
        report = bounty.delta(self.repo, self.audited)
        paths = [row['path'] for row in report['ranked']]
        self.assertEqual(paths[0], 'src/Risky.sol')
        self.assertIn('src/Quiet.sol', paths)
        self.assertNotIn('README.md', paths)
        self.assertNotIn('test/Quiet.t.sol', paths)
        self.assertEqual(report['test_files_excluded'], 1)
        risky = report['ranked'][0]
        self.assertIn('external-call', risky['signals'])
        self.assertIn('token-move', risky['signals'])
        self.assertTrue(risky['untested_by_name'])

    def test_tested_file_is_marked_as_named_in_tests(self):
        report = bounty.delta(self.repo, self.audited)
        quiet = next(r for r in report['ranked'] if r['path'] == 'src/Quiet.sol')
        self.assertFalse(quiet['untested_by_name'])

    def test_scope_prefix_filters(self):
        report = bounty.delta(self.repo, self.audited, ['src/nonexistent/'])
        self.assertEqual(report['ranked'], [])

    def test_unknown_baseline_is_an_error_not_a_guess(self):
        with self.assertRaises(ValueError):
            bounty.delta(self.repo, 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef')

    def test_score_target_uses_code_and_program_facts(self):
        program = Path(self.temp.name) / 'program.json'
        program.write_text(json.dumps({
            'program': 'Example', 'audited_revision': self.audited,
            'in_scope_paths': ['src/'], 'duplicate_policy': 'first-to-report',
            'deposit_required': False, 'known_issues_count': 7,
            'upstream_fork': 'aave-v3', 'payout_max_usd': 100000}))
        result = bounty.score_target(self.repo, program)
        self.assertEqual(result['band'], 'hunt')
        self.assertGreaterEqual(result['priority_score'], 60)
        self.assertEqual(result['in_scope_files'], 3)
        self.assertIn('src/Risky.sol', result['untested_sample'])
        self.assertTrue(any('first-to-report' in r for r in result['reasons']))

    def test_evidence_filename_accepts_a_base58_program_id(self):
        """A Solana program id is base58 and case-significant. Requiring the EVM hex form, and
        lowercasing it, made deployment_status exact unreachable on every Solana target however
        good the evidence - reported from a live run that left its gate failing rather than
        edit the skill to pass."""
        evm = '0xAbC0000000000000000000000000000000000001'
        self.assertEqual(bounty._evidence_stem(evm), evm.lower())
        program_id = 'SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf'
        self.assertEqual(bounty._evidence_stem(program_id), program_id)
        for junk in ('not-an-address', '0xZZ', '', '0OIl' * 9):
            self.assertIsNone(bounty._evidence_stem(junk), junk)

    def test_review_count_is_scored_once_from_the_larger_source(self):
        """program.json's count and the shipped artifacts measure the same fact: eyes on this
        code. Penalising both double-counts it, and rewarding both double-rewards an unaudited
        target, so the score takes whichever source is larger and applies one penalty."""
        audits = self.repo / 'audit'
        audits.mkdir(exist_ok=True)
        for n in range(6):
            (audits / f'firm-{n}-audit.md').write_text(f'review {n}\n')
        commit(self.repo, 'ship six review reports')

        def score(declared):
            body = {'program': 'Example', 'in_scope_paths': ['src/']}
            if declared is not None:
                body['public_audit_count'] = declared
            path = Path(self.temp.name) / f'p-{declared}.json'
            path.write_text(json.dumps(body))
            return bounty.score_target(self.repo, path)

        shipped_only, both, declared_higher = score(None), score(6), score(20)
        # Six shipped and six declared is the same six: the penalty must not double.
        self.assertEqual(shipped_only['priority_score'], both['priority_score'])
        # One reason mentions the count, never two.
        for result in (shipped_only, both, declared_higher):
            counted = [r for r in result['reasons'] if 'review report' in r]
            self.assertEqual(len(counted), 1, counted)
        # The larger source wins, so a bigger declared count scores strictly worse.
        self.assertLess(declared_higher['priority_score'], both['priority_score'])
        self.assertTrue(any('program.json declares' in r for r in declared_higher['reasons']))
        self.assertTrue(any('the repository ships' in r for r in shipped_only['reasons']))
        self.assertEqual(shipped_only['review_artifacts']['count'], 6)

    def test_no_review_anywhere_is_unknown_not_a_clean_bill(self):
        bare = Path(self.temp.name) / 'no-reviews.json'
        bare.write_text(json.dumps({'program': 'Bare', 'in_scope_paths': ['src/']}))
        result = bounty.score_target(self.repo, bare)
        self.assertEqual(result['review_artifacts']['count'], 0)
        self.assertTrue(any('public_audit_count unknown' in u for u in result['unknowns']))
        self.assertFalse(any('few eyes per dollar' in r for r in result['reasons']))

    def test_score_target_records_unknowns_instead_of_assuming(self):
        program = Path(self.temp.name) / 'bare.json'
        program.write_text(json.dumps({'program': 'Bare', 'in_scope_paths': ['src/']}))
        result = bounty.score_target(self.repo, program)
        self.assertIsNone(result['churn_share_since_audit'])
        self.assertTrue(any('audited_revision' in u for u in result['unknowns']))
        self.assertTrue(any('duplicate_policy' in u for u in result['unknowns']))

    # ---- duplicate risk at stage 0 ----
    def program_file(self, name='program.json', **facts):
        path = Path(self.temp.name) / name
        payload = {'program': 'Example', 'in_scope_paths': ['src/']}
        payload.update(facts)
        path.write_text(json.dumps(payload))
        return path

    def remote(self):
        git(self.repo, 'remote', 'add', 'origin', 'https://example.invalid/org/vault.git')

    def seed_ledger(self, *outcomes):
        """Prior reports of your own to this project, through the real import path.

        Each call gets its own ledger, so two records can be scored in one test.
        """
        self.ledgers = getattr(self, 'ledgers', 0) + 1
        ledger = Path(self.temp.name) / f'private-{self.ledgers}' / 'history.jsonl'
        for number, outcome in enumerate(outcomes, 1):
            bounty.history_import('example.invalid/org/vault', f'OLD-{number}',
                                  'fee-accounting-not-decremented', ['src/Audited.sol'],
                                  'a prior mechanism of mine', outcome, ledger)
        return ledger

    def ship_reviews(self, count):
        (self.repo / 'audits').mkdir(exist_ok=True)
        for number in range(count):
            (self.repo / 'audits' / f'report-{number}.pdf').write_bytes(b'%PDF ' + bytes([number]))
        commit(self.repo, 'ship reviews')

    def test_score_target_reads_your_own_outcomes_on_this_project(self):
        self.remote()
        ledger = self.seed_ledger('duplicate', 'duplicate', 'paid')
        result = bounty.score_target(self.repo, self.program_file(), ledger)
        own = result['own_history']
        self.assertEqual(own['project_key'], 'example.invalid/org/vault')
        self.assertEqual(own['reports'], 3)
        self.assertEqual(own['dispositions'], {'duplicate': 2, 'paid': 1})
        self.assertEqual((own['decided'], own['duplicates'], own['landed']), (3, 2, 1))
        self.assertEqual([row['finding_id'] for row in own['recent']],
                         ['OLD-3', 'OLD-2', 'OLD-1'])
        self.assertTrue(all(row['recorded_at'] for row in own['recent']))
        self.assertTrue(any('closed as duplicate' in reason for reason in result['reasons']),
                        result['reasons'])

    def test_a_duplicate_only_record_scores_worse_than_a_clean_one(self):
        self.remote()
        program = self.program_file(duplicate_policy='first-to-report', deposit_required=False)
        duplicates = bounty.score_target(self.repo, program,
                                         self.seed_ledger('duplicate', 'duplicate'))
        landed = bounty.score_target(self.repo, program, self.seed_ledger('paid', 'accepted'))
        self.assertLess(duplicates['priority_score'], landed['priority_score'])
        self.assertTrue(any('accepted or paid and none closed as duplicate' in reason
                            for reason in landed['reasons']), landed['reasons'])

    def test_one_duplicate_among_several_weighs_less_than_a_mostly_duplicate_record(self):
        self.remote()
        program = self.program_file(duplicate_policy='first-to-report', deposit_required=False)
        one = bounty.score_target(self.repo, program,
                                  self.seed_ledger('duplicate', 'paid', 'paid'))
        most = bounty.score_target(self.repo, program,
                                   self.seed_ledger('duplicate', 'duplicate', 'paid'))
        self.assertGreater(one['priority_score'], most['priority_score'])

    def test_an_empty_ledger_is_an_unknown_and_never_a_clear_record(self):
        self.remote()
        result = bounty.score_target(self.repo, self.program_file(),
                                     Path(self.temp.name) / 'none' / 'history.jsonl')
        self.assertEqual(result['own_history']['reports'], 0)
        self.assertTrue(any('no reports of your own' in unknown
                            for unknown in result['unknowns']), result['unknowns'])
        self.assertFalse(any('duplicate' in reason for reason in result['reasons']),
                         result['reasons'])

    def test_undecided_reports_of_your_own_are_scored_as_neither(self):
        self.remote()
        result = bounty.score_target(self.repo, self.program_file(),
                                     self.seed_ledger('submitted', 'pending'))
        self.assertEqual(result['own_history']['decided'], 0)
        self.assertTrue(any('still undecided' in unknown
                            for unknown in result['unknowns']), result['unknowns'])

    def test_a_repository_with_no_remote_says_your_history_cannot_be_looked_up(self):
        result = bounty.score_target(self.repo, self.program_file())
        self.assertIsNone(result['own_history'])
        self.assertTrue(any('no origin remote' in unknown
                            for unknown in result['unknowns']), result['unknowns'])

    def test_an_unreadable_ledger_is_an_unknown_not_a_crash(self):
        self.remote()
        ledger = Path(self.temp.name) / 'private' / 'history.jsonl'
        ledger.parent.mkdir()
        ledger.write_text('{not-json}\n')
        result = bounty.score_target(self.repo, self.program_file(), ledger)
        self.assertIsNone(result['own_history'])
        self.assertTrue(any('private ledger not readable' in unknown
                            for unknown in result['unknowns']), result['unknowns'])

    def test_score_target_counts_the_review_artifacts_the_repository_ships(self):
        program = self.program_file()
        bare = bounty.score_target(self.repo, program)
        self.assertEqual(bare['review_artifacts']['count'], 0)
        self.assertTrue(any('no review artifact' in reason for reason in bare['reasons']),
                        bare['reasons'])
        self.ship_reviews(6)
        farmed = bounty.score_target(self.repo, program)
        self.assertEqual(farmed['review_artifacts']['count'], 6)
        self.assertEqual(len(farmed['review_artifacts']['paths']), 6)
        self.assertLess(farmed['priority_score'], bare['priority_score'])
        self.assertTrue(any('audit coverage, not by prize' in reason
                            for reason in farmed['reasons']), farmed['reasons'])

    def test_a_handful_of_reviews_weighs_less_than_a_shelf_of_them(self):
        program = self.program_file()
        self.ship_reviews(3)
        some = bounty.score_target(self.repo, program)
        self.ship_reviews(8)
        many = bounty.score_target(self.repo, program)
        self.assertEqual((some['review_artifacts']['count'], many['review_artifacts']['count']),
                         (3, 8))
        self.assertGreater(some['priority_score'], many['priority_score'])

    def test_the_finder_is_the_one_audit_inventory_uses(self):
        # One helper, two callers: what the score counts is what the inventory accounts for.
        self.ship_reviews(2)
        run = Path(self.temp.name) / 'run'
        bounty.initialize(self.repo, run)
        inventory = bounty.audit_inventory(self.repo, run)
        scored = bounty.score_target(self.repo, self.program_file())
        self.assertEqual(scored['review_artifacts']['paths'],
                         [row['path'] for row in inventory['artifacts']])

    def test_neither_duplicate_factor_decides_a_band_on_its_own(self):
        # Both are inputs to a heuristic. Each moves the score by less than the largest code
        # factor (churn at 30), so neither can carry a target into or out of a band alone.
        self.remote()
        program = self.program_file(audited_revision=self.audited,
                                    duplicate_policy='first-to-report', deposit_required=False,
                                    known_issues_count=7, upstream_fork='aave-v3',
                                    payout_max_usd=100000)
        empty = Path(self.temp.name) / 'none' / 'history.jsonl'
        base = bounty.score_target(self.repo, program, empty)
        self.assertEqual(base['band'], 'hunt')
        duplicates = bounty.score_target(self.repo, program,
                                         self.seed_ledger('duplicate', 'duplicate'))
        self.assertLessEqual(abs(duplicates['priority_score'] - base['priority_score']), 30)
        self.assertNotEqual(duplicates['band'], 'deprioritise')
        self.ship_reviews(10)
        farmed = bounty.score_target(self.repo, program, empty)
        self.assertLessEqual(abs(farmed['priority_score'] - base['priority_score']), 30)
        self.assertNotEqual(farmed['band'], 'deprioritise')

    def test_the_notice_still_refuses_to_predict(self):
        result = bounty.score_target(self.repo, self.program_file())
        self.assertIn('does not predict', result['notice'])
        self.assertIn('your own recorded outcomes', result['notice'])


    def test_cross_directory_rename_keeps_the_real_path(self):
        (self.repo / 'src/a').mkdir()
        (self.repo / 'src/a/Vault.sol').write_text(
            'contract Vault {\n  function f() external { (bool ok,) = msg.sender.call(""); }\n}\n')
        commit(self.repo, 'vault')
        base = subprocess.run(['git', '-C', str(self.repo), 'rev-parse', 'HEAD'], check=True,
                              stdout=subprocess.PIPE).stdout.decode().strip()
        (self.repo / 'src/b').mkdir()
        git(self.repo, 'mv', 'src/a/Vault.sol', 'src/b/Vault.sol')
        with open(self.repo / 'src/b/Vault.sol', 'a') as handle:
            handle.write('// moved\n')
        commit(self.repo, 'move vault')
        report = bounty.delta(self.repo, base)
        paths = [row['path'] for row in report['ranked']]
        self.assertEqual(paths, ['src/b/Vault.sol'])          # was: 'b}/Vault.sol'
        self.assertTrue(report['ranked'][0]['exists_at_head'])
        self.assertIn('external-call', report['ranked'][0]['signals'])

    def test_delta_scope_matches_whole_segments(self):
        (self.repo / 'src-legacy').mkdir()
        (self.repo / 'src-legacy/Old.sol').write_text('contract Old { uint256 z; }\n')
        commit(self.repo, 'legacy')
        report = bounty.delta(self.repo, self.audited, ['src'])
        paths = [row['path'] for row in report['ranked']]
        self.assertIn('src/Risky.sol', paths)
        self.assertNotIn('src-legacy/Old.sol', paths)

    def test_delta_and_score_target_do_not_follow_symlinks(self):
        outside = Path(self.temp.name) / 'outside.sol'
        outside.write_text('contract X { function f() external { msg.sender.call(""); } }\n')
        os.symlink(outside, self.repo / 'src/Link.sol')
        commit(self.repo, 'symlink')
        report = bounty.delta(self.repo, self.audited)
        link = next(r for r in report['ranked'] if r['path'] == 'src/Link.sol')
        self.assertEqual(link['signals'], {})
        self.assertIn({'path': 'src/Link.sol', 'reason': 'symlink'}, report['skipped_files'])
        program = Path(self.temp.name) / 'program.json'
        program.write_text(json.dumps({'program': 'P', 'in_scope_paths': ['src/']}))
        scored = bounty.score_target(self.repo, program)
        self.assertIn({'path': 'src/Link.sol', 'reason': 'symlink'}, scored['skipped_files'])


class GitHardeningTests(unittest.TestCase):
    """Review 0.9.1, item 8: a target's .git/config must not run commands through git."""

    def test_target_fsmonitor_hook_is_never_executed(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = base / 'repo'
            (repo / 'src').mkdir(parents=True)
            git(repo, 'init', '-q')
            (repo / 'src/Vault.sol').write_text('contract Vault {}\n')
            commit(repo, 'fixture')
            marker = base / 'pwned'
            hook = base / 'hook.sh'
            hook.write_text(f'#!/bin/sh\necho ran > "{marker}"\nexit 1\n')
            hook.chmod(0o755)
            git(repo, 'config', 'core.fsmonitor', str(hook))
            git(repo, 'config', 'core.hooksPath', str(base))
            (repo / 'src/Vault.sol').write_text('contract Vault { uint x; }\n')  # dirty
            subprocess.run(['git', '-C', str(repo), 'status', '--porcelain'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if not marker.exists():
                self.skipTest('this git does not run fsmonitor hooks; premise not testable')
            marker.unlink()
            bounty.initialize(repo, base / 'run')
            bounty.git(repo, 'status', '--porcelain')
            bounty.git(repo, 'diff', '--numstat', 'HEAD')
            self.assertFalse(marker.exists(), 'core.fsmonitor from the target config ran')


class TemplateTests(unittest.TestCase):
    def test_the_solana_control_test_cannot_pass_while_empty(self):
        # A passing empty negative control looks like evidence and establishes nothing.
        text = (ROOT / 'skills/bounty-pilot/templates/anchor_poc.rs').read_text()
        control = text.split('fn control_correct_account_path')[1]
        self.assertIn('unimplemented!', control)

    def test_every_template_demands_a_negative_control(self):
        for name in ('ForkPoC.t.sol', 'LocalPoC.t.sol', 'anchor_poc.rs'):
            text = (ROOT / 'skills/bounty-pilot/templates' / name).read_text()
            self.assertIn('control', text.lower(), name)


class CapabilityProbeTests(unittest.TestCase):
    """A probe that measures its own reach: toolchains, build surface, and how far an RPC sees."""

    # Deterministic stand-ins for the real probe tables: one tool that is always present, one
    # that never is, and a build/test pair that costs milliseconds instead of a compile.
    PROBES = (('python3', ('python3', '--version')),
              ('nosuchtool', ('bounty-pilot-nosuchtool-xyz', '--version')))
    BUILD = (('foundry.toml', ('python3', '-c', 'print("built")'), 'python3'),)
    TEST = (('foundry.toml', ('python3', '-c', 'print("tested")'), 'python3'),)
    RPC = 'https://eth-mainnet.g.alchemy.com/v2/Kx7SECRETKEY9012345678901234'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        (self.repo / 'test').mkdir()
        git(self.repo, 'init', '-q')
        (self.repo / 'src/Vault.sol').write_text('contract Vault {}\n')
        (self.repo / 'test/Vault.t.sol').write_text('contract VaultTest {}\n')
        (self.repo / 'foundry.toml').write_text('[profile.default]\nsrc = "src"\n')
        commit(self.repo, 'fixture')
        self.run = self.base / 'run'
        bounty.initialize(self.repo, self.run)

    def probe(self, **kwargs):
        with mock.patch.object(bounty, 'TOOLCHAIN_PROBES', self.PROBES), \
                mock.patch.object(bounty, 'BUILD_COMMANDS', self.BUILD), \
                mock.patch.object(bounty, 'TEST_COMMANDS', self.TEST):
            return bounty.capability_probe(self.repo, self.run, **kwargs)

    def node(self, head=0x200000):
        return FakeNode({'eth_chainId': '0x1', 'eth_blockNumber': hex(head),
                         'eth_getBalance': '0x0', 'eth_getLogs': []})

    def test_a_missing_toolchain_is_recorded_rather_than_raised(self):
        result = self.probe()
        self.assertFalse(result['toolchains']['nosuchtool']['present'])
        self.assertEqual(result['toolchains']['nosuchtool']['reason'], 'not on PATH')
        self.assertTrue(result['toolchains']['python3']['present'])
        self.assertRegex(result['toolchains']['python3']['version'], r'\d+\.\d+')

    def test_without_deep_the_build_is_reported_as_not_executed(self):
        result = self.probe()
        self.assertIsNone(result['deep_build'])
        self.assertIsNone(result['deep_test'])
        for kind in ('source-build', 'native-test-execution'):
            self.assertEqual(result['evidence'][kind]['state'], 'unknown')
            self.assertIn('NOT executed', result['evidence'][kind]['reason'])
        self.assertIn('build was NOT executed', result['notice'])

    def test_deep_executes_the_build_and_the_tests_and_records_both(self):
        result = self.probe(deep=True)
        self.assertEqual(result['deep_build']['exit_code'], 0)
        self.assertIn('built', result['deep_build']['output_excerpt'])
        self.assertIn('tested', result['deep_test']['output_excerpt'])
        self.assertEqual(result['evidence']['source-build']['state'], 'available')
        self.assertEqual(result['evidence']['native-test-execution']['state'], 'available')

    def test_a_failing_deep_build_is_unavailable_with_what_it_printed(self):
        failing = (('foundry.toml', ('python3', '-c', 'raise SystemExit("boom")'), 'python3'),)
        with mock.patch.object(bounty, 'TOOLCHAIN_PROBES', self.PROBES), \
                mock.patch.object(bounty, 'BUILD_COMMANDS', failing), \
                mock.patch.object(bounty, 'TEST_COMMANDS', self.TEST):
            result = bounty.capability_probe(self.repo, self.run, deep=True)
        self.assertEqual(result['evidence']['source-build']['state'], 'unavailable')
        self.assertIn('boom', result['evidence']['source-build']['reason'])

    def test_a_missing_build_toolchain_is_unavailable_not_unknown(self):
        with mock.patch.object(bounty, 'TOOLCHAIN_PROBES', self.PROBES[1:]), \
                mock.patch.object(bounty, 'BUILD_COMMANDS', self.BUILD), \
                mock.patch.object(bounty, 'TEST_COMMANDS', self.TEST):
            result = bounty.capability_probe(self.repo, self.run)
        self.assertEqual(result['evidence']['source-build']['state'], 'unavailable')
        self.assertIn('not on PATH', result['evidence']['source-build']['reason'])

    def test_the_rpc_url_is_never_printed_or_written(self):
        node = self.node()
        result = self.probe(rpc=self.RPC, opener=node)
        written = (self.run / 'capabilities.json').read_text(encoding='utf-8')
        for haystack in (json.dumps(result), written):
            self.assertNotIn(self.RPC, haystack)
            self.assertNotIn('Kx7SECRETKEY', haystack)
            self.assertNotIn('alchemy.com', haystack)
        self.assertEqual(result['rpc']['endpoint'], 'not recorded')
        self.assertEqual(result['rpc']['chain_id'], 1)
        self.assertEqual(result['rpc']['head_block'], 0x200000)

    def test_the_archive_probe_records_the_oldest_block_that_answered(self):
        head = 0x200000
        shallow = {'eth_chainId': '0x1', 'eth_blockNumber': hex(head), 'eth_getLogs': [],
                   'eth_getBalance': lambda params: (
                       '0x0' if int(params[1], 16) >= head - 128 else None)}

        def opener(request, timeout=None):
            body = json.loads(request.data.decode('utf-8'))
            value = shallow[body['method']]
            value = value(body['params']) if callable(value) else value
            if value is None:
                return FakeResponse({'jsonrpc': '2.0', 'id': body['id'],
                                     'error': {'code': -32000,
                                               'message': 'missing trie node'}})
            return FakeResponse({'jsonrpc': '2.0', 'id': body['id'], 'result': value})

        result = self.probe(rpc=self.RPC, opener=opener)
        self.assertEqual(result['rpc']['archive_depth_blocks'], 128)
        self.assertEqual(result['rpc']['oldest_answering_block'], head - 128)
        self.assertEqual(result['evidence']['archive-state']['state'], 'unavailable')
        self.assertIn('128 blocks behind the head',
                      result['evidence']['archive-state']['reason'])

    def test_a_deep_endpoint_makes_archive_state_available(self):
        result = self.probe(rpc=self.RPC, opener=self.node())
        self.assertEqual(result['rpc']['archive_depth_blocks'], 1_000_000)
        self.assertEqual(result['evidence']['archive-state']['state'], 'available')
        self.assertEqual(result['evidence']['historical-logs']['state'], 'available')

    def test_an_unreachable_endpoint_does_not_leak_its_url_in_the_reason(self):
        def opener(request, timeout=None):
            raise urllib.error.URLError('connection refused to ' + self.RPC)

        result = self.probe(rpc=self.RPC, opener=opener)
        written = (self.run / 'capabilities.json').read_text(encoding='utf-8')
        self.assertFalse(result['rpc']['reachable'])
        self.assertNotIn('Kx7SECRETKEY', json.dumps(result))
        self.assertNotIn('alchemy.com', written)
        self.assertEqual(result['evidence']['mainnet-fork']['state'], 'unavailable')

    def test_no_rpc_leaves_every_on_chain_capability_unknown(self):
        result = self.probe()
        for kind in ('mainnet-fork', 'archive-state', 'historical-logs', 'bytecode-comparison'):
            self.assertEqual(result['evidence'][kind]['state'], 'unknown')
            self.assertIn('no --rpc', result['evidence'][kind]['reason'])

    def test_a_root_package_json_workspace_declaration_is_read_not_assumed(self):
        (self.repo / 'package.json').write_text(
            json.dumps({'name': 'monorepo', 'workspaces': ['packages/*'],
                        'scripts': {'build': 'turbo build'}}))
        commit(self.repo, 'workspaces')
        declares = self.probe()['build_surface']['manifests']['package.json']['declares']
        self.assertTrue(declares['declares_workspaces'])
        self.assertEqual(declares['workspaces'], ['packages/*'])

    def test_a_subproject_copied_out_of_its_monorepo_is_visible(self):
        # The mistake itself: the manifest the blocker said did not exist lives one level up.
        (self.repo / 'packages/app').mkdir(parents=True)
        (self.repo / 'packages/app/package.json').write_text('{"name": "app"}')
        commit(self.repo, 'nested only')
        surface = self.probe()['build_surface']
        self.assertEqual(surface['nested_manifests_without_a_root_one'], ['package.json'])
        self.assertFalse(surface['manifests']['package.json']['at_root'])
        self.assertEqual(surface['manifests']['package.json']['elsewhere'],
                         ['packages/app/package.json'])
        self.assertIn('copied out of its monorepo', surface['note'])

    def test_a_cargo_workspace_root_is_detected_with_its_members(self):
        (self.repo / 'Cargo.toml').write_text(
            '[workspace]\nmembers = ["programs/vault", "crates/common"]\nresolver = "2"\n')
        commit(self.repo, 'cargo workspace')
        declares = self.probe()['build_surface']['manifests']['Cargo.toml']['declares']
        self.assertTrue(declares['workspace_root'])
        self.assertEqual(declares['workspace_members'], ['programs/vault', 'crates/common'])

    def test_every_evidence_kind_reports_one_of_the_declared_states(self):
        # `contradicted_blockers` compares against `available`; a stray spelling would read as
        # "not measured" and the contradiction would never be reported.
        for result in (self.probe(), self.probe(rpc=self.RPC, opener=self.node())):
            self.assertEqual(sorted(result['evidence']),
                             ['archive-state', 'bytecode-comparison', 'historical-logs',
                              'mainnet-fork', 'native-test-execution', 'source-build'])
            for kind, entry in result['evidence'].items():
                self.assertIn(entry['state'], bounty.EVIDENCE_STATES, kind)
                self.assertTrue(entry['reason'].strip(), kind)

    def test_the_test_surface_names_the_files_and_the_command(self):
        tests = self.probe()['test_surface']
        self.assertEqual(tests['test_files'], 1)
        self.assertEqual(tests['examples'], ['test/Vault.t.sol'])
        self.assertEqual(tests['command']['from_manifest'], 'foundry.toml')

    def test_the_probe_refuses_a_run_directory_init_never_made(self):
        with self.assertRaises(ValueError):
            bounty.capability_probe(self.repo, self.base / 'not-a-run')

    def test_the_probe_refuses_to_write_inside_the_target(self):
        inside = self.repo / 'run'
        inside.mkdir()
        (inside / 'run.json').write_text('{}')
        with self.assertRaises(ValueError):
            bounty.capability_probe(self.repo, inside)


class CoverageFloorTests(unittest.TestCase):
    """What the word `exhausted` has to answer to: recorded rows against the in-scope list."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        for name in ('Vault.sol', 'Pool.sol', 'Oracle.sol', 'Router.sol'):
            (self.repo / 'src' / name).write_text('contract C {}\n')
        commit(self.repo, 'fixture')
        self.run = self.base / 'run'
        bounty.initialize(self.repo, self.run)

    def coverage(self, *rows):
        body = ('# Coverage\n\n| Surface / invariant | Lens | Pass | Experiment | Result |\n'
                '| --- | --- | --- | --- | --- |\n')
        for row in rows:
            body += '| ' + row + ' | accounting | 1 | ran | nothing |\n'
        (self.run / 'coverage.md').write_text(body, encoding='utf-8')

    def known(self, *rows):
        body = '# Known hypotheses\n\n'
        for row in rows:
            body += row + '\n'
        (self.run / 'known-hypotheses.md').write_text(body, encoding='utf-8')

    def records(self, *paths):
        rows = []
        for i, path in enumerate(paths, 1):
            row = bounty.template()
            row.update(id='BP-%03d' % i, affected_paths=[path])
            rows.append(row)
        bounty.dump(self.run / 'findings.json', rows)

    def floor(self, **kwargs):
        kwargs.setdefault('scope_prefixes', ['src'])
        return bounty.coverage_floor(self.repo, self.run, **kwargs)

    def test_coverage_md_alone_marks_a_file_examined(self):
        self.coverage('src/Vault.sol:Vault.withdraw')
        result = self.floor()
        self.assertEqual(result['files_in_scope'], 4)
        self.assertEqual(result['examined_by_source'],
                         {'coverage.md': 1, 'known-hypotheses.md': 0, 'findings.json': 0,
                          'examined.json': 0})
        self.assertEqual(result['unexamined'],
                         ['src/Oracle.sol', 'src/Pool.sol', 'src/Router.sol'])
        self.assertEqual(result['examined_fraction'], 0.25)

    def test_known_hypotheses_alone_marks_a_file_examined(self):
        self.known('| src/Pool.sol:Pool.swap | stale-index | closed | guarded |')
        result = self.floor()
        self.assertEqual(result['examined_by_source'],
                         {'coverage.md': 0, 'known-hypotheses.md': 1, 'findings.json': 0,
                          'examined.json': 0})

    def test_affected_paths_alone_marks_a_file_examined(self):
        self.records('src/Oracle.sol')
        result = self.floor()
        self.assertEqual(result['examined_by_source'],
                         {'coverage.md': 0, 'known-hypotheses.md': 0, 'findings.json': 1,
                          'examined.json': 0})

    def test_the_three_sources_add_up_without_double_counting(self):
        self.coverage('src/Vault.sol:Vault.withdraw', 'src/Pool.sol')
        self.known('| src/Pool.sol | stale-index | closed | guarded |')
        self.records('src/Oracle.sol')
        result = self.floor()
        self.assertEqual(result['files_examined'], 3)
        self.assertEqual(result['examined_fraction'], 0.75)
        self.assertEqual(result['unexamined'], ['src/Router.sol'])

    def test_a_surface_matches_whole_path_segments_only(self):
        (self.repo / 'src-legacy').mkdir()
        (self.repo / 'src-legacy/Vault.sol').write_text('contract C {}\n')
        commit(self.repo, 'legacy')
        self.coverage('src/')
        # `src/` is a directory of the in-scope tree, so it reaches all four - but it names none
        # of them, so they are listed apart and do not count; `src-legacy` is a different
        # directory and was never in scope to begin with.
        result = self.floor()
        self.assertEqual(result['files_examined'], 0)
        self.assertEqual(result['credited_by_directory_only_count'], 4)
        self.assertNotIn('src-legacy/Vault.sol', result['unexamined'])
        self.assertNotIn('src-legacy/Vault.sol', result['credited_by_directory_only'])
        # A bare directory name with no separator is not credited: one such row would mark a
        # whole tree examined, and it reads the same as an invariant name.
        self.coverage('src')
        self.assertEqual(self.floor()['files_examined'], 0)

    def test_a_bare_file_name_matches_by_whole_name_never_by_substring(self):
        self.coverage('Vault.sol')
        self.assertEqual(self.floor()['files_examined'], 1)
        self.coverage('ault.sol')
        self.assertEqual(self.floor()['files_examined'], 0)

    def test_tests_and_vendored_trees_are_excluded_and_counted(self):
        (self.repo / 'src/test').mkdir()
        (self.repo / 'src/test/Vault.t.sol').write_text('contract T {}\n')
        (self.repo / 'src/lib').mkdir()
        (self.repo / 'src/lib/ERC20.sol').write_text('contract E {}\n')
        commit(self.repo, 'noise')
        result = self.floor()
        self.assertEqual(result['files_in_scope'], 4)
        self.assertEqual(result['excluded_vendored'], ['src/lib/ERC20.sol'])
        self.assertNotIn('src/test/Vault.t.sol', result['unexamined'])

    def test_the_full_unexamined_list_is_in_the_file_and_capped_in_the_summary(self):
        with mock.patch.object(bounty, 'UNEXAMINED_SHOWN', 2):
            result = self.floor()
        written = bounty.read_json(self.run / 'coverage-floor.json')
        self.assertEqual(len(result['unexamined']), 2)
        self.assertTrue(result['unexamined_truncated'])
        self.assertEqual(len(written['unexamined']), 4)
        self.assertEqual(result['unexamined_count'], 4)

    def test_the_gate_fails_below_the_floor_and_passes_at_or_above_it(self):
        self.coverage('src/Vault.sol')
        argv = ['coverage-floor', '--repo', str(self.repo), '--run', str(self.run),
                '--scope', 'src', '--gate']
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(bounty.main(argv), 1)
        self.assertEqual(json.loads(out.getvalue())['state'], 'below-floor')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(bounty.main(argv + ['--min-fraction', '0.25']), 0)
        # One directory row used to pass this gate at 100%; it names no file, so it fails.
        self.coverage('src/')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(bounty.main(argv), 1)
        self.coverage('src/Vault.sol', 'src/Pool.sol', 'src/Oracle.sol', 'src/Router.sol')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(bounty.main(argv), 0)

    def test_an_empty_in_scope_list_measures_nothing_and_never_passes(self):
        result = self.floor(scope_prefixes=['does/not/exist'])
        self.assertEqual(result['state'], 'no-files-in-scope')
        self.assertEqual(result['examined_fraction'], 0.0)

    def test_a_nonsense_min_fraction_is_an_error_not_a_pass(self):
        with self.assertRaises(ValueError):
            self.floor(min_fraction=1.5)

    def test_the_default_floor_is_declared_once_and_used_by_the_cli(self):
        self.assertEqual(bounty.COVERAGE_FLOOR_DEFAULT, 0.8)
        args = bounty.build_parser().parse_args(
            ['coverage-floor', '--repo', 'r', '--run', 'x'])
        self.assertEqual(args.min_fraction, bounty.COVERAGE_FLOOR_DEFAULT)


class CliTests(unittest.TestCase):
    def test_subcommands_are_wired(self):
        parser = bounty.build_parser()
        for argv in (['init', '--repo', '.', '--out', 'x'], ['check', '--run', 'x'],
                     ['check', '--run', 'x', '--submission'], ['dup-check', '--run', 'x'],
                     ['queue', '--run', 'x'],
                     ['capability-probe', '--repo', '.', '--run', 'x'],
                     ['capability-probe', '--repo', '.', '--run', 'x', '--rpc', 'u',
                      '--deep', '--timeout', '120'],
                     ['coverage-floor', '--repo', '.', '--run', 'x'],
                     ['coverage-floor', '--repo', '.', '--run', 'x', '--scope', 'src',
                      '--gate', '--min-fraction', '0.6'],
                     ['converge', '--readings', 'readings', '--run', 'x'],
                     ['converge', '--readings', 'a', '--readings', 'b', '--run', 'x',
                      '--threshold', '3'],
                     ['history', 'check', '--run', 'x'],
                     ['history', 'record', '--run', 'x', '--finding', 'BP-001',
                      '--outcome', 'submitted'],
                     ['history', 'import', '--project', 'github.com/org/repo',
                      '--finding-id', 'C4-001', '--bug-class', 'bad-accounting',
                      '--surface', 'src/Vault.sol:withdraw', '--root-cause', 'missing decrement',
                      '--outcome', 'duplicate'],
                     ['history', 'import', '--from-file', 'export.json'],
                     ['history', 'import', '--from-file', 'export.json', '--ledger', 'l.jsonl',
                      '--program', 'Cantina', '--project', 'github.com/org/repo', '--dry-run'],
                     ['history', 'summary'],
                     ['audit-inventory', '--repo', '.', '--run', 'x'],
                     ['audit-inventory', '--repo', '.', '--run', 'x', '--gate'],
                     ['delta', '--repo', '.', '--since', 'HEAD'],
                     ['bundle', '--repo', '.', '--run', 'x', '--lens', 'attack'],
                     ['bundle', '--repo', '.', '--run', 'x', '--lens', 'triage'],
                     ['solc-bugs', '--repo', '.'],
                     ['solc-bugs', '--version', '0.8.19'],
                     ['value', '--rpc', 'u', '--address', 'a'],
                     ['backtest', 'init', '--name', 'n', '--repo', '.', '--out', 'o'],
                     ['backtest', 'seal', '--case', 'c', '--run', 'r'],
                     ['backtest', 'score', '--case', 'c'],
                     ['score-target', '--repo', '.', '--program', 'p.json'],
                     ['score-target', '--repo', '.', '--program', 'p.json',
                      '--ledger', 'l.jsonl'],
                     ['verify-deployment', '--rpc', 'u', '--address', 'a'],
                     ['verify-deployment', '--rpc', 'u', '--address', 'a', '--artifact', 'f',
                      '--block', '1', '--run', 'r'],
                     ['sig', 'transfer(address,uint256)'],
                     ['eth-call', '--rpc', 'u', '--to', 't', '--sig', 's']):
            parser.parse_args(argv)

    def test_sig_subcommand_prints_a_selector(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = bounty.main(['sig', 'transfer(address,uint256)'])
        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue().strip(), '0xa9059cbb')

    def test_bad_input_exits_two_without_a_traceback(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = bounty.main(['delta', '--repo', '/nonexistent', '--since', 'HEAD'])
        self.assertEqual(code, 2)
        self.assertTrue(err.getvalue().startswith('Error:'))


    def test_unexpected_exceptions_become_one_error_line(self):
        err = io.StringIO()
        with mock.patch.object(bounty, 'validate', side_effect=TypeError('unhashable type')), \
                mock.patch.dict(bounty.os.environ, {'BOUNTY_DEBUG': ''}), \
                contextlib.redirect_stderr(err):
            code = bounty.main(['check', '--run', 'x'])
        self.assertEqual(code, 2)
        lines = err.getvalue().strip().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith('Error: unexpected TypeError'))

if __name__ == '__main__':
    unittest.main()
