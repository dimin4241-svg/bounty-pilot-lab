import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cs = load('config_snapshot', 'skills/bounty-pilot/scripts/config_snapshot.py')

RPC = 'https://eth-mainnet.secretnode.example/v2/AbCdEf0123456789SuperSecretKey'
HOST = 'eth-mainnet.secretnode.example'
KEY = 'AbCdEf0123456789SuperSecretKey'
BLOCK = 1_000_000
NOW = 1_800_000_000


def a(n):
    return '0x' + format(n, '040x')


def w(n):
    return format(n % 2 ** 256, '064x')


def addr_word(address):
    return '0' * 24 + address[2:]


def ret(*words):
    return '0x' + ''.join(words)


def addr_array_ret(items, extra_head=()):
    """(address[] arr, ...extra static words) return encoding."""
    head = 32 * (1 + len(extra_head))
    return ret(w(head), *extra_head, w(len(items)), *[addr_word(x) for x in items])


def bytes_ret(raw):
    padded = raw + b'\0' * (-len(raw) % 32)
    return ret(w(32), w(len(raw))) + padded.hex()


class FakeChain:
    """Dispatch on method, `to` and the calldata selector. No network."""

    def __init__(self):
        self.calls = {}      # (to, selector) -> hex result, or callable(data) -> hex
        self.code = {}       # address -> hex code
        self.storage = {}    # (address, slot) -> 32-byte hex word
        self.logs = []
        self.fail = {}       # (to, selector) -> message raised
        self.log_calls = []
        self.log_fail_wide = None
        self.methods = []

    def on(self, to, sig, result):
        self.calls[(to.lower(), cs.selector(sig))] = result

    def __call__(self, method, params):
        self.methods.append(method)
        if method == 'eth_chainId':
            return '0x1'
        if method == 'eth_blockNumber':
            return hex(BLOCK)
        if method == 'eth_getBlockByNumber':
            return {'number': params[0], 'timestamp': hex(NOW)}
        if method == 'eth_getCode':
            return self.code.get(params[0].lower(), '0x')
        if method == 'eth_getBalance':
            return '0xde0b6b3a7640000'
        if method == 'eth_getStorageAt':
            return '0x' + self.storage.get((params[0].lower(), params[1]), '0' * 64)
        if method == 'eth_getLogs':
            f = params[0]
            lo, hi = int(f['fromBlock'], 16), int(f['toBlock'], 16)
            self.log_calls.append((lo, hi))
            if self.log_fail_wide and hi - lo + 1 > self.log_fail_wide:
                raise OSError(f'range too wide for {RPC} at {HOST}')
            return [x for x in self.logs if lo <= int(x['blockNumber'], 16) <= hi
                    and x['address'] == f['address']]
        if method == 'eth_call':
            to, data = params[0]['to'].lower(), params[0]['data']
            key = (to, data[:10])
            if key in self.fail:
                raise OSError(self.fail[key])
            result = self.calls.get(key)
            if result is None:
                return '0x'
            return result(data) if callable(result) else result
        raise AssertionError(f'unexpected method {method}')


def run(chain, targets, known=None, block='latest'):
    return cs.snapshot(RPC, targets, known=known, block=block, opener=chain)


def codes(target):
    return [f['code'] for f in target['flags']]


class DerivedConstantsTests(unittest.TestCase):
    def test_selectors_topics_and_slots_equal_published_values(self):
        self.assertEqual(cs.selector('getThreshold()'), '0xe75235b8')
        self.assertEqual(cs.selector('owner()'), '0x8da5cb5b')
        self.assertEqual(cs.selector('latestRoundData()'), '0xfeaf968c')
        self.assertEqual(cs.topic('Transfer(address,address,uint256)'),
                         '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef')
        self.assertEqual(cs.TOPICS['RoleGranted'],
                         '0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d')
        self.assertEqual(cs.SLOTS['implementation'],
                         '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc')
        self.assertEqual(cs.SLOTS['admin'],
                         '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103')
        self.assertEqual(cs.SLOTS['beacon'],
                         '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50')
        self.assertEqual(cs.SLOTS['safe_guard'],
                         '0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8')
        self.assertEqual(cs.role_id('MINTER_ROLE'),
                         '0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6')

    def test_source_has_no_pasted_selector_constants(self):
        text = (ROOT / 'skills/bounty-pilot/scripts/config_snapshot.py').read_text()
        for published in ('e75235b8', '360894a13ba1', '2f8788117e7e', 'ddf252ad'):
            self.assertNotIn(published, text)


class AbiTests(unittest.TestCase):
    def test_uln_config_round_trip(self):
        req, opt = [a(0xD1), a(0xD2)], [a(0xE1), a(0xE2), a(0xE3)]
        raw = cs.encode_uln_config(15, req, opt, 2)
        got = cs.decode_uln_config(raw)
        self.assertEqual(got['confirmations'], 15)
        self.assertEqual(got['required_dvn_count'], 2)
        self.assertEqual(got['optional_dvn_count'], 3)
        self.assertEqual(got['optional_dvn_threshold'], 2)
        self.assertEqual(got['required_dvns'], req)
        self.assertEqual(got['optional_dvns'], opt)

    def test_nil_dvn_count_reads_as_zero(self):
        raw = bytearray(cs.encode_uln_config(1, [], [], 0))
        raw[32 + 63] = 255   # requiredDVNCount word of the tuple head
        got = cs.decode_uln_config(bytes(raw))
        self.assertEqual(got['required_dvn_count'], 0)
        self.assertEqual(got['required_dvn_count_raw'], 255)

    def test_encode_call(self):
        data = cs.encode_call('peers(uint32)', [30101])
        self.assertTrue(data.startswith(cs.selector('peers(uint32)')))
        self.assertEqual(int(data[10:], 16), 30101)
        with self.assertRaises(ValueError):
            cs.encode_call('peers(uint32)', [])

    def test_disallowed_method_is_refused(self):
        reader = cs.Reader(FakeChain(), 'latest', RPC)
        with self.assertRaises(cs.RpcFailure):
            reader.raw('eth_sendRawTransaction', ['0x00'])


SAFE = a(0x5AFE)


def safe_chain(threshold, owners, modules=(), owner_code=()):
    chain = FakeChain()
    chain.code[SAFE] = '0x6080'
    for o in owner_code:
        chain.code[o] = '0x60'
    chain.on(SAFE, 'getThreshold()', ret(w(threshold)))
    chain.on(SAFE, 'getOwners()', addr_array_ret(owners))
    chain.on(SAFE, 'getModulesPaginated(address,uint256)',
             addr_array_ret(list(modules), extra_head=[addr_word(a(1))]))
    chain.on(SAFE, 'nonce()', ret(w(42)))
    return chain


class SafeTests(unittest.TestCase):
    def test_minority_threshold_and_module_flagged(self):
        owners = [a(i) for i in range(10, 15)]
        chain = safe_chain(2, owners, modules=[a(0xAA)], owner_code=[owners[0]])
        t = run(chain, [{'address': SAFE, 'kind': 'safe'}])['targets'][0]
        self.assertEqual(t['errors'], [])
        self.assertIn('SAFE_MINORITY_THRESHOLD', codes(t))
        self.assertIn('SAFE_MODULE_ENABLED', codes(t))
        self.assertEqual(t['reads']['threshold'], 2)
        self.assertEqual(t['reads']['nonce'], 42)
        self.assertEqual(t['reads']['owners'][0]['code_size'], 1)
        self.assertEqual(t['reads']['owners'][1]['code_size'], 0)
        self.assertIn('Drift', [f for f in t['flags']
                                if f['code'] == 'SAFE_MINORITY_THRESHOLD'][0]['shape'])

    def test_threshold_one_flagged(self):
        chain = safe_chain(1, [a(10), a(11)])
        t = run(chain, [{'address': SAFE, 'kind': 'safe'}])['targets'][0]
        self.assertEqual(codes(t), ['SAFE_THRESHOLD_ONE'])

    def test_majority_threshold_no_modules_is_clean(self):
        chain = safe_chain(3, [a(10), a(11), a(12), a(13)])
        chain.storage[(SAFE, cs.SLOTS['safe_guard'])] = addr_word(a(0x9))
        t = run(chain, [{'address': SAFE, 'kind': 'safe'}])['targets'][0]
        self.assertEqual(t['flags'], [])
        self.assertEqual(t['reads']['guard'], a(0x9))


class TimelockTests(unittest.TestCase):
    def test_zero_delay_and_below_expected(self):
        chain = FakeChain()
        chain.on(a(1), 'getMinDelay()', ret(w(0)))
        chain.on(a(2), 'delay()', ret(w(3600)))
        chain.on(a(3), 'getMinDelay()', ret(w(172800)))
        out = run(chain, [{'address': a(1), 'kind': 'timelock'},
                          {'address': a(2), 'kind': 'timelock', 'expect': {'min_delay': 86400}},
                          {'address': a(3), 'kind': 'timelock', 'expect': {'min_delay': 86400}}])
        t1, t2, t3 = out['targets']
        self.assertEqual(codes(t1), ['TIMELOCK_ZERO_DELAY'])
        self.assertEqual(codes(t2), ['TIMELOCK_DELAY_BELOW_EXPECTED'])
        self.assertEqual(t2['reads']['read_via'], 'delay()')
        self.assertEqual(t3['flags'], [])


class OwnableTests(unittest.TestCase):
    def test_eoa_owner_not_known(self):
        chain = FakeChain()
        chain.code[a(1)] = '0x' + '00' * 100
        chain.on(a(1), 'owner()', ret(addr_word(a(0xEE))))
        t = run(chain, [{'address': a(1), 'kind': 'ownable'}], known=[a(1)])['targets'][0]
        self.assertEqual(sorted(codes(t)), ['OWNER_IS_EOA', 'OWNER_NOT_KNOWN'])
        self.assertEqual(t['reads']['target_code_size'], 100)
        self.assertIsNone(t['reads']['pending_owner'])

    def test_known_contract_owner_is_clean(self):
        chain = FakeChain()
        chain.code[a(1)] = '0x00'
        chain.code[a(2)] = '0x00'
        chain.on(a(1), 'owner()', ret(addr_word(a(2))))
        chain.on(a(1), 'pendingOwner()', ret(w(0)))
        t = run(chain, [{'address': a(1), 'kind': 'ownable'}], known=[a(1), a(2)])['targets'][0]
        self.assertEqual(t['flags'], [])
        self.assertEqual(t['reads']['pending_owner'], cs.ZERO_ADDRESS)


AC = a(0xAC)


def role_log(event, role, account, block, index=0):
    return {'address': AC, 'blockNumber': hex(block), 'logIndex': hex(index),
            'topics': [cs.TOPICS[event], role, '0x' + addr_word(account), '0x' + addr_word(a(1))]}


class AccessControlTests(unittest.TestCase):
    def setUp(self):
        self.chain = FakeChain()
        c = self.chain
        admin, minter = cs.role_id('DEFAULT_ADMIN_ROLE'), cs.role_id('REBALANCER_ROLE')
        self.old, self.new, self.eoa = a(0x01D), a(0x2EE), a(0xE0A)
        for x in (self.old, self.new, a(0x5AFE)):
            c.code[x] = '0x60'
        c.logs = [role_log('RoleGranted', admin, a(0x5AFE), 10),
                  role_log('RoleGranted', minter, self.old, 20),
                  role_log('RoleGranted', minter, self.new, 900_000),
                  role_log('RoleGranted', minter, self.eoa, 900_001),
                  role_log('RoleRevoked', minter, self.eoa, 900_002)]
        c.on(AC, 'hasRole(bytes32,address)', lambda data: ret(w(1)))

    def test_replaced_component_keeps_role(self):
        t = run(self.chain, [{'address': AC, 'kind': 'access-control',
                              'expect': {'max_range': 100_000}}],
                known=[AC, a(0x5AFE), self.new])['targets'][0]
        self.assertEqual(t['errors'], [])
        self.assertEqual(codes(t), ['ROLE_MEMBER_NOT_KNOWN'])
        self.assertIn(self.old, t['flags'][0]['detail'])
        members = [m['address'] for m in t['reads']['roles']['REBALANCER_ROLE']]
        self.assertEqual(sorted(members), sorted([self.old, self.new]))
        self.assertFalse(t['reads']['log_scan']['truncated'])

    def test_admin_eoa_and_no_code_member(self):
        self.chain.logs.append(role_log('RoleGranted', cs.role_id('DEFAULT_ADMIN_ROLE'),
                                        a(0xBAD), 30))
        self.chain.logs.append(role_log('RoleGranted', cs.role_id('MINTER_ROLE'), a(0xDEAD), 31))
        t = run(self.chain, [{'address': AC, 'kind': 'access-control',
                              'expect': {'max_range': 1_000_000}}])['targets'][0]
        self.assertIn('ADMIN_ROLE_EOA', codes(t))
        self.assertIn('ROLE_MEMBER_NO_CODE', codes(t))
        self.assertNotIn('ROLE_MEMBER_NOT_KNOWN', codes(t))   # no known set given
        self.assertIn('known_note', t['reads'])

    def test_all_known_is_clean(self):
        t = run(self.chain, [{'address': AC, 'kind': 'access-control',
                              'expect': {'max_range': 1_000_000}}],
                known=[a(0x5AFE), self.old, self.new])['targets'][0]
        self.assertEqual(t['flags'], [])

    def test_chunk_truncation_is_reported(self):
        t = run(self.chain, [{'address': AC, 'kind': 'access-control',
                              'expect': {'max_range': 1000, 'max_chunks': 5}}])['targets'][0]
        scan = t['reads']['log_scan']
        self.assertTrue(scan['truncated'])
        self.assertEqual(scan['scanned_to'], 4999)
        self.assertIn('NOT scanned', scan['truncation'])
        self.assertEqual(len(self.chain.log_calls), 5)

    def test_failed_range_is_split_and_scrubbed(self):
        self.chain.log_fail_wide = 1
        t = run(self.chain, [{'address': AC, 'kind': 'access-control',
                              'expect': {'from_block': 0, 'max_range': 1_000_001}}])['targets'][0]
        scan = t['reads']['log_scan']
        self.assertTrue(scan['truncated'])
        self.assertTrue(scan['failed_ranges'])
        blob = json.dumps(t)
        self.assertNotIn(HOST, blob)
        self.assertNotIn(KEY, blob)


PROXY = a(0x9A0)


class ProxyTests(unittest.TestCase):
    def test_eoa_admin_unknown_implementation(self):
        chain = FakeChain()
        chain.storage[(PROXY, cs.SLOTS['implementation'])] = addr_word(a(0x111))
        chain.storage[(PROXY, cs.SLOTS['admin'])] = addr_word(a(0xEEE))
        chain.code[a(0x111)] = '0x60'
        t = run(chain, [{'address': PROXY, 'kind': 'erc1967-proxy'}], known=[PROXY])['targets'][0]
        self.assertEqual(sorted(codes(t)), ['PROXY_ADMIN_EOA', 'PROXY_IMPLEMENTATION_NOT_KNOWN'])

    def test_known_implementation_contract_admin_clean(self):
        chain = FakeChain()
        chain.storage[(PROXY, cs.SLOTS['implementation'])] = addr_word(a(0x111))
        chain.storage[(PROXY, cs.SLOTS['admin'])] = addr_word(a(0x222))
        chain.code[a(0x111)] = '0x60'
        chain.code[a(0x222)] = '0x60'
        t = run(chain, [{'address': PROXY, 'kind': 'erc1967-proxy'}],
                known=[PROXY, a(0x111), a(0x222)])['targets'][0]
        self.assertEqual(t['flags'], [])


OAPP, ENDPOINT, LIB = a(0x0A99), a(0xE9D), a(0x11B)


def lz_chain(required, optional, threshold, confirmations=15, peer=a(0x9EE), custom=True):
    chain = FakeChain()
    chain.on(OAPP, 'peers(uint32)', ret(addr_word(peer)))
    chain.on(ENDPOINT, 'getReceiveLibrary(address,uint32)', ret(addr_word(LIB), w(0)))
    chain.on(ENDPOINT, 'getConfig(address,address,uint32,uint32)',
             bytes_ret(cs.encode_uln_config(confirmations, required, optional, threshold)))
    app = cs.encode_uln_config(confirmations, required, optional, threshold) if custom else \
        cs.encode_uln_config(0, [], [], 0)
    chain.on(LIB, 'getAppUlnConfig(address,uint32)', '0x' + app.hex())
    return chain


class LayerZeroTests(unittest.TestCase):
    def target(self, **extra):
        expect = {'endpoint': ENDPOINT, 'eids': [30101], 'min_confirmations': 10}
        expect.update(extra)
        return [{'address': OAPP, 'kind': 'layerzero-oapp', 'expect': expect}]

    def test_single_required_dvn_is_the_kelp_shape(self):
        t = run(lz_chain([a(0xD1)], [], 0), self.target())['targets'][0]
        self.assertEqual(t['errors'], [])
        self.assertEqual(codes(t), ['LZ_SINGLE_VERIFIER'])
        self.assertIn('KelpDAO', t['flags'][0]['shape'])
        entry = t['reads']['eids']['30101']
        self.assertEqual(entry['uln_config']['required_dvns'], [a(0xD1)])
        self.assertEqual(entry['uln_config_source'], 'custom')

    def test_two_verifiers_clean_and_default_detected(self):
        t = run(lz_chain([a(0xD1), a(0xD2)], [a(0xE1)], 1, custom=False),
                self.target(peers={'30101': '0x' + addr_word(a(0x9EE))}))['targets'][0]
        self.assertEqual(t['flags'], [])
        self.assertEqual(t['reads']['eids']['30101']['uln_config_source'], 'default')

    def test_low_confirmations_zero_peer_and_unexpected_library(self):
        chain = lz_chain([a(0xD1), a(0xD2)], [], 0, confirmations=2, peer=cs.ZERO_ADDRESS)
        t = run(chain, self.target(receive_library=a(0x777)))['targets'][0]
        self.assertEqual(sorted(codes(t)), ['LZ_LOW_CONFIRMATIONS', 'LZ_PEER_ZERO',
                                            'LZ_RECEIVE_LIBRARY_UNEXPECTED'])


FEED = a(0xFEED)


class ChainlinkTests(unittest.TestCase):
    def chain(self, answer, updated):
        chain = FakeChain()
        chain.on(FEED, 'latestRoundData()', ret(w(7), w(answer), w(updated), w(updated), w(7)))
        chain.on(FEED, 'decimals()', ret(w(8)))
        chain.on(FEED, 'description()', bytes_ret(b'ETH / USD'))
        return chain

    def test_stale_and_negative(self):
        t = run(self.chain(-5, NOW - 7200), [{'address': FEED, 'kind': 'chainlink-feed',
                                              'expect': {'heartbeat': 3600}}])['targets'][0]
        self.assertEqual(sorted(codes(t)), ['FEED_NONPOSITIVE_ANSWER', 'FEED_STALE'])
        self.assertEqual(t['reads']['answer'], '-5')

    def test_fresh_positive_clean(self):
        t = run(self.chain(3000_00000000, NOW - 60),
                [{'address': FEED, 'kind': 'chainlink-feed',
                  'expect': {'heartbeat': 3600}}])['targets'][0]
        self.assertEqual(t['flags'], [])
        self.assertEqual(t['reads']['description'], 'ETH / USD')
        self.assertEqual(t['reads']['decimals'], 8)
        self.assertEqual(t['reads']['age_seconds'], 60)


class GetterTests(unittest.TestCase):
    def test_conditions(self):
        chain = FakeChain()
        chain.on(a(1), 'signatureThreshold()', ret(w(0)))
        chain.on(a(1), 'mintCap()', ret(w(2 ** 256 - 1)))
        chain.on(a(1), 'markets(address)', ret(w(1), w(9 * 10 ** 17), w(0)))
        chain.on(a(1), 'quorum(uint256)', lambda data: ret(w(int(data[10:], 16))))
        calls = [
            {'sig': 'signatureThreshold()', 'returns': 'uint256', 'flag_if': {'lt': 2}},
            {'sig': 'mintCap()', 'flag_if': {'eq': 'max'}},
            {'sig': 'markets(address)', 'args': [a(5)], 'returns': ['bool', 'uint256', 'bool'],
             'pick': 1, 'flag_if': {'gt': '800000000000000000'}, 'label': 'CF'},
            {'sig': 'quorum(uint256)', 'args': ['$block-1'], 'flag_if': {'eq': 0}},
        ]
        t = run(chain, [{'address': a(1), 'kind': 'getter', 'expect': {'calls': calls}}])
        t = t['targets'][0]
        self.assertEqual(t['errors'], [])
        self.assertEqual(codes(t), ['GETTER_CONDITION'] * 3)
        self.assertEqual(t['reads']['calls'][3]['values'], [str(BLOCK - 1)])

    def test_condition_not_met_clean(self):
        chain = FakeChain()
        chain.on(a(1), 'signatureThreshold()', ret(w(5)))
        t = run(chain, [{'address': a(1), 'kind': 'getter', 'expect': {'calls': [
            {'sig': 'signatureThreshold()', 'flag_if': {'lt': 2}}]}}])['targets'][0]
        self.assertEqual(t['flags'], [])


class IsolationAndScrubbingTests(unittest.TestCase):
    def test_failing_target_does_not_abort_and_url_is_scrubbed(self):
        chain = FakeChain()
        chain.fail[(a(1), cs.selector('owner()'))] = (
            f'HTTPSConnectionPool(host={HOST!r}): failed {RPC} 429 Too Many Requests')
        chain.on(a(2), 'getMinDelay()', ret(w(0)))
        out = run(chain, [{'address': a(1), 'kind': 'ownable'},
                          {'address': a(2), 'kind': 'timelock'},
                          {'address': 'nope', 'kind': 'safe'},
                          {'address': a(3), 'kind': 'mystery'}])
        bad, good, malformed, unknown = out['targets']
        self.assertTrue(bad['errors'])
        self.assertIn('<endpoint>', bad['errors'][0])
        self.assertEqual(codes(good), ['TIMELOCK_ZERO_DELAY'])
        self.assertTrue(malformed['errors'] and unknown['errors'])
        blob = json.dumps(out)
        self.assertNotIn(RPC, blob)
        self.assertNotIn(HOST, blob)
        self.assertNotIn(KEY, blob)
        self.assertEqual(out['endpoint'], 'not recorded')
        self.assertEqual(out['block'], BLOCK)
        self.assertEqual(out['chain_id'], 1)
        self.assertIn('UNPRIVILEGED', out['notice'])

    def test_every_method_sent_is_read_only(self):
        chain = safe_chain(1, [a(10)])
        run(chain, [{'address': SAFE, 'kind': 'safe'}])
        self.assertTrue(set(chain.methods) <= cs.READ_ONLY_METHODS)

    def test_unreachable_endpoint_reports_without_url(self):
        def dead(method, params):
            raise OSError(f'Name or service not known: {HOST} ({RPC})')
        out = cs.snapshot(RPC, [{'address': a(1), 'kind': 'ownable'}], opener=dead)
        self.assertIsNone(out['block'])
        blob = json.dumps(out)
        self.assertNotIn(HOST, blob)
        self.assertNotIn(KEY, blob)
        self.assertEqual(out['targets'][0]['errors'], ['not read: no pinned block'])

    def test_explicit_block_is_pinned(self):
        chain = FakeChain()
        seen = []
        chain.on(a(2), 'getMinDelay()', ret(w(10)))
        original = chain.__call__

        def spy(method, params):
            if method == 'eth_call':
                seen.append(params[1])
            return original(method, params)
        out = cs.snapshot(RPC, [{'address': a(2), 'kind': 'timelock'}], block=123, opener=spy)
        self.assertEqual(out['block'], 123)
        self.assertEqual(set(seen), {hex(123)})

    def test_main_writes_out_and_prints_summary_without_url(self):
        chain = safe_chain(1, [a(10)])
        with tempfile.TemporaryDirectory() as tmp:
            targets = Path(tmp) / 't.json'
            targets.write_text(json.dumps([{'address': SAFE, 'kind': 'safe', 'label': 'ops'}]))
            known = Path(tmp) / 'k.json'
            known.write_text(json.dumps([SAFE]))
            out = Path(tmp) / 'snap.json'
            buf = io.StringIO()
            with mock.patch.object(cs, 'urllib_opener', lambda url: chain), \
                    contextlib.redirect_stdout(buf):
                code = cs.main(['--rpc', RPC, '--targets', str(targets), '--known', str(known),
                                '--out', str(out)])
            self.assertEqual(code, 0)
            summary = json.loads(buf.getvalue())
            self.assertEqual(summary['flags'], {'SAFE_THRESHOLD_ONE': 1})
            self.assertEqual(summary['endpoint'], 'not recorded')
            written = out.read_text()
            for secret in (RPC, HOST, KEY):
                self.assertNotIn(secret, written)
                self.assertNotIn(secret, buf.getvalue())
            self.assertEqual(json.loads(written)['targets'][0]['label'], 'ops')


if __name__ == '__main__':
    unittest.main()
