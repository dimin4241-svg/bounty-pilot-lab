"""Dispatcher selector extraction, ABI canonicalisation and the selector lead (stdlib only).

Two kinds of input. Hand-built bytecode pins one dispatch shape per test, so a failure names the
shape. tests/fixtures/selectors/compiled.json holds real solc 0.8.26 and Vyper 0.4.0 output with
each contract's own ABI, and the relation asserted over it is the one that matters: the selectors
extracted from a runtime equal the selectors of the ABI it was compiled with. Neither needs a
compiler at test time; the two solc-gated tests at the end skip when none is installed.
"""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/bounty-pilot/scripts'
COMPILED = ROOT / 'tests/fixtures/selectors/compiled.json'


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


selectors = load('bp_test_selectors', 'skills/bounty-pilot/scripts/evm_selectors.py')
bounty = load('bp_test_sel_bounty', 'skills/bounty-pilot/scripts/bounty.py')
keccak = load('bp_test_sel_keccak', 'skills/bounty-pilot/scripts/keccak.py')


# --------------------------------------------------------------------------- #
# hand-built bytecode
# --------------------------------------------------------------------------- #

PREAMBLE = '6080604052'               # PUSH1 80 PUSH1 40 MSTORE
SHORT_CALLDATA = '60043610'           # PUSH1 04 CALLDATASIZE LT, then PUSH2 <tail> JUMPI
LOAD_SELECTOR = '5f3560e01c'          # PUSH0 CALLDATALOAD PUSH1 e0 SHR
REVERT_BLOCK = '5b5f80fd'             # JUMPDEST PUSH0 DUP1 REVERT


def leaf(selector, dest='0100'):
    """solc's dispatch leaf: DUP1 PUSH4 <selector> EQ PUSH2 <dest> JUMPI."""
    return '80' + '63' + selector + '14' + '61' + dest + '57'


def pivot(selector, dest='0200'):
    """solc's binary-search step: DUP1 PUSH4 <selector> GT PUSH2 <dest> JUMPI."""
    return '80' + '63' + selector + '11' + '61' + dest + '57'


def narrow_leaf(selector_hex, dest='0100'):
    """The same leaf for a selector with leading zero bytes, pushed in fewer bytes."""
    body = selector_hex.lstrip('0') or '0'
    body = body if len(body) % 2 == 0 else '0' + body
    push = format(0x5f + len(body) // 2, '02x')
    return '80' + push + body + '14' + '61' + dest + '57'


def vyper_leaf(selector, dest='0100'):
    """Vyper's dispatch leaf: PUSH4 <selector> DUP2 XOR PUSH2 <dest> JUMPI."""
    return '63' + selector + '81' + '18' + '61' + dest + '57'


def runtime(*parts, **kwargs):
    """A dispatcher whose short-calldata branch really lands on the block that follows it.

    The jump destination is computed, because where that branch leads is what says whether the
    runtime has a fallback or a receive.
    """
    tail = kwargs.pop('tail', REVERT_BLOCK)
    assert not kwargs, kwargs
    body = ''.join(parts)
    guard = len(SHORT_CALLDATA) + 8          # the idiom plus PUSH2 <dest> JUMPI
    dest = (len(PREAMBLE) + guard + len(LOAD_SELECTOR) + len(body)) // 2
    return ('0x' + PREAMBLE + SHORT_CALLDATA + '61' + format(dest, '04x') + '57'
            + LOAD_SELECTOR + body + tail)


class WalkerTests(unittest.TestCase):
    def test_push_data_is_never_decoded_as_code(self):
        # PUSH32 whose operand spells out a dispatch leaf. Decoding the operand would invent
        # instructions no execution reaches, and a selector with them.
        hidden = leaf('deadbeef')
        operand = (hidden + '00' * 32)[:64]
        code = bytes.fromhex('7f' + operand + '00')
        self.assertEqual([op for _, op, _ in selectors.instructions(code)], [0x7f, 0x00])
        self.assertEqual(selectors.extract_selectors('0x' + code.hex())['selectors'], [])

    def test_a_truncated_push_operand_does_not_run_off_the_end(self):
        self.assertEqual(list(selectors.instructions(bytes.fromhex('63dead'))),
                         [(0, 0x63, bytes.fromhex('dead'))])

    def test_bounty_and_the_helper_strip_the_same_metadata(self):
        blob = b'\xa2dipfsX"\x12 ' + b'\x11' * 32 + b'dsolcC\x00\x08\x1a'
        code = '0x' + (bytes.fromhex('6080604052') + blob + len(blob).to_bytes(2, 'big')).hex()
        self.assertEqual(bounty.strip_metadata(code), selectors.strip_metadata(code))
        self.assertEqual(selectors.strip_metadata(code)[1], len(blob) + 2)

    def test_a_tail_that_is_not_solc_metadata_is_left_alone(self):
        blob = b'\xa2' + b'\x41' * 40          # CBOR map header, no solc/ipfs/bzzr marker
        code = '0x' + (b'\x60\x01' + blob + len(blob).to_bytes(2, 'big')).hex()
        self.assertEqual(selectors.strip_metadata(code)[1], 0)

    def test_a_selector_inside_the_metadata_is_not_dispatched(self):
        # The metadata is data: a leaf shape appearing in it must not reach the list. The leaf
        # sits inside the 34-byte ipfs hash of a well-formed solc map {ipfs, solc}.
        ipfs_hash = (bytes.fromhex(leaf('cafebabe')) + b'\x00' * 34)[:34]
        blob = b'\xa2' + b'dipfs' + b'\x58\x22' + ipfs_hash + b'dsolc' + b'\x43\x00\x08\x18'
        code = runtime(leaf('a9059cbb'))[2:] + blob.hex() + format(len(blob), '04x')
        found = selectors.extract_selectors('0x' + code)
        self.assertEqual(found['selectors'], ['0xa9059cbb'])
        self.assertEqual(found['metadata_bytes'], len(blob) + 2)


class DispatchShapeTests(unittest.TestCase):
    def test_a_linear_solc_dispatcher_is_read_whole(self):
        found = selectors.extract_selectors(
            runtime(leaf('a9059cbb'), leaf('095ea7b3'), leaf('70a08231')))
        self.assertEqual(found['selectors'], ['0x095ea7b3', '0x70a08231', '0xa9059cbb'])
        self.assertEqual(found['dispatcher'], 'solc-linear')
        self.assertEqual(found['count'], 3)

    def test_a_binary_search_pivot_is_not_reported_as_a_selector_of_its_own(self):
        # The pivot here is compared with GT and never for equality, so it is a pivot only.
        found = selectors.extract_selectors(
            runtime(pivot('80000000'), leaf('a9059cbb'), leaf('095ea7b3')))
        self.assertEqual(found['selectors'], ['0x095ea7b3', '0xa9059cbb'])
        self.assertEqual(found['pivots'], ['0x80000000'])
        self.assertEqual(found['dispatcher'], 'solc-binary-search')
        self.assertTrue(any('pivots only' in note for note in found['notes']), found['notes'])

    def test_a_pivot_that_is_also_an_equality_leaf_stays_in_the_list(self):
        # How solc really writes it: the pivot is one of the selectors, and the half below it
        # tests the same value for equality.
        found = selectors.extract_selectors(
            runtime(pivot('a9059cbb'), leaf('a9059cbb'), leaf('095ea7b3')))
        self.assertEqual(found['selectors'], ['0x095ea7b3', '0xa9059cbb'])
        self.assertNotIn('pivots only', ' '.join(found['notes']))

    def test_the_via_ir_trailing_leaf_subtracts_instead_of_comparing(self):
        found = selectors.extract_selectors(
            runtime(leaf('a9059cbb'), '63' + '095ea7b3' + '03' + '61000e' + '57'))
        self.assertEqual(found['selectors'], ['0x095ea7b3', '0xa9059cbb'])

    def test_a_vyper_xor_dispatcher_is_recognised_as_vyper(self):
        found = selectors.extract_selectors(
            runtime(vyper_leaf('a9059cbb'), vyper_leaf('095ea7b3')))
        self.assertEqual(found['selectors'], ['0x095ea7b3', '0xa9059cbb'])
        self.assertEqual(found['dispatcher'], 'vyper')

    def test_a_vyper_leaf_may_fold_the_calldata_size_check_into_the_branch(self):
        # PUSH4 sel DUP2 EQ PUSH1 03 CALLDATASIZE GT AND ISZERO PUSH2 dest JUMPI
        folded = '63' + 'ef77ef00' + '81' + '14' + '6003' + '36' + '11' + '16' + '15' + '61006c57'
        found = selectors.extract_selectors(runtime(folded))
        self.assertEqual(found['selectors'], ['0xef77ef00'])

    def test_both_compiler_shapes_at_once_read_as_mixed(self):
        found = selectors.extract_selectors(
            runtime(pivot('80000000'), leaf('a9059cbb'), vyper_leaf('095ea7b3')))
        self.assertEqual(found['dispatcher'], 'mixed')

    def test_a_runtime_with_no_dispatcher_says_so(self):
        found = selectors.extract_selectors('0x' + PREAMBLE + REVERT_BLOCK)
        self.assertEqual(found['selectors'], [])
        self.assertEqual(found['dispatcher'], 'unknown')
        self.assertTrue(any('no dispatch comparison' in note for note in found['notes']))

    def test_a_forwarder_is_told_apart_from_a_contract_with_no_entry_points(self):
        # The EIP-1167 clone runtime: it dispatches nothing and delegates everything.
        clone = ('0x363d3d373d3d3d363d73' + '33' * 20 + '5af43d82803e903d91602b57fd5bf3')
        found = selectors.extract_selectors(clone)
        self.assertEqual(found['selectors'], [])
        self.assertEqual(found['dispatcher'], 'unknown')
        self.assertTrue(any('DELEGATECALL' in note for note in found['notes']), found['notes'])

    def test_empty_code_is_reported_rather_than_guessed(self):
        found = selectors.extract_selectors('0x')
        self.assertEqual(found['selectors'], [])
        self.assertEqual(found['dispatcher'], 'unknown')
        self.assertTrue(any('no runtime code' in note for note in found['notes']))

    def test_the_zero_selector_and_the_four_byte_mask_are_excluded(self):
        found = selectors.extract_selectors(
            runtime(leaf('00000000'), leaf('ffffffff'), leaf('a9059cbb')))
        self.assertEqual(found['selectors'], ['0xa9059cbb'])

    def test_a_leading_zero_selector_pushed_in_three_bytes_is_still_read(self):
        found = selectors.extract_selectors(
            runtime(narrow_leaf('0018eaa8'), leaf('0c55699c'), leaf('10065ed2')))
        self.assertEqual(found['selectors'], ['0x0018eaa8', '0x0c55699c', '0x10065ed2'])

    def test_a_narrow_push_outside_a_dispatcher_is_not_a_selector(self):
        # The same shape in a function body, far from any dispatch comparison: `x == 0x1000`
        # is arithmetic, not a dispatch, and reading it as one invents an entry point.
        body = '5b' * 200 + '80' + '611000' + '14' + '61010057'
        found = selectors.extract_selectors(runtime(leaf('a9059cbb')) + body)
        self.assertEqual(found['selectors'], ['0xa9059cbb'])

    def test_a_one_byte_constant_is_never_read_as_a_selector(self):
        found = selectors.extract_selectors(
            runtime(leaf('a9059cbb'), '80' + '6001' + '14' + '61010057'))
        self.assertEqual(found['selectors'], ['0xa9059cbb'])

    def test_a_left_aligned_bytes4_constant_is_not_a_dispatch(self):
        # How Solidity compares an ERC-165 interface id: the constant is shifted up by 224
        # bits, because a bytes4 value sits in the high bytes of its word.
        shifted = '63' + '80ac58cd' + '60e0' + '1b' + '81' + '14' + '61010057'
        found = selectors.extract_selectors(runtime(leaf('a9059cbb')) + shifted)
        self.assertEqual(found['selectors'], ['0xa9059cbb'])

    def test_a_comparison_with_no_branch_is_not_a_dispatch(self):
        found = selectors.extract_selectors(runtime('80' + '63' + 'a9059cbb' + '14' + '50'))
        self.assertEqual(found['selectors'], [])

    def test_a_second_dispatcher_later_in_the_runtime_is_reported_apart(self):
        # A factory's runtime carries the creation code of what it deploys, and that code has
        # its own dispatcher. Those selectors belong to the deployed contract.
        child = '5f' * 1 + LOAD_SELECTOR + leaf('11111111') + leaf('22222222')
        found = selectors.extract_selectors(
            runtime(leaf('a9059cbb')) + '5b' * 200 + child)
        self.assertEqual(found['selectors'], ['0xa9059cbb'])
        self.assertEqual([group['selectors'] for group in found['secondary_dispatch']],
                         [['0x11111111', '0x22222222']])
        self.assertTrue(any('secondary_dispatch' in note for note in found['notes']))

    def test_a_distant_region_without_its_own_selector_load_stays_in_the_list(self):
        # Dropping a real selector is the worse mistake, so a far-apart chain that does not
        # load a selector of its own is kept.
        found = selectors.extract_selectors(
            runtime(leaf('a9059cbb')) + '5b' * 200 + leaf('33333333'))
        self.assertEqual(found['selectors'], ['0x33333333', '0xa9059cbb'])
        self.assertEqual(found['secondary_dispatch'], [])


class TailFunctionTests(unittest.TestCase):
    def test_a_dispatcher_whose_no_match_path_reverts_has_neither_tail_function(self):
        found = selectors.extract_selectors(runtime(leaf('a9059cbb')))
        self.assertEqual((found['has_fallback'], found['has_receive']), (False, False))

    def test_an_unrecognised_no_match_path_is_unknown_rather_than_false(self):
        # No `calldatasize < 4` guard at all: the path is not there to read.
        found = selectors.extract_selectors('0x' + PREAMBLE + LOAD_SELECTOR + leaf('a9059cbb'))
        self.assertIsNone(found['has_fallback'])
        self.assertIsNone(found['has_receive'])
        self.assertTrue(any('fallback() and receive() are unknown' in note
                            for note in found['notes']), found['notes'])


class CompiledFixtureTests(unittest.TestCase):
    """The relation that matters, over checked-in compiler output."""

    @classmethod
    def setUpClass(cls):
        cls.cases = json.loads(COMPILED.read_text(encoding='utf-8'))['contracts']

    def test_the_fixture_covers_both_compilers_and_several_settings(self):
        self.assertGreaterEqual(len(self.cases), 20)
        compilers = {case['compiler'].split()[0] for case in self.cases}
        self.assertEqual(compilers, {'solc', 'vyper'})
        self.assertGreaterEqual(len({case['setting'] for case in self.cases}), 6)

    def test_extracted_selectors_equal_the_selectors_of_each_contracts_own_abi(self):
        for case in self.cases:
            with self.subTest(contract=case['name'], setting=case['setting']):
                found = selectors.extract_selectors(case['code'])
                known = selectors.selectors_from_abi(case['abi'])
                diff = selectors.diff_selectors(found['selectors'], known)
                # Equality holds except where the fixture records why it cannot: a dispatcher
                # written in assembly, or selectors Vyper keeps in a data table.
                self.assertEqual(diff['only_onchain'], case['expect']['only_onchain'])
                self.assertEqual(diff['only_known'], case['expect']['only_known'])

    def test_the_dispatcher_kind_and_tail_functions_are_the_recorded_ones(self):
        for case in self.cases:
            with self.subTest(contract=case['name'], setting=case['setting']):
                found = selectors.extract_selectors(case['code'])
                self.assertEqual(found['dispatcher'], case['expect']['dispatcher'])
                self.assertEqual(found['has_fallback'], case['expect']['has_fallback'])
                self.assertEqual(found['has_receive'], case['expect']['has_receive'])
                self.assertEqual([group['selectors'] for group in found['secondary_dispatch']],
                                 case['expect']['secondary_dispatch'])

    def test_a_recorded_tail_function_is_never_contradicted_by_the_abi(self):
        for case in self.cases:
            found = selectors.extract_selectors(case['code'])
            declared = selectors.abi_tail_functions(case['abi'])
            with self.subTest(contract=case['name'], setting=case['setting']):
                for got, want in zip((found['has_fallback'], found['has_receive']), declared):
                    if got is not None:
                        self.assertEqual(got, want)

    def test_solcs_own_signature_map_agrees_with_this_canonicalisation(self):
        checked = 0
        for case in self.cases:
            if not case.get('hashes'):
                continue
            checked += 1
            mine = selectors.selectors_from_abi(case['abi'])
            theirs = {'0x' + value: key for key, value in case['hashes'].items()}
            with self.subTest(contract=case['name']):
                self.assertEqual(mine, theirs)
        self.assertGreater(checked, 0, 'no fixture carries solc\'s own signature map')

    def test_a_vyper_jump_table_explains_its_empty_selector_list(self):
        dense = [case for case in self.cases if case['setting'] == 'vyper-codesize']
        self.assertTrue(dense, 'the fixture should keep a dense Vyper dispatcher')
        for case in dense:
            found = selectors.extract_selectors(case['code'])
            self.assertEqual(found['dispatcher'], 'vyper')
            self.assertTrue(any('copies out of its own code' in note for note in found['notes']),
                            found['notes'])


# --------------------------------------------------------------------------- #
# selectors from an ABI
# --------------------------------------------------------------------------- #

# Selectors published in the standards and in wide use. Each is derived here from its
# signature, so the test fails if the derivation drifts, not if a constant was mistyped.
PUBLISHED = {
    'transfer(address,uint256)': '0xa9059cbb',
    'transferFrom(address,address,uint256)': '0x23b872dd',
    'approve(address,uint256)': '0x095ea7b3',
    'balanceOf(address)': '0x70a08231',
    'totalSupply()': '0x18160ddd',
    'supportsInterface(bytes4)': '0x01ffc9a7',
    'safeTransferFrom(address,address,uint256,uint256,bytes)': '0xf242432a',
    'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)': '0xd505accf',
    'DOMAIN_SEPARATOR()': '0x3644e515',
    'upgradeToAndCall(address,bytes)': '0x4f1ef286',
    'proxiableUUID()': '0x52d1902d',
    'isValidSignature(bytes32,bytes)': '0x1626ba7e',
    'hasRole(bytes32,address)': '0x91d14854',
    'owner()': '0x8da5cb5b',
    'deposit(uint256,address)': '0x6e553f65',
    'redeem(uint256,address,address)': '0xba087652',
}


class AbiSelectorTests(unittest.TestCase):
    def test_derived_selectors_equal_the_published_values(self):
        derived = selectors.selectors_from_signatures(PUBLISHED)
        for signature, published in PUBLISHED.items():
            self.assertEqual(derived.get(published), signature, signature)

    def test_a_struct_argument_is_canonicalised_as_a_tuple(self):
        abi = [{'type': 'function', 'name': 'one', 'inputs': [
            {'name': 'i', 'type': 'tuple', 'components': [
                {'name': 'who', 'type': 'address'}, {'name': 'ok', 'type': 'bool'}]}]}]
        self.assertEqual(list(selectors.selectors_from_abi(abi).values()),
                         ['one((address,bool))'])

    def test_nested_structs_and_array_suffixes_keep_their_order(self):
        inner = {'name': 'inner', 'type': 'tuple', 'components': [
            {'name': 'who', 'type': 'address'}, {'name': 'ok', 'type': 'bool'}]}
        outer = {'name': 'o', 'type': 'tuple[2][]', 'components': [
            {'name': 'amount', 'type': 'uint256'}, inner,
            {'name': 'tags', 'type': 'bytes32[2]'}]}
        self.assertEqual(selectors.canonical_signature(
            {'type': 'function', 'name': 'three', 'inputs': [outer]}),
            'three((uint256,(address,bool),bytes32[2])[2][])')

    def test_an_empty_tuple_and_a_missing_input_list_are_both_written_out(self):
        self.assertEqual(selectors.canonical_signature({'type': 'function', 'name': 'f'}), 'f()')
        self.assertEqual(selectors.canonical_signature(
            {'type': 'function', 'name': 'g', 'inputs': [{'name': 'e', 'type': 'tuple',
                                                          'components': []}]}), 'g(())')

    def test_only_function_entries_have_selectors(self):
        abi = [
            {'type': 'function', 'name': 'kept', 'inputs': []},
            {'name': 'defaults_to_function', 'inputs': []},
            {'type': 'event', 'name': 'Transfer', 'inputs': [{'name': 'a', 'type': 'address'}]},
            {'type': 'error', 'name': 'Bad', 'inputs': [{'name': 'x', 'type': 'uint256'}]},
            {'type': 'constructor', 'inputs': [{'name': 'x', 'type': 'uint256'}]},
            {'type': 'fallback'}, {'type': 'receive'},
        ]
        self.assertEqual(sorted(selectors.selectors_from_abi(abi).values()),
                         ['defaults_to_function()', 'kept()'])

    def test_an_artifact_object_is_accepted_and_a_bare_object_is_refused(self):
        abi = [{'type': 'function', 'name': 'f', 'inputs': []}]
        self.assertEqual(selectors.selectors_from_abi({'abi': abi, 'bytecode': '0x'}),
                         selectors.selectors_from_abi(abi))
        with self.assertRaises(ValueError):
            selectors.selectors_from_abi({'bytecode': '0x'})

    def test_a_malformed_entry_is_refused_rather_than_hashed(self):
        for abi in ([{'type': 'function', 'inputs': []}],
                    [{'type': 'function', 'name': 'f', 'inputs': [{'name': 'x'}]}],
                    [{'type': 'function', 'name': 'f', 'inputs': {'x': 'uint256'}}]):
            with self.assertRaises(ValueError):
                selectors.selectors_from_abi(abi)

    def test_a_signature_that_is_not_canonical_is_refused(self):
        with self.assertRaises(ValueError):
            selectors.selectors_from_signatures(['transfer address,uint256'])

    def test_whitespace_in_a_supplied_signature_is_ignored(self):
        self.assertEqual(selectors.selectors_from_signatures(['transfer(address, uint256)']),
                         {'0xa9059cbb': 'transfer(address,uint256)'})

    def test_two_signatures_sharing_a_selector_are_both_kept_in_the_name(self):
        # A documented four-byte collision: transferFrom(address,address,uint256) and
        # gasprice_bit_ether(int128) hash to the same selector. Both names stay, so whoever
        # reads the output sees the clash instead of one silently chosen answer.
        collide = ('transferFrom(address,address,uint256)', 'gasprice_bit_ether(int128)')
        self.assertEqual(keccak.selector(collide[0]), keccak.selector(collide[1]))
        name = selectors.selectors_from_signatures(collide)['0x23b872dd']
        self.assertEqual(name, ' / '.join(collide))


class KnownSignatureTests(unittest.TestCase):
    def test_the_table_is_derived_and_not_pasted(self):
        source = (SCRIPTS / 'evm_selectors.py').read_text(encoding='utf-8')
        table = source[source.index('KNOWN_SIGNATURES = {'):source.index('def known_signatures')]
        self.assertNotIn('0x', table, 'a pasted selector is a constant nobody can check')

    def test_every_table_entry_names_the_standard_it_came_from(self):
        table = selectors.known_signatures()
        self.assertEqual(table[keccak.selector('transfer(address,uint256)')],
                         {'name': 'transfer(address,uint256)', 'standard': 'erc20'})
        self.assertEqual(table[keccak.selector('upgradeToAndCall(address,bytes)')]['standard'],
                         'proxy-upgrade')
        for group in ('erc20', 'erc721', 'erc1155', 'erc4626', 'erc165', 'ownable',
                      'access-control', 'pausable', 'proxy-upgrade', 'permit', 'erc1271',
                      'multicall'):
            self.assertIn(group, selectors.KNOWN_SIGNATURES)

    def test_a_name_from_the_table_says_where_it_came_from(self):
        named = selectors.name_selectors(['0xa9059cbb', '0xdeadbeef'])
        self.assertEqual(named[0]['name'], 'transfer(address,uint256)')
        self.assertEqual(named[0]['source'], 'known-signature-table')
        self.assertNotIn('name', named[1])

    def test_a_supplied_signature_wins_over_the_built_in_table(self):
        named = selectors.name_selectors(['0xa9059cbb'], {'0xa9059cbb': 'mine(address,uint256)'})
        self.assertEqual(named[0], {'selector': '0xa9059cbb', 'name': 'mine(address,uint256)',
                                    'source': 'supplied'})


class DiffTests(unittest.TestCase):
    def test_the_two_sides_and_the_counts(self):
        diff = selectors.diff_selectors(['0x01', '0x02'], {'0x02': 'b()', '0x03': 'c()'})
        self.assertEqual(diff['only_onchain'], ['0x01'])
        self.assertEqual(diff['only_known'], ['0x03'])
        self.assertEqual(diff['shared'], ['0x02'])
        self.assertEqual(diff['counts'], {'onchain': 2, 'known': 2, 'shared': 1,
                                          'only_onchain': 1, 'only_known': 1})

    def test_an_abi_and_a_runtime_that_agree_leave_both_sides_empty(self):
        case = next(entry for entry in
                    json.loads(COMPILED.read_text(encoding='utf-8'))['contracts']
                    if entry['name'] == 'Overloads')
        found = selectors.extract_selectors(case['code'])
        diff = selectors.diff_selectors(found['selectors'],
                                        selectors.selectors_from_abi(case['abi']))
        self.assertEqual((diff['only_onchain'], diff['only_known']), ([], []))
        self.assertEqual(diff['counts']['shared'], 9)


# --------------------------------------------------------------------------- #
# the lead verify-deployment attaches, and the CLI
# --------------------------------------------------------------------------- #

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
        if body['method'] not in self.answers:
            return FakeResponse({'jsonrpc': '2.0', 'id': body['id'],
                                 'error': {'code': 3, 'message': 'execution reverted'}})
        value = self.answers[body['method']]
        if callable(value):
            value = value(body['params'])
        return FakeResponse({'jsonrpc': '2.0', 'id': body['id'], 'result': value})


def fixture(name, setting=None):
    for case in json.loads(COMPILED.read_text(encoding='utf-8'))['contracts']:
        if case['name'] == name and (setting is None or case['setting'] == setting):
            return case
    raise AssertionError('no fixture named ' + name)


class DeploymentLeadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.dir = Path(self.temp.name)
        self.case = fixture('Five', 'default')
        self.artifact = self.dir / 'Five.json'
        self.artifact.write_text(json.dumps({'abi': self.case['abi'],
                                             'deployedBytecode': {'object': self.case['code']}}))

    def tearDown(self):
        self.temp.cleanup()

    def node(self, code=None):
        return FakeNode({'eth_chainId': '0x1', 'eth_blockNumber': '0x100',
                         'eth_getCode': code or self.case['code'],
                         'eth_getStorageAt': '0x' + '00' * 32})

    def test_the_lead_names_the_dispatched_selectors_and_adds_no_rpc_call(self):
        node = self.node()
        result = bounty.verify_deployment('http://node.invalid', '0x' + '11' * 20,
                                          str(self.artifact), 'latest', opener=node)
        lead = result['selectors']
        self.assertEqual(lead['onchain_count'], 6)
        self.assertEqual(lead['dispatcher'], 'solc-linear')
        self.assertEqual(lead['counts']['only_onchain'], 0)
        self.assertEqual(lead['counts']['only_known'], 0)
        self.assertEqual(sum(1 for method, _ in node.calls if method == 'eth_getCode'), 1)

    def test_the_lead_never_changes_the_status_or_the_comparison(self):
        result = bounty.verify_deployment('http://node.invalid', '0x' + '11' * 20,
                                          str(self.artifact), 'latest', opener=self.node())
        self.assertEqual(result['deployment_status'], 'exact')
        self.assertEqual(result['comparison']['status'], 'exact')
        self.assertNotIn('selectors', result['comparison'])
        self.assertTrue(result['selectors']['notice'].startswith('This is the list'))

    def test_an_undeclared_selector_shows_up_as_only_onchain(self):
        # The deployed runtime dispatches a selector the artifact's ABI does not declare: the
        # case this lead exists for. It stays a lead; the status is still the comparison's.
        artifact = self.dir / 'trimmed.json'
        trimmed = [entry for entry in self.case['abi']
                   if entry.get('name') not in ('d', 'e')]
        artifact.write_text(json.dumps({'abi': trimmed,
                                        'deployedBytecode': {'object': self.case['code']}}))
        result = bounty.verify_deployment('http://node.invalid', '0x' + '11' * 20,
                                          str(artifact), 'latest', opener=self.node())
        lead = result['selectors']
        self.assertEqual([item['selector'] for item in lead['only_onchain']],
                         ['0xba9a87f6', '0xffae15ba'])
        self.assertEqual(result['deployment_status'], 'exact')
        self.assertTrue(any('lead to read, not a finding' in note for note in lead['notes']))

    def test_a_proxy_lead_says_the_implementation_is_where_the_selectors_are(self):
        proxy, impl = '0x' + '22' * 20, '0x' + '33' * 20
        clone = '0x363d3d373d3d3d363d73' + impl[2:] + '5af43d82803e903d91602b57fd5bf3'
        node = FakeNode({'eth_chainId': '0x1', 'eth_blockNumber': '0x100',
                         'eth_getCode': lambda params: (self.case['code']
                                                        if params[0] == impl else clone),
                         'eth_getStorageAt': '0x' + '00' * 32})
        result = bounty.verify_deployment('http://node.invalid', proxy, str(self.artifact),
                                          'latest', opener=node)
        lead = result['selectors']
        self.assertEqual(result['compared'], 'implementation')
        self.assertEqual(lead['onchain_count'], 0, 'a forwarder dispatches nothing itself')
        self.assertTrue(any('forwards calls' in note for note in lead['notes']), lead['notes'])
        self.assertEqual(lead['implementation']['address'], impl)
        self.assertEqual(lead['implementation']['onchain_count'], 6)
        self.assertEqual(lead['implementation']['counts']['only_onchain'], 0)
        self.assertNotIn('counts', lead, 'the ABI describes the implementation, not the proxy')

    def test_an_address_with_no_code_gets_no_lead(self):
        node = FakeNode({'eth_chainId': '0x1', 'eth_blockNumber': '0x10', 'eth_getCode': '0x'})
        result = bounty.verify_deployment('http://node.invalid', '0x' + '22' * 20, None,
                                          'latest', opener=node)
        self.assertNotIn('selectors', result)

    def test_the_evidence_file_carries_the_lead(self):
        run = self.dir / 'run'
        run.mkdir()
        (run / 'run.json').write_text('{}')
        result = bounty.verify_deployment('http://node.invalid', '0x' + '11' * 20,
                                          str(self.artifact), 'latest', opener=self.node(),
                                          run=str(run))
        record = json.loads(Path(result['evidence_file']).read_text())
        self.assertEqual(record['selectors']['onchain_count'], 6)
        self.assertEqual(record['record_sha256'], bounty.deployment_digest(record))


class SelectorsCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        # resolved: the lead file is reported resolved, and macOS tempdirs sit under the /var symlink
        self.dir = Path(self.temp.name).resolve()
        self.case = fixture('Five', 'default')

    def tearDown(self):
        self.temp.cleanup()

    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = bounty.main(['selectors', *argv])
        self.assertEqual(code, 0, out.getvalue())
        return json.loads(out.getvalue())

    def test_inline_bytecode_is_read(self):
        result = self.run_cli('--code', self.case['code'])
        self.assertEqual(result['onchain_count'], 6)
        self.assertEqual(result['source']['read_from'], 'bytecode argument')
        self.assertEqual(result['source']['runtime_code_bytes'], len(self.case['code']) // 2 - 1)
        # None of this contract's functions is a standard signature, so none is named.
        self.assertEqual(result['unknown'], result['selectors'])

    def test_known_signatures_are_named_and_the_unknown_ones_come_first(self):
        result = self.run_cli('--code', runtime(leaf('a9059cbb'), leaf('095ea7b3'),
                                                leaf('deadbeef')))
        self.assertEqual(result['unknown'], ['0xdeadbeef'])
        self.assertEqual(result['selectors'],
                         ['0xdeadbeef', '0x095ea7b3', '0xa9059cbb'])
        self.assertEqual([item['name'] for item in result['named']],
                         ['approve(address,uint256)', 'transfer(address,uint256)'])
        self.assertTrue(all(item['source'] == 'known-signature-table'
                            for item in result['named']))

    def test_an_artifact_supplies_both_the_runtime_and_the_names(self):
        artifact = self.dir / 'Five.json'
        artifact.write_text(json.dumps({'abi': self.case['abi'],
                                        'deployedBytecode': {'object': self.case['code']}}))
        result = self.run_cli('--code', str(artifact), '--abi', str(artifact))
        self.assertEqual(result['source']['read_from'], 'build artifact')
        self.assertEqual(result['unknown'], [])
        self.assertEqual(result['counts']['only_onchain'], 0)
        self.assertEqual(len(result['named']), 6)

    def test_a_signature_file_names_selectors_without_an_abi(self):
        listing = self.dir / 'sigs.txt'
        listing.write_text('# one per line\nd(bytes)\n\nffff_not_here()\n')
        result = self.run_cli('--code', self.case['code'], '--signatures', str(listing))
        named = {item['selector']: item['name'] for item in result['named']}
        self.assertEqual(named[keccak.selector('d(bytes)')], 'd(bytes)')
        self.assertEqual([item['selector'] for item in result['only_known']],
                         [keccak.selector('ffff_not_here()')])

    def test_reading_an_address_pins_one_block_and_only_reads_code(self):
        node = FakeNode({'eth_chainId': '0x1', 'eth_blockNumber': '0x1e240',
                         'eth_getCode': self.case['code']})
        result = bounty.selectors_report(rpc='http://node.invalid', address='0x' + '11' * 20,
                                         opener=node)
        self.assertEqual(result['source']['block'], 123456)
        self.assertEqual(result['source']['chain_id'], 1)
        self.assertEqual([method for method, _ in node.calls],
                         ['eth_chainId', 'eth_blockNumber', 'eth_getCode'])
        self.assertEqual(result['onchain_count'], 6)

    def test_a_block_tag_is_resolved_to_the_number_it_meant(self):
        node = FakeNode({'eth_chainId': '0x1', 'eth_blockNumber': '0x1e240',
                         'eth_getBlockByNumber': {'number': '0x1e23f'},
                         'eth_getCode': self.case['code']})
        result = bounty.selectors_report(rpc='http://node.invalid', address='0x' + '11' * 20,
                                         block='finalized', opener=node)
        self.assertEqual(result['source']['block'], 123455)

    def test_the_run_keeps_the_lead_under_selectors(self):
        run = self.dir / 'run'
        run.mkdir()
        (run / 'run.json').write_text('{}')
        result = self.run_cli('--code', self.case['code'], '--run', str(run))
        saved = Path(result['lead_file'])
        self.assertEqual(saved.parent, run / 'selectors')
        self.assertTrue(saved.name.startswith('code-'))
        self.assertEqual(json.loads(saved.read_text())['tool'], 'bounty.py selectors')

    def test_an_address_names_the_file_it_is_saved_as(self):
        run = self.dir / 'run'
        run.mkdir()
        (run / 'run.json').write_text('{}')
        node = FakeNode({'eth_chainId': '0x1', 'eth_blockNumber': '0x10',
                         'eth_getCode': self.case['code']})
        address = '0x' + 'AB' * 20
        result = bounty.selectors_report(rpc='http://node.invalid', address=address,
                                         run=str(run), opener=node)
        self.assertEqual(Path(result['lead_file']).name, address.lower() + '.json')

    def test_the_arguments_are_checked_before_any_read(self):
        for argv in (['--code', '0x00', '--address', '0x' + '11' * 20, '--rpc', 'http://x'],
                     ['--address', '0x' + '11' * 20],
                     ['--rpc', 'http://node.invalid'],
                     []):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(bounty.main(['selectors', *argv]), 2, argv)

    def test_a_bad_address_is_refused(self):
        with self.assertRaises(ValueError):
            bounty.selectors_report(rpc='http://node.invalid', address='0x1234')

    def test_bytecode_that_is_not_hex_is_refused(self):
        with self.assertRaises(ValueError):
            bounty.selectors_report(code='not-bytecode')

    def test_an_empty_runtime_is_reported_as_empty(self):
        result = self.run_cli('--code', '0x')
        self.assertEqual(result['selectors'], [])
        self.assertIn('no runtime code', result['source']['empty'])


# --------------------------------------------------------------------------- #
# with a compiler present
# --------------------------------------------------------------------------- #

SOLC = shutil.which('solc')
SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

contract Wide {
    uint256 public s;
    struct Inner { address who; bool ok; }
    struct Outer { uint256 amount; Inner inner; }
%s
    function nested(Outer[2][] calldata o) external returns (uint256) { s = o.length; return s; }
    function pay() external payable { s += msg.value; }
    receive() external payable { s += 1; }
}
"""


def _compile(source, *flags):
    """solc --combined-json for one source, or None when solc cannot be used."""
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / 'Wide.sol'
        path.write_text(source)
        done = subprocess.run([SOLC, '--combined-json', 'abi,bin-runtime,hashes', *flags,
                               str(path)], capture_output=True, text=True,
                              cwd=temp, env=dict(os.environ, SOLC_NO_UPDATE='1'))
        if done.returncode != 0:
            return None
        return json.loads(done.stdout)


@unittest.skipUnless(SOLC, 'solc is not installed')
class CompilerTests(unittest.TestCase):
    """Compile here when a compiler happens to be present; the suite never needs one."""

    def assert_matches(self, output):
        self.assertIsNotNone(output, 'solc refused the fixture source')
        for key, contract in output['contracts'].items():
            abi = contract['abi'] if isinstance(contract['abi'], list) \
                else json.loads(contract['abi'])
            found = selectors.extract_selectors(contract['bin-runtime'])
            known = selectors.selectors_from_abi(abi)
            diff = selectors.diff_selectors(found['selectors'], known)
            with self.subTest(contract=key):
                self.assertEqual(diff['only_onchain'], [])
                self.assertEqual(diff['only_known'], [])
                self.assertEqual(found['has_receive'], True)

    def test_a_wide_dispatcher_matches_its_own_abi(self):
        many = '\n'.join('    function f%d(uint256 x) external returns (uint256) '
                         '{ s += x + %d; return s; }' % (i, i) for i in range(60))
        self.assert_matches(_compile(SOURCE % many))

    def test_the_same_source_optimised_still_matches(self):
        many = '\n'.join('    function g%d(address a) external returns (uint256) '
                         '{ s += uint160(a) + %d; return s; }' % (i, i) for i in range(60))
        self.assert_matches(_compile(SOURCE % many, '--optimize', '--optimize-runs', '200'))


if __name__ == '__main__':
    unittest.main()
