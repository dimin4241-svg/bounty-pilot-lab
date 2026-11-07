"""The stateful harness skeleton generator.

It draws the machinery around a property - handler, actors, bounds, revert counters, selector
targeting - and leaves every property failing until a human writes it. It must never emit an
address, an attack sequence or a passing stub.
"""
import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


harness = load('bp_test_harness_gen', 'skills/bounty-pilot/scripts/harness_gen.py')

VAULT_ABI = {
    "abi": [
        {"type": "constructor", "inputs": [{"name": "asset", "type": "address"}]},
        {"type": "function", "name": "deposit", "stateMutability": "nonpayable",
         "inputs": [{"name": "assets", "type": "uint256"}, {"name": "receiver", "type": "address"}],
         "outputs": [{"name": "", "type": "uint256"}]},
        {"type": "function", "name": "withdraw", "stateMutability": "nonpayable",
         "inputs": [{"name": "assets", "type": "uint256"}, {"name": "receiver", "type": "address"},
                    {"name": "owner", "type": "address"}],
         "outputs": [{"name": "", "type": "uint256"}]},
        {"type": "function", "name": "totalAssets", "stateMutability": "view", "inputs": [],
         "outputs": [{"name": "", "type": "uint256"}]},
        {"type": "function", "name": "submitOrder", "stateMutability": "nonpayable",
         "inputs": [{"name": "order", "type": "tuple",
                     "components": [{"name": "amount", "type": "uint256"}]}]},
        {"type": "function", "name": "batch", "stateMutability": "nonpayable",
         "inputs": [{"name": "targets", "type": "address[]"}, {"name": "data", "type": "bytes[]"},
                    {"name": "fees", "type": "uint16[3]"}, {"name": "memo", "type": "string"}]},
        {"type": "function", "name": "donate", "stateMutability": "payable", "inputs": []},
        {"type": "event", "name": "Deposit", "inputs": []},
    ]
}

MODEL = """# model
- actors: depositor, keeper
INVARIANT: totalAssets covers the sum of redeemable shares
INVARIANT: noFreeMint: shares never increase without assets "in"
"""


class HarnessGen(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.repo = self.base / 'repo'
        (self.repo / 'out/Vault.sol').mkdir(parents=True)
        self.artifact = self.repo / 'out/Vault.sol/Vault.json'
        self.artifact.write_text(json.dumps(VAULT_ABI), encoding='utf-8')
        self.out = self.base / 'private/harness'

    def tearDown(self):
        self.tmp.cleanup()

    def generate(self, **kw):
        props = harness.parse_properties(MODEL)
        return harness.generate([str(self.artifact)], self.out, properties=props,
                                repo=self.repo, **kw)

    def test_plan_includes_state_changers_and_skips_with_reasons(self):
        plan = self.generate()
        included = {f['signature'] for f in plan['functions_included']}
        self.assertEqual(included, {'deposit(uint256,address)',
                                    'withdraw(uint256,address,address)',
                                    'batch(address[],bytes[],uint16[3],string)'})
        skipped = {f['signature']: f['reason'] for f in plan['functions_skipped']}
        self.assertTrue(skipped['totalAssets()'].startswith('view'))
        self.assertTrue(skipped['donate()'].startswith('payable-unhandled'))
        self.assertIn('tuple', skipped['submitOrder(tuple)'])
        self.assertTrue(skipped['submitOrder(tuple)'].startswith('unsupported type'))
        self.assertEqual(plan['contracts'][0]['name'], 'Vault')
        self.assertIn('not', plan['notice'])
        self.assertIn('experiments.json', plan['notice'])
        on_disk = json.loads((self.out / 'harness-plan.json').read_text(encoding='utf-8'))
        self.assertEqual(on_disk['functions_skipped'], plan['functions_skipped'])
        deposit = [f for f in plan['functions_included'] if f['handler'] == 'call_deposit'][0]
        self.assertEqual(deposit['selector'], '0x6e553f65')

    def test_two_invariant_lines_become_two_failing_stubs(self):
        self.generate()
        text = (self.out / 'VaultInvariants.t.sol').read_text(encoding='utf-8')
        stubs = re.findall(r'function (invariant_\w+)\(\)', text)
        self.assertIn('invariant_noFreeMint', stubs)
        self.assertIn('invariant_totalassets_covers_the_sum_of_redeemable', stubs)
        self.assertIn('invariant_callSummary', stubs)
        self.assertEqual(len(stubs), 3)
        self.assertEqual(text.count('assertTrue(false, "TODO: write the property:'), 2)
        self.assertIn('\\"in\\"', text)  # model text is escaped data
        self.assertIn('targetContract(address(handler))', text)
        self.assertIn('targetSelector(FuzzSelector', text)
        self.assertIn('VaultHandler.call_deposit.selector', text)
        self.assertNotIn('property_', text)

    def test_handler_machinery(self):
        self.generate()
        text = (self.out / 'VaultHandler.sol').read_text(encoding='utf-8')
        self.assertIn('bound(', text)
        self.assertIn('vm.startPrank(actor)', text)
        self.assertIn('actors[bound(actorSeed, 0, actors.length - 1)]', text)
        self.assertIn('makeAddr(', text)
        self.assertIn('reverts[sel]++', text)
        self.assertIn('calls[sel]++', text)
        self.assertIn('try target.deposit(', text)
        self.assertIn('MAX_ARRAY', text)
        self.assertIn('_capBytes(', text)
        self.assertIn('TODO', text)
        self.assertNotIn('totalAssets', text)
        self.assertNotIn('submitOrder', text)

    def test_no_address_literals_anywhere(self):
        self.generate()
        for name in ('VaultHandler.sol', 'VaultInvariants.t.sol'):
            text = (self.out / name).read_text(encoding='utf-8')
            self.assertIsNone(re.search(r'0x[0-9a-fA-F]{40}', text), name)
            self.assertNotIn('address(0)', text)

    def test_out_dir_inside_repo_refused(self):
        with self.assertRaises(ValueError):
            harness.generate([str(self.artifact)], self.repo / 'harness', repo=self.repo)
        with self.assertRaises(SystemExit):
            harness.main(['--artifact', str(self.artifact), '--repo', str(self.repo),
                          '--out-dir', str(self.repo / 'test/harness')])
        self.assertFalse((self.repo / 'test/harness').exists())

    def test_existing_files_are_not_overwritten(self):
        self.generate()
        with self.assertRaises(ValueError):
            self.generate()

    def test_medusa_adds_failing_property_functions(self):
        self.generate(framework='medusa')
        text = (self.out / 'VaultInvariants.t.sol').read_text(encoding='utf-8')
        self.assertEqual(text.count('return false;'), 2)
        self.assertIn('function property_noFreeMint()', text)

    def test_no_model_still_fails(self):
        harness.generate([str(self.artifact)], self.out)
        text = (self.out / 'VaultInvariants.t.sol').read_text(encoding='utf-8')
        self.assertIn('assertTrue(false', text)

    def test_semantic_graph_input(self):
        graph = {"schema": 1, "symbols": [
            {"language": "solidity", "contract": "Pool", "name": "Pool.swap", "entry": True,
             "visibility": "external", "function_kind": "function", "contract_deployable": True,
             "state_mutability": "nonpayable", "abi_parameter_types": ["uint256", "bool"]},
            {"language": "solidity", "contract": "Pool", "name": "Pool.quote", "entry": True,
             "visibility": "public", "function_kind": "function", "contract_deployable": True,
             "state_mutability": "view", "abi_parameter_types": []},
            {"language": "solidity", "contract": "Pool", "name": "Pool._settle", "entry": False,
             "visibility": "internal", "function_kind": "function", "contract_deployable": True,
             "state_mutability": "nonpayable", "abi_parameter_types": []},
            {"language": "solidity", "contract": "Base", "name": "Base.hook", "entry": True,
             "visibility": "external", "function_kind": "function", "contract_deployable": False,
             "state_mutability": "nonpayable", "abi_parameter_types": []},
        ]}
        path = self.base / 'semantic-graph.json'
        path.write_text(json.dumps(graph), encoding='utf-8')
        rc = harness.main(['--semantic-graph', str(path), '--out-dir', str(self.out),
                           '--repo', str(self.repo)])
        self.assertEqual(rc, 0)
        plan = json.loads((self.out / 'harness-plan.json').read_text(encoding='utf-8'))
        self.assertEqual([f['signature'] for f in plan['functions_included']],
                         ['swap(uint256,bool)'])
        self.assertEqual([c['name'] for c in plan['contracts']], ['Pool'])

    def test_type_classification(self):
        self.assertEqual(harness.classify('uint')[1], 'uint256')
        self.assertEqual(harness.classify('bytes32[2]')[0], 'array')
        self.assertIsNone(harness.classify('uint256[][]')[0])
        self.assertIsNone(harness.classify('tuple[]')[0])
        self.assertIsNone(harness.classify('uint256[64]')[0])


if __name__ == '__main__':
    unittest.main()
