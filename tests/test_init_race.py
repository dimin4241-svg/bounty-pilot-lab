"""Deployment atomicity and initializer exposure, read from broadcast logs and source.

Kinto (July 2025) deployed an ERC1967 proxy and initialized it in a separate transaction; the
initialize call was front-run. The broadcast log shows that gap, and an implementation without
`_disableInitializers()` is the Parity shape. Nothing here runs target code.
"""
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


race = load('bp_test_init_race', 'skills/bounty-pilot/scripts/init_race.py')

IMPL = '0x' + '11' * 20
SPLIT = '0x' + '22' * 20
ATOMIC = '0x' + '33' * 20
ORPHAN = '0x' + '44' * 20


def tx(kind, name=None, address=None, args=None, function=None, to=None, h=None):
    return {"hash": h, "transactionType": kind, "contractName": name,
            "contractAddress": address, "arguments": args, "function": function,
            "transaction": {"to": to, "input": "0x"}}


BROADCAST = {
    "transactions": [
        tx("CREATE", "Vault", IMPL, None, h="0xa1"),
        tx("CREATE", "ERC1967Proxy", SPLIT, [IMPL, "0x"], h="0xa2"),
        tx("CREATE", "ERC1967Proxy", ATOMIC, [IMPL, "0x8129fc1c"], h="0xa3"),
        tx("CREATE", "TransparentUpgradeableProxy", ORPHAN, [IMPL, IMPL, ""], h="0xa4"),
        tx("CALL", None, SPLIT, None, "initialize(address)", to=SPLIT, h="0xa5"),
    ],
    "receipts": [{"transactionHash": "0xa2", "blockNumber": "0x10"},
                 {"transactionHash": "0xa5", "blockNumber": "0x12"}],
    "timestamp": 1700000000,
}

UNPROTECTED = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
contract Vault is Initializable {
    address public owner;
    // constructor() { _disableInitializers(); }   <- commented out, must not count
    function initialize(address o) external initializer { owner = o; }
}
"""

PROTECTED = """pragma solidity ^0.8.20;
contract Safe is Initializable {
    address public owner;
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() { _disableInitializers(); }
    function initialize(address o) external initializer { owner = o; }
}
"""

UNGUARDED = """pragma solidity ^0.8.20;
contract Loose {
    address public owner;
    constructor() {}
    function initialize(address o) public { owner = o; }
}
contract Flagged {
    bool private initialized;
    address public owner;
    function initialize(address o) external {
        require(!initialized, "done");
        initialized = true;
        owner = o;
    }
}
"""

SCRIPT = """pragma solidity ^0.8.20;
contract Deploy is Script {
    function run() external {
        Vault impl = new Vault();
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), "");
        Vault(address(proxy)).initialize(msg.sender);
    }
}
"""


class InitRace(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / 'repo'
        files = {
            'src/Vault.sol': UNPROTECTED, 'src/Safe.sol': PROTECTED, 'src/Loose.sol': UNGUARDED,
            'test/Mock.t.sol': UNGUARDED, 'script/Deploy.s.sol': SCRIPT,
        }
        for rel, text in files.items():
            (self.repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / rel).write_text(text, encoding='utf-8')
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'add', '-A'], check=True)
        # The broadcast is untracked (usually gitignored): read from the working tree.
        run_dir = self.repo / 'broadcast/Deploy.s.sol/1'
        run_dir.mkdir(parents=True)
        (run_dir / 'run-1700000000.json').write_text(json.dumps(BROADCAST), encoding='utf-8')
        (run_dir / 'run-latest.json').write_text(json.dumps(BROADCAST), encoding='utf-8')
        self.report = race.analyze(self.repo)
        self.leads = self.report['leads']

    def tearDown(self):
        self.tmp.cleanup()

    def codes(self, code):
        return [lead for lead in self.leads if lead['code'] == code]

    def test_split_deploy_then_initialize_is_a_lead(self):
        split = self.codes('split-deploy-init')
        self.assertEqual(len(split), 1)
        self.assertIn(SPLIT, split[0]['detail'])
        self.assertIn('block gap 2', split[0]['detail'])
        self.assertEqual(split[0]['confidence'], 'high')
        proxy = [p for p in self.report['proxies'] if p.get('address') == SPLIT][0]
        self.assertEqual(proxy['tx_distance'], 3)
        self.assertEqual(proxy['block_gap'], 2)

    def test_atomic_proxy_is_counted_not_a_lead(self):
        self.assertFalse(any(ATOMIC in lead['detail'] for lead in self.leads))
        self.assertEqual(self.report['counts']['atomic'], 1)
        proxy = [p for p in self.report['proxies'] if p.get('address') == ATOMIC][0]
        self.assertEqual(proxy['status'], 'atomic')

    def test_never_initialized(self):
        orphan = self.codes('no-init-call-seen')
        self.assertEqual(len(orphan), 1)
        self.assertIn(ORPHAN, orphan[0]['detail'])

    def test_broadcast_provenance_and_dedup(self):
        read = self.report['broadcasts_read']
        self.assertEqual([r['file'] for r in read],
                         ['broadcast/Deploy.s.sol/1/run-1700000000.json'])
        self.assertFalse(read[0]['tracked'])
        self.assertEqual(self.report['counts']['proxies'], 3)

    def test_implementation_without_disable_initializers(self):
        impl = self.codes('implementation-initializable')
        files = {lead['file'].split(':')[0] for lead in impl}
        self.assertIn('src/Vault.sol', files)
        self.assertNotIn('src/Safe.sol', files)
        self.assertFalse(any(f.startswith('test/') for f in files))

    def test_unguarded_initialize(self):
        loose = self.codes('unguarded-initialize')
        self.assertEqual([lead['file'] for lead in loose], ['src/Loose.sol:5'])
        self.assertIn('Loose.initialize', loose[0]['detail'])

    def test_script_with_empty_init_data(self):
        script = self.codes('script-empty-init-data')
        self.assertEqual(len(script), 1)
        self.assertTrue(script[0]['file'].startswith('script/Deploy.s.sol:'))

    def test_scope_limits_sources(self):
        report = race.analyze(self.repo, scope=['src/Safe.sol'])
        self.assertFalse(any(lead['code'] in ('implementation-initializable', 'unguarded-initialize')
                             for lead in report['leads']))
        self.assertTrue(any(lead['code'] == 'split-deploy-init' for lead in report['leads']))

    def test_derived_initializable_slot(self):
        self.assertEqual(race.initializable_slot(),
                         '0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00')
        self.assertEqual(self.report['oz_v5_initializable_slot'], race.initializable_slot())

    def test_out_inside_repo_refused(self):
        with self.assertRaises(SystemExit):
            race.main(['--repo', str(self.repo), '--out', str(self.repo / 'init-race.json')])
        self.assertFalse((self.repo / 'init-race.json').exists())

    def test_dry_run_is_labelled(self):
        dry = self.repo / 'broadcast/Other.s.sol/5/dry-run'
        dry.mkdir(parents=True)
        data = {"transactions": [tx("CREATE", "ERC1967Proxy", '0x' + '55' * 20, [IMPL, "0x"])]}
        (dry / 'run-1.json').write_text(json.dumps(data), encoding='utf-8')
        report = race.analyze(self.repo)
        lead = [x for x in report['leads'] if '55' * 20 in x['detail']][0]
        self.assertEqual(lead['confidence'], 'low')
        self.assertIn('never broadcast', lead['detail'])

    def test_hardhat_deploy_record(self):
        net = self.repo / 'deployments/mainnet'
        net.mkdir(parents=True)
        (net / 'Vault_Proxy.json').write_text(json.dumps(
            {"address": SPLIT, "transactionHash": "0xb1", "implementation": IMPL}), encoding='utf-8')
        (net / 'Pool.json').write_text(json.dumps(
            {"address": ATOMIC, "implementation": IMPL,
             "execute": {"methodName": "initialize", "args": []}}), encoding='utf-8')
        report = race.analyze(self.repo)
        leads = [x for x in report['leads'] if x['code'] == 'proxy-no-recorded-init']
        self.assertEqual([x['file'] for x in leads], ['deployments/mainnet/Vault_Proxy.json'])
        self.assertEqual(report['counts']['atomic'], 2)


if __name__ == '__main__':
    unittest.main()
