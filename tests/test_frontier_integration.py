"""Lab 0.53 wiring: the frontier lenses, the stacks and surfaces that route to them, and the
standalone helpers reachable through bounty.py.

The helpers have their own test modules. This one checks only that the pieces are joined: a lens
nobody can bundle, a helper `bounty.py` cannot reach, or a surface that never routes is a feature
that exists on disk and nowhere in a run.
"""
import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / 'skills/bounty-pilot'
SCRIPTS = SKILL / 'scripts'
sys.path.insert(0, str(SCRIPTS))


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bounty = load('bp_frontier_bounty', 'skills/bounty-pilot/scripts/bounty.py')
stack_route = load('bp_frontier_route', 'skills/bounty-pilot/scripts/stack_route.py')

FRONTIER = ('bridge-messaging', 'zk-soundness', 'oracle-listing', 'governance-capture',
            'account-abstraction', 'hooks-keepers', 'agent-wallet')


def git_repo(files):
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    subprocess.run(['git', '-C', str(root), 'add', '-A'], check=True)
    subprocess.run(['git', '-C', str(root), '-c', 'user.name=t', '-c', 'user.email=t@t',
                    'commit', '-qm', 'init'], check=True)
    return root


class LensRegistryTests(unittest.TestCase):
    def test_frontier_lenses_are_registered_with_instruction_files(self):
        self.assertEqual(bounty.FRONTIER_LENSES, FRONTIER)
        for lens in FRONTIER:
            self.assertIn(lens, bounty.LENSES)
            path = SKILL / 'references/hunt-agents' / f'{lens}-agent.md'
            self.assertTrue(path.is_file(), lens)
            text = path.read_text(encoding='utf-8')
            for heading in ('## Procedure', '## Proof standard'):
                self.assertIn(heading, text, f'{lens} lacks {heading}')

    def test_attack_group_still_leads_with_privileged_path(self):
        self.assertEqual(bounty.ATTACK_LENSES[0], 'privileged-path')

    def test_frontier_group_bundles_every_frontier_lens(self):
        repo = git_repo({'src/Bridge.sol': 'pragma solidity ^0.8.20;\ncontract Bridge {}\n'})
        run = Path(tempfile.mkdtemp()) / 'run'
        with contextlib.redirect_stdout(io.StringIO()):
            bounty.initialize(str(repo), str(run))
        result = bounty.bundle(str(repo), str(run), ['frontier'])
        built = {row['lens'] for row in result['bundles']}
        self.assertEqual(built, set(FRONTIER))

    def test_every_analysis_consumer_is_a_registered_lens(self):
        names = {row[0] for row in bounty.ANALYSIS_FILES}
        for expected in ('rounding-map.json', 'config-snapshot.json', 'nday-scan.json',
                         'legacy-sweep.json', 'init-race.json'):
            self.assertIn(expected, names)
        for name, lenses, note in bounty.ANALYSIS_FILES:
            for lens in lenses:
                self.assertIn(lens, bounty.LENSES, f'{name} hands its output to {lens!r}')
            self.assertTrue(note.strip().endswith('.'), name)


class HelperCommandTests(unittest.TestCase):
    def test_every_helper_command_has_a_module_with_main(self):
        for command, (module, text) in bounty.HELPER_COMMANDS.items():
            path = SCRIPTS / f'{module}.py'
            self.assertTrue(path.is_file(), command)
            self.assertTrue(callable(getattr(bounty.load_impact_helper(module), 'main', None)),
                            command)
            self.assertTrue(text)

    def test_helper_help_comes_from_the_helper_parser(self):
        for command in bounty.HELPER_COMMANDS:
            done = subprocess.run([sys.executable, str(SCRIPTS / 'bounty.py'), command, '--help'],
                                  capture_output=True, text=True, timeout=60)
            self.assertEqual(done.returncode, 0, f'{command}: {done.stderr[-300:]}')
            self.assertIn('--', done.stdout, command)

    def test_helper_commands_are_listed_in_the_cli(self):
        parser = bounty.build_parser()
        actions = [a for a in parser._actions if a.__class__.__name__ == '_SubParsersAction']
        for command in bounty.HELPER_COMMANDS:
            self.assertIn(command, actions[0].choices)


class RoutingTests(unittest.TestCase):
    def selected(self, files, budget=8):
        report = stack_route.route(git_repo(files))
        return report, stack_route.prioritize(report, budget=budget)['selected']

    def test_circom_routes_to_the_zk_adapter_and_lens(self):
        report, selected = self.selected({'circuits/transfer.circom': 'template T() {}\n'})
        stacks = {row['stack']: row for row in report['stacks']}
        self.assertEqual(stacks['zk']['adapter'], 'adapters/zk.md')
        self.assertIn('zk-soundness', selected)
        self.assertTrue((SKILL / 'references' / stacks['zk']['adapter']).is_file())

    def test_halo2_dependency_routes_to_zk(self):
        report, _ = self.selected({'Cargo.toml': '[package]\nname="c"\n[dependencies]\n'
                                                 'halo2_proofs = "0.3"\n',
                                   'src/lib.rs': 'fn main() {}\n'})
        self.assertIn('zk', {row['stack'] for row in report['stacks']})

    def test_cosmos_sdk_go_mod_routes_to_the_cosmos_adapter(self):
        report, selected = self.selected({'go.mod': 'module x\nrequire github.com/cosmos/'
                                                    'cosmos-sdk v0.50.1\n',
                                          'app/app.go': 'package app\n'})
        stacks = {row['stack']: row for row in report['stacks']}
        self.assertEqual(stacks['cosmos-sdk']['adapter'], 'adapters/cosmos-sdk.md')
        self.assertTrue((SKILL / 'references/adapters/cosmos-sdk.md').is_file())
        self.assertIn('node-client', selected)

    def test_messaging_selects_the_bridge_messaging_lens(self):
        _, selected = self.selected({'src/OFTAdapter.sol': 'contract OFTAdapter {}\n'})
        self.assertIn('bridge-messaging', selected)
        self.assertIn('integration-auth', selected)

    def test_surface_signals_route_their_lenses(self):
        report, selected = self.selected({'src/PriceOracle.sol': 'contract PriceOracle {}\n',
                                          'src/Governor.sol': 'contract Governor {}\n',
                                          'src/Paymaster.sol': 'contract Paymaster {}\n'},
                                         budget=12)
        for lens in ('oracle-listing', 'governance-capture', 'account-abstraction'):
            self.assertIn(lens, report['surface_signals'])
            self.assertIn(lens, selected)

    def test_a_react_hooks_directory_is_not_a_v4_hook(self):
        report, selected = self.selected({'src/Vault.sol': 'contract Vault {}\n',
                                          'web/hooks/useWallet.ts': 'export {}\n'}, budget=12)
        self.assertNotIn('hooks-keepers', report['surface_signals'])
        self.assertNotIn('hooks-keepers', selected)

    def test_agent_wallet_needs_an_llm_beside_a_wallet_library(self):
        chatbot = {'package.json': json.dumps({'dependencies': {'openai': '4'}})}
        report, _ = self.selected(chatbot)
        self.assertNotIn('agent-wallet', report['surface_signals'])
        agent = {'package.json': json.dumps({'dependencies': {'openai': '4', 'viem': '2'}})}
        report, _ = self.selected(agent)
        self.assertIn('agent-wallet', report['surface_signals'])

    def test_no_signal_selects_no_surface_lens(self):
        _, selected = self.selected({'src/Vault.sol': 'contract Vault {}\n'}, budget=19)
        for lens in FRONTIER:
            self.assertNotIn(lens, selected)


if __name__ == '__main__':
    unittest.main()
