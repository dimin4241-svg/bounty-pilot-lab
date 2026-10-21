"""Tier 2 of the 2026-10-21 design: a mechanism instead of a theme, and the three layers no
lens was reading.

Every test here failed on `b6ee81f` (0.24.0). The two changes answer two measured facts: an
agent doing this job organises the audit around themes and writes a plausible report that
misses the bug (the same model scores 50.7% given the file against 92.6% given the mechanism);
and both confirmed Highs in this skill's own ledger, plus six of the seven largest public
bounties, came from layers that had no lens at all.
"""
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/bounty-pilot/scripts'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bounty = load('t2_bounty', 'bounty.py')
stack_route = load('t2_stack_route', 'stack_route.py')


def git(repo, *args):
    subprocess.run(['git', '-C', str(repo), *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def commit(repo, message='fixture'):
    git(repo, 'add', '-A')
    git(repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
        '-c', 'commit.gpgsign=false', 'commit', '-qm', message)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        (self.repo / 'src/Vault.sol').write_text(
            'contract Vault {\n    function withdraw(uint256 a) external {}\n}\n')
        commit(self.repo)
        self.run = self.base / 'run'
        bounty.initialize(self.repo, self.run)

    def reading(self, name, *lines):
        folder = self.base / 'readings'
        folder.mkdir(exist_ok=True)
        (folder / name).write_text('\n'.join(lines) + '\n')
        return folder


# ---------------------------------------------------------------------------------------------
# T2.1 — a mechanism, not a theme
# ---------------------------------------------------------------------------------------------

class MechanismContractTests(Fixture):
    def test_a_reading_with_no_mechanism_line_is_counted_as_a_theme_sweep(self):
        folder = self.reading(
            'themes.md',
            'CANDIDATE | lens: accounting | surface: src/Vault.sol:Vault.withdraw | '
            'bug_class: accounting-drift',
            'breaks: the accounting may drift')
        result = bounty.converge([str(folder)], self.run)
        self.assertEqual([r['reading'] for r in result['theme_sweeps']], ['themes.md'])
        self.assertEqual(result['blocks_without_mechanism'], 1)    # b6ee81f: not counted

    def test_a_reading_that_names_the_mechanism_is_not_a_sweep(self):
        folder = self.reading(
            'named.md',
            'CANDIDATE | lens: accounting | surface: src/Vault.sol:Vault.withdraw | '
            'bug_class: accounting-drift',
            'mechanism: withdraw writes balances and never totalDebt, so the two disagree',
            'breaks: totalDebt no longer equals the sum of balances')
        result = bounty.converge([str(folder)], self.run)
        self.assertEqual(result['theme_sweeps'], [])
        self.assertEqual(result['blocks_without_mechanism'], 0)

    def test_one_named_block_clears_the_reading(self):
        folder = self.reading(
            'mixed.md',
            'LEAD | lens: liveness | surface: src/Vault.sol:Vault.withdraw | bug_class: dos',
            'smell: unbounded',
            'CANDIDATE | lens: accounting | surface: src/Vault.sol:Vault.withdraw | '
            'bug_class: accounting-drift',
            'mechanism: totalDebt is never decremented in the partial-repay branch')
        result = bounty.converge([str(folder)], self.run)
        self.assertEqual(result['theme_sweeps'], [])
        self.assertEqual(result['blocks_without_mechanism'], 1)

    def test_queue_reports_the_theme_sweeps(self):
        folder = self.reading(
            'themes.md',
            'CANDIDATE | lens: accounting | surface: src/Vault.sol:Vault.withdraw | '
            'bug_class: accounting-drift', 'breaks: concerns')
        bounty.converge([str(folder)], self.run)
        self.assertEqual([r['reading'] for r in bounty.lead_queue(self.run)['theme_sweeps']],
                         ['themes.md'])

    def test_the_shared_rules_demand_a_falsifiable_mechanism(self):
        text = (ROOT / 'skills/bounty-pilot/references/hunt-agents/_shared.md').read_text()
        self.assertIn('A mechanism, not a theme', text)             # b6ee81f: absent
        self.assertIn('mechanism: one sentence', text)
        self.assertIn('could a reader disprove this sentence', text.lower())


# ---------------------------------------------------------------------------------------------
# T2.3 — the three layers that had no lens
# ---------------------------------------------------------------------------------------------

class NewLensTests(Fixture):
    NEW = ('node-client', 'secrets-artifacts', 'wallet')

    def test_each_new_lens_is_registered_with_an_instruction_file(self):
        for lens in self.NEW:
            self.assertIn(lens, bounty.LENSES)                      # b6ee81f: unknown lens
            path = ROOT / 'skills/bounty-pilot/references/hunt-agents' / f'{lens}-agent.md'
            self.assertTrue(path.is_file(), lens)

    def test_each_new_lens_bundles_with_its_own_instructions(self):
        result = bounty.bundle(self.repo, self.run, list(self.NEW))
        self.assertEqual([b['lens'] for b in result['bundles']], list(self.NEW))
        node = (self.run / 'bundles/node-client-bundle.md').read_text()
        self.assertIn('trace the panic to the process', node)
        self.assertIn('Lens: **node-client**', node)
        secrets = (self.run / 'bundles/secrets-artifacts-bundle.md').read_text()
        self.assertIn('Never use a credential you find', secrets)
        wallet = (self.run / 'bundles/wallet-bundle.md').read_text()
        self.assertIn('the user saw A and signed B', wallet)

    def test_the_group_names_expand(self):
        for group, expected in (('node', ['node-client']),
                                ('artifacts', ['secrets-artifacts']),
                                ('wallet-app', ['wallet'])):
            result = bounty.bundle(self.repo, self.run, [group])
            self.assertEqual([b['lens'] for b in result['bundles']], expected)

    def test_an_unknown_group_still_names_the_new_ones(self):
        with self.assertRaises(ValueError) as caught:
            bounty.bundle(self.repo, self.run, ['nope'])
        for group in ('node', 'artifacts', 'wallet-app'):
            self.assertIn(group, str(caught.exception))

    def test_each_new_lens_states_the_exclusion_that_decides_its_class(self):
        agents = ROOT / 'skills/bounty-pilot/references/hunt-agents'
        wallet = (agents / 'wallet-agent.md').read_text()
        # Every programme prices "malware already on the device reads the seed" at zero.
        self.assertIn('pay nothing', wallet)
        self.assertIn('remote', wallet)
        node = ' '.join((agents / 'node-client-agent.md').read_text().split())
        self.assertIn('validator attacking the network is usually out of scope', node)
        secrets = ' '.join((agents / 'secrets-artifacts-agent.md').read_text().split())
        self.assertIn('what does it authorise', secrets)

    def test_the_catalogue_documents_all_three(self):
        text = (ROOT / 'skills/bounty-pilot/references/lenses.md').read_text()
        for name in ('node-client-agent.md', 'secrets-artifacts-agent.md', 'wallet-agent.md'):
            self.assertIn(name, text)


class WalletBundleSourceTests(Fixture):
    def test_the_wallet_lens_reads_web_sources_when_the_target_ships_them(self):
        (self.repo / 'src/background.ts').write_text(
            'chrome.runtime.onMessage.addListener((msg, sender) => approve(msg.origin));\n')
        commit(self.repo, 'extension')
        bounty.bundle(self.repo, self.run, ['wallet'])
        text = (self.run / 'bundles/wallet-bundle.md').read_text()
        self.assertIn('onMessage.addListener', text)                # b6ee81f: no such lens

    def test_a_native_wallet_falls_back_to_the_source_tree_and_says_so(self):
        result = bounty.bundle(self.repo, self.run, ['wallet'])
        text = (self.run / 'bundles/wallet-bundle.md').read_text()
        self.assertIn('contract Vault', text)
        self.assertTrue(any('read as a native client' in note for note in result['notes']))


class NodeLensRoutingTests(unittest.TestCase):
    """The node lens belongs to a client or runtime stack, and to no other target."""

    def route(self, files):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        repo = Path(temp.name) / 'repo'
        for rel, body in files.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(body)
        git(repo, 'init', '-q')
        commit(repo)
        return stack_route.route(repo)['prioritization']['selected']

    def test_a_go_client_selects_it(self):
        selected = self.route({'go.mod': 'module example.com/node\n\ngo 1.22\n',
                               'p2p/handler.go': 'package p2p\n\nfunc Handle() {}\n'})
        self.assertIn('node-client', selected)                      # b6ee81f: not a lens

    def test_a_contracts_only_target_does_not(self):
        selected = self.route({'foundry.toml': '[profile.default]\nsrc = "src"\n',
                               'src/Vault.sol': 'contract Vault {}\n'})
        self.assertNotIn('node-client', selected)

    def test_a_rust_client_selects_it(self):
        selected = self.route({'Cargo.toml': '[package]\nname = "node"\nversion = "0.1.0"\n',
                               'src/main.rs': 'fn main() {}\n'})
        self.assertIn('node-client', selected)


if __name__ == '__main__':
    unittest.main()
