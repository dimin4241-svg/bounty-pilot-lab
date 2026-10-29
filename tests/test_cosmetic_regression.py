"""The cosmetic-regression sweep, calibrated against the commit that introduced a live bug.

`tests/fixtures/cosmetic-regression/` holds the real patch and the real message of
trezor-firmware `ce2282bd`, the commit that replaced a provenance predicate with a comparison of
rendered strings and so let a signed Ethereum transaction hide its own outgoing value. It was
accepted for a bounty two and a half months later, and it was still live on `main` when this
test was written. Measured over the whole history of that repository, paths `core/src/apps` and
`core/src/trezor/ui`, this classifier returned exactly one candidate out of 2559 commits that
touch those paths, and it was this one.

A detector with one known positive and no negatives is a story, so the negatives below pin the
two ways the shape is not present: a cosmetic message over a diff that changes no predicate, and
a diff that swaps one semantic predicate for another.
"""
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/cosmetic-regression'


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cosmetic = load('bp_test_cosmetic', 'skills/bounty-pilot/scripts/cosmetic_regression.py')
PATCH = (FIXTURES / 'ce2282bd-clear-signing.patch').read_text(encoding='utf-8')
MESSAGE = (FIXTURES / 'ce2282bd-message.txt').read_text(encoding='utf-8')


class KnownPositiveTests(unittest.TestCase):
    def test_the_real_regression_is_a_candidate(self):
        verdict = cosmetic.classify(MESSAGE, PATCH)
        self.assertTrue(verdict['is_candidate'])

    def test_it_names_the_predicate_that_was_dropped(self):
        """The anchors are what a report quotes, so they are asserted, not just the verdict."""
        verdict = cosmetic.classify(MESSAGE, PATCH)
        self.assertEqual(verdict['removed_anchor'], 'fd.path == ContainerPath.Value')
        self.assertEqual(verdict['added_anchor'],
                         'if amount is not None and formatted == amount:')

    def test_it_sees_every_semantic_signal_the_commit_dropped(self):
        verdict = cosmetic.classify(MESSAGE, PATCH)
        self.assertEqual(verdict['semantic_removed'],
                         ['enum/const cmp', 'formatter probe', 'isinstance', 'path/tag field'])
        self.assertEqual(verdict['rendered_added'], ['rendered var cmp'])

    def test_the_message_funnel_catches_this_subject(self):
        self.assertEqual(cosmetic.classify(MESSAGE, PATCH)['message_funnel'], 'double display')

    def test_the_funnel_alone_does_not_make_a_candidate(self):
        """It passed 46% of commits on the calibration target; the diff shape carries the sweep."""
        benign = '--- a/ui.py\n+++ b/ui.py\n-    title = "Swap"\n+    title = "Swap tokens"\n'
        verdict = cosmetic.classify('fix: wording of the swap title', benign)
        self.assertEqual(verdict['message_funnel'], 'wording')
        self.assertFalse(verdict['is_candidate'])


class NegativeTests(unittest.TestCase):
    def test_semantic_for_semantic_is_not_a_candidate(self):
        diff = ('--- a/x.py\n+++ b/x.py\n'
                '-    if isinstance(field.get_formatter(), AmountFormatter):\n'
                '+    if field.path == ContainerPath.Value:\n')
        self.assertFalse(cosmetic.classify('refactor: tidy the check', diff)['is_candidate'])

    def test_a_rendered_comparison_that_replaced_nothing_is_not_a_candidate(self):
        diff = '--- a/x.py\n+++ b/x.py\n+    if formatted == amount:\n'
        self.assertFalse(cosmetic.classify('cosmetic: dedupe', diff)['is_candidate'])

    def test_an_empty_diff_is_not_a_candidate(self):
        self.assertFalse(cosmetic.classify('cosmetic: no changelog', '')['is_candidate'])


class HistoryGuardTests(unittest.TestCase):
    """A history lens may not answer with silence from a checkout that has no history."""

    def test_full_history_passes(self):
        self.assertIsNone(cosmetic.guard_history(
            {'commits': 19288, 'shallow': False, 'grafted': False,
             'blobless_partial_clone': True}))

    def test_a_depth_one_clone_is_a_blocker(self):
        blocker = cosmetic.guard_history(
            {'commits': 1, 'shallow': True, 'grafted': False, 'blobless_partial_clone': False})
        self.assertIn('1 commit(s)', blocker['output_excerpt'])
        self.assertIn('shallow', blocker['output_excerpt'])
        self.assertIn('command', blocker)
        self.assertIn('--filter=blob:none', blocker['remedy'])

    def test_a_grafted_head_is_a_blocker(self):
        blocker = cosmetic.guard_history(
            {'commits': 500, 'shallow': False, 'grafted': True,
             'blobless_partial_clone': False})
        self.assertIn('grafted', blocker['output_excerpt'])

    def test_an_unreadable_head_is_a_blocker(self):
        blocker = cosmetic.guard_history(
            {'commits': None, 'shallow': False, 'grafted': False,
             'blobless_partial_clone': False})
        self.assertIn('no readable history', blocker['output_excerpt'])


class CapabilityEvidenceTests(unittest.TestCase):
    """The probe must carry the guard as an evidence kind, or no lens can read it."""

    bounty = load('bp_test_cosmetic_bounty', 'skills/bounty-pilot/scripts/bounty.py')

    def test_a_shallow_checkout_is_unavailable_and_says_why(self):
        kind = self.bounty._history_evidence(
            {'commits': 1, 'shallow': True, 'grafted': True, 'blobless_partial_clone': False})
        self.assertEqual(kind['state'], 'unavailable')
        self.assertIn('1 commit(s)', kind['reason'])
        self.assertIn('not a clean result', kind['reason'])

    def test_full_history_is_available(self):
        kind = self.bounty._history_evidence(
            {'commits': 19288, 'shallow': False, 'grafted': False,
             'blobless_partial_clone': False})
        self.assertEqual(kind['state'], 'available')
        self.assertIn('19288 commits', kind['reason'])

    def test_a_blobless_clone_is_available_and_flagged_as_slower(self):
        kind = self.bounty._history_evidence(
            {'commits': 19288, 'shallow': False, 'grafted': False,
             'blobless_partial_clone': True})
        self.assertEqual(kind['state'], 'available')
        self.assertIn('fetch on demand', kind['reason'])

    def test_the_kind_reaches_capabilities_without_an_rpc(self):
        """The no-rpc path returns early; the kind has to be set before that branch."""
        build = {'command': None, 'root_manifests': []}
        tests = {'command': None, 'test_files': []}
        kinds = self.bounty._evidence_kinds(
            build, tests, None, None, None, False,
            {'commits': 1, 'shallow': True, 'grafted': False,
             'blobless_partial_clone': False})
        self.assertEqual(kinds['commit-history']['state'], 'unavailable')


@unittest.skipUnless(__import__('shutil').which('git'), 'git is not on PATH')
class SweepAgainstGitTests(unittest.TestCase):
    """End to end over a real repository built here, so the git plumbing is exercised too."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.repo = Path(self.dir.name)
        self.addCleanup(self.dir.cleanup)
        env = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@e',
                   GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@e')
        self.env = env

        def run(*args):
            subprocess.run(['git', '-C', str(self.repo), *args], check=True, env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        run('init', '-q', '-b', 'main')
        target = self.repo / 'ui.py'
        target.write_text('if field.path == ContainerPath.Value:\n    show(value)\n',
                          encoding='utf-8')
        run('add', 'ui.py')
        run('commit', '-qm', 'initial: show the value')
        target.write_text('if formatted == amount:\n    show(value)\n', encoding='utf-8')
        run('add', 'ui.py')
        run('commit', '-qm', 'fix(ui): double display of amount.\n\n- compare rendered strings '
                             'now.\n\n[no changelog]')

    def test_the_sweep_finds_the_commit_and_reports_its_funnel(self):
        report = cosmetic.sweep(self.repo, ['ui.py'])
        self.assertEqual(report['state'], 'swept')
        self.assertEqual(report['commits_touching_paths'], 2)
        self.assertEqual(len(report['candidates']), 1)
        row = report['candidates'][0]
        self.assertEqual(row['subject'], 'fix(ui): double display of amount.')
        self.assertEqual(row['removed_anchor'], 'if field.path == ContainerPath.Value:')
        self.assertEqual(row['added_anchor'], 'if formatted == amount:')

    def test_all_commits_skips_the_funnel_and_still_finds_it(self):
        report = cosmetic.sweep(self.repo, ['ui.py'], funnel=False)
        self.assertFalse(report['message_funnel_applied'])
        self.assertEqual(report['commits_diffed'], 2)
        self.assertEqual(len(report['candidates']), 1)

    def test_history_surface_reads_a_real_checkout(self):
        surface = cosmetic.history_surface(self.repo)
        self.assertEqual(surface['commits'], 2)
        self.assertFalse(surface['shallow'])

    def test_a_shallow_clone_is_blocked_rather_than_empty(self):
        shallow = Path(self.dir.name) / 'shallow.git'
        subprocess.run(['git', 'clone', '-q', '--depth', '1', '--no-local',
                        'file://' + str(self.repo), str(shallow)], check=True, env=self.env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        report = cosmetic.sweep(shallow, ['ui.py'])
        self.assertEqual(report['state'], 'blocked')
        self.assertEqual(report['candidates'], [])
        self.assertIn('shallow', report['blocker']['output_excerpt'])

    def test_the_cli_exits_nonzero_on_a_blocked_checkout(self):
        shallow = Path(self.dir.name) / 'shallow-cli.git'
        subprocess.run(['git', 'clone', '-q', '--depth', '1', '--no-local',
                        'file://' + str(self.repo), str(shallow)], check=True, env=self.env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        out = self.repo / 'report.json'
        code = cosmetic.main(['--repo', str(shallow), '--out', str(out)])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out.read_text(encoding='utf-8'))['state'], 'blocked')


if __name__ == '__main__':
    unittest.main()
