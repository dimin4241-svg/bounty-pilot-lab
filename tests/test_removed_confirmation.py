"""The removed-confirmation sweep, calibrated on the redesign that dropped Stellar's network.

`tests/fixtures/removed-confirmation/` holds the real diff of trezor-firmware `6dc393af6`,
"refactor(core): improve Stellar signing UX", and the message of `7e4bbee93`, which put the
network back thirteen months later because "for users that have accounts both on mainnet and
testnet, it is crucial to be able to distinguish that they don't sign a transaction for mainnet
that was actually meant to be sent to testnet only".

The string catalogue is what makes the signal precise: a label that leaves the code may have been
renamed, but a label deleted from the code *and* from the catalogue in the same commit is a string
the product no longer has.
"""
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/removed-confirmation'


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


removed = load('bp_test_removed', 'skills/bounty-pilot/scripts/removed_confirmation.py')
HINTS = [hint for hint in removed.CATALOGUE_HINT.split(',') if hint]
DIFF = (FIXTURES / '6dc393af6-stellar-redesign.diff').read_text(encoding='utf-8')
MESSAGE = (FIXTURES / '6dc393af6-message.txt').read_text(encoding='utf-8')

MOVED_TO_ANOTHER_SCREEN = """
diff --git a/a/layout.py b/a/layout.py
-    props.append((TR.stellar__network, network))
diff --git a/a/sign_tx.py b/a/sign_tx.py
+    info_items = [(TR.stellar__network, network)]
"""

REINDENTED_CATALOGUE = """
diff --git a/core/translations/en.json b/core/translations/en.json
-  "stellar__confirm_network": "Confirm network",
+    "stellar__confirm_network": "Confirm network",
"""


class CalibrationTests(unittest.TestCase):
    def test_the_labels_that_left_both_the_code_and_the_catalogue(self):
        lost, gone = removed.labels_lost(DIFF, HINTS)
        self.assertEqual(sorted(lost & gone), [
            'stellar__confirm_network', 'stellar__confirm_stellar', 'stellar__initial_balance',
            'stellar__initialize_signing_with', 'stellar__on_network_template',
            'stellar__private_network', 'stellar__testnet_network', 'stellar__your_account'])

    def test_four_of_them_are_the_network_display(self):
        """The field a report put back thirteen months later."""
        lost, gone = removed.labels_lost(DIFF, HINTS)
        network = {name for name in lost & gone if 'network' in name}
        self.assertEqual(sorted(network), [
            'stellar__confirm_network', 'stellar__on_network_template',
            'stellar__private_network', 'stellar__testnet_network'])

    def test_renames_stay_at_rank_one(self):
        """Reworded screens - memo, timebounds, fee templates - keep their strings."""
        lost, gone = removed.labels_lost(DIFF, HINTS)
        self.assertIn('stellar__confirm_memo', lost - gone)
        self.assertIn('stellar__sign_tx_fee_template', lost - gone)

    def test_the_funnel_takes_this_message_and_is_not_a_removal(self):
        self.assertTrue(removed.REDESIGN.search(MESSAGE))
        self.assertFalse(removed.DELIBERATE.search(MESSAGE))

    def test_a_message_that_announces_the_removal_is_excluded(self):
        """Somebody decided to drop that screen; that decision is not this sweep's business."""
        self.assertTrue(removed.DELIBERATE.search('refactor(core): remove the memo confirmation'))

    def test_a_message_that_announces_a_key_rename_is_excluded(self):
        """The catalogue loses the old key and gains a differently-named one.

        Over `core/src/apps` this exclusion accounted for every rank-0 commit except the
        calibration case, and the calibration case must not match it.
        """
        for message in ('refactor(translations): generalize some keys',
                        'refactor(translations): merge {cardano,ethereum}__network',
                        'refactor(translations): rename cardano__weight to words__weight'):
            with self.subTest(message=message):
                self.assertTrue(removed.RENAMED.search(message))
        self.assertFalse(removed.RENAMED.search(MESSAGE))


class RuleTests(unittest.TestCase):
    def test_a_label_moved_to_another_screen_is_not_lost(self):
        lost, _ = removed.labels_lost(MOVED_TO_ANOTHER_SCREEN, HINTS)
        self.assertEqual(lost, set())

    def test_a_reindented_catalogue_key_is_not_gone(self):
        _, gone = removed.labels_lost(REINDENTED_CATALOGUE, HINTS)
        self.assertEqual(gone, set())

    def test_the_catalogue_hint_is_what_separates_the_two_sides(self):
        """With no hint matching, the catalogue reads as code and nothing is rank 0."""
        lost, gone = removed.labels_lost(DIFF, ['no-such-directory/'])
        self.assertEqual(gone, set())
        self.assertTrue(lost)


@unittest.skipUnless(__import__('shutil').which('git'), 'git is not on PATH')
class HistoryGuardTests(unittest.TestCase):
    """The same checkout rule as every other history lens, from the same source of truth."""

    def test_a_shallow_clone_is_blocked_rather_than_empty(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder) / 'repo'
            (repo).mkdir()
            env = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@e',
                       GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@e')

            def run(*args, cwd=None):
                subprocess.run(['git', '-C', str(cwd or repo), *args], check=True, env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            run('init', '-q', '-b', 'main')
            (repo / 'layout.py').write_text('x = 1\n', encoding='utf-8')
            run('add', '-A')
            run('commit', '-qm', 'initial')
            (repo / 'layout.py').write_text('x = 2\n', encoding='utf-8')
            run('add', '-A')
            run('commit', '-qm', 'refactor: improve the UX')
            shallow = Path(folder) / 'shallow.git'
            subprocess.run(['git', 'clone', '-q', '--depth', '1', '--no-local',
                            'file://' + str(repo), str(shallow)], check=True, env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            report = removed.sweep(shallow)
            self.assertEqual(report['state'], 'blocked')
            self.assertEqual(report['leads'], [])
            self.assertIn('shallow', report['blocker']['output_excerpt'])
            out = Path(folder) / 'report.json'
            self.assertEqual(removed.main(['--repo', str(shallow), '--out', str(out)]), 1)
            self.assertEqual(json.loads(out.read_text(encoding='utf-8'))['state'], 'blocked')


if __name__ == '__main__':
    unittest.main()
