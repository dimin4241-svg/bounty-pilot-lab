"""The PoC the program is handed, and the voice the report is written in.

Every test here failed on `2ab8637` (0.25.0). Two reasons. A report whose proof the team cannot
rerun is a claim, so the submission gate now requires a published, unlisted gist holding the
test, its log and the runner result. And programs are explicitly delaying triage over
machine-written submissions, so `report.md` has to name the tells rather than describe a
template.
"""
import importlib.util
import json
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


bounty = load('pg_bounty', 'bounty.py')
ALCHEMY = 'https://eth-mainnet.g.alchemy.com/v2/Kx7SECRETKEY9012345678901234'


def git(repo, *args):
    subprocess.run(['git', '-C', str(repo), *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def commit(repo, message='fixture'):
    git(repo, 'add', '-A')
    git(repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
        '-c', 'commit.gpgsign=false', 'commit', '-qm', message)


def fake_gh(files=None, public=False, url='https://gist.github.com/t/abc123', seen=None):
    """A stand-in for `gh`: records the calls, creates nothing, touches no network."""
    seen = seen if seen is not None else []

    def call(args):
        seen.append(args)
        if args[:2] == ['gist', 'create']:
            assert '--public' not in args, 'secret is the default; never opt in to public'
            return url
        listed = files if files is not None else [Path(a).name for a in seen[0][4:]]
        return {'files': listed, 'public': public}
    call.seen = seen
    return call


class BundleFixture(unittest.TestCase):
    """A run holding one verified record whose PoC, log and runner result are real files."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        (self.repo / 'src/Vault.sol').write_text('contract Vault {}\n')
        commit(self.repo)
        self.run = self.base / 'run'
        bounty.initialize(self.repo, self.run)
        (self.run / 'test').mkdir()
        (self.run / 'test/Exploit.t.sol').write_text(
            'function test_exploit() public {\n    assertGt(vault.totalDebt(), sum);\n}\n')
        (self.run / 'log.txt').write_text('[PASS] test_exploit() (gas: 25575)\n')
        bounty.dump(self.run / 'native-BP-001.json',
                    {'schema': 1, 'finding_id': 'BP-001', 'cases': []})
        bounty.dump(self.run / 'experiments.json', {'version': 1, 'experiments': [
            {'finding_id': 'BP-001', 'status': 'executed', 'revision': 'abc1234',
             'result_path': 'native-BP-001.json',
             'observation': 'The candidate passed and the control failed.'}]})
        bounty.dump(self.run / 'findings.json', [self.record()])

    def record(self, **fields):
        row = bounty.template()
        row.update(id='BP-001', title='Debt is never decremented', status='verified',
                   severity='high', bug_class='aggregate-not-decremented', revision='abc1234',
                   root_cause='repay does not decrement totalDebt',
                   affected_paths=['src/Vault.sol:Vault.repay'],
                   attacker_capabilities='any caller', preconditions='an open loan',
                   impact='later borrowers are priced against inflated debt')
        row['evidence'] = {'command': 'forge test --mt test_exploit', 'exit_code': 0,
                           'poc_path': 'test/Exploit.t.sol', 'log_path': 'log.txt',
                           'assertion': 'totalDebt exceeds the sum of loans',
                           'negative_control': 'repaying in full on a fresh vault reverts',
                           'source_integrity': 'unmodified checkout'}
        row.update(fields)
        return row


class PocBundleTests(BundleFixture):
    def test_it_packs_the_test_the_log_and_the_runner_result(self):
        result = bounty.poc_bundle(self.run, 'BP-001')
        roles = {item['role'] for item in result['files']}
        self.assertEqual(roles, {'poc', 'log', 'runner-result'})   # 2ab8637: no such command
        self.assertFalse(result['published'])                       # preparing never publishes
        folder = self.run / result['folder']
        self.assertTrue((folder / 'README.md').is_file())
        for item in result['files']:
            self.assertTrue((folder / item['gist_name']).is_file(), item['gist_name'])

    def test_the_readme_carries_the_flattened_layout_and_the_command(self):
        bounty.poc_bundle(self.run, 'BP-001')
        readme = (self.run / 'gists/BP-001/README.md').read_text()
        # A gist has no directories, so the reader needs the original path for every file.
        self.assertIn('test__Exploit.t.sol', readme)
        self.assertIn('test/Exploit.t.sol', readme)
        self.assertIn('forge test --mt test_exploit', readme)
        self.assertIn('not** access-controlled', readme)
        self.assertIn('abc1234', readme)        # the commit the PoC ran at, not the run's HEAD

    def test_a_credential_in_the_poc_is_a_refusal_not_a_redaction(self):
        (self.run / 'test/Exploit.t.sol').write_text(
            f'vm.createSelectFork("{ALCHEMY}");\n')
        with self.assertRaises(ValueError) as caught:
            bounty.poc_bundle(self.run, 'BP-001')
        self.assertIn('refusing to bundle', str(caught.exception))   # 2ab8637: nothing checked
        self.assertIn('placeholder', str(caught.exception))
        self.assertFalse((self.run / bounty.POC_GIST_FILE).exists())

    def test_a_record_with_no_poc_is_refused_even_when_a_runner_result_exists(self):
        # The runner result is still on disk; the test is what the team reruns, so its absence
        # is the refusal.
        row = self.record()
        row['evidence'] = {'command': 'forge test'}
        bounty.dump(self.run / 'findings.json', [row])
        with self.assertRaisesRegex(ValueError, 'names no PoC file'):
            bounty.poc_bundle(self.run, 'BP-001')

    def test_an_unknown_finding_is_named(self):
        with self.assertRaisesRegex(ValueError, 'BP-999'):
            bounty.poc_bundle(self.run, 'BP-999')

    def test_rerunning_replaces_that_findings_entry_and_keeps_the_others(self):
        bounty.dump(self.run / bounty.POC_GIST_FILE, {
            'schema_version': bounty.SCHEMA_VERSION,
            'bundles': [{'finding': 'BP-002', 'published': True, 'url': 'https://x/2'}]})
        bounty.poc_bundle(self.run, 'BP-001')
        held = {e['finding'] for e in
                bounty.read_json(self.run / bounty.POC_GIST_FILE)['bundles']}
        self.assertEqual(held, {'BP-001', 'BP-002'})


class PublishTests(BundleFixture):
    """`gh` is injected, so nothing is created and no network is touched."""

    def test_publishing_creates_an_unlisted_gist_and_verifies_it_file_for_file(self):
        gh = fake_gh()
        result = bounty.poc_bundle(self.run, 'BP-001', publish=True, opener=gh)
        self.assertTrue(result['published'])
        self.assertEqual(result['visibility'], 'secret (unlisted)')
        self.assertTrue(result['verified_file_for_file'])
        self.assertEqual(result['delete_command'], 'gh gist delete abc123 --yes')
        self.assertEqual(gh.seen[0][:2], ['gist', 'create'])

    def test_a_gist_missing_a_file_is_not_verified(self):
        result = bounty.poc_bundle(self.run, 'BP-001', publish=True,
                                   opener=fake_gh(files=['README.md']))
        self.assertFalse(result['verified_file_for_file'])
        self.assertTrue(result['verification']['missing'])

    def test_a_public_gist_is_reported_as_one_to_delete_now(self):
        result = bounty.poc_bundle(self.run, 'BP-001', publish=True,
                                   opener=fake_gh(public=True))
        self.assertIn('delete it now', result['visibility'])


class SubmissionGateTests(BundleFixture):
    def errors(self):
        return [e for e in bounty.validate(self.run, submission=True)
                if e.startswith(bounty.POC_GIST_FILE)]

    def test_a_verified_record_with_no_bundle_blocks_submission(self):
        errors = self.errors()
        self.assertTrue(any('has no PoC bundle' in e for e in errors), errors)
        self.assertTrue(any('poc-bundle --run' in e for e in errors))   # names the command

    def test_a_packed_but_unpublished_bundle_still_blocks(self):
        bounty.poc_bundle(self.run, 'BP-001')
        self.assertTrue(any('packed but not published' in e for e in self.errors()))

    def test_a_published_bundle_clears_this_gate(self):
        bounty.poc_bundle(self.run, 'BP-001', publish=True,
                          opener=fake_gh())
        self.assertEqual(self.errors(), [])

    def test_a_published_bundle_that_does_not_match_the_gist_blocks(self):
        bounty.poc_bundle(self.run, 'BP-001', publish=True,
                          opener=fake_gh(files=['README.md']))
        self.assertTrue(any('does not match the manifest' in e for e in self.errors()))

    def test_a_hypothesis_is_not_held_to_this_gate(self):
        bounty.dump(self.run / 'findings.json', [self.record(status='hypothesis')])
        self.assertEqual(self.errors(), [])

    def test_queue_reports_the_bundle_and_how_to_delete_it(self):
        bounty.poc_bundle(self.run, 'BP-001', publish=True,
                          opener=fake_gh())
        reported = bounty.lead_queue(self.run)['poc_gists']['bundles'][0]
        self.assertEqual(reported['finding'], 'BP-001')
        self.assertTrue(reported['published'])
        self.assertIn('gh gist delete', reported['delete_command'])


class ReportVoiceTests(unittest.TestCase):
    """The report has to read like a hunter wrote it, because triage sorts on that."""

    @classmethod
    def setUpClass(cls):
        cls.text = (ROOT / 'skills/bounty-pilot/references/report.md').read_text(encoding='utf-8')
        cls.flat = ' '.join(cls.text.split())

    def test_it_says_why_the_voice_decides_whether_the_report_is_read(self):
        self.assertIn('Why the voice matters now', self.text)        # 2ab8637: absent
        self.assertIn('LLM-generated submissions', self.flat)
        self.assertIn('duplicate rates', self.flat)

    def test_it_names_the_tells_with_what_to_write_instead(self):
        for tell in ('hope this message finds you well', 'Executive Summary',
                     'could potentially', 'leverage', 'In conclusion'):
            self.assertIn(tell, self.text, tell)
        self.assertIn('Hedging', self.text)
        self.assertIn('Confidence you have not earned', self.text)

    def test_it_asks_for_english_first_person_and_numbers(self):
        self.assertIn('Write it in English', self.flat)
        self.assertIn('First person for what you did', self.flat)
        self.assertIn('Numbers instead of adjectives', self.flat)

    def test_it_tells_the_hunter_to_attach_the_proof_not_paste_it(self):
        self.assertIn('poc-bundle', self.text)
        self.assertIn('Never paste a long PoC into the report body', self.flat)
        self.assertIn('Unlisted is not private', self.text)
        self.assertIn('Delete it when the finding is triaged', self.flat)

    def test_it_keeps_the_no_automatic_submission_rule(self):
        self.assertIn('Do not submit, do not open a public issue', self.flat)

    def test_the_hardening_note_guidance_survived_the_rewrite(self):
        self.assertIn('When every piece is individually excluded', self.text)
        self.assertIn('not** a bounty claim', self.text)


if __name__ == '__main__':
    unittest.main()
