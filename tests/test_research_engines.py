"""CaseForge and passive identity/phase engines: synthetic, no target network."""
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/bounty-pilot/scripts'


def load(name):
    spec = importlib.util.spec_from_file_location('test_research_' + name,
                                                  SCRIPTS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


caseforge = load('caseforge')
research = load('research_diff')


class CaseForgeTests(unittest.TestCase):
    def test_seed_catalog_has_published_references_but_no_fabricated_revisions(self):
        catalog = caseforge._read(caseforge.CATALOG)
        summary = caseforge.validate(catalog)
        self.assertEqual(summary['total_cases'], 7)
        self.assertEqual(summary['measurement_ready'], 0)
        self.assertEqual(caseforge.blind_queue(catalog)['tasks'], [])
        self.assertIn('source_url', caseforge.index(catalog)['cases'][0])

    def test_invalid_revision_and_duplicate_refused(self):
        item = dict(caseforge._read(caseforge.CATALOG)['cases'][0])
        bad = {'schema_version': 1, 'cases': [dict(item, status='revision-pinned',
                                                   vulnerable_commit='not-a-sha')]}
        with self.assertRaisesRegex(ValueError, 'requires 40-hex commit'):
            caseforge.validate(bad)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            caseforge.validate({'schema_version': 1, 'cases': [item, item]})

    def test_blind_task_hides_mechanism_source_and_case_id(self):
        item = dict(caseforge._read(caseforge.CATALOG)['cases'][0],
                    status='revision-pinned', vulnerable_commit='1' * 40,
                    repository_url='https://github.com/example/project')
        result = caseforge.blind_queue({'schema_version': 1, 'cases': [item]})
        self.assertEqual(len(result['tasks']), 1)
        body = json.dumps(result)
        for secret in ('POLYGON-PLASMA', 'exit identifiers', 'immunefi.com',
                       'semantic-identity'):
            self.assertNotIn(secret, body)
        self.assertEqual(result['tasks'][0]['pinned_commit'], '1' * 40)
        self.assertEqual(result['measured_rediscoveries'], 0)


class IdentityDifferentialTests(unittest.TestCase):
    def test_collision_split_and_negative_controls(self):
        result = research.identity({'schema_version': 1, 'pairs': [
            {'id': 'same-semantic-split', 'expected_semantic_relation': 'same',
             'equivalence_basis': 'two encodings decode to one exit',
             'left': {'identity_key': 'exit-1'}, 'right': {'identity_key': 'exit-2'}},
            {'id': 'different-context-same', 'expected_semantic_relation': 'different',
             'equivalence_basis': 'proof includes different asset',
             'left': {'identity_key': 'cache-1'}, 'right': {'identity_key': 'cache-1'}},
            {'id': 'negative-control', 'expected_semantic_relation': 'different',
             'equivalence_basis': 'different output', 'left': {'identity_key': 'k1'},
             'right': {'identity_key': 'k2'}},
        ]})
        self.assertEqual([r['signal'] for r in result['findings']],
                         ['SAME_ACTION_DISTINCT_KEY', 'DISTINCT_CONTEXT_SHARED_KEY'])
        self.assertEqual(result['confirmed_vulnerabilities'], 0)

    def test_missing_basis_stays_unverified(self):
        result = research.identity({'schema_version': 1, 'pairs': [
            {'id': 'unproven', 'expected_semantic_relation': 'same',
             'equivalence_basis': '', 'left': {'identity_key': 'a'},
             'right': {'identity_key': 'b'}}]})
        self.assertEqual(result['findings'][0]['basis_status'], 'MISSING')
        self.assertEqual(result['findings'][0]['classification'], 'NEEDS_EVIDENCE')

    def test_wrong_shape_and_large_sets_fail(self):
        with self.assertRaises(ValueError):
            research.identity({'schema_version': 1, 'pairs': [
                {'id': 'bad', 'expected_semantic_relation': 'unknown',
                 'left': {'identity_key': 'a'}, 'right': {'identity_key': 'b'},
                 'equivalence_basis': 'x'}]})
        with self.assertRaises(ValueError):
            research.identity({'schema_version': 1,
                               'pairs': [{} for _ in range(1001)]})


class PhaseDifferentialTests(unittest.TestCase):
    def test_payload_and_policy_mismatch_are_separate_signals(self):
        report = research.phases({'schema_version': 1, 'cases': [
            {'id': 'authorization', 'same_policy_expected': True,
             'equivalence_basis': 'same request id / policy epoch',
             'stages': [
                 {'name': 'api', 'decision': 'allow', 'payload_digest': 'a',
                  'policy_id': 'v1'},
                 {'name': 'worker', 'decision': 'deny', 'payload_digest': 'b',
                  'policy_id': 'v2'}]},
            {'id': 'negative-control', 'same_policy_expected': True,
             'equivalence_basis': 'same original request',
             'stages': [
                 {'name': 'api', 'decision': 'allow', 'payload_digest': 'a'},
                 {'name': 'worker', 'decision': 'allow', 'payload_digest': 'a'}]},
        ]})
        self.assertEqual(report['candidate_count'], 1)
        self.assertEqual(report['findings'][0]['signals'],
                         ['DECISION_DIVERGENCE', 'PAYLOAD_DRIFT', 'POLICY_VERSION_DRIFT'])
        self.assertFalse(report['findings'][0]['comparable'])
        self.assertEqual(report['findings'][0]['comparison_blocker'], 'POLICY_VERSION_MISMATCH')
        self.assertEqual(report['confirmed_vulnerabilities'], 0)

    def test_no_basis_makes_signal_not_comparable(self):
        report = research.phases({'schema_version': 1, 'cases': [
            {'id': 'different-policies', 'stages': [
                {'name': 'mempool', 'decision': 'allow'},
                {'name': 'block', 'decision': 'deny'}]}]})
        self.assertEqual(report['candidate_count'], 1)
        self.assertFalse(report['findings'][0]['comparable'])

    def test_stages_need_unique_names_and_valid_decisions(self):
        with self.assertRaisesRegex(ValueError, 'stage name repeated'):
            research.phases({'schema_version': 1, 'cases': [
                {'id': 'dup', 'stages': [
                    {'name': 'a', 'decision': 'allow'},
                    {'name': 'a', 'decision': 'deny'}]}]})


class LocalCodeAndCLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)

    def test_passive_scan_finds_cues_without_executing_target(self):
        source = self.repo / 'src' / 'proof.sol'
        source.parent.mkdir()
        source.write_text(
            'contract Proof { bytes32 x = keccak256(abi.encodePacked(left, right)); }\n')
        subprocess.run(['git', '-C', str(self.repo), 'add', '-A'], check=True)
        result = research.source_scan(self.repo, ['src'])
        self.assertTrue(any(x['signal'] == 'packed_dynamic' for x in result['findings']))
        self.assertEqual(result['confirmed_vulnerabilities'], 0)
        self.assertTrue(all(x['classification'] == 'LEXICAL_LEAD'
                            for x in result['findings']))

    def test_scan_scope_is_required(self):
        with self.assertRaisesRegex(ValueError, 'scope'):
            research.source_scan(self.repo, None)
        with self.assertRaisesRegex(ValueError, 'scope'):
            research.source_scan(self.repo, ['../other'])

    def test_direct_clis_output_json(self):
        inp = self.root / 'input.json'
        inp.write_text(json.dumps({'schema_version': 1, 'pairs': []}))
        command = ['python3', str(SCRIPTS / 'research_diff.py'), 'identity',
                   '--input', str(inp)]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)['candidate_count'], 0)
        command = ['python3', str(SCRIPTS / 'caseforge.py'), 'validate']
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)['total_cases'], 7)

    def test_bounty_cli_registration(self):
        result = subprocess.run(['python3', str(SCRIPTS / 'bounty.py'), 'caseforge',
                                 'validate'], capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)['total_cases'], 7)
        result = subprocess.run(['python3', str(SCRIPTS / 'bounty.py'), 'research-diff',
                                 'scan', '--repo', str(self.repo), '--scope', 'src'],
                                capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)['mode'], 'source-scan')


if __name__ == '__main__':
    unittest.main()
