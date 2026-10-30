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
        self.assertEqual(summary['total_cases'], 10)
        self.assertEqual(summary['measurement_ready'], 1)
        self.assertEqual(summary['pinned_finding_truths'], 4)
        self.assertEqual(len(caseforge.blind_queue(catalog)['tasks']), 1)
        self.assertEqual(caseforge.blind_queue(catalog)['tasks'][0]['pinned_commit'],
                         '6aaccc2ec51eac66a2cf18ec64ab0df2c1448990')
        self.assertIn('source_url', caseforge.index(catalog)['cases'][0])

    def test_one_snapshot_groups_multiple_known_findings_without_leaking_count(self):
        catalog = caseforge._read(caseforge.CATALOG)
        self.assertEqual(sum(x['status'] == 'revision-pinned'
                             for x in catalog['cases']), 4)
        queue = caseforge.blind_queue(catalog)
        self.assertEqual(len(queue['tasks']), 1)
        self.assertEqual(queue['tasks'][0]['case'], 'CASE-0001')
        content = json.dumps(queue)
        for forbidden in ('MONAD-2026-H01', 'MONAD-2026-H03',
                          'MONAD-2026-H04', 'signatures', 'block policy'):
            self.assertNotIn(forbidden, content)

    def test_bool_schema_does_not_pass_integer_version_check(self):
        bad = dict(caseforge._read(caseforge.CATALOG), schema_version=True)
        with self.assertRaisesRegex(ValueError, 'schema_version'):
            caseforge.validate(bad)
        with self.assertRaisesRegex(ValueError, 'schema_version'):
            research.byte_tuple({'schema_version': True, 'pairs': []})
        with self.assertRaisesRegex(ValueError, 'schema_version'):
            research.identity({'schema_version': True, 'pairs': []})
        with self.assertRaisesRegex(ValueError, 'schema_version'):
            research.phases({'schema_version': True, 'cases': []})

    def test_invalid_revision_and_duplicate_refused(self):
        item = dict(caseforge._read(caseforge.CATALOG)['cases'][0])
        bad = {'schema_version': 1, 'cases': [dict(item, status='revision-pinned',
                                                   repository_url='https://github.com/example/project',
                                                   vulnerable_commit='not-a-sha')]}
        with self.assertRaisesRegex(ValueError, 'requires 40-hex commit'):
            caseforge.validate(bad)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            caseforge.validate({'schema_version': 1, 'cases': [item, item]})

    def test_pinned_scope_cannot_escape_target_checkout(self):
        original = dict(caseforge._read(caseforge.CATALOG)['cases'][2])
        self.assertEqual(original['status'], 'revision-pinned')
        with self.assertRaisesRegex(ValueError, 'invalid scope path'):
            caseforge.validate({'schema_version': 1, 'cases': [
                dict(original, scope_paths=['../secrets.json'])]})
        with self.assertRaisesRegex(ValueError, 'source revision citation'):
            caseforge.validate({'schema_version': 1, 'cases': [
                dict(original, revision_source_url=None)]})

    def test_blind_task_hides_mechanism_source_and_case_id(self):
        item = dict(caseforge._read(caseforge.CATALOG)['cases'][0],
                    status='revision-pinned', vulnerable_commit='1' * 40,
                    repository_url='https://github.com/example/project',
                    scope_paths=['src/Module.sol'],
                    revision_source_url='https://example.org/report')
        result = caseforge.blind_queue({'schema_version': 1, 'cases': [item]})
        self.assertEqual(len(result['tasks']), 1)
        body = json.dumps(result)
        for secret in ('POLYGON-PLASMA', 'exit identifiers', 'immunefi.com',
                       'semantic-identity'):
            self.assertNotIn(secret, body)
        self.assertEqual(result['tasks'][0]['pinned_commit'], '1' * 40)
        self.assertEqual(result['measured_rediscoveries'], 0)

    def test_monad_truths_have_unique_report_ids_and_one_verified_snapshot(self):
        catalog = caseforge._read(caseforge.CATALOG)
        monad = [row for row in catalog['cases'] if row['project'] == 'Monad']
        self.assertEqual({row['id'] for row in monad}, {
            'MONAD-2026-H01', 'MONAD-2026-H02',
            'MONAD-2026-H03', 'MONAD-2026-H04'})
        self.assertEqual(len({(row['repository_url'], row['vulnerable_commit'])
                              for row in monad}), 1)
        self.assertEqual(len(caseforge.blind_queue(catalog)['tasks']), 1)
        expected_paths = {
            'MONAD-2026-H01': {'monad-eth-block-policy/src/lib.rs'},
            'MONAD-2026-H02': {'monad-eth-txpool/src/pool/transaction.rs',
                               'monad-eth-block-validator/src/lib.rs'},
            'MONAD-2026-H03': {'monad-eth-txpool/src/pool/mod.rs',
                               'monad-eth-block-policy/src/lib.rs'},
            'MONAD-2026-H04': {'monad-eth-txpool/src/pool/tracked/sequencer.rs',
                               'monad-eth-block-policy/src/lib.rs'},
        }
        for row in monad:
            self.assertTrue(row['scope_paths'])
            self.assertEqual(len(row['scope_paths']), len(set(row['scope_paths'])))
            self.assertEqual(row['vulnerable_commit'],
                             '6aaccc2ec51eac66a2cf18ec64ab0df2c1448990')
            self.assertEqual(set(row['scope_paths']), expected_paths[row['id']])

    def test_schema_types_duplicate_json_keys_and_unicode_fail_closed(self):
        original = caseforge._read(caseforge.CATALOG)['cases'][0]
        for field, value in (('source_type', []), ('family', {}), ('status', [])):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    caseforge.validate({'schema_version': 1,
                                        'cases': [dict(original, **{field: value})]})
        with self.assertRaisesRegex(ValueError, 'Unicode'):
            caseforge.validate({'schema_version': 1,
                                'cases': [dict(original, project='\ud800')]})
        with tempfile.TemporaryDirectory() as temp:
            duplicate = Path(temp) / 'duplicate.json'
            duplicate.write_text('{"schema_version":1,"schema_version":1,"cases":[]}',
                                 encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'duplicate object key'):
                caseforge._read(duplicate)

    def test_catalog_cli_returns_validation_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'invalid.json'
            source = caseforge._read(caseforge.CATALOG)['cases'][0]
            path.write_text(json.dumps({'schema_version': 1,
                                        'cases': [dict(source, source_type=[])]}),
                            encoding='utf-8')
            result = subprocess.run(['python3', str(SCRIPTS / 'caseforge.py'),
                                     'validate', '--catalog', str(path)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('Error:', result.stderr)
            self.assertNotIn('Traceback', result.stderr)

    def test_catalog_reader_rejects_symlinks_malformed_json_and_oversize(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'catalog.json'
            source.write_text('{bad json', encoding='utf-8')
            with self.assertRaises(json.JSONDecodeError):
                caseforge._read(source)
            source.unlink()
            target = root / 'target.json'
            target.write_text('{"schema_version":1,"cases":[]}', encoding='utf-8')
            link = root / 'link.json'
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'non-symlink'):
                caseforge._read(link)
            oversized = root / 'oversized.json'
            oversized.write_bytes(b' ' * 3_000_001)
            with self.assertRaisesRegex(ValueError, 'under 3 MB'):
                caseforge._read(oversized)


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
        self.assertEqual([r['signal'] for r in result['leads']],
                         ['SAME_ACTION_DISTINCT_KEY', 'DISTINCT_CONTEXT_SHARED_KEY'])
        self.assertEqual(result['confirmed_vulnerabilities'], 0)

    def test_synthetic_unframed_boundary_collision_and_framed_control(self):
        # A controlled teaching fixture, not a live Elements or Polygon exploit.
        left_parts, right_parts = (b'a', b'bc'), (b'ab', b'c')
        raw = lambda parts: b''.join(parts)
        framed = lambda parts: b''.join(len(p).to_bytes(2, 'big') + p for p in parts)
        self.assertEqual(raw(left_parts), raw(right_parts))
        self.assertNotEqual(framed(left_parts), framed(right_parts))
        compare = research.identity({'schema_version': 1, 'pairs': [
            {'id': 'unsafe', 'expected_semantic_relation': 'different',
             'equivalence_basis': 'distinct two-field tuples',
             'left': {'identity_key': raw(left_parts).hex()},
             'right': {'identity_key': raw(right_parts).hex()}},
            {'id': 'framed-control', 'expected_semantic_relation': 'different',
             'equivalence_basis': 'distinct two-field tuples',
             'left': {'identity_key': framed(left_parts).hex()},
             'right': {'identity_key': framed(right_parts).hex()}}
        ]})
        self.assertEqual([r['id'] for r in compare['leads']], ['unsafe'])

    def test_missing_basis_stays_unverified(self):
        result = research.identity({'schema_version': 1, 'pairs': [
            {'id': 'unproven', 'expected_semantic_relation': 'same',
             'equivalence_basis': '', 'left': {'identity_key': 'a'},
             'right': {'identity_key': 'b'}}]})
        self.assertEqual(result['leads'][0]['basis_status'], 'MISSING')
        self.assertEqual(result['leads'][0]['classification'], 'NEEDS_EVIDENCE')

    def test_native_message_execution_and_encoding_observations_are_fingerprinted(self):
        result = research.identity({'schema_version': 1, 'pairs': [{
            'id': 'native-boundary', 'expected_semantic_relation': 'same',
            'equivalence_basis': 'native decoder produced the same canonical message',
            'left': {'identity_key': 'key-a', 'encoded_payload_hex': '0x61',
                     'verified_message_fingerprint': 'message-a',
                     'executed_operation_fingerprint': 'operation-drift',
                     'domain': 'chain:1/bridge', 'chain_id': '1', 'nonce': '7'},
            'right': {'identity_key': 'key-b', 'encoded_payload_hex': '0x6162',
                      'verified_message_fingerprint': 'message-a',
                      'executed_operation_fingerprint': 'message-a',
                      'domain': 'chain:1/bridge', 'chain_id': '1', 'nonce': '7'},
        }]})
        lead = result['leads'][0]
        self.assertIn('SAME_ACTION_DISTINCT_KEY', lead['signals'])
        self.assertIn('VERIFIED_MESSAGE_EXECUTION_MISMATCH', lead['signals'])
        self.assertFalse(lead['encoded_payloads_equal'])
        self.assertEqual(lead['message_execution_mismatch_sides'], ['left'])
        self.assertIn('SEMANTICALLY_EQUIVALENT_DIFFERENT_BYTES', lead['signals'])
        self.assertEqual(len(lead['security_context_fingerprints']['left']['chain_id']), 64)
        self.assertNotIn('operation-drift', json.dumps(result))
        self.assertEqual(result['confirmed_vulnerabilities'], 0)

    def test_identity_repeated_pair_id_is_rejected(self):
        pair = {'id': 'same', 'expected_semantic_relation': 'different',
                'equivalence_basis': '', 'left': {'identity_key': 'a'},
                'right': {'identity_key': 'b'}}
        with self.assertRaisesRegex(ValueError, 'unique'):
            research.identity({'schema_version': 1, 'pairs': [pair, pair]})

    def test_valid_unicode_is_supported_and_unpaired_surrogates_are_rejected(self):
        result = research.identity({'schema_version': 1, 'pairs': [{
            'id': 'идентичность', 'expected_semantic_relation': 'same',
            'equivalence_basis': 'одна операция 🔐',
            'left': {'identity_key': 'ключ-A'}, 'right': {'identity_key': 'ключ-B'}}]})
        self.assertEqual(result['leads'][0]['id'], 'идентичность')
        with self.assertRaisesRegex(ValueError, 'Unicode'):
            research.identity({'schema_version': 1, 'pairs': [{
                'id': 'bad', 'expected_semantic_relation': 'same',
                'equivalence_basis': '', 'left': {'identity_key': '\ud800'},
                'right': {'identity_key': 'b'}}]})

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
        self.assertEqual(report['leads'][0]['signals'],
                         ['DECISION_DIVERGENCE', 'PAYLOAD_DRIFT', 'POLICY_VERSION_DRIFT'])
        self.assertFalse(report['leads'][0]['comparable'])
        self.assertEqual(report['leads'][0]['comparison_blocker'], 'POLICY_VERSION_MISMATCH')
        self.assertEqual(report['confirmed_vulnerabilities'], 0)
        self.assertNotIn('"policy_id": "v1"', json.dumps(report))
        self.assertNotIn('"payload_digest": "a"', json.dumps(report))
        self.assertEqual(len(report['leads'][0]['stages'][0]['policy_id_fingerprint']), 64)

    def test_synthetic_two_stage_rule_disagreement_with_normal_control(self):
        # A crafted local policy mismatch; a disagreement alone proves no exploit.
        admission = lambda nonce: nonce >= 0
        execution = lambda nonce: nonce > 0
        def stage_case(ident, nonce):
            return {'id': ident, 'same_policy_expected': True,
                    'equivalence_basis': 'two implementations of one stated nonce rule',
                    'stages': [
                        {'name': 'admission', 'decision': 'allow' if admission(nonce) else 'deny',
                         'policy_id': 'epoch-1'},
                        {'name': 'execution', 'decision': 'allow' if execution(nonce) else 'deny',
                         'policy_id': 'epoch-1'}]}
        report = research.phases({'schema_version': 1, 'cases': [
            stage_case('edge-case', 0), stage_case('normal-control', 1)]})
        self.assertEqual([r['id'] for r in report['leads']], ['edge-case'])
        self.assertTrue(report['leads'][0]['comparable'])

    def test_no_basis_makes_signal_not_comparable(self):
        report = research.phases({'schema_version': 1, 'cases': [
            {'id': 'different-policies', 'stages': [
                {'name': 'mempool', 'decision': 'allow'},
                {'name': 'block', 'decision': 'deny'}]}]})
        self.assertEqual(report['candidate_count'], 1)
        self.assertFalse(report['leads'][0]['comparable'])

    def test_stages_need_unique_names_and_valid_decisions(self):
        with self.assertRaisesRegex(ValueError, 'stage name repeated'):
            research.phases({'schema_version': 1, 'cases': [
                {'id': 'dup', 'stages': [
                    {'name': 'a', 'decision': 'allow'},
                    {'name': 'a', 'decision': 'deny'}]}]})

    def test_order_and_security_context_drift_block_phase_comparison(self):
        report = research.phases({'schema_version': 1, 'cases': [{
            'id': 'worker-context', 'same_policy_expected': True,
            'equivalence_basis': 'same signed operation and policy',
            'required_context_fields': ['chain_id', 'epoch', 'nonce', 'state_digest',
                                        'attacker_permissions'],
            'stages': [
                {'name': 'api', 'decision': 'allow', 'policy_id': 'v1',
                 'chain_id': '1', 'epoch': '8', 'nonce': '4', 'state_digest': 's0',
                 'attacker_permissions': 'submit'},
                {'name': 'worker', 'decision': 'deny', 'policy_id': 'v1',
                 'chain_id': '1', 'epoch': '9', 'nonce': '4', 'state_digest': 's1',
                 'attacker_permissions': 'admin'},
            ]}]})
        lead = report['leads'][0]
        self.assertEqual([step['order_index'] for step in lead['stages']], [0, 1])
        self.assertFalse(lead['comparable'])
        self.assertIn('EPOCH_DRIFT', lead['signals'])
        self.assertIn('ATTACKER_PERMISSIONS_DRIFT', lead['signals'])
        self.assertIn('STATE_CONTEXT_DRIFT', lead['signals'])
        self.assertIn('EPOCH_MISMATCH', lead['comparison_blockers'])
        self.assertNotIn('admin', json.dumps(report))

    def test_expected_state_transition_is_reported_and_still_blocks_equivalence(self):
        report = research.phases({'schema_version': 1, 'cases': [{
            'id': 'stateful-flow', 'same_policy_expected': True,
            'equivalence_basis': 'same request across ordered state transition',
            'state_transition_expected': True,
            'stages': [
                {'name': 'admission', 'decision': 'allow', 'policy_id': 'v1',
                 'chain_id': '1', 'epoch': '2', 'nonce': '3', 'state_digest': 'before'},
                {'name': 'execution', 'decision': 'deny', 'policy_id': 'v1',
                 'chain_id': '1', 'epoch': '2', 'nonce': '3', 'state_digest': 'after'},
            ]}]})
        lead = report['leads'][0]
        self.assertIn('EXPECTED_STATE_TRANSITION', lead['context_observations'])
        self.assertIn('STATE_TRANSITION_CONTEXT', lead['comparison_blockers'])
        self.assertFalse(lead['comparable'])

    def test_partial_policy_context_and_duplicate_case_ids_fail_closed(self):
        result = research.phases({'schema_version': 1, 'cases': [{
            'id': 'partial', 'same_policy_expected': True, 'equivalence_basis': 'same request',
            'stages': [{'name': 'api', 'decision': 'allow', 'policy_id': 'v1'},
                       {'name': 'worker', 'decision': 'deny'}]}]})
        self.assertIn('INCOMPLETE_POLICY_CONTEXT', result['leads'][0]['comparison_blockers'])
        self.assertFalse(result['leads'][0]['comparable'])
        case = {'id': 'duplicate', 'stages': [{'name': 'a', 'decision': 'allow'},
                                               {'name': 'b', 'decision': 'deny'}]}
        with self.assertRaisesRegex(ValueError, 'unique'):
            research.phases({'schema_version': 1, 'cases': [case, case]})

    def test_missing_policy_context_blocks_comparison_even_when_all_stages_omit_it(self):
        report = research.phases({'schema_version': 1, 'cases': [{
            'id': 'missing-policy', 'same_policy_expected': True,
            'equivalence_basis': 'same request and intended policy',
            'stages': [
                {'name': 'api', 'decision': 'allow'},
                {'name': 'worker', 'decision': 'allow'},
            ]}]})
        self.assertEqual(report['candidate_count'], 0)
        self.assertEqual(report['non_comparable_count'], 1)
        self.assertIn('MISSING_POLICY_CONTEXT',
                      report['non_comparable_cases'][0]['comparison_blockers'])

    def test_incomplete_context_is_reported_even_when_decisions_match(self):
        report = research.phases({'schema_version': 1, 'cases': [{
            'id': 'missing-chain', 'same_policy_expected': True,
            'equivalence_basis': 'same request',
            'required_context_fields': ['chain_id'],
            'stages': [
                {'name': 'api', 'decision': 'allow', 'policy_id': 'v1', 'chain_id': '1'},
                {'name': 'worker', 'decision': 'allow', 'policy_id': 'v1'},
            ]}]})
        self.assertEqual(report['candidate_count'], 0)
        self.assertEqual(report['non_comparable_count'], 1)
        self.assertIn('MISSING_CHAIN_ID_CONTEXT',
                      report['non_comparable_cases'][0]['comparison_blockers'])


class SignerQuorumTests(unittest.TestCase):
    def test_duplicate_signers_are_compared_with_valid_unique_signer_control(self):
        report = research.quorum({'schema_version': 1, 'cases': [
            {'id': 'candidate', 'pair_id': 'quorum', 'role': 'candidate',
             'threshold': 2, 'authorized_signers': ['alice', 'bob'],
             'authenticated_signers': ['alice', 'alice'],
             'context': {'chain_id': '1', 'epoch': '4', 'policy_id': 'v1',
                         'attacker_permissions': 'public-relayer'}},
            {'id': 'control', 'pair_id': 'quorum', 'role': 'negative-control',
             'threshold': 2, 'authorized_signers': ['alice', 'bob'],
             'authenticated_signers': ['alice', 'bob'],
             'context': {'chain_id': '1', 'epoch': '4', 'policy_id': 'v1',
                         'attacker_permissions': 'public-relayer'}},
        ]})
        self.assertEqual(report['candidate_count'], 1)
        lead = report['leads'][0]
        self.assertEqual(lead['signal'], 'INSUFFICIENT_UNIQUE_AUTHORIZED_SIGNERS')
        self.assertEqual(lead['authenticated_signature_count'], 2)
        self.assertEqual(lead['unique_authorized_signer_count'], 1)
        self.assertEqual(len(lead['context_fingerprints']['policy_id']), 64)
        self.assertNotIn('alice', json.dumps(report))
        self.assertEqual(report['confirmed_vulnerabilities'], 0)

    def test_quorum_requires_paired_control_and_rejects_bad_threshold_or_duplicates(self):
        candidate = {'id': 'candidate', 'pair_id': 'q', 'role': 'candidate',
                     'threshold': 2, 'authorized_signers': ['alice', 'bob'],
                     'authenticated_signers': ['alice', 'alice']}
        with self.assertRaisesRegex(ValueError, 'negative-control'):
            research.quorum({'schema_version': 1, 'cases': [candidate]})
        control = {'id': 'control', 'pair_id': 'q', 'role': 'negative-control',
                   'threshold': 2, 'authorized_signers': ['alice', 'bob'],
                   'authenticated_signers': ['alice', 'bob']}
        with self.assertRaisesRegex(ValueError, 'threshold'):
            research.quorum({'schema_version': 1, 'cases': [
                dict(candidate, threshold=True), control]})
        with self.assertRaisesRegex(ValueError, 'unique'):
            research.quorum({'schema_version': 1, 'cases': [
                dict(candidate, authorized_signers=['alice', 'alice']),
                dict(control, authorized_signers=['alice', 'alice'])]})
        with self.assertRaisesRegex(ValueError, 'schema_version'):
            research.quorum({'schema_version': True, 'cases': [candidate, control]})
        with self.assertRaisesRegex(ValueError, 'same security context'):
            research.quorum({'schema_version': 1, 'cases': [
                dict(candidate, context={'policy_id': 'v1'}),
                dict(control, context={'policy_id': 'v2'})]})


class ByteTupleTests(unittest.TestCase):
    def test_real_byte_collision_and_length_framed_negative_control(self):
        result = research.byte_tuple({'schema_version': 1, 'pairs': [
            {'id': 'ambiguous', 'left_fields': ['0x61', '0x6263'],
             'right_fields': ['0x6162', '0x63']},
            {'id': 'separate', 'left_fields': ['0x61', '0x6263'],
             'right_fields': ['0x61', '0x6264']},
        ]})
        self.assertEqual(result['mode'], 'byte-tuple')
        self.assertEqual(result['candidate_count'], 1)
        self.assertEqual(result['non_collision_pairs'], 1)
        hit = result['leads'][0]
        self.assertEqual(hit['signal'], 'UNFRAMED_TUPLE_COLLISION')
        self.assertEqual(hit['framed_negative_control'], 'DISTINCT')
        self.assertNotEqual(hit['framed_sha256'][0], hit['framed_sha256'][1])
        self.assertEqual(result['confirmed_vulnerabilities'], 0)

    def test_single_field_odd_length_and_many_fields_rejected(self):
        for left in (['0x61'], ['0x6'], ['0x00'] * 17):
            with self.subTest(fields=left):
                with self.assertRaises(ValueError):
                    research.byte_tuple({'schema_version': 1, 'pairs': [
                        {'id': 'bad', 'left_fields': left,
                         'right_fields': ['0x62', '0x63']} ]})

    def test_cli_byte_tuple_writes_no_raw_field_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / 'pair.json'
            file.write_text(json.dumps({'schema_version': 1, 'pairs': [
                {'id': 'collision', 'left_fields': ['0x61', '0x6263'],
                 'right_fields': ['0x6162', '0x63']}]}))
            result = subprocess.run([
                'python3', str(SCRIPTS / 'bounty.py'), 'research-diff',
                'byte-tuple', '--input', str(file)
            ], capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            self.assertEqual(data['candidate_count'], 1)
            self.assertNotIn('0x6162', result.stdout)


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
        self.assertTrue(any(x['signal'] == 'packed_dynamic' for x in result['leads']))
        self.assertEqual(result['confirmed_vulnerabilities'], 0)
        self.assertTrue(all(x['classification'] == 'LEXICAL_LEAD'
                            for x in result['leads']))

    def test_scan_scope_is_required(self):
        with self.assertRaisesRegex(ValueError, 'scope'):
            research.source_scan(self.repo, None)
        with self.assertRaisesRegex(ValueError, 'scope'):
            research.source_scan(self.repo, ['../other'])

    def test_scan_caps_only_after_scope_filter_and_discloses_empty_scope(self):
        # A leading out-of-scope file must not consume the entire scan budget.
        (self.repo / 'aardvark.py').write_text('print(1)\n')
        scoped = self.repo / 'src' / 'proof.sol'
        scoped.parent.mkdir(parents=True, exist_ok=True)
        scoped.write_text('contract P { bytes32 a = keccak256(abi.encodePacked(x, y)); }\n')
        subprocess.run(['git', '-C', str(self.repo), 'add', '-A'], check=True)
        original = research.MAX_SOURCE_FILES
        try:
            research.MAX_SOURCE_FILES = 1
            report = research.source_scan(self.repo, ['src'])
            self.assertEqual(report['in_scope_tracked_files'], 1)
            self.assertEqual(report['scanned_files'], 1)
            self.assertEqual(report['files_over_cap'], 0)
            self.assertGreaterEqual(report['candidate_count'], 1)
        finally:
            research.MAX_SOURCE_FILES = original
        absent = research.source_scan(self.repo, ['missing'])
        self.assertEqual(absent['scanned_files'], 0)
        self.assertTrue(any('not a clean scan' in note for note in absent['notes']))

    def test_scan_skips_symlinks_oversized_files_and_preserves_unicode_paths(self):
        external = self.root / 'external.py'
        external.write_text('keccak256(abi.encodePacked(a, b))\n', encoding='utf-8')
        source = self.repo / 'src' / 'проверка.py'
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text('keccak256(abi.encodePacked(a, b))\n', encoding='utf-8')
        oversized = self.repo / 'src' / 'large.py'
        oversized.write_bytes(b'x' * (research.MAX_SOURCE_BYTES + 1))
        link = self.repo / 'src' / 'link.py'
        link.symlink_to(external)
        subprocess.run(['git', '-C', str(self.repo), 'add', '-A'], check=True)
        result = research.source_scan(self.repo, ['src'])
        self.assertTrue(any(lead['path'] == 'src/проверка.py' for lead in result['leads']))
        self.assertEqual(result['skipped']['oversized'], 1)
        self.assertEqual(result['skipped']['unreadable'], 1)
        self.assertFalse(any(lead['path'] == 'src/link.py' for lead in result['leads']))

    def test_json_reader_rejects_duplicate_keys_symlinks_and_oversize(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            duplicate = root / 'duplicate.json'
            duplicate.write_text('{"schema_version":1,"schema_version":1,"pairs":[]}',
                                 encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'duplicate object key'):
                research._json(duplicate)
            target = root / 'target.json'
            target.write_text('{"schema_version":1,"pairs":[]}', encoding='utf-8')
            link = root / 'link.json'
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'non-symlink'):
                research._json(link)
            oversized = root / 'oversized.json'
            oversized.write_bytes(b' ' * 2_000_001)
            with self.assertRaisesRegex(ValueError, 'under 2 MB'):
                research._json(oversized)
            malformed = root / 'malformed.json'
            malformed.write_text('{broken', encoding='utf-8')
            with self.assertRaises(json.JSONDecodeError):
                research._json(malformed)

    def test_direct_clis_output_json(self):
        inp = self.root / 'input.json'
        inp.write_text(json.dumps({'schema_version': 1, 'pairs': []}))
        command = ['python3', str(SCRIPTS / 'research_diff.py'), 'identity',
                   '--input', str(inp)]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)['candidate_count'], 0)
        command = ['python3', str(SCRIPTS / 'caseforge.py'), 'validate']
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)['total_cases'], 10)

    def test_bounty_cli_registration(self):
        result = subprocess.run(['python3', str(SCRIPTS / 'bounty.py'), 'caseforge',
                                 'validate'], capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)['total_cases'], 10)
        result = subprocess.run(['python3', str(SCRIPTS / 'bounty.py'), 'research-diff',
                                 'scan', '--repo', str(self.repo), '--scope', 'src'],
                                capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)['mode'], 'source-scan')
        quorum = {'schema_version': 1, 'cases': [
            {'id': 'candidate', 'pair_id': 'q', 'role': 'candidate', 'threshold': 2,
             'authorized_signers': ['a', 'b'], 'authenticated_signers': ['a', 'a']},
            {'id': 'control', 'pair_id': 'q', 'role': 'negative-control', 'threshold': 2,
             'authorized_signers': ['a', 'b'], 'authenticated_signers': ['a', 'b']}]}
        input_path = self.root / 'quorum.json'
        input_path.write_text(json.dumps(quorum), encoding='utf-8')
        result = subprocess.run(['python3', str(SCRIPTS / 'bounty.py'), 'research-diff',
                                 'quorum', '--input', str(input_path)],
                                capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)['mode'], 'signer-quorum')


class ScanVocabularyTests(unittest.TestCase):
    """A zero from the scan is only as good as the vocabulary behind it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)

    def write(self, name, text):
        (self.repo / 'src' / name).write_text(text, encoding='utf-8')
        subprocess.run(['git', '-C', str(self.repo), 'add', '-A'], check=True)

    def signals(self, cues=None):
        report = research.source_scan(self.repo, ['src'], cues)
        return {lead['signal'] for lead in report['leads']}, report

    def test_identifier_shapes_a_word_cue_cannot_reach(self):
        # Each line is a real spelling that the word-only cue set missed: the
        # multi-word camelCase mirror, a cue inside a longer snake_case name, a
        # Go/Rust length call, and the no-prefix ABI helper.
        self.write('shapes.go', 'func validateBlock() {}\n'
                                'func build_cache_key() {}\n'
                                'var n = signatures.len()\n'
                                'var h = encodePacked(a, b)\n')
        signals, _ = self.signals()
        self.assertEqual(signals, {'phase_boundary', 'cache_context', 'signature_quorum',
                                   'packed_dynamic'})

    def test_key_builder_shape_is_its_own_kind(self):
        # The exact construct that read as clean on a Go relay checkout.
        self.write('redis.go', 'func keyCacheGetHeaderResponse(slot uint64) string {\n'
                               '\treturn prefixGetHeaderResponse + itoa(slot)\n}\n')
        signals, report = self.signals()
        self.assertEqual(signals, {'cache_key_builder'})
        self.assertIn('cache_key_builder', report['default_cue_kinds'])

    def test_single_word_camel_case_still_matches(self):
        # (?i) already bridged these; the fix must not regress them.
        self.write('words.ts', 'const cacheKey = 1; const memPool = 2;\n')
        signals, _ = self.signals()
        self.assertEqual(signals, {'cache_context', 'phase_boundary'})

    def test_project_vocabulary_is_silent_by_default_and_fires_with_cue(self):
        # The paired assertion: one module, scanned twice. What a project calls
        # its own cache identity is per project, and no default can know it.
        self.write('house.rs', 'fn bucket_fingerprint_for(slot: u64) -> String { snapshot_tag(slot) }\n')
        default_signals, default_report = self.signals()
        self.assertEqual(default_signals, set())
        self.assertEqual(default_report['candidate_count'], 0)
        self.assertEqual(default_report['custom_cues'], 0)
        self.assertTrue(any('only covers the cue kinds' in note
                            for note in default_report['notes']),
                        'a zero must disclose the vocabulary that produced it')

        cued_signals, cued_report = self.signals(
            ['cache_context=bucket_fingerprint|snapshot_tag'])
        self.assertEqual(cued_signals, {'cache_context'})
        self.assertEqual(cued_report['custom_cues'], 1)
        self.assertTrue(all(lead['classification'] == 'LEXICAL_LEAD'
                            for lead in cued_report['leads']))
        self.assertEqual(cued_report['confirmed_vulnerabilities'], 0)

    def test_custom_cue_may_declare_a_new_kind(self):
        self.write('house.go', 'func settleWithdrawalBatch() {}\n')
        signals, report = self.signals(['settlement_boundary=settleWithdrawal\\w*'])
        self.assertIn('settlement_boundary', signals)
        self.assertIn('settlement_boundary', report['cue_kinds'])
        self.assertNotIn('settlement_boundary', report['default_cue_kinds'])

    def test_bad_cues_fail_closed(self):
        self.write('x.go', 'package x\n')
        for bad, message in (
                (['cache_context'], 'kind=regex'),
                (['Cache=abc'], 'lowercase slug'),
                (['cache_context='], '1\\.\\.'),
                (['cache_context=(unclosed'], 'does not compile'),
                (['cache_context=a', 'cache_context=a'], 'duplicate'),
                (['cache_context=a'] * (research.MAX_CUSTOM_CUES + 1), 'at most'),
                ('cache_context=a', 'repeatable')):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(ValueError, message):
                    research.source_scan(self.repo, ['src'], bad)

    def test_cli_passes_cues_and_refuses_them_off_scan(self):
        self.write('house.rs', 'fn snapshot_tag() {}\n')
        result = subprocess.run(
            ['python3', str(SCRIPTS / 'bounty.py'), 'research-diff', 'scan',
             '--repo', str(self.repo), '--scope', 'src',
             '--cue', 'cache_context=snapshot_tag'],
            capture_output=True, text=True, check=True)
        report = json.loads(result.stdout)
        self.assertEqual(report['custom_cues'], 1)
        self.assertEqual(report['candidate_count'], 1)

        observations = self.root / 'obs.json'
        observations.write_text(json.dumps({'schema_version': 1, 'pairs': []}),
                                encoding='utf-8')
        rejected = subprocess.run(
            ['python3', str(SCRIPTS / 'bounty.py'), 'research-diff', 'identity',
             '--input', str(observations), '--cue', 'cache_context=a'],
            capture_output=True, text=True)
        self.assertNotEqual(rejected.returncode, 0)


if __name__ == '__main__':
    unittest.main()
