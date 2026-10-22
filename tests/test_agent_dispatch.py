"""Provider-neutral independent agent dispatch, persistence, and cost-accounting tests."""

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/bounty-pilot/scripts'
if str(SCRIPTS) not in os.sys.path:
    os.sys.path.insert(0, str(SCRIPTS))
import bounty


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dispatch = load('agent_dispatch_tests', 'skills/bounty-pilot/scripts/agent_dispatch.py')


READING = '''CANDIDATE | lens: accounting | surface: src/Vault.sol:Vault.withdraw | bug_class: stale-debt
mechanism: `withdraw` transfers the amount before reducing debt, so a callback reads the old debt.
capability: A depositor can invoke withdraw.
path: withdraw -> transfer callback -> stale debt is reused.
breaks: A debt value must not be reusable after a withdrawal.
next_experiment:
  question: Can the callback reach the second debt read?
  method: run a local paired test against the pinned source.
  expected_evidence: candidate reuses debt and negative control cannot.

EXAMINED | src/Vault.sol:Vault.withdraw
'''


FAKE_CLI = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
provider = os.environ['BPT_DISPATCH_PROVIDER']
job = pathlib.Path.cwd().parents[1].name
reading = ''' + repr(READING) + r'''
if provider == 'claude':
    print(json.dumps({'result': reading, 'session_id': 'session-' + job,
                      'total_cost_usd': 0.0125,
                      'usage': {'input_tokens': 1200, 'output_tokens': 90}}))
elif provider == 'codex':
    print(json.dumps({'type': 'thread.started', 'thread_id': 'session-' + job}))
    print(json.dumps({'type': 'item.completed', 'item': {'type': 'agent_message', 'text': reading}}))
    print(json.dumps({'type': 'turn.completed', 'usage': {'input_tokens': 1200, 'output_tokens': 90}}))
elif provider == 'zcode':
    print(json.dumps({'type': 'result', 'sessionId': 'session-' + job, 'response': reading}))
else:
    print(json.dumps({'type': 'session.created', 'sessionID': 'session-' + job}))
    print(json.dumps({'type': 'text', 'part': {'text': reading}}))
'''


class AgentDispatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        (self.repo / 'src/Vault.sol').write_text(
            'contract Vault { function withdraw(uint256 amount) external {} }\n', encoding='utf-8')
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'add', '-A'], check=True)
        subprocess.run(['git', '-C', str(self.repo), '-c', 'user.name=Test', '-c',
                        'user.email=test@example.invalid', 'commit', '-qm', 'fixture'], check=True)
        self.run = self.base / 'private-run'
        bounty.initialize(self.repo, self.run)
        bounty.bundle(self.repo, self.run, ['accounting', 'liveness'])
        self.fake_cli = self.base / 'fake-agent'
        self.fake_cli.write_text(FAKE_CLI, encoding='utf-8')
        self.fake_cli.chmod(0o755)

    def test_provider_logs_reuse_broad_secret_redaction(self):
        private_key = '0x' + 'ab' * 32
        rpc = 'https://eth-mainnet.g.alchemy.com/v2/Kx7SECRETKEY9012345678901234'
        output = dispatch._scrub('{"private_key": "' + private_key + '", "rpc": "' + rpc + '"}')
        self.assertNotIn(private_key, output)
        self.assertNotIn('Kx7SECRETKEY9012345678901234', output)

    def test_blind_plan_creates_same_input_with_distinct_jobs_and_no_execution(self):
        result = dispatch.plan(self.run, 'independent-blind', ['accounting'], replicas=3)
        jobs = result['jobs']
        self.assertEqual(len(jobs), 3)
        self.assertEqual({job['bundle_sha256'] for job in jobs}, {jobs[0]['bundle_sha256']})
        self.assertEqual(len({job['job_id'] for job in jobs}), 3)
        self.assertTrue(all(job['status'] == 'queued' for job in jobs))
        self.assertFalse(any(job['attempts'] for job in jobs))

    def test_plan_job_limit_bounds_provider_spend(self):
        bundle = self.run / 'bundles/accounting-bundle.md'
        digest = bounty._sha256_file(bundle)
        rows = [{'lens': f'lens-{index}', 'bundle': 'bundles/accounting-bundle.md',
                 'sha256': digest, 'source_commit': 'a' * 40} for index in range(4)]
        with mock.patch.object(dispatch, '_latest_bundles', return_value=rows):
            with self.assertRaisesRegex(ValueError, 'at most 24 jobs'):
                dispatch.plan(self.run, 'independent-blind', replicas=8)

    def test_diverse_plan_needs_distinct_lens_bundles(self):
        with self.assertRaisesRegex(ValueError, 'at least two'):
            dispatch.plan(self.run, 'diverse-strategy', ['accounting'])
        result = dispatch.plan(self.run, 'diverse-strategy', ['accounting', 'liveness'])
        self.assertEqual({job['lens'] for job in result['jobs']}, {'accounting', 'liveness'})
        self.assertTrue(all(job['replica'] == 1 for job in result['jobs']))

    def test_all_four_cli_adapters_save_isolated_results_logs_cost_and_usage(self):
        planned = dispatch.plan(self.run, 'independent-blind', ['accounting'], replicas=4)
        providers = ('opencode', 'zcode', 'claude', 'codex')
        for provider, job in zip(providers, planned['jobs']):
            result = dispatch.run_job(self.run, job['job_id'], provider,
                                      binary=str(self.fake_cli), timeout=30,
                                      max_budget_usd=0.25 if provider == 'claude' else None)
            self.assertEqual(result['status'], 'completed')
            self.assertTrue(Path(result['result_file']).is_file())
            self.assertTrue(result['isolation']['fresh_process'])
            self.assertFalse(result['isolation']['resume_requested'])
            self.assertTrue(result['isolation']['provider_session_id'].startswith('session-'))
            attempt = (self.run / 'agents' / job['job_id'] / 'attempt-01')
            self.assertTrue((attempt / 'stdout.log').is_file())
            self.assertTrue((attempt / 'stderr.log').is_file())
            self.assertEqual((attempt / 'workspace/bundle.md').stat().st_mode & 0o777, 0o400)
        report = dispatch.review(self.run)
        self.assertEqual(report['state'], 'complete')
        self.assertEqual(report['known_reported_cost_usd'], 0.0125)
        self.assertEqual(report['cost_attempt_coverage'], '1/4')
        plan_row = report['plans'][0]
        self.assertEqual(plan_row['distinct_mechanism_count'], 1)
        self.assertTrue(all(value == 0 for value in plan_row['unique_agent_mechanisms'].values()))

    def test_reused_provider_session_is_reported_as_independence_conflict(self):
        planned = dispatch.plan(self.run, 'independent-blind', ['accounting'], replicas=2)
        for job in planned['jobs']:
            result = dispatch.run_job(self.run, job['job_id'], 'codex',
                                      binary=str(self.fake_cli), timeout=30)
            self.assertEqual(result['status'], 'completed')
        state_path = self.run / dispatch.STATE_REL
        state = json.loads(state_path.read_text(encoding='utf-8'))
        ids = state['plans'][0]['job_ids']
        state['jobs'][ids[1]]['attempts'][0]['provider_session_id'] = \
            state['jobs'][ids[0]]['attempts'][0]['provider_session_id']
        state_path.write_text(json.dumps(state), encoding='utf-8')
        report = dispatch.review(self.run)
        self.assertEqual(report['state'], 'incomplete')
        self.assertEqual(len(report['independence_conflicts']), 1)

    def test_failed_attempt_can_be_retried_without_deleting_prior_logs(self):
        planned = dispatch.plan(self.run, 'diverse-strategy', ['accounting', 'liveness'])
        job = planned['jobs'][0]
        broken = self.base / 'broken-agent'
        broken.write_text('#!/bin/sh\necho unavailable >&2\nexit 8\n', encoding='utf-8')
        broken.chmod(0o755)
        result = dispatch.run_job(self.run, job['job_id'], 'codex', binary=str(broken), timeout=30)
        self.assertEqual(result['status'], 'failed')
        first_log = self.run / 'agents' / job['job_id'] / 'attempt-01/stderr.log'
        self.assertIn('unavailable', first_log.read_text(encoding='utf-8'))
        self.assertEqual(dispatch.retry_job(self.run, job['job_id'])['next_attempt'], 2)
        retried = dispatch.run_job(self.run, job['job_id'], 'codex',
                                   binary=str(self.fake_cli), timeout=30)
        self.assertEqual(retried['status'], 'completed')
        self.assertTrue(first_log.is_file())
        self.assertTrue((self.run / 'agents' / job['job_id'] / 'attempt-02/stdout.log').is_file())

    def test_missing_provider_cost_is_unknown_and_not_a_zero_cost_claim(self):
        planned = dispatch.plan(self.run, 'diverse-strategy', ['accounting', 'liveness'])
        dispatch.run_job(self.run, planned['jobs'][0]['job_id'], 'codex',
                         binary=str(self.fake_cli), timeout=30)
        report = dispatch.review(self.run)
        self.assertEqual(report['cost_attempt_coverage'], '0/1')
        self.assertEqual(report['cost_job_coverage'], '0/2')
        self.assertEqual(report['known_reported_cost_usd'], 0)
        self.assertIn('unknown', report['notice'])


if __name__ == '__main__':
    unittest.main()
