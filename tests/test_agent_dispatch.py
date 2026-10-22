"""Provider-neutral independent agent dispatch, persistence, and cost-accounting tests."""

import importlib.util
import json
import os
import socket
import subprocess
import sys
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

    def test_zcode_app_cli_is_staged_with_its_bundled_provider_config(self):
        app = self.base / 'ZCode.app' / 'Contents' / 'Resources'
        binary = app / 'glm' / 'zcode.cjs'
        binary.parent.mkdir(parents=True)
        binary.write_text('#!/usr/bin/env node\nprocess.exit(0);\n', encoding='utf-8')
        binary.chmod(0o755)
        config = app / 'config' / 'provider' / 'zcode-builtin.json'
        config.parent.mkdir(parents=True)
        config.write_text('{"fixture":true}\n', encoding='utf-8')
        attempt = self.run / 'agents' / 'zcode-attempt'
        staged = Path(dispatch._stage_zcode_cli(str(binary), attempt))
        expected_config = (attempt / 'zcode-cli-runtime' / 'config' / 'provider' /
                           'zcode-builtin.json')
        self.assertNotEqual(staged, binary)
        self.assertEqual(staged.read_text(encoding='utf-8'), binary.read_text(encoding='utf-8'))
        self.assertEqual(staged.stat().st_mode & 0o777, 0o500)
        self.assertEqual(expected_config.read_text(encoding='utf-8'),
                         config.read_text(encoding='utf-8'))
        self.assertEqual(expected_config.stat().st_mode & 0o777, 0o400)
        self.assertEqual(binary.stat().st_mode & 0o777, 0o755)

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

    def test_submission_gate_blocks_any_incomplete_agent_plan(self):
        dispatch.plan(self.run, 'diverse-strategy', ['accounting', 'liveness'])
        errors = []
        bounty._check_dispatch(self.run, errors)
        self.assertTrue(any('agents/dispatch.json' in error and 'state=\'incomplete\'' in error
                            for error in errors), errors)

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

    def test_evidence_review_job_is_bound_to_producer_and_reviewer_invocations(self):
        planned = dispatch.plan(self.run, 'diverse-strategy', ['accounting', 'liveness'])
        producer = planned['jobs'][0]
        reviewer = planned['jobs'][1]
        producer_result = dispatch.run_job(self.run, producer['job_id'], 'codex',
                                           binary=str(self.fake_cli), timeout=30)
        self.assertEqual(producer_result['status'], 'completed')
        evidence_context = self.run / 'review-evidence.md'
        evidence_context.write_text('candidate and control logs are attached here', encoding='utf-8')
        reviewer_cli = self.base / 'reviewer-agent'
        reviewer_cli.write_text('''#!/usr/bin/env python3
import json, sys
prompt = sys.argv[-1]
def receipt(name):
    lines = prompt.splitlines()
    return json.loads(lines[lines.index(name) + 1])
producer = receipt("Producer invocation receipt:")
reviewer = receipt("Reviewer invocation receipt:")
body = {"schema": 1, "producer_id": producer["job_id"],
        "reviewer_id": reviewer["job_id"], "independent": True,
        "session_bindings": {"producer": producer, "reviewer": reviewer}}
print(json.dumps({"type":"thread.started","thread_id":"review-session"}))
print(json.dumps({"type":"item.completed","item":{"type":"agent_message",
      "text":json.dumps(body)}}))
print(json.dumps({"type":"turn.completed"}))
''', encoding='utf-8')
        reviewer_cli.chmod(0o755)
        reviewed = dispatch.run_job(self.run, reviewer['job_id'], 'codex',
                                    binary=str(reviewer_cli), timeout=30,
                                    evidence_review=True, producer_job_id=producer['job_id'],
                                    evidence_context='review-evidence.md')
        self.assertEqual(reviewed['status'], 'completed')
        review_path = Path(reviewed['result_file'])
        self.assertEqual(review_path.name, 'review-output.json')
        self.assertNotIn('readings', review_path.parts)
        job_workspace = review_path.parent / 'workspace'
        context = (job_workspace / 'review-context.md').read_text(encoding='utf-8')
        self.assertIn('CANDIDATE | lens: accounting', context)
        self.assertIn('candidate and control logs are attached here', context)
        self.assertEqual((job_workspace / 'review-context.md').stat().st_mode & 0o777, 0o400)

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
        self.assertEqual(report['state'], 'independence_conflict')
        self.assertEqual(len(report['independence_conflicts']), 1)

    def test_missing_session_ids_get_a_separate_unverified_independence_state(self):
        planned = dispatch.plan(self.run, 'independent-blind', ['accounting'], replicas=2)
        no_session = self.base / 'no-session-agent'
        source = ('#!/usr/bin/env python3\nimport json\n'
                  'print(json.dumps({"type":"item.completed","item":{"type":"agent_message",'
                  '"text":' + repr(READING) + '}}))\n'
                  'print(json.dumps({"type":"turn.completed"}))\n')
        no_session.write_text(source, encoding='utf-8')
        no_session.chmod(0o755)
        for job in planned['jobs']:
            self.assertEqual(dispatch.run_job(self.run, job['job_id'], 'codex',
                                              binary=str(no_session), timeout=30)['status'],
                             'completed')
        report = dispatch.review(self.run)
        self.assertEqual(report['state'], 'independence_unverified')
        self.assertEqual(report['independence_status'], 'independence_unverified')
        self.assertEqual(set(report['independence_unverified_jobs']),
                         {job['job_id'] for job in planned['jobs']})

    def test_nonzero_agent_output_is_a_draft_and_never_enters_readings(self):
        planned = dispatch.plan(self.run, 'diverse-strategy', ['accounting', 'liveness'])
        failed = self.base / 'failed-with-reading'
        source = ('#!/usr/bin/env python3\nimport json\n'
                  'print(json.dumps({"type":"thread.started","thread_id":"s"}))\n'
                  'print(json.dumps({"type":"item.completed","item":{"type":"agent_message",'
                  '"text":' + repr(READING) + '}}))\n'
                  'print(json.dumps({"type":"turn.completed"}))\nraise SystemExit(9)\n')
        failed.write_text(source, encoding='utf-8')
        failed.chmod(0o755)
        result = dispatch.run_job(self.run, planned['jobs'][0]['job_id'], 'codex',
                                  binary=str(failed), timeout=30)
        self.assertEqual(result['status'], 'failed')
        self.assertIsNone(result['result_file'])
        self.assertTrue(Path(result['draft_result_file']).is_file())
        self.assertFalse((self.run / 'readings').exists())

    def test_recovery_marks_dead_runner_retryable_without_promoting_partial_output(self):
        planned = dispatch.plan(self.run, 'diverse-strategy', ['accounting', 'liveness'])
        job = planned['jobs'][0]
        state_path = self.run / dispatch.STATE_REL
        state = json.loads(state_path.read_text(encoding='utf-8'))
        state['jobs'][job['job_id']].update({'status': 'running', 'attempts': [{
            'number': 1, 'invocation_id': 'crashed-invocation', 'status': 'running',
            'runner_pid': 2_000_000_000, 'runner_host': socket.gethostname(), 'child_pid': None,
        }]})
        state_path.write_text(json.dumps(state), encoding='utf-8')
        result = dispatch.recover(self.run)
        self.assertEqual(result['recovered'], [job['job_id']])
        recovered = json.loads(state_path.read_text(encoding='utf-8'))['jobs'][job['job_id']]
        self.assertEqual(recovered['status'], 'failed')
        self.assertEqual(recovered['attempts'][0]['failure_reason'],
                         'dispatcher-process-interrupted')
        self.assertEqual(dispatch.retry_job(self.run, job['job_id'])['status'], 'queued')
        self.assertFalse((self.run / 'readings').exists())

    def test_review_recovers_committed_reading_after_publish_crash(self):
        planned = dispatch.plan(self.run, 'diverse-strategy', ['accounting', 'liveness'])
        job = planned['jobs'][0]
        run = self.run.resolve()
        invocation = 'committed-before-publish'
        header = ('<!-- BP_AGENT_RESULT v1 job=' + job['job_id'] + ' attempt=1 invocation=' +
                  invocation + ' bundle_sha256=' + job['bundle_sha256'] + ' -->\n')
        reading = header + READING
        pending = run / 'agents' / job['job_id'] / 'attempt-01' / 'reading.pending'
        pending.parent.mkdir(parents=True)
        pending.write_text(reading, encoding='utf-8')
        target = run / 'readings' / (job['lens'] + '-' + job['job_id'] + '-attempt-1.md')
        state_path = run / dispatch.STATE_REL
        state = json.loads(state_path.read_text(encoding='utf-8'))
        recorded = state['jobs'][job['job_id']]
        recorded.update({
            'status': 'completed',
            'attempts': [{'number': 1, 'invocation_id': invocation, 'provider': 'codex',
                          'provider_session_id': 'saved-session', 'status': 'completed',
                          'fresh_process': True, 'resume_requested': False}],
            'latest_result': {'reading_file': str(target), 'pending_reading_file': str(pending),
                              'reading_sha256': dispatch._sha256(reading.encode()),
                              'bundle_sha256': job['bundle_sha256'], 'attempt': 1,
                              'invocation_id': invocation},
        })
        dispatch._atomic_json(state_path, state)

        dispatch.review(self.run)

        repaired = json.loads(state_path.read_text(encoding='utf-8'))['jobs'][job['job_id']]
        self.assertEqual(repaired['status'], 'completed')
        self.assertTrue(target.is_file())
        self.assertEqual(target.read_text(encoding='utf-8'), reading)
        self.assertFalse(pending.exists())
        self.assertNotIn('pending_reading_file', repaired['latest_result'])

    def test_orphaned_provider_process_blocks_retry_until_it_exits(self):
        planned = dispatch.plan(self.run, 'diverse-strategy', ['accounting', 'liveness'])
        job = planned['jobs'][0]
        state_path = self.run / dispatch.STATE_REL
        state = json.loads(state_path.read_text(encoding='utf-8'))
        state['jobs'][job['job_id']].update({'status': 'running', 'attempts': [{
            'number': 1, 'invocation_id': 'orphaned-invocation', 'status': 'running',
            'runner_pid': 2_000_000_000, 'runner_host': socket.gethostname(), 'child_pid': os.getpid(),
        }]})
        state_path.write_text(json.dumps(state), encoding='utf-8')
        self.assertEqual(dispatch.recover(self.run)['orphaned_provider_processes'],
                         [{'job_id': job['job_id'], 'pid': os.getpid()}])
        with self.assertRaisesRegex(ValueError, 'orphaned provider process is still running'):
            dispatch.retry_job(self.run, job['job_id'])

    def test_concurrent_plan_and_four_job_processes_preserve_every_update(self):
        script = ('import sys,time\n'
                  'sys.path.insert(0, sys.argv[1])\n'
                  'import agent_dispatch as d\n'
                  'original = d._load_state\n'
                  'def slow_load(*args, **kwargs):\n'
                  '    state = original(*args, **kwargs)\n'
                  '    time.sleep(0.2)\n'
                  '    return state\n'
                  'd._load_state = slow_load\n'
                  'd.plan(sys.argv[2], "diverse-strategy", ["accounting", "liveness"])\n')
        planners = [subprocess.Popen([sys.executable, '-c', script, str(SCRIPTS), str(self.run)],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    for _ in range(2)]
        for process in planners:
            stdout, stderr = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 0, stdout + stderr)
        state_path = self.run / dispatch.STATE_REL
        state = json.loads(state_path.read_text(encoding='utf-8'))
        self.assertEqual(len(state['plans']), 2)
        jobs = list(state['jobs'].values())
        self.assertEqual(len(jobs), 4)

        slow_cli = self.base / 'slow-agent'
        body = FAKE_CLI.replace('import json, os, pathlib, sys',
                                'import json, os, pathlib, sys, time')
        body = body.replace("provider = os.environ['BPT_DISPATCH_PROVIDER']",
                            "time.sleep(0.2)\nprovider = os.environ['BPT_DISPATCH_PROVIDER']")
        slow_cli.write_text(body, encoding='utf-8')
        slow_cli.chmod(0o755)
        processes = [subprocess.Popen([sys.executable, str(SCRIPTS / 'agent_dispatch.py'), 'run',
                                       '--run', str(self.run), '--job-id', job['job_id'],
                                       '--provider', 'codex', '--binary', str(slow_cli),
                                       '--timeout', '30'], stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True) for job in jobs]
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 0, stdout + stderr)
            self.assertEqual(json.loads(stdout)['status'], 'completed')
        state = json.loads(state_path.read_text(encoding='utf-8'))
        self.assertEqual(len(state['jobs']), 4)
        self.assertTrue(all(job['status'] == 'completed' for job in state['jobs'].values()))
        self.assertEqual(dispatch.review(self.run)['state'], 'complete')

    def test_lock_is_released_by_operating_system_after_process_crash(self):
        script = ('import sys,time\n'
                  'sys.path.insert(0, sys.argv[1])\n'
                  'import agent_dispatch as d\n'
                  'from pathlib import Path\n'
                  'with d._state_lock(Path(sys.argv[2])):\n'
                  '    print("locked", flush=True)\n'
                  '    time.sleep(20)\n')
        process = subprocess.Popen([sys.executable, '-c', script, str(SCRIPTS), str(self.run)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(process.stdout.readline().strip(), 'locked')
        process.kill()
        process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()
        plan = dispatch.plan(self.run, 'diverse-strategy', ['accounting', 'liveness'])
        self.assertEqual(len(plan['jobs']), 2)

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
