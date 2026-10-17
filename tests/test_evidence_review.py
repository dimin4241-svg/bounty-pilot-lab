"""Regressions from an independent review of the 0.19.0 evidence gates (stdlib only).

Each case is a corner a hunting agent - or a tired human - could cut, reproduced against the
released gates and closed here, or a correct submission the gates used to refuse. None of them
claims the gates stop a deliberate forgery of files in the hunter's own private run: they do
not, and the messages say so. Tool output below is copied from real runs (forge 1.5.1, cargo
1.97, go, pytest 8, mocha 10, Vyper 0.4.0), not remembered.
"""
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# One instance of each helper, shared with the hardening fixture this file builds on.
hardening = load('bp_review_hardening', 'tests/test_evidence_hardening.py')
bounty, gate, runner = hardening.bounty, hardening.gate, hardening.runner
FakeNode, git, commit = hardening.FakeNode, hardening.git, hardening.commit

# Vyper 0.4.0, `vyper -f bytecode,bytecode_runtime` of a contract with one immutable address.
VYPER_INIT = (
    '0x607b51503461001c5733607b5261007b61002060003961009b6000f35b5f80fd5f3560e01c600260038206'
    '60011b61007501601e395f51565b633f81a2c0811861006d57602436103417610071576004355f55005b6311'
    '7803e3811861006d573461007157602061007b60403960206040f35b63e582dd31811861006d573461007157'
    '5f5460405260206040f35b5f5ffd5b5f80fd00180034005284187b81061820a1657679706572830004000014')
VYPER_RUNTIME = (
    '0x5f3560e01c60026003820660011b61007501601e395f51565b633f81a2c0811861006d5760243610341761'
    '0071576004355f55005b63117803e3811861006d573461007157602061007b60403960206040f35b63e582dd'
    '31811861006d5734610071575f5460405260206040f35b5f5ffd5b5f80fd001800340052')
# What anvil returned for that contract deployed by its first account: the runtime, then the
# 32-byte immutable Vyper writes after it. The address holds an 0xf4 byte.
VYPER_ONCHAIN = VYPER_RUNTIME + '000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266'


def digest(record):
    body = {key: value for key, value in record.items() if key != 'record_sha256'}
    payload = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


class ReviewCase(hardening.SubmissionCase):
    def check(self, rows):
        return self.gates(rows)

    def evidence(self, row):
        return self.run / row['deployment_evidence'][0]


# --------------------------------------------------------------------------- #
# 1. deployment evidence is about a build of the target, at an address the program lists
# --------------------------------------------------------------------------- #

class DeploymentBindingTests(ReviewCase):
    def forged(self, artifact, code=None):
        """A deployments/ file written by hand with the digest recomputed: deliberate forgery."""
        address = '0x' + 'ab' * 20
        record = {'address': address, 'tool': bounty.DEPLOYMENT_TOOL, 'chain_id': 1,
                  'block': 21000000, 'deployment_status': 'exact',
                  'comparison': {'status': 'exact'},
                  'artifact': {'path': str(artifact), 'sha256': bounty._sha256_file(artifact)}}
        if code is not None:
            raw = bytes.fromhex(code[2:])
            record['compared_code'] = {'hex': code, 'bytes': len(raw),
                                       'keccak256': hardening.keccak.keccak_hex(raw)}
        record['record_sha256'] = digest(record)
        (self.run / 'deployments' / (address + '.json')).write_text(json.dumps(record))
        return 'deployments/' + address + '.json'

    def test_a_forged_record_needs_a_real_build_and_matching_stored_code(self):
        row = self.record()
        outside = self.base / 'hostname.txt'
        outside.write_text('not a build\n')
        row['deployment_evidence'] = [self.forged(outside)]
        self.assertTrue(any('is not inside the target checkout' in e for e in self.check([row])))
        build = self.repo / 'out' / 'Vault.json'
        build.write_text(json.dumps({'deployedBytecode': {'object': '0x6001600055'}}))
        row['deployment_evidence'] = [self.forged(build)]
        self.assertTrue(any('stores no compared runtime code' in e for e in self.check([row])))
        row['deployment_evidence'] = [self.forged(build, code='0x6002600055')]
        self.assertTrue(any('rerunning the comparison' in e and 'not exact' in e
                            for e in self.check([row])))
        # Consistent stored code and build still pass: what is left is deliberate forgery,
        # which the message does not pretend to catch.
        row['deployment_evidence'] = [self.forged(build, code='0x6001600055')]
        self.assertEqual(self.check([row]), [])

    def test_the_digest_says_what_it_is(self):
        data = bounty.read_json(self.run / self.deploy())
        self.assertIn('accidental edits', data['record_sha256_meaning'])
        self.assertIn('not a signature', data['record_sha256_meaning'])
        self.assertEqual(data['compared_code']['bytes'], 40)

    def test_a_local_development_chain_is_never_the_programs_deployment(self):
        row = self.record()
        node = FakeNode({'eth_chainId': hex(31337), 'eth_blockNumber': '0x5',
                         'eth_getCode': '0x' + '60' * 40, 'eth_getStorageAt': '0x' + '00' * 32})
        address = '0x' + '44' * 20
        result = bounty.verify_deployment('http://node.invalid', address, str(self.artifact),
                                          'latest', opener=node, run=self.run)
        self.assertTrue(result['local_chain'])
        self.assertEqual(result['deployment_status'], 'exact')
        row['deployment_evidence'] = ['deployments/' + address + '.json']
        self.assertTrue(any('local development chain' in e for e in self.check([row])))

    def test_program_json_binds_addresses_and_chains(self):
        row = self.record()
        listed = row['deployment_evidence'][0].split('/')[1][:-5]
        bounty.dump(self.run / 'program.json', {'in_scope_addresses': ['0x' + '99' * 20]})
        self.assertTrue(any('not among program.json' in e for e in self.check([row])))
        bounty.dump(self.run / 'program.json',
                    {'in_scope_addresses': [{'address': listed.upper().replace('0X', '0x'),
                                             'chain_id': 1}]})
        self.assertEqual(self.check([row]), [])
        bounty.dump(self.run / 'program.json', {'in_scope_addresses': [listed],
                                                'chain_ids': [10]})
        self.assertTrue(any("chain_ids does not list" in e for e in self.check([row])))
        bounty.dump(self.run / 'program.json', {'in_scope_addresses': 'all of them'})
        self.assertTrue(any('in_scope_addresses must be an array' in e
                            for e in self.check([row])))

    def test_symlinked_folders_and_artifacts_are_refused(self):
        row = self.record()
        real = self.base / 'elsewhere'
        shutil.move(str(self.run / 'deployments'), str(real))
        os.symlink(real, self.run / 'deployments')
        self.assertTrue(any('deployments/ folder is a symlink' in e for e in self.check([row])))

    def test_a_configured_foundry_out_directory_counts_as_build_output(self):
        (self.repo / 'foundry.toml').write_text('[profile.default]\nout = "forge-out"\n')
        meta = {'target_root': str(self.repo)}
        built = self.repo / 'forge-out' / 'Vault.sol' / 'Vault.json'
        built.parent.mkdir(parents=True)
        built.write_text('{}')
        self.assertEqual(bounty._artifact_location_problem(meta, built), '')
        loose = self.repo / 'Vault.json'
        loose.write_text('{}')
        self.assertIn('build output', bounty._artifact_location_problem(meta, loose))


# --------------------------------------------------------------------------- #
# 2. zero-test detection fails closed
# --------------------------------------------------------------------------- #

FORGE_NONE = ('No files changed, compilation skipped\nNo tests found in project! Forge looks '
              'for functions that start with `test`\n')
FORGE_PASS = ('Ran 1 test for test/Exploit.t.sol:ExploitTest\n[PASS] test_exploit() (gas: 25575)\n'
              'Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 586.37us\n\n'
              'Ran 1 test suite in 2.60ms (586.37us CPU time): 1 tests passed, 0 failed, '
              '0 skipped (1 total tests)\n')
FORGE_JSON_PASS = ('{"test/Exploit.t.sol:ExploitTest":{"duration":"496µs","test_results":{'
                   '"test_exploit()":{"status":"Success","reason":null,"counterexample":null,'
                   '"logs":[],"kind":{"Unit":{"gas":25575}}}},"warnings":[]}}\n')
FORGE_JSON_SKIP = FORGE_JSON_PASS.replace('"Success"', '"Skipped"')
FORGE_LIST = ('test/Exploit.t.sol\n  ExploitTest\n    test_control\n    test_exploit\n')
CARGO_IGNORED = ('\nrunning 1 test\ntest skipped::exploit_ignored ... ignored\n\ntest result: '
                 'ok. 0 passed; 0 failed; 1 ignored; 0 measured; 4 filtered out; finished in '
                 '0.00s\n\n     Running unittests src/lib.rs (target/debug/deps/demo-88d7)\n')
MOCHA_JSON_NONE = ('{\n  "stats": {\n    "suites": 0,\n    "tests": 0,\n    "passes": 0,\n'
                   '    "pending": 0,\n    "failures": 0\n  },\n  "tests": []\n}\n')


class FailClosedDetectionTests(unittest.TestCase):
    def outcome(self, argv, text, code=0, marker=None):
        return runner.read_test_output(argv, code, text, marker)[0]

    def test_an_unknown_runner_is_never_a_test_that_ran(self):
        self.assertEqual(self.outcome(['true', 'candidate'], ''), 'unknown-runner')
        self.assertEqual(self.outcome(['cargo', 'build'], 'Finished `dev` profile'),
                         'unknown-runner')
        self.assertEqual(self.outcome(['node', '--test', 't.js'], '# tests 0\n'),
                         'unknown-runner')
        self.assertEqual(self.outcome(['./poc.sh'], 'ok 1 - drained\n', marker=r'^ok \d+ '),
                         'ran')
        self.assertEqual(self.outcome(['./poc.sh'], 'not ok 1\n', marker=r'^ok \d+ '),
                         'no-tests-ran')
        for marker in ('.*', '^', 'x*', ''):
            with self.assertRaises(ValueError, msg=marker):
                runner.read_test_output(['./poc.sh'], 0, 'ok', marker)

    def test_wrappers_and_aliases_are_read_as_the_command_they_run(self):
        for argv in (['forge', 't', '--mt', 'x'], ['env', 'forge', 'test', '--mt', 'x'],
                     ['env', '-i', 'PATH=/bin', 'forge', 'test'],
                     ['timeout', '-k', '5', '120', 'forge', 'test'],
                     ['nice', '-n', '10', 'forge', 'test'], ['/opt/foundry/forge', 'test']):
            self.assertEqual(self.outcome(argv, FORGE_NONE), 'no-tests-ran', argv)
            self.assertEqual(self.outcome(argv, FORGE_PASS), 'ran', argv)
        self.assertEqual(self.outcome(['cargo', 't', 'nope'],
                                      'running 0 tests\n\ntest result: ok. 0 passed; 0 failed'),
                         'no-tests-ran')

    def test_skipped_ignored_listed_and_dry_runs_executed_nothing(self):
        self.assertEqual(self.outcome(['cargo', 'test', 'exploit_ignored'], CARGO_IGNORED),
                         'no-tests-ran')
        self.assertEqual(self.outcome(['forge', 'test', '--list'], FORGE_LIST), 'no-tests-ran')
        self.assertEqual(self.outcome(['go', 'test', '-list', '.', './...'],
                                      'TestExploit\nok  \tex/gom\t0.002s\n'), 'no-tests-ran')
        self.assertEqual(self.outcome(['go', 'test', '-v', '-run', 'TestSkipped', './...'],
                                      '=== RUN   TestSkipped\n--- SKIP: TestSkipped (0.00s)\n'
                                      'PASS\nok  \tex/gom\t0.003s\n'), 'no-tests-ran')
        self.assertEqual(self.outcome(['go', 'test', '-run', 'TestSkipped', './...'],
                                      'ok  \tex/gom\t0.002s\n'), 'no-tests-ran')
        self.assertEqual(self.outcome(['pytest', '--collect-only', '-q'],
                                      'test_x.py::T::test_exploit\n\n2 tests collected in 0.00s\n'),
                         'no-tests-ran')
        self.assertEqual(self.outcome(['pytest', '-q', '-k', 'skip'],
                                      's   [100%]\n1 skipped, 4 deselected in 0.01s\n'),
                         'no-tests-ran')
        self.assertEqual(self.outcome(['pytest', '-qq', '-k', 'exploit'], '.   [100%]\n'),
                         'no-tests-ran')
        self.assertEqual(self.outcome(['pytest', '-q', '-k', 'exploit'],
                                      '.   [100%]\n1 passed, 4 deselected in 0.01s\n'), 'ran')
        self.assertEqual(self.outcome(['npx', 'mocha', '--dry-run', 't.spec.js'],
                                      '  2 passing (3ms)\n  1 pending\n'), 'no-tests-ran')
        self.assertEqual(self.outcome(['python3', '-m', 'unittest', 'test_z.S.test_skipped'],
                                      'Ran 1 test in 0.000s\n\nOK (skipped=1)\n'), 'no-tests-ran')
        self.assertEqual(self.outcome(['python3', '-m', 'unittest', 'test_z'],
                                      'Ran 3 tests in 0.000s\n\nOK (skipped=1, expected '
                                      'failures=1)\n'), 'ran')

    def test_json_output_is_parsed_rather_than_read_as_zero(self):
        self.assertEqual(self.outcome(['forge', 'test', '--mt', 'x', '--json'], FORGE_JSON_PASS),
                         'ran')
        self.assertEqual(self.outcome(['forge', 'test', '--mt', 'x', '--json'], FORGE_JSON_SKIP),
                         'no-tests-ran')
        self.assertEqual(self.outcome(['forge', 'test', '--json'], FORGE_NONE), 'no-tests-ran')
        passing = MOCHA_JSON_NONE.replace('"passes": 0', '"passes": 1')
        self.assertEqual(self.outcome(['npx', 'mocha', '--reporter', 'json'], passing), 'ran')
        self.assertEqual(self.outcome(['npx', 'mocha', '--reporter=json'], MOCHA_JSON_NONE),
                         'no-tests-ran')
        self.assertEqual(self.outcome(['go', 'test', '-json', '-run', 'TestA', '.'],
                                      '{"Action":"run","Test":"TestA"}\n'
                                      '{"Action":"pass","Test":"TestA","Elapsed":0}\n'), 'ran')

    def test_the_runner_records_status_detection_and_resolved_cwd(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            (repo / 'sub').mkdir()
            (repo / 'poc.py').write_text("print('ok 1 - drained')\n")
            plan = {'finding_id': 'BP-001', 'cases': [
                {'id': 'c', 'pair_id': 'p', 'role': 'candidate', 'cwd': './',
                 'argv': [sys.executable, 'poc.py']},
                {'id': 'n', 'pair_id': 'p', 'role': 'negative-control', 'cwd': 'sub/..',
                 'argv': [sys.executable, 'poc.py'], 'expect_tests_marker': r'^ok 1 '}]}
            out = runner.execute(plan, repo, allow_exec=True)
        self.assertEqual([c['cwd_resolved'] for c in out['cases']], ['.', '.'])
        self.assertEqual([c['status'] for c in out['cases']], ['unknown-runner', 'ran'])
        self.assertEqual(out['cases'][1]['test_detection'], 'marker')
        self.assertIn('expect_tests_marker', out['cases'][0]['test_detection_note'])
        self.assertNotEqual(out['result'], 'experiments-conformed')
        self.assertIn('unknown-runner', out['test_detection'])

    def test_the_runner_writes_each_cases_log_next_to_its_result(self):
        with tempfile.TemporaryDirectory() as temp:
            repo, out = Path(temp) / 'repo', Path(temp) / 'run' / 'native-BP-001.json'
            repo.mkdir()
            out.parent.mkdir()
            (repo / 'poc.py').write_text("print('ok 1 - drained')\n")
            plan = Path(temp) / 'plan.json'
            plan.write_text(json.dumps({'finding_id': 'BP-001', 'cases': [
                {'id': 'cand', 'pair_id': 'p', 'role': 'candidate', 'argv': [sys.executable,
                                                                             'poc.py', 'a'],
                 'expect_tests_marker': '^ok 1 '},
                {'id': 'ctrl', 'pair_id': 'p', 'role': 'negative-control',
                 'argv': [sys.executable, 'poc.py', 'b'], 'expect_tests_marker': '^ok 1 '}]}))
            with unittest.mock.patch('sys.stdout', new_callable=io.StringIO):
                code = runner.main(['--plan', str(plan), '--repo', str(repo), '--allow-exec',
                                    '--out', str(out)])
            result = json.loads(out.read_text())
            log = (out.parent / result['cases'][0]['log_file']).read_text()
        self.assertEqual(code, 0)
        self.assertEqual(result['cases'][0]['log_file'], 'native-BP-001.cand.log')
        self.assertIn('ok 1 - drained', log)

    def test_the_shell_guard_reads_clusters_and_wrappers(self):
        for argv in (['bash', '-lc', 'true'], ['sh', '-ec', 'true'], ['zsh', '-o', 'x', '-c', 'y'],
                     ['env', '-i', 'bash', '-c', 'true'], ['env', '-S', 'bash -c true'],
                     ['timeout', '5', 'sh', '-c', 'true'], ['python3', '-Ic', 'print(1)'],
                     ['python3', '-W', 'error', '-c', 'print(1)'], ['python3.12', '-c', '1'],
                     ['node', '-pe', '1'], ['node', '--eval=1'], ['perl', '-ne', 'print'],
                     ['ruby', '-e', '1'], ['deno', 'eval', '1'], ['php', '-r', 'echo 1;'],
                     ['pwsh', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', 'ls'],
                     ['powershell', '-enc', 'AAAA'], ['cmd', '/c', 'dir']):
            with self.assertRaises(ValueError, msg=argv):
                runner._reject_shell(argv)
        for argv in (['python3', '-m', 'pytest', '-c', 'pytest.ini'], ['bash', 'poc.sh', '-c'],
                     ['node', 'test.js', '-e'], ['python3', '-u', 'poc.py']):
            runner._reject_shell(argv)


# --------------------------------------------------------------------------- #
# 3-6. revision, contrast, placeholders, blockers - the experiment and submission gates
# --------------------------------------------------------------------------- #

class RevisionRuleTests(ReviewCase):
    def test_a_short_or_uppercase_revision_passes_the_submission_gate(self):
        for revision in (self.commit[:7], self.commit[:12], self.commit.upper()):
            row = self.record()
            row['revision'] = revision
            entry = self.executed('BP-001', 'native-BP-001.json')
            entry['revision'] = revision[:9]
            self.ledger_entries(entry)
            self.assertEqual(self.check([row]), [], revision)

    def test_a_deployed_commit_other_than_the_runs_is_accepted_if_the_target_knows_it(self):
        row = self.record()
        old = self.commit
        (self.repo / 'src/Vault.sol').write_text('contract Vault { uint x; }\n')
        commit(self.repo, 'head moved on')
        meta = bounty.read_json(self.run / 'run.json')
        meta['commit'] = subprocess.run(['git', '-C', str(self.repo), 'rev-parse', 'HEAD'],
                                        capture_output=True, text=True).stdout.strip()
        bounty.dump(self.run / 'run.json', meta)
        self.assertEqual(row['revision'], old)
        self.assertEqual(self.check([row]), [])
        # A commit the target never had - one made in a disposable copy - is refused.
        made_locally = 'c0ffee' + old[6:]
        result = bounty.read_json(self.run / 'native-BP-001.json')
        result['source_revision'] = made_locally
        bounty.dump(self.run / 'native-BP-001.json', result)
        row['revision'] = made_locally
        entry = self.executed('BP-001', 'native-BP-001.json')
        entry['revision'] = made_locally
        self.ledger_entries(entry)
        self.assertTrue(any('neither the run\'s commit nor a commit in the target checkout' in e
                            for e in self.check([row])))


class ContrastAndSharingTests(ReviewCase):
    def test_a_control_that_differs_only_by_directory_spelling_contrasts_nothing(self):
        row = self.record()
        result = bounty.read_json(self.run / 'native-BP-001.json')
        result['cases'][1]['argv'] = result['cases'][0]['argv']
        result['cases'][0]['cwd'], result['cases'][1]['cwd'] = '.', './'
        bounty.dump(self.run / 'native-BP-001.json', result)
        self.assertTrue(any('ran the same command in the same directory' in e
                            for e in self.check([row])))

    def test_one_experiment_backs_one_finding(self):
        first = self.record()
        second = json.loads(json.dumps(first))
        second.update(id='BP-002', title='A second root cause', bug_class='accounting-drift')
        name = self.pair('BP-002', 'forge test --mt test_exploit', name='native-BP-002.json')
        self.ledger_entries(self.executed('BP-001', 'native-BP-001.json'),
                            self.executed('BP-002', name))
        errors = self.check([first, second])
        self.assertTrue(any('ran the same candidate command' in e for e in errors), errors)
        self.assertTrue(any('evidence.poc_path files have identical content' in e
                            for e in errors), errors)

    def test_a_hard_link_to_bookkeeping_is_not_evidence(self):
        row = self.record()
        (self.run / 'log.txt').unlink()
        os.link(self.run / 'run.json', self.run / 'log.txt')
        bounty.dump(self.run / 'findings.json', [row])
        self.assertTrue(any('hard link to a file the run keeps' in e
                            for e in bounty.validate(self.run)))


class PlaceholderTests(unittest.TestCase):
    ARGV = ['forge', 'test', '--mt', 'test_exploit', '--fork-url', 'http://127.0.0.1:8545',
            '--fork-block-number', '21000000']

    def same(self, command, argv=None):
        return bounty._same_command(command, argv or self.ARGV)

    def test_placeholders_stand_only_for_values(self):
        self.assertTrue(self.same('forge test --mt test_exploit --fork-url $RPC '
                                  '--fork-block-number 21000000'))
        self.assertTrue(self.same('forge test --mt test_exploit --fork-url $RPC '
                                  '--fork-block-number $BLOCK'))
        self.assertFalse(self.same('$A $B $C $D $E $F $G $H'))
        self.assertFalse(self.same('<a> <b> <c> <d> <e> <f> <g> <h>'))
        self.assertFalse(self.same('$FORGE test --mt test_exploit --fork-url $RPC '
                                   '--fork-block-number 21000000'))
        self.assertFalse(self.same('forge test --mt $TEST --fork-url $RPC '
                                   '--fork-block-number 21000000'))
        self.assertFalse(self.same('forge test --mt test_$ANY --fork-url $RPC '
                                   '--fork-block-number 21000000'))
        # A redaction the runner made may be named by any variable, wherever it is.
        self.assertTrue(self.same('forge test --fork-url $ETH_RPC_URL',
                                  ['forge', 'test', '--fork-url',
                                   'https://eth-mainnet.g.alchemy.com/v2/<REDACTED>']))
        # Placeholders for most of the command say nothing about it.
        self.assertFalse(self.same('forge --a=$A --b=$B', ['forge', '--a=1', '--b=2']))
        self.assertTrue(self.same('forge test --a=$A', ['forge', 'test', '--a=1']))


class LedgerBlockerTests(ReviewCase):
    def held(self):
        row = hardening.bounty.template()
        row.update(id='BP-002', status='needs-evidence', revision=self.commit, title='t',
                   root_cause='r', affected_paths=['src/Vault.sol'], bug_class='x-y',
                   attacker_capabilities='a', preconditions='p', impact='i', severity='high',
                   next_experiment={'question': 'q', 'method': 'm', 'expected_evidence': 'e'})
        return row

    def test_a_ledger_blocker_carries_its_command_exit_code_and_output(self):
        verified = self.record()
        blocked = {'finding_id': 'BP-002', 'status': 'blocked',
                   'reason': 'cannot build it, sorry, really', 'attempted_alternative':
                   'tried something else too, also no'}
        self.ledger_entries(self.executed('BP-001', 'native-BP-001.json'), blocked)
        rows = [verified, self.held()]
        self.assertTrue(any('not evidence' in e for e in self.check(rows)))
        self.assertEqual(gate.review(self.run)['result'], 'failed')
        queued = bounty.lead_queue(self.run)['unverified_blockers']
        self.assertEqual([(q['id'], q['source']) for q in queued], [('BP-002', 'experiments.json')])
        blocked.update(command='forge build', exit_code=1,
                       output_excerpt='Error: Compiler run failed: Source "lib/x.sol" not found')
        self.ledger_entries(self.executed('BP-001', 'native-BP-001.json'), blocked)
        self.assertEqual(self.check(rows), [])
        self.assertEqual(bounty.lead_queue(self.run)['unverified_blockers'], [])

    def test_the_two_failure_patterns_stay_identical(self):
        self.assertEqual(bounty.FAILURE_OUTPUT.pattern, gate.FAILURE_OUTPUT.pattern)
        self.assertEqual(bounty.SUCCESS_COUNTS.pattern, gate.SUCCESS_COUNTS.pattern)


# --------------------------------------------------------------------------- #
# 7. not-applicable: the manifest decides, and every on-chain suffix is refused
# --------------------------------------------------------------------------- #

class OnchainClassificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def crate(self, rel, manifest, source='fn main() {}\n'):
        folder = self.root / rel
        (folder / 'src').mkdir(parents=True)
        (folder / 'Cargo.toml').write_text('[package]\nname = "x"\nversion = "0.1.0"\n\n'
                                           + manifest)
        (folder / 'src' / 'main.rs').write_text(source)
        return rel + '/src/main.rs'

    def why(self, path):
        return bounty._onchain_source(path, str(self.root))

    def test_the_manifest_decides_before_the_path(self):
        keeper = self.crate('programs/keeper', '[dependencies]\ntokio = "1"\n')
        self.assertEqual(self.why(keeper), '')
        relayer = self.crate('relayer', '[dependencies]\ntokio = "1"\nsolana-program = "1.18"\n'
                                        'solana-client = "1.18"\n')
        self.assertEqual(self.why(relayer), '')
        program = self.crate('onchain', '[dependencies]\nanchor-lang.workspace = true\n',
                             'use anchor_lang::prelude::*;\n')
        self.assertIn('Anchor', self.why(program))
        renamed = self.crate('renamed', '[dependencies]\nanchor = { package = "anchor-lang", '
                                        'version = "0.30" }\n')
        self.assertIn('Anchor', self.why(renamed))
        entry = self.crate('both', '[dependencies]\nsolana-program = "2"\ntokio = "1"\n',
                           'solana_program::entrypoint!(process_instruction);\n')
        self.assertIn('Solana', self.why(entry))
        self.assertIn('programs/', self.why('programs/missing/src/lib.rs'))

    def test_every_onchain_suffix_is_one_set(self):
        self.assertIs(bounty.ONCHAIN_SOURCE_SUFFIXES, bounty.ONCHAIN_SUFFIXES)
        for path in ('contracts/Jetton.tact', 'src/main.sw', 'src/Vault.vy', 'src/a.fc'):
            self.assertEqual(self.why(path), 'contract source', path)


# --------------------------------------------------------------------------- #
# 8, 12. Vyper's appended immutables, and data that reads as DELEGATECALL
# --------------------------------------------------------------------------- #

class VyperTests(unittest.TestCase):
    def test_the_footer_of_a_real_build_is_read(self):
        meta = bounty.vyper_metadata(VYPER_INIT)
        self.assertEqual(meta, {'version': '0.4.0', 'runtime_size': 123, 'immutables_size': 32})
        self.assertIsNone(bounty.vyper_metadata(VYPER_RUNTIME))

    def test_a_deployment_with_immutables_compares_exact(self):
        exact = bounty.compare_bytecode(VYPER_ONCHAIN, VYPER_RUNTIME, appended_immutables=32)
        self.assertEqual(exact['status'], 'exact')
        self.assertEqual(exact['masked_ranges'][0]['kind'], 'vyper-immutables')
        self.assertTrue(exact['masked_ranges'][0]['onchain_value'].endswith('cfffb92266'))
        unsized = bounty.compare_bytecode(VYPER_ONCHAIN, VYPER_RUNTIME)
        self.assertEqual(unsized['status'], 'partial')
        self.assertIn('Vyper', unsized['reason'])
        wrong = bounty.compare_bytecode(VYPER_ONCHAIN, VYPER_RUNTIME, appended_immutables=64)
        self.assertNotEqual(wrong['status'], 'exact')

    def test_verify_deployment_reads_the_artifact_and_ignores_the_immutable_bytes(self):
        node = FakeNode({'eth_chainId': '0x1', 'eth_blockNumber': '0x10',
                         'eth_getCode': VYPER_ONCHAIN, 'eth_getStorageAt': '0x' + '00' * 32})
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / 'Box.json'
            artifact.write_text(json.dumps({'bytecode': {'object': VYPER_INIT},
                                            'deployedBytecode': {'object': VYPER_RUNTIME}}))
            result = bounty.verify_deployment('http://node.invalid', '0x' + '12' * 20,
                                              str(artifact), opener=node)
        self.assertEqual(result['deployment_status'], 'exact')
        self.assertNotIn('proxy_heuristic', result)
        self.assertEqual(result['artifact_vyper']['immutables_size'], 32)

    def test_only_reachable_code_is_scanned_for_delegatecall(self):
        onchain = bytes.fromhex(VYPER_ONCHAIN[2:])
        self.assertIn(bounty.OP_DELEGATECALL, onchain)
        self.assertFalse(bounty.has_delegatecall(onchain))
        # A real one still counts, after a terminator only through a JUMPDEST.
        self.assertTrue(bounty.has_delegatecall(bytes.fromhex('5af4')))
        self.assertTrue(bounty.has_delegatecall(bytes.fromhex('00' + '5b5af4')))
        self.assertFalse(bounty.has_delegatecall(bytes.fromhex('00' + '60f4')))


# --------------------------------------------------------------------------- #
# 9-10. secrets, and commands that need no network or no manual copying
# --------------------------------------------------------------------------- #

class SecretShapeTests(unittest.TestCase):
    SHAPES = {
        'ETH_KEY=0x' + 'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80': 'private key',
        'https://lb.drpc.org/ogrpc?network=ethereum&dkey=AkZx81Qm2PLu0sRt7yVwB9': 'query string',
        'https://nd-123-456-789.p2pify.com/3c6e0b8a9c15224a8228b9a98ca1531d': 'provider key',
        'https://:Sup3rSecretPw4@eth.rpc.example.com': 'username and password',
        'https://alice:Sup3rSecretPw4@eth.rpc.example.com': 'username and password'}

    def test_the_shapes_are_detected_and_scrubbed(self):
        for text, kind in self.SHAPES.items():
            self.assertTrue(any(kind in found for found in bounty.secret_kinds(text)), text)
            self.assertIn('<REDACTED>', runner._scrub(text), text)
        self.assertEqual(bounty.secret_kinds('SLOT 0x' + '00' * 32 + ' tx 0x' + 'ab' * 32), [])


class OfflineCommandTests(ReviewCase):
    def test_an_empty_reason_needs_no_tracker_and_no_network(self):
        meta = bounty.read_json(self.run / 'run.json')
        meta['project_key'] = None
        bounty.dump(self.run / 'run.json', meta)

        def no_network(*args, **kwargs):
            raise AssertionError('dup-harvest called the network')
        result = bounty.dup_harvest(self.run, empty_reason='No public tracker: the program '
                                    'takes reports through its own form', opener=no_network)
        self.assertEqual(result['source'], 'no-tracker')
        self.assertFalse(result['vacuous'])
        with self.assertRaisesRegex(ValueError, '--empty-reason'):
            bounty.dup_harvest(self.run, opener=no_network)

    def test_history_check_says_how_to_name_the_project(self):
        meta = bounty.read_json(self.run / 'run.json')
        meta['project_key'] = None
        bounty.dump(self.run / 'run.json', meta)
        with self.assertRaisesRegex(ValueError, 'no origin remote.*--project'):
            bounty.history_check(self.run, self.ledger)



if __name__ == '__main__':
    unittest.main()
