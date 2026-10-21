"""Evidence and submission-gate hardening regressions (stdlib only).

Each case is one way a weak or hand-typed record used to pass `check --submission`, or one way a
correct deployment used to be refused. They never need forge, cargo, solc or a network.
"""
import base64
import contextlib
import importlib.util
import io
import json
import os
import shlex
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bounty = load('bounty_hardening', 'skills/bounty-pilot/scripts/bounty.py')
keccak = load('bp_keccak_hardening', 'skills/bounty-pilot/scripts/keccak.py')
gate = load('bp_gate_hardening', 'skills/bounty-pilot/scripts/experiment_gate.py')
runner = load('bp_runner_hardening', 'skills/bounty-pilot/scripts/scenario_runner.py')

ALCHEMY_KEY = 'AbCdEfGhIjKlMnOpQrStUvWx'
PRIVATE_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'


class FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode('utf-8')

    def read(self):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeNode:
    """Answers JSON-RPC from a dict; a callable answer may raise ValueError for an RPC error."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, request, timeout=None):
        body = json.loads(request.data.decode('utf-8'))
        self.calls.append((body['method'], body['params']))
        value = self.answers.get(body['method'])
        try:
            if value is None:
                raise ValueError('execution reverted')
            if callable(value):
                value = value(body['params'])
        except ValueError as exc:
            return FakeResponse({'jsonrpc': '2.0', 'id': body['id'],
                                 'error': {'code': 3, 'message': str(exc)}})
        return FakeResponse({'jsonrpc': '2.0', 'id': body['id'], 'result': value})


def git(repo, *args):
    subprocess.run(['git', '-C', str(repo), *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def commit(repo, message):
    git(repo, 'add', '-A')
    git(repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
        '-c', 'commit.gpgsign=false', 'commit', '-qm', message)


def padded(address):
    return '0x' + '00' * 12 + address[2:]


class SubmissionCase(unittest.TestCase):
    """A run holding one honestly submittable record, built through the real commands."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        (self.repo / 'src/Vault.sol').write_text('contract Vault {}\n')
        commit(self.repo, 'fixture')
        self.run = self.base / 'run'
        bounty.initialize(self.repo, self.run)
        meta = bounty.read_json(self.run / 'run.json')
        meta['project_key'] = 'example.invalid/test'
        bounty.dump(self.run / 'run.json', meta)
        self.commit = meta['commit']
        self.ledger = self.base / 'private' / 'history.jsonl'
        self.ledger.parent.mkdir()
        self.ledger.write_text('')

    def deploy(self, address='0x' + '11' * 20, onchain=None, built=None):
        code = '0x' + '60' * 40
        node = FakeNode({'eth_chainId': '0x1', 'eth_blockNumber': '0x100',
                         'eth_getCode': onchain or code,
                         'eth_getStorageAt': '0x' + '00' * 32})
        # The gate accepts only a build in the target checkout's own build output.
        self.artifact = self.repo / 'out' / ('artifact-' + address[-6:] + '.json')
        self.artifact.parent.mkdir(exist_ok=True)
        self.artifact.write_text(json.dumps({'deployedBytecode': {'object': built or code}}))
        result = bounty.verify_deployment('http://node.invalid', address, str(self.artifact),
                                          'latest', opener=node, run=self.run)
        return str(Path(result['evidence_file']).relative_to(self.run.resolve()))

    def pair(self, finding_id, command, control=None, bound=True, name=None):
        argv = shlex.split(command)

        def case(role, words):
            return {'id': role, 'pair_id': 'p1', 'role': role, 'argv': words, 'cwd': '.',
                    'executed': True, 'tests_ran': True, 'timed_out': False, 'status': 'ran',
                    'exit_code': 0, 'expected_exit': 0, 'matched_expected_exit': True}
        name = name or 'native-' + finding_id + '.json'
        bounty.dump(self.run / name, {
            'schema': 1, 'finding_id': finding_id if bound else None,
            'source_revision': self.commit, 'source_status': 'clean', 'mode': 'executed',
            'result': 'experiments-conformed',
            'cases': [case('candidate', argv),
                      case('negative-control', control if control is not None
                           else argv + ['--control'])]})
        return name

    def ledger_entries(self, *entries):
        bounty.dump(self.run / 'experiments.json', {'version': 1, 'experiments': list(entries)})

    def executed(self, finding_id, result_path):
        return {'finding_id': finding_id, 'status': 'executed', 'revision': self.commit,
                'result_path': result_path,
                'observation': 'The candidate passed and the negative control failed.'}

    def record(self, finding_id='BP-001', command='forge test --mt test_exploit'):
        (self.run / 'poc.t.sol').write_text('// PoC\n')
        (self.run / 'log.txt').write_text('[PASS] test_exploit()\n')
        row = bounty.template()
        row.update(
            id=finding_id, title='Debt is never decremented', status='verified', severity='high',
            bug_class='aggregate-not-decremented', revision=self.commit, lens='manual',
            root_cause='repay() does not decrement totalDebt', affected_paths=['src/Vault.sol'],
            attacker_capabilities='Unprivileged caller', preconditions='An open loan',
            impact='Later borrowers are priced against inflated debt', scope_status='in-scope',
            deployment_status='exact', deployment_evidence=[self.deploy()],
            severity_rationale='Program rubric: High, theft of unclaimed yield')
        row['novelty'] = {'status': 'no-public-match-found',
                          'sources': ['https://example.invalid/known-issues',
                                      'https://example.invalid/audit.pdf']}
        row['evidence'] = {'command': command, 'exit_code': 0, 'poc_path': 'poc.t.sol',
                           'log_path': 'log.txt', 'assertion': 'totalDebt exceeds the loans',
                           'negative_control': 'repaying in full on a fresh vault reverts',
                           'source_integrity': 'unmodified checkout',
                           'impact_quantification': '12,000 USDC at 0.01 ETH cost'}
        row['next_experiment'] = {'question': '', 'method': '', 'expected_evidence': '',
                                  'blocker': ''}
        row['history_review'] = {'status': 'no-match', 'case_ids': [],
                                 'rationale': 'history check 2026-10-17: no match'}
        row['dup_review'] = {'status': 'no-match', 'entry_ids': [],
                             'rationale': 'dup-check 2026-10-17: clean'}
        row['escalation'] = {
            'attempted': [{'amplifier': a, 'result': 'blocked',
                           'anchor': 'code: src/Vault.sol:1 bounds ' + a}
                          for a in bounty.ESCALATION_AMPLIFIERS],
            'ceiling': 'high', 'ceiling_evidence': 'every amplifier came back blocked'}
        row['objections'] = [{'gate': 'interruption', 'claim': 'a guard stops repay()',
                              'anchor': 'code: src/Vault.sol:1', 'outcome': 'answered',
                              'answer': 'repayFor() skips it', 'answer_anchor': 'code: :2'}]
        self.ledger_entries(self.executed(finding_id, self.pair(finding_id, command)))
        return row

    def gates(self, rows, empty_map_reason='Read the known-issues page and both audits.'):
        bounty.dump(self.run / 'findings.json', rows)
        bounty.history_check(self.run, self.ledger, project='example.invalid/test')
        items = self.base / 'harvest.json'
        items.write_text(json.dumps({'items': []}))
        bounty.dup_harvest(self.run, repo='example.invalid/test', labels=['wontfix'],
                           from_file=str(items))
        bounty.dup_check(self.run, empty_map_reason=empty_map_reason)
        if not (self.run / 'audit-inventory.json').exists():
            bounty.audit_inventory(self.repo, self.run)
        if not (self.run / bounty.POC_GIST_FILE).exists():
            self.published_poc(*[r['id'] for r in rows
                                 if isinstance(r, dict) and isinstance(r.get('id'), str)])
        return bounty.validate(self.run, submission=True)

    def published_poc(self, *findings):
        """Record a prepared-and-published PoC bundle, the way `poc-bundle --publish` writes it.

        The gate requires one before a report goes out: the team gets the test, its log and the
        runner result on an unlisted gist instead of taking the claim on trust. Publishing needs
        the network, so the fixture writes what the command would have written.
        """
        run_id = bounty.read_json(self.run / 'run.json')['run_id']
        bounty.dump(self.run / bounty.POC_GIST_FILE, {
            'schema_version': bounty.SCHEMA_VERSION, 'run_id': run_id,
            'bundles': [{'finding': ident, 'run_id': run_id, 'published': True,
                         'url': f'https://gist.github.com/tester/{i:032x}',
                         'gist_id': f'{i:032x}', 'visibility': 'secret (unlisted)',
                         'files': [{'gist_name': 'poc.t.sol', 'path': 'poc.t.sol',
                                    'role': 'poc', 'bytes': 7, 'sha256': 'ab' * 32}],
                         'verified_file_for_file': True,
                         'delete_command': f'gh gist delete {i:032x} --yes'}
                        for i, ident in enumerate(findings or ('BP-001',), start=1)]})


class HonestBaselineTests(SubmissionCase):
    def test_the_fixture_passes_and_every_gate_input_is_real(self):
        self.assertEqual(self.gates([self.record()]), [])


# --------------------------------------------------------------------------- #
# 1. a verified record stands on its own executed experiment
# --------------------------------------------------------------------------- #

class VerifiedNeedsExperimentTests(SubmissionCase):
    def test_a_blocked_experiment_never_backs_a_verified_record(self):
        row = self.record()
        self.ledger_entries({'finding_id': 'BP-001', 'status': 'blocked',
                             'reason': 'forge build fails: missing dependency lib/forge-std',
                             'attempted_alternative': 'tried hardhat compile, also failed'})
        errors = self.gates([row])
        self.assertTrue(any('recorded as blocked' in e for e in errors), errors)
        # The between-passes gate never looked at a verified record; it still does not.
        self.assertEqual(gate.review(self.run)['result'], 'passed')

    def test_a_missing_or_queued_entry_is_an_error(self):
        row = self.record()
        self.ledger_entries()
        self.assertTrue(any('records no executed experiment' in e for e in self.gates([row])))
        self.ledger_entries({'finding_id': 'BP-001', 'status': 'queued'})
        self.assertTrue(any('status must be executed or blocked' in e
                            for e in self.gates([row])))

    def test_a_run_without_an_experiment_ledger_fails_closed(self):
        row = self.record()
        (self.run / 'experiments.json').unlink()
        errors = self.gates([row])
        self.assertTrue(any(e.startswith('experiments.json: missing') for e in errors), errors)

    def test_the_entry_is_held_to_the_experiment_gates_own_checks(self):
        row = self.record()
        result = bounty.read_json(self.run / 'native-BP-001.json')
        result['mode'] = 'dry-run'
        bounty.dump(self.run / 'native-BP-001.json', result)
        self.assertTrue(any('runner was not executed' in e for e in self.gates([row])))


# --------------------------------------------------------------------------- #
# 2. verified evidence: real files, a real commit, the exit code the run observed
# --------------------------------------------------------------------------- #

class VerifiedEvidenceTests(SubmissionCase):
    def check(self, row):
        bounty.dump(self.run / 'findings.json', [row])
        return bounty.validate(self.run)

    def test_the_same_file_or_a_bookkeeping_file_is_not_evidence(self):
        row = self.record()
        row['evidence'].update(log_path='poc.t.sol')
        self.assertTrue(any('name the same file' in e for e in self.check(row)))
        row['evidence'].update(log_path='run.json', poc_path='run.json')
        errors = self.check(row)
        self.assertTrue(any('log_path names run.json' in e for e in errors), errors)
        self.assertTrue(any('poc_path names run.json' in e for e in errors), errors)
        row['evidence'].update(log_path=row['deployment_evidence'][0], poc_path='poc.t.sol')
        self.assertTrue(any('a file the run keeps about itself' in e for e in self.check(row)))

    def test_a_killed_or_failing_run_is_not_a_demonstration(self):
        row = self.record()
        row['evidence']['exit_code'] = 137
        errors = self.check(row)
        self.assertTrue(any('evidence.exit_code is 137' in e for e in errors), errors)
        self.assertTrue(any('not the exit code the paired run observed' in e for e in errors))

    def test_revision_is_a_commit_the_run_or_its_experiment_pinned(self):
        row = self.record()
        row['revision'] = 'main (roughly last week)'
        self.assertTrue(any('commit hash the PoC ran against' in e for e in self.check(row)))
        row['revision'] = self.commit[:7]
        self.assertEqual(self.check(row), [])
        row['revision'] = 'abc1234'
        self.assertTrue(any('neither the run\'s commit' in e for e in self.check(row)))

    def test_the_command_must_be_the_candidate_the_runner_executed(self):
        row = self.record(command='forge test --mt test_exploit --fork-url <REDACTED>')
        row['evidence']['command'] = 'forge test --mt test_exploit --fork-url $ETH_RPC_URL'
        self.assertEqual(self.check(row), [])
        row['evidence']['command'] = 'forge test --mt test_something_else --fork-url $ETH_RPC_URL'
        self.assertTrue(any('not the candidate command the paired run executed' in e
                            for e in self.check(row)))

    def test_placeholders_and_redactions_match_any_value_in_their_position(self):
        self.assertTrue(bounty._same_command(
            'FOUNDRY_PROFILE=ci forge test --fork-url=${RPC}',
            ['forge', 'test', '--fork-url=https://rpc.example/<REDACTED>']))
        self.assertFalse(bounty._same_command('forge test', ['forge', 'test', '-vvv']))
        self.assertFalse(bounty._same_command('forge test "unclosed', ['forge', 'test']))


# --------------------------------------------------------------------------- #
# 3. deployment evidence: only a file verify-deployment wrote, about bytes that still exist
# --------------------------------------------------------------------------- #

class DeploymentProvenanceTests(SubmissionCase):
    def test_a_hand_typed_exact_file_is_refused(self):
        row = self.record()
        address = '0x' + '22' * 20
        bounty.dump(self.run / 'deployments' / (address + '.json'),
                    {'address': address, 'deployment_status': 'exact',
                     'artifact': {'sha256': 'x'}})
        row['deployment_evidence'] = ['deployments/' + address + '.json']
        errors = self.gates([row])
        self.assertTrue(any('was not written by verify-deployment --run' in e for e in errors))

    def test_a_hand_edited_record_is_refused(self):
        row = self.record()
        partial = self.deploy('0x' + '33' * 20, built='0x' + '60' * 39 + '61')
        path = self.run / partial
        data = bounty.read_json(path)
        self.assertEqual(data['deployment_status'], 'partial')
        self.assertEqual(data['record_sha256'], bounty.deployment_digest(data))
        data['deployment_status'] = 'exact'
        data['comparison']['status'] = 'exact'
        bounty.dump(path, data)
        row['deployment_evidence'] = [partial]
        self.assertTrue(any('edited after it was' in e for e in self.gates([row])))

    def test_a_deleted_artifact_cannot_be_rechecked(self):
        row = self.record()
        self.artifact.unlink()
        errors = self.gates([row])
        self.assertTrue(any('no longer exists' in e for e in errors), errors)

    def test_the_record_carries_its_provenance(self):
        data = bounty.read_json(self.run / self.deploy())
        self.assertEqual(data['tool'], 'bounty.py verify-deployment')
        self.assertEqual((data['chain_id'], data['block']), (1, 256))
        self.assertEqual(data['comparison']['status'], 'exact')
        self.assertEqual(data['artifact']['sha256'], bounty._sha256_file(self.artifact))

    def test_a_move_or_cairo_address_is_never_exact(self):
        row = self.record()
        address = '0x' + 'ab' * 32
        (self.run / 'deployments' / (address + '.json')).write_text(
            json.dumps({'address': address, 'deployment_status': 'exact'}))
        row['deployment_evidence'] = ['deployments/' + address + '.json']
        self.assertTrue(any('EVM contracts and Solana programs only' in e
                            for e in self.gates([row])))

    def test_a_block_tag_is_recorded_as_the_number_it_meant(self):
        node = FakeNode({'eth_chainId': '0x1', 'eth_blockNumber': '0x200',
                         'eth_getBlockByNumber': {'number': '0x1f0'},
                         'eth_getCode': '0x' + '60' * 40, 'eth_getStorageAt': '0x' + '00' * 32})
        result = bounty.verify_deployment('http://node.invalid', '0x' + '11' * 20, None,
                                          'finalized', opener=node)
        self.assertEqual(result['block'], 0x1f0)
        self.assertTrue(all(params[-1] == '0x1f0' for method, params in node.calls
                            if method == 'eth_getCode'))


class SolanaProgramTests(SubmissionCase):
    def solana_node(self, elf, loader=None, authority=True):
        program_id = bounty.b58decode(self.program_id)
        programdata = bytes(range(1, 33))
        upgradeable = loader is None
        data_key = bounty.b58encode(programdata)
        header = (b'\x03\x00\x00\x00' + (1234).to_bytes(8, 'little')
                  + (b'\x01' + b'\x07' * 32 if authority else b'\x00' + b'\x00' * 32))
        accounts = {
            self.program_id: {
                'owner': bounty.SOLANA_UPGRADEABLE_LOADER if upgradeable else loader,
                'executable': True,
                'raw': (b'\x02\x00\x00\x00' + programdata) if upgradeable else elf},
            data_key: {'owner': bounty.SOLANA_UPGRADEABLE_LOADER, 'executable': False,
                       'raw': header + elf + b'\x00' * 64}}
        self.assertEqual(len(program_id), 32)

        def account(params):
            found = accounts.get(params[0])
            value = None if found is None else {
                'owner': found['owner'], 'executable': found['executable'], 'lamports': 1,
                'data': [base64.b64encode(found['raw']).decode(), 'base64']}
            return {'context': {'slot': 99}, 'value': value}
        return FakeNode({'getGenesisHash': '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d',
                         'getAccountInfo': account})

    def setUp(self):
        super().setUp()
        self.program_id = bounty.b58encode(bytes([9] * 32))
        self.elf = b'\x7fELF' + bytes(range(200)) + b'\x00' * 3
        self.so = self.repo / 'target' / 'deploy' / 'vault.so'
        self.so.parent.mkdir(parents=True)
        self.so.write_bytes(self.elf)

    def test_an_upgradeable_program_is_compared_as_solana_verify_hashes_it(self):
        result = bounty.verify_deployment('http://node.invalid', self.program_id, str(self.so),
                                          opener=self.solana_node(self.elf), run=self.run)
        self.assertEqual(result['deployment_status'], 'exact')
        self.assertEqual(result['executable_hash'],
                         bounty.solana_executable_hash(self.elf))
        self.assertEqual(result['last_deploy_slot'], 1234)
        self.assertEqual(result['upgrade_authority'], bounty.b58encode(b'\x07' * 32))
        self.assertEqual(Path(result['evidence_file']).name, self.program_id + '.json')
        row = self.record()
        row['deployment_evidence'] = ['deployments/' + self.program_id + '.json']
        self.assertEqual(self.gates([row]), [])

    def test_a_different_build_is_a_mismatch_and_a_legacy_loader_is_read_directly(self):
        other = self.base / 'other.so'
        other.write_bytes(b'\x7fELF' + b'\x01' * 50)
        node = self.solana_node(self.elf)
        result = bounty.verify_deployment('http://node.invalid', self.program_id, str(other),
                                          opener=node)
        self.assertEqual(result['deployment_status'], 'mismatch')
        legacy = self.solana_node(self.elf, loader=bounty.SOLANA_LEGACY_LOADERS[0])
        result = bounty.verify_deployment('http://node.invalid', self.program_id, str(self.so),
                                          opener=legacy)
        self.assertEqual(result['deployment_status'], 'exact')

    def test_no_build_is_unknown_and_a_non_elf_build_is_refused(self):
        result = bounty.verify_deployment('http://node.invalid', self.program_id,
                                          opener=self.solana_node(self.elf))
        self.assertEqual(result['deployment_status'], 'unknown')
        evm_artifact = self.base / 'vault.json'
        evm_artifact.write_text(json.dumps({'deployedBytecode': '0x6060'}))
        with self.assertRaisesRegex(ValueError, 'ELF'):
            bounty.verify_deployment('http://node.invalid', self.program_id, str(evm_artifact),
                                     opener=self.solana_node(self.elf))

    def test_base58_round_trips_the_loader_ids(self):
        for name in (bounty.SOLANA_UPGRADEABLE_LOADER,) + bounty.SOLANA_LEGACY_LOADERS:
            raw = bounty.b58decode(name)
            self.assertEqual(len(raw), 32)
            self.assertEqual(bounty.b58encode(raw), name)


# --------------------------------------------------------------------------- #
# 4, 10, 11. proxies the old heuristics missed, and clones they refused
# --------------------------------------------------------------------------- #

class ProxyAndCloneTests(unittest.TestCase):
    proxy = '0x' + '22' * 20
    impl = '0x' + '33' * 20
    impl_code = '0x' + '61' * 60

    def verify(self, code, artifact_code, calls=None, codes=None):
        calls = calls or {}
        codes = dict({self.impl: self.impl_code}, **(codes or {}))

        def call(params):
            selector = params[0]['data'][:10]
            if selector not in calls:
                raise ValueError('execution reverted')
            return calls[selector]
        node = FakeNode({'eth_chainId': '0x1', 'eth_blockNumber': '0x100',
                         'eth_getCode': lambda p: codes.get(p[0], code if p[0] == self.proxy
                                                            else '0x'),
                         'eth_getStorageAt': '0x' + '00' * 32, 'eth_call': call})
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / 'a.json'
            artifact.write_text(json.dumps({'deployedBytecode': artifact_code}
                                           if isinstance(artifact_code, dict) else
                                           {'deployedBytecode': {'object': artifact_code}}))
            return bounty.verify_deployment('http://node.invalid', self.proxy, str(artifact),
                                            'latest', opener=node)

    def delegator(self):
        # CErc20Delegator's shape: well over 1 KB, delegates, dispatches implementation().
        return '0x63' + keccak.selector('implementation()')[2:] + '5af4' + '5b' * 1100

    def test_a_large_delegator_is_compared_at_its_implementation(self):
        getter = {keccak.selector('implementation()'): padded(self.impl)}
        result = self.verify(self.delegator(), self.impl_code, calls=getter)
        self.assertEqual(result['proxy_kind'], 'implementation-getter')
        self.assertEqual(result['compared'], 'implementation')
        self.assertEqual(result['deployment_status'], 'exact')
        own = self.verify(self.delegator(), self.delegator(), calls=getter)
        self.assertEqual(own['deployment_status'], 'partial')

    def test_an_unresolved_implementation_getter_is_never_exact(self):
        result = self.verify(self.delegator(), self.delegator())
        self.assertEqual(result['proxy']['implementation-getter'], 'detected-but-unresolved')
        self.assertEqual(result['proxy_resolution'], 'unresolved')
        self.assertEqual(result['deployment_status'], 'partial')

    def test_a_getter_without_delegatecall_is_not_a_proxy(self):
        # An UpgradeableBeacon answers implementation() and delegates nothing.
        code = '0x63' + keccak.selector('implementation()')[2:] + '5b' * 40
        result = self.verify(code, code,
                             calls={keccak.selector('implementation()'): padded(self.impl)})
        self.assertEqual(result['proxy'], {})
        self.assertEqual(result['deployment_status'], 'exact')

    def test_clone_forms_hash_to_soladys_published_code_hashes(self):
        # LibClone.sol: CWIA_CODE_HASH, CLONE_CODE_HASH, PUSH0_CLONE_CODE_HASH, each with the
        # implementation set to address(0).
        published = {
            'eip1167-minimal-clone':
                '0x3cf92464268225a4513da40a34d967354684c32cd0edd67b5f668dfe3550e940',
            'solady-0age-clone':
                '0x48db2cfdb2853fce0b464f1f93a1996469459df3ab6c812106074c4106a1eb1f',
            'solady-push0-clone':
                '0x67bc6bde1b84d66e267c718ba44cf3928a615d29885537955cb43d44b3e789dc'}
        for kind, prefix, suffix, _ in bounty.CLONE_FORMS:
            self.assertEqual(keccak.keccak_hex(bytes.fromhex(prefix + '00' * 20 + suffix)),
                             published[kind], kind)

    def test_clones_with_immutable_args_resolve_and_record_the_args(self):
        args = '00' * 31 + '07' + 'cafe'
        code = '0x363d3d373d3d3d363d73' + self.impl[2:] + '5af43d82803e903d91602b57fd5bf3' + args
        result = self.verify(code, self.impl_code)
        self.assertEqual(result['proxy_kind'], 'eip1167-minimal-clone')
        self.assertEqual(result['deployment_status'], 'exact')
        self.assertEqual(result['clone_immutable_args'],
                         {'bytes': 34, 'hex': '0x' + args, 'truncated': False})

    def test_solady_clones_resolve(self):
        for kind, prefix, suffix, _ in bounty.CLONE_FORMS[1:]:
            code = '0x' + prefix + self.impl[2:] + suffix
            result = self.verify(code, self.impl_code)
            self.assertEqual((result['proxy_kind'], result['deployment_status']),
                             (kind, 'exact'))
            # A forwarder that matches is still a proxy runtime, never the logic.
            self.assertEqual(self.verify(code, code)['deployment_status'], 'partial')
        self.assertIsNone(bounty.clone_forwarder(
            '0x' + bounty.CLONE_FORMS[1][1] + self.impl[2:] + bounty.CLONE_FORMS[1][2] + '00'))

    def test_a_linked_library_with_no_code_is_not_exact(self):
        prefix = bytes.fromhex('608060405234') + b'\x5b' * 40
        suffix = b'\x5b' * 40 + bytes.fromhex('00')
        library = '0x' + '44' * 20
        live = '0x' + (prefix + bytes.fromhex(library[2:]) + suffix).hex()
        built = {'object': '0x' + prefix.hex() + '__$' + 'ab' * 17 + '$__' + suffix.hex(),
                 'linkReferences': {'src/Lib.sol': {'Lib': [{'start': len(prefix),
                                                             'length': 20}]}}}
        empty = self.verify(live, built)
        self.assertEqual(empty['deployment_status'], 'partial')
        self.assertEqual(empty['linked_libraries'][0]['runtime_code_bytes'], 0)
        present = self.verify(live, built, codes={library: '0x' + '62' * 30})
        self.assertEqual(present['deployment_status'], 'exact')
        self.assertEqual(present['linked_libraries'][0]['address'], library)


# --------------------------------------------------------------------------- #
# 5. not-applicable names a file, and never deployed contract source
# --------------------------------------------------------------------------- #

class NotApplicableTests(SubmissionCase):
    def check(self, *paths, write=None):
        for rel, body in (write or {}).items():
            (self.repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / rel).write_text(body)
        row = self.record()
        row.update(affected_paths=list(paths), deployment_status='not-applicable',
                   deployment_evidence=[], deployment_rationale='Off-chain keeper service.')
        return self.gates([row])

    def test_anchors_symbols_and_notes_do_not_hide_contract_source(self):
        for path in ('src/Vault.sol#L42', 'src/Vault.sol (withdraw)', 'src/Vault.sol:withdraw',
                     'src/Vault.sol::Vault.withdraw()', 'sources/vault.move', 'src/vault.cairo',
                     'src/Vault.huff', 'contracts/Pool.vy', 'src/Vault.yul', 'src/Vault.fe'):
            self.assertTrue(any('refused for deployed contract source' in e
                                for e in self.check(path)), path)

    def test_a_path_that_names_no_file_is_refused(self):
        for path in ('Vault.withdraw()', 'withdraw', 'relayer/src/'):
            self.assertTrue(any('names none; name the file' in e for e in self.check(path)), path)

    def test_solana_and_other_contract_crates_are_onchain_rust(self):
        self.assertTrue(any('Anchor workspace layout' in e
                            for e in self.check('programs/vault/src/lib.rs')))
        manifest = '[package]\nname = "pool"\n\n[dependencies]\ncosmwasm-std = "1.5"\n'
        errors = self.check('contracts/pool/src/contract.rs',
                            write={'contracts/pool/Cargo.toml': manifest,
                                   'contracts/pool/src/contract.rs': '// x\n'})
        self.assertTrue(any('CosmWasm contract crate' in e for e in errors), errors)

    def test_off_chain_code_keeps_not_applicable(self):
        manifest = '[package]\nname = "relayer"\n\n[dependencies]\nsolana-sdk = "2"\n'
        self.assertEqual(self.check('relayer/src/main.rs',
                                    write={'relayer/Cargo.toml': manifest,
                                           'relayer/src/main.rs': '// x\n'}), [])
        self.assertEqual(self.check('services/keeper/main.go:submitBatch'), [])


# --------------------------------------------------------------------------- #
# 6. paired runs that test nothing
# --------------------------------------------------------------------------- #

class PairedRunTests(SubmissionCase):
    def open_findings(self, *ids):
        rows = []
        for ident in ids:
            row = bounty.template()
            row.update(id=ident, status='needs-evidence', revision=self.commit,
                       severity='high')
            rows.append(row)
        bounty.dump(self.run / 'findings.json', rows)

    def test_identical_candidate_and_control_test_nothing(self):
        self.open_findings('BP-001')
        name = self.pair('BP-001', 'true', control=['true'])
        self.ledger_entries(self.executed('BP-001', name))
        report = gate.review(self.run)
        self.assertEqual(report['result'], 'failed')
        self.assertIn('ran the same command', report['selected'][0]['review_note'])
        # The same test in a patched checkout is a real contrast.
        result = bounty.read_json(self.run / name)
        result['cases'][1]['cwd'] = 'patched'
        bounty.dump(self.run / name, result)
        self.assertEqual(gate.review(self.run)['result'], 'passed')

    def test_a_result_is_bound_to_its_finding_and_backs_only_one(self):
        self.open_findings('BP-001', 'BP-002', 'BP-003')
        shared = self.pair('BP-001', 'forge test --mt test_a')
        self.ledger_entries(*[self.executed(i, shared) for i in ('BP-001', 'BP-002', 'BP-003')])
        report = gate.review(self.run)
        notes = [row.get('review_note', '') for row in report['selected']]
        self.assertIn('bound to BP-001, not BP-002', notes[1])
        self.assertTrue(any('cite the same result_path' in e for e in report['errors']))
        unbound = self.pair('BP-001', 'forge test --mt test_a', bound=False, name='u.json')
        self.ledger_entries(self.executed('BP-001', unbound))
        self.assertIn('names no finding_id', gate.review(self.run)['selected'][0]['review_note'])

    def test_the_runner_records_finding_and_cwd(self):
        repo = self.base / 'checkout'
        repo.mkdir()
        plan = {'finding_id': 'BP-007', 'cases': [
            {'id': 'c', 'pair_id': 'p', 'role': 'candidate', 'argv': ['git', '--version']},
            {'id': 'n', 'pair_id': 'p', 'role': 'negative-control',
             'argv': ['git', '--version'], 'cwd': '.'}]}
        out = runner.execute(plan, repo)
        self.assertEqual(out['finding_id'], 'BP-007')
        self.assertEqual([case['cwd'] for case in out['cases']], ['.', '.'])
        with self.assertRaisesRegex(ValueError, 'finding_id'):
            runner.execute(dict(plan, finding_id='finding one'), repo)


class ZeroTestTests(unittest.TestCase):
    """Strings taken from the tools' own output or source, not remembered."""

    CARGO_ERR = ('    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.01s\n'
                 '     Running unittests src/lib.rs (target/debug/deps/vault-0154b19d)\n'
                 '     Running tests/it.rs (target/debug/deps/it-b7a3e988)\n'
                 '   Doc-tests vault\n')

    @staticmethod
    def libtest(*counts, doc=False):
        out = ''
        for count in counts:
            out += '\nrunning %d test%s\n' % (count, '' if count == 1 else 's')
            for i in range(count):
                out += ('test src/lib.rs - add (line %d) ... ok\n' % (i + 3) if doc
                        else 'test tests::case_%d ... ok\n' % i)
            out += '\ntest result: ok. %d passed; 0 failed; 0 ignored\n' % count
        return out

    def zero(self, argv, text, code=0):
        return runner._zero_tests(argv, code, text)

    def test_cargo(self):
        unit = self.libtest(0, 0)
        # As the runner joins them: libtest on stdout, cargo's headers on stderr.
        doc_only = unit + self.libtest(1, doc=True) + '\n' + self.CARGO_ERR
        self.assertTrue(self.zero(['cargo', 'test', '--', 'add'], doc_only))
        self.assertFalse(self.zero(['cargo', 'test'], self.libtest(1, 0) + self.libtest(1, doc=True)
                                   + '\n' + self.CARGO_ERR))
        self.assertTrue(self.zero(['cargo', 'test', '--no-run'],
                                  '  Executable unittests src/lib.rs (target/debug/deps/x)\n'))
        self.assertTrue(self.zero(['cargo', 'test', '--doc'], self.libtest(1, doc=True)))
        self.assertTrue(self.zero(['cargo', 'test', '-q', 'nomatch'], unit))
        self.assertTrue(self.zero(['cargo', 'test', '-q'], self.libtest(0) +
                                  self.libtest(1, doc=True)))
        self.assertFalse(self.zero(['cargo', 'test', '-q', 'case'], self.libtest(1)))

    def test_forge(self):
        self.assertTrue(self.zero(['forge', 'test'], 'Warning: No tests found in project! '
                                  'Forge looks for functions that start with `test`'))
        skipped = ('Ran 1 test for test/V.t.sol:VTest\n[SKIP] test_x()\n\nRan 1 test suite in '
                   '1.20ms (0.50ms CPU time): 0 tests passed, 0 failed, 1 skipped (1 total tests)')
        self.assertTrue(self.zero(['forge', 'test'], skipped))
        self.assertFalse(self.zero(['forge', 'test'], skipped.replace(
            '0 tests passed, 0 failed, 1 skipped', '1 tests passed, 0 failed, 0 skipped')))

    def test_mocha_hardhat_and_anchor(self):
        for argv in (['npx', 'hardhat', 'test'], ['npx', 'mocha', 'test/a.js'],
                     ['anchor', 'test'], ['yarn', 'run', 'ts-mocha', 'tests/x.ts']):
            self.assertTrue(self.zero(argv, '\n\n  0 passing (2ms)\n'), argv)
            self.assertTrue(self.zero(argv, '\x1b[32m  0 passing\x1b[0m (1ms)\n'), argv)
            self.assertFalse(self.zero(argv, '  0 passing (3ms)\n  1 failing\n'), argv)
            self.assertFalse(self.zero(argv, '  12 passing (40ms)\n'), argv)
            self.assertTrue(self.zero(argv, 'Compiled 3 Solidity files\n'), argv)

    def test_move_python_and_go(self):
        for argv in (['sui', 'move', 'test', 'nomatch'], ['aptos', 'move', 'test']):
            self.assertTrue(self.zero(argv, 'Test result: OK. Total tests: 0; passed: 0; '
                                            'failed: 0'))
            self.assertFalse(self.zero(argv, 'Test result: OK. Total tests: 2; passed: 2; '
                                             'failed: 0'))
        self.assertTrue(self.zero(['python3', '-m', 'unittest', '-k', 'x'],
                                  'Ran 0 tests in 0.000s\n\nOK\n'))
        self.assertFalse(self.zero(['python3', '-m', 'unittest'], 'Ran 1 test in 0.000s\n\nOK\n'))
        self.assertTrue(self.zero(['pytest', '-k', 'x'],
                                  'collected 2 items / 2 deselected / 0 selected', code=1))
        self.assertTrue(self.zero(['pytest'], 'collected 0 items\n', code=1))
        self.assertTrue(self.zero(['go', 'test', './...'],
                                  '?   \texample.com/p\t[no test files]\n'))
        mixed = ('ok  \texample.com/p\t0.004s\n'
                 'ok  \texample.com/q\t0.003s [no tests to run]\n')
        # Without -v a test that called t.Skip prints the same `ok` line as one that passed,
        # so only -v (or -json) output can show a test executed.
        self.assertTrue(self.zero(['go', 'test', '-run', 'TestA', './...'], mixed))
        self.assertFalse(self.zero(['go', 'test', '-v', '-run', 'TestA', './...'],
                                   '=== RUN   TestA\n--- PASS: TestA (0.00s)\nPASS\n' + mixed))

    def test_doc_tests_alone_never_conform_through_the_runner(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            bindir = repo / 'bin'
            bindir.mkdir()
            fake = bindir / 'cargo'
            fake.write_text('#!/bin/sh\nprintf "%s" "$OUT"\nprintf "%s" "$ERR" >&2\nexit 0\n')
            fake.chmod(0o755)
            plan = {'cases': [
                {'id': 'c', 'pair_id': 'p', 'role': 'candidate', 'argv': ['cargo', 'test', 'x']},
                {'id': 'n', 'pair_id': 'p', 'role': 'negative-control',
                 'argv': ['cargo', 'test', 'y']}], 'pass_env': ['OUT', 'ERR']}
            saved = dict(os.environ)
            try:
                os.environ.update(PATH=str(bindir) + os.pathsep + saved.get('PATH', ''),
                                  OUT=self.libtest(0, 0) + self.libtest(1, doc=True),
                                  ERR=self.CARGO_ERR)
                out = runner.execute(plan, repo, allow_exec=True)
            finally:
                os.environ.clear()
                os.environ.update(saved)
        self.assertEqual({case['status'] for case in out['cases']}, {'no-tests-ran'})
        self.assertNotEqual(out['result'], 'experiments-conformed')


# --------------------------------------------------------------------------- #
# 7. a blocker is a failure somebody observed
# --------------------------------------------------------------------------- #

class BlockerEvidenceTests(SubmissionCase):
    def blocker(self, **fields):
        return dict({'claim': 'the project cannot be built', 'command': 'forge build'}, **fields)

    def test_a_command_that_succeeded_is_not_a_blocker(self):
        success = self.blocker(exit_code=0, output_excerpt='Compiler run successful!')
        self.assertEqual(bounty.blocker_state(success), 'unverified')
        self.assertIn('exited 0', bounty.blocker_reason(success))
        clean = self.blocker(exit_code=0, output_excerpt='Compiler run successful with 0 errors')
        self.assertEqual(bounty.blocker_state(clean), 'unverified')

    def test_failure_evidence_reproduces_it(self):
        for fields in ({'exit_code': 1, 'output_excerpt': 'Error: unresolved import'},
                       {'exit_code': 0, 'output_excerpt': 'HTTP/1.1 403 Forbidden'},
                       {'exit_code': 0, 'output_excerpt': '{"jsonrpc":"2.0","error":{"code":'
                                                          '-32601,"message":"not available"}}'},
                       {'exit_code': 0, 'output_excerpt': 'debug_traceCall: method not found'}):
            self.assertEqual(bounty.blocker_state(self.blocker(**fields)), 'reproduced', fields)

    def test_an_exit_code_is_required(self):
        missing = self.blocker(output_excerpt='Error: unresolved import')
        self.assertEqual(bounty.blocker_state(missing), 'unverified')
        self.assertIn('exit_code', bounty.blocker_reason(missing))

    def test_the_queue_and_the_gate_say_why(self):
        held = bounty.template()
        held.update(id='BP-002', status='needs-evidence', revision=self.commit, title='t',
                    root_cause='r', affected_paths=['src/Vault.sol'], bug_class='x-y',
                    attacker_capabilities='a', preconditions='p', impact='i',
                    next_experiment={'question': 'q', 'method': 'm', 'expected_evidence': 'e',
                                     'blocker': self.blocker(exit_code=0, output_excerpt='ok')})
        errors = self.gates([self.record(), held])
        self.assertTrue(any('unverified blocker' in e and 'exited 0' in e for e in errors))
        queued = bounty.lead_queue(self.run)['unverified_blockers']
        self.assertIn('exited 0', queued[0]['reason'])


# --------------------------------------------------------------------------- #
# 8. secrets in commands and excerpts
# --------------------------------------------------------------------------- #

class SecretTests(SubmissionCase):
    def test_the_reported_shapes_are_detected(self):
        command = ('forge test --fork-url https://eth-mainnet.g.alchemy.com/v2/' + ALCHEMY_KEY
                   + ' --private-key ' + PRIVATE_KEY)
        kinds = bounty.secret_kinds(command)
        self.assertIn('an RPC provider key in a URL', kinds)
        self.assertIn('a secret passed as a command-line flag', kinds)
        for text in ('PRIVATE_KEY=' + PRIVATE_KEY + ' forge script X',
                     "curl -H 'Authorization: Bearer abcdef0123456789xyz' https://api.x.io",
                     'curl https://user:pass@rpc.example.com',
                     "curl 'https://api.etherscan.io/api?module=x&apikey=ABCD1234EFGH5678'",
                     'cast call --rpc-url https://mainnet.infura.io/v3/0123456789abcdef0123'):
            self.assertTrue(bounty.secret_kinds(text), text)

    def test_placeholders_and_ordinary_output_are_not_secrets(self):
        for text in ('forge test --fork-url $ETH_RPC_URL --private-key ${PRIVATE_KEY}',
                     'PRIVATE_KEY=$PK forge script X', 'forge verify-contract --etherscan-api-key '
                     '<key>', 'Error: HTTP 403 Forbidden from https://rpc.ankr.com/eth',
                     'cast storage 0xdead 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a92'
                     '0a3ca505d382bbc', 'see https://docs.alchemy.com/reference/throughput-limits',
                     'https://github.com/org/repo/blob/v1/abcdefghijklmnopqrstuvwxyz'):
            self.assertEqual(bounty.secret_kinds(text), [], text)

    def test_check_names_the_field_and_never_echoes_the_value(self):
        row = self.record(command='forge test --mt test_exploit')
        row['evidence']['command'] = ('forge test --mt test_exploit --fork-url '
                                      'https://eth-mainnet.g.alchemy.com/v2/' + ALCHEMY_KEY)
        blocked = bounty.template()
        blocked.update(id='BP-002', status='hypothesis', revision=self.commit, title='t',
                       root_cause='r', affected_paths=['src/Vault.sol'], bug_class='x-y',
                       attacker_capabilities='a', preconditions='p', impact='i',
                       next_experiment={'question': 'q', 'method': 'm', 'expected_evidence': 'e',
                                        'blocker': {'claim': 'no archive', 'command': 'cast rpc',
                                                    'exit_code': 1, 'output_excerpt':
                                                    'cast --private-key ' + PRIVATE_KEY}})
        ledger = bounty.read_json(self.run / 'experiments.json')
        ledger['experiments'][0]['observation'] += ' ETHERSCAN_API_KEY=ABCD1234EFGH5678'
        bounty.dump(self.run / 'experiments.json', ledger)
        bounty.dump(self.run / 'findings.json', [row, blocked])
        errors = bounty.validate(self.run)
        joined = '\n'.join(errors)
        self.assertIn('finding[0]: evidence.command carries an RPC provider key', joined)
        self.assertIn('finding[1]: next_experiment.blocker.output_excerpt carries', joined)
        self.assertIn('experiments.json: experiments[0].observation carries', joined)
        self.assertIn('environment variable placeholder', joined)
        for secret in (ALCHEMY_KEY, PRIVATE_KEY, 'ABCD1234EFGH5678'):
            self.assertNotIn(secret, joined)


# --------------------------------------------------------------------------- #
# 9. soft spots: escalation, history ledger, empty dup map, audit inventory
# --------------------------------------------------------------------------- #

class SubmissionSoftSpotTests(SubmissionCase):
    def test_bare_not_applicable_amplifiers_and_no_ceiling_are_refused(self):
        row = self.record()
        row['escalation'] = {'attempted': [{'amplifier': a, 'result': 'not-applicable'}
                                           for a in bounty.ESCALATION_AMPLIFIERS]}
        errors = self.gates([row])
        self.assertTrue(any('not-applicable with no reason' in e for e in errors), errors)
        self.assertTrue(any('requires escalation.ceiling' in e for e in errors), errors)
        row['escalation'] = {'attempted': [{'amplifier': a, 'result': 'not-applicable',
                                            'anchor': 'the vault holds no shared pool'}
                                           for a in bounty.ESCALATION_AMPLIFIERS],
                             'ceiling': 'high', 'ceiling_evidence': 'the PoC drains one loan'}
        self.assertEqual(self.gates([row]), [])
        # Structure still lets an open record carry an unexplained one while it is worked.
        bounty.dump(self.run / 'findings.json', [dict(row, status='hypothesis', escalation={
            'attempted': [{'amplifier': 'timing', 'result': 'not-applicable'}]},
            next_experiment={'question': 'q', 'method': 'm', 'expected_evidence': 'e'})])
        self.assertEqual(bounty.validate(self.run), [])

    def test_a_missing_ledger_is_recorded_and_never_a_clean_no_match(self):
        row = self.record()
        self.ledger = self.base / 'private' / 'typo.jsonl'
        errors = self.gates([row])
        self.assertTrue(any('found no ledger' in e and 'BP-001' in e for e in errors), errors)
        matches = bounty.read_json(self.run / 'history-matches.json')
        self.assertEqual((matches['ledger_found'], matches['ledger_created']), (False, False))
        self.assertIn('never a clean no-match', matches['warning'])
        self.assertFalse(self.ledger.exists())        # a second run must not read it as found
        self.assertTrue(any('found no ledger' in e for e in self.gates([row])))
        created = bounty.history_check(self.run, self.ledger, project='example.invalid/test',
                                       create_ledger=True)
        self.assertTrue(created['ledger_created'])
        self.assertEqual(stat.S_IMODE(self.ledger.stat().st_mode), 0o600)
        self.assertEqual(bounty.validate(self.run, submission=True), [])

    def test_a_history_result_from_before_ledger_tracking_must_be_rerun(self):
        row = self.record()
        self.assertEqual(self.gates([row]), [])
        data = bounty.read_json(self.run / 'history-matches.json')
        del data['ledger_found'], data['ledger_created']
        bounty.dump(self.run / 'history-matches.json', data)
        self.assertTrue(any('rerun history check' in e
                            for e in bounty.validate(self.run, submission=True)))

    def test_an_empty_dup_map_needs_the_sources_that_were_read(self):
        row = self.record()
        errors = self.gates([row], empty_map_reason=None)
        self.assertTrue(any(e.startswith('dup-map.json: empty') for e in errors), errors)
        self.assertEqual(self.gates([row], empty_map_reason='Known-issues page read.'), [])
        # The statement survives a rerun while the map stays empty.
        bounty.dup_check(self.run)
        self.assertEqual(bounty.validate(self.run, submission=True), [])
        bounty.dump(self.run / 'dup-map.json', [{
            'id': 'KI-1', 'kind': 'past-audit', 'source': 'https://x.invalid/audit.pdf',
            'surfaces': ['src/Other.sol'], 'bug_classes': ['reentrancy']}])
        result = bounty.dup_check(self.run)
        self.assertEqual(result['empty_map_reason'], '')
        self.assertEqual(bounty.validate(self.run, submission=True), [])

    def test_the_inventory_is_required(self):
        row = self.record()
        self.assertEqual(self.gates([row]), [])
        (self.run / 'audit-inventory.json').unlink()
        self.assertTrue(any(e.startswith('audit-inventory.json: missing')
                            for e in bounty.validate(self.run, submission=True)))


class CliFlagTests(SubmissionCase):
    def main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = bounty.main(list(argv))
        return code, out.getvalue()

    def test_the_new_flags_are_wired(self):
        bounty.dump(self.run / 'findings.json', [])
        ledger = self.base / 'private' / 'fresh.jsonl'
        code, out = self.main('history', 'check', '--run', str(self.run), '--ledger',
                              str(ledger), '--project', 'example.invalid/test',
                              '--create-ledger')
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)['ledger_created'])
        self.assertTrue(ledger.is_file())
        code, out = self.main('dup-check', '--run', str(self.run), '--empty-map-reason',
                              'Known-issues page and the 2025 audit, read 2026-10-17')
        self.assertEqual(json.loads(out)['empty_map_reason'],
                         'Known-issues page and the 2025 audit, read 2026-10-17')


if __name__ == '__main__':
    unittest.main()
