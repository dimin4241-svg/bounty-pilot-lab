"""Regressions for the P1 items of the 2026-10-21 review of 0.22.0 (`2924bc2`).

Every test here failed on `2924bc2`. Each one names the review item it pins (A = bounty.py
1-2541, B = 2542-5800, C = 5801-7675, D = 7676-10413, E = the other scripts), and states the
failure it reproduces, so a later edit that brings one back says which promise it broke.
"""
import contextlib
import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/bounty-pilot/scripts'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bounty = load('p1_bounty', 'bounty.py')
stack_route = load('p1_stack_route', 'stack_route.py')
semantic_graph = load('p1_semantic_graph', 'semantic_graph.py')
state_graph = load('p1_state_graph', 'state_graph.py')
scope_coverage = load('p1_scope_coverage', 'scope_coverage.py')
scenario_runner = load('p1_scenario_runner', 'scenario_runner.py')

ALCHEMY = 'https://eth-mainnet.g.alchemy.com/v2/Kx7SECRETKEY9012345678901234'
PRIVATE_KEY = '0x' + 'ab' * 32


def git(repo, *args):
    subprocess.run(['git', '-C', str(repo), *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def commit(repo, message='fixture'):
    git(repo, 'add', '-A')
    git(repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
        '-c', 'commit.gpgsign=false', 'commit', '-qm', message)


@contextlib.contextmanager
def chdir(path):
    old = os.getcwd()
    os.chdir(str(path))
    try:
        yield
    finally:
        os.chdir(old)


class Fixture(unittest.TestCase):
    """A committed one-contract target and a private run directory next to it."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        (self.repo / 'test').mkdir()
        git(self.repo, 'init', '-q')
        (self.repo / 'src/Vault.sol').write_text('contract Vault { function f() external {} }\n')
        (self.repo / 'test/Vault.t.sol').write_text('contract VaultTest {}\n')
        (self.repo / 'foundry.toml').write_text('[profile.default]\nsrc = "src"\n')
        commit(self.repo)
        self.run = self.base / 'run'
        bounty.initialize(self.repo, self.run)


# ---------------------------------------------------------------------------------------------
# Group 1: running target code, and leaking secrets
# ---------------------------------------------------------------------------------------------

class ToolchainProbeIsolationTests(Fixture):
    """A1: the version probes ran in the caller's directory and picked up the target's config."""

    def fake_tool(self, name):
        bin_dir = self.base / 'bin'
        bin_dir.mkdir(exist_ok=True)
        tool = bin_dir / name
        # Prints where it ran and whether yarn's own escape hatch was set.
        tool.write_text('#!/bin/sh\necho "9.9.9 cwd=$PWD ignore=${YARN_IGNORE_PATH:-unset}"\n')
        tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
        return bin_dir

    def test_version_probes_never_run_inside_the_target_checkout(self):
        (self.repo / '.yarnrc').write_text('yarn-path "./tools/yarn-shim.js"\n')
        bin_dir = self.fake_tool('yarn')
        with chdir(self.repo), mock.patch.dict(os.environ, {'PATH': str(bin_dir)}), \
                mock.patch.object(bounty, 'TOOLCHAIN_PROBES', (('yarn', ('yarn', '--version')),)):
            found = bounty._probe_toolchains(5)
        version = found['yarn']['version']
        self.assertNotIn(str(self.repo), version)            # failed on 2924bc2: cwd=<repo>
        self.assertIn('ignore=1', version)                   # yarn-path switched off as well

    def test_toolchain_downloads_are_switched_off(self):
        self.assertEqual(bounty.TOOLCHAIN_PROBE_ENV.get('GOTOOLCHAIN'), 'local')


class DeepProbeEndpointTests(Fixture):
    """A7: --deep output that echoed the RPC endpoint was stored in capabilities.json."""

    RPC = 'http://10.0.0.5:8545'

    def test_deep_test_output_is_scrubbed_of_the_endpoint(self):
        # The endpoint reaches the test the way MAINNET_RPC_URL does: through the environment.
        echo = ('python3', '-c',
                'import os; print("fork failed: could not reach " + os.environ["P1_FORK_URL"])')
        node_answers = {'eth_chainId': '0x1', 'eth_blockNumber': '0x200000',
                        'eth_getBalance': '0x0', 'eth_getLogs': []}

        def opener(request, timeout=None):
            body = json.loads(request.data.decode('utf-8'))
            payload = {'jsonrpc': '2.0', 'id': body['id'],
                       'result': node_answers.get(body['method'])}

            class Response:
                def read(self):
                    return json.dumps(payload).encode('utf-8')

                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False
            return Response()
        with mock.patch.dict(os.environ, {'P1_FORK_URL': self.RPC}), \
                mock.patch.object(bounty, 'TOOLCHAIN_PROBES', (('python3', ('python3', '--version')),)), \
                mock.patch.object(bounty, 'BUILD_COMMANDS', (('foundry.toml', echo, 'python3'),)), \
                mock.patch.object(bounty, 'TEST_COMMANDS', (('foundry.toml', echo, 'python3'),)):
            bounty.capability_probe(self.repo, self.run, rpc=self.RPC, deep=True, opener=opener)
        stored = (self.run / 'capabilities.json').read_text()
        self.assertIn('fork failed', stored)                 # the excerpt itself is kept
        self.assertNotIn('10.0.0.5', stored)                 # failed on 2924bc2


class GitFsmonitorTests(unittest.TestCase):
    """E5: helper git calls ran the target's core.fsmonitor program, even in a dry-run."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name).resolve()
        self.repo = base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        (self.repo / 'src/a.py').write_text('def f():\n    return 1\n')
        commit(self.repo)
        self.marker = base / 'fsmonitor-ran'
        hook = base / 'hook.sh'
        hook.write_text(f'#!/bin/sh\ntouch "{self.marker}"\nexit 1\n')
        hook.chmod(hook.stat().st_mode | stat.S_IXUSR)
        git(self.repo, 'config', 'core.fsmonitor', str(hook))
        self.run = base / 'run'
        self.run.mkdir()
        # Control: the planted hook must actually fire for a plain git call, or the test below
        # would pass vacuously on a git that ignores fsmonitor for these commands.
        subprocess.run(['git', '-C', str(self.repo), 'status', '--porcelain'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not self.marker.exists():
            self.skipTest('this git never runs core.fsmonitor, so there is nothing to block')
        self.marker.unlink()

    def assert_hook_never_ran(self, call):
        call()
        self.assertFalse(self.marker.exists())

    def test_stack_route(self):
        self.assert_hook_never_ran(lambda: stack_route.route(self.repo))

    def test_semantic_graph_py_symbols(self):
        self.assert_hook_never_ran(lambda: semantic_graph.py_symbols(self.repo))

    def test_state_graph_tracked(self):
        self.assert_hook_never_ran(lambda: state_graph._tracked(self.repo))

    def test_scope_coverage_audit(self):
        self.assert_hook_never_ran(lambda: scope_coverage.audit(self.repo, self.run))

    def test_scenario_runner_checkout_identity(self):
        self.assert_hook_never_ran(lambda: scenario_runner._checkout_identity(self.repo))


class BundleRedactionTests(Fixture):
    """C9: --include bodies and run-context files went into bundles unredacted."""

    def test_included_file_is_redacted_and_counted(self):
        extra = self.base / 'hardhat.config.ts'
        extra.write_text(f'networks: {{ mainnet: {{ url: "{ALCHEMY}",\n'
                         f'  accounts: ["{PRIVATE_KEY}"] }} }}\n')
        result = bounty.bundle(self.repo, self.run, ['accounting'], includes=[str(extra)])
        text = (self.run / 'bundles/accounting-bundle.md').read_text()
        self.assertNotIn('Kx7SECRETKEY9012345678901234', text)   # failed on 2924bc2
        self.assertNotIn(PRIVATE_KEY[2:], text)                   # failed on 2924bc2
        self.assertTrue(any(r['path'].endswith('hardhat.config.ts')
                            for r in result['redacted_secrets']))

    def test_run_context_notes_are_redacted(self):
        (self.run / 'coverage.md').write_text(
            '| Surface | Lens | Pass | Result |\n|---|---|---|---|\n'
            f'| src/Vault.sol | accounting | 1 | forked at {ALCHEMY} |\n')
        bounty.bundle(self.repo, self.run, ['accounting'])
        text = (self.run / 'bundles/accounting-bundle.md').read_text()
        self.assertNotIn('Kx7SECRETKEY9012345678901234', text)   # failed on 2924bc2

    def test_account_keys_in_tracked_config_are_redacted(self):
        (self.repo / 'hardhat.config.js').write_text(
            f'module.exports = {{ networks: {{ main: {{ accounts: ["{PRIVATE_KEY}"] }} }} }};\n')
        commit(self.repo, 'config')
        bounty.bundle(self.repo, self.run, ['accounting'])
        text = (self.run / 'bundles/accounting-bundle.md').read_text()
        self.assertNotIn(PRIVATE_KEY[2:], text)                   # failed on 2924bc2

    def test_a_bytes32_constant_in_source_is_left_alone(self):
        source, count = bounty._redact_source_secrets(
            f'bytes32 constant ROOT = {PRIVATE_KEY};\nuint256[] accounts = [1, 2];\n')
        self.assertIn(PRIVATE_KEY, source)
        self.assertEqual(count, 0)


class NestedSecretScanTests(unittest.TestCase):
    """B9: the record secret scan read only top-level string values."""

    def errors_for(self, evidence):
        errors = []
        bounty._check_record_secrets({'evidence': evidence}, 'BP-001', errors)
        return errors

    def test_a_key_in_a_list_is_flagged(self):
        errors = self.errors_for({'commands': [f'cast call --rpc-url {ALCHEMY} 0x1 "f()"']})
        self.assertTrue(any('evidence.commands[0]' in e for e in errors), errors)

    def test_a_key_in_a_nested_object_is_flagged(self):
        errors = self.errors_for({'runs': {'fork': ALCHEMY}})
        self.assertTrue(any('evidence.runs.fork' in e for e in errors), errors)

    def test_a_placeholder_is_still_clean(self):
        self.assertEqual(self.errors_for({'commands': ['cast call --rpc-url $ETH_RPC_URL']}), [])


# ---------------------------------------------------------------------------------------------
# Group 2: false `exact` in verify-deployment
# ---------------------------------------------------------------------------------------------

class Response:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode('utf-8')

    def read(self):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Node:
    """Answers JSON-RPC from a dict. An answer that is an `Error` comes back as an error object;
    an eth_call nobody configured reverts the way a node says it does (code 3)."""

    class Error:
        def __init__(self, code, message):
            self.error = {'code': code, 'message': message}

    def __init__(self, answers):
        self.answers = answers

    def __call__(self, request, timeout=None):
        body = json.loads(request.data.decode('utf-8'))
        method, params = body['method'], body['params']
        value = self.answers.get(method, Node.Error(3, 'execution reverted'))
        if callable(value) and not isinstance(value, Node.Error):
            value = value(params)
        if isinstance(value, Node.Error):
            return Response({'jsonrpc': '2.0', 'id': body['id'], 'error': value.error})
        return Response({'jsonrpc': '2.0', 'id': body['id'], 'result': value})


SOLC_TAIL_A = ('a2' + '64' + b'ipfs'.hex() + '5822' + '12' * 34
               + '64' + b'solc'.hex() + '43' + '000818' + '0033')
SOLC_TAIL_B = SOLC_TAIL_A.replace('12' * 34, '34' * 34)


class VerifyDeploymentFalseExactTests(unittest.TestCase):
    address = '0x' + '22' * 20
    # Over SMALL_RUNTIME_BYTES, and it delegates: the shape of a diamond or a large proxy.
    big_delegating = '0x' + '6000' + '5af4' + '5b' * 1100

    def verify(self, code, artifact_code, calls=None, storage=None):
        calls, storage = calls or {}, storage or {}

        def call(params):
            selector = params[0]['data'][:10]
            return calls.get(selector, Node.Error(3, 'execution reverted'))

        def get_storage(params):
            return storage.get(params[1], '0x' + '00' * 32)
        node = Node({'eth_chainId': '0x1', 'eth_blockNumber': '0x100',
                     'eth_getCode': code, 'eth_getStorageAt': get_storage, 'eth_call': call})
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / 'a.json'
            artifact.write_text(json.dumps({'deployedBytecode': {'object': artifact_code}}))
            return bounty.verify_deployment('http://node.invalid', self.address, str(artifact),
                                            'latest', opener=node)

    def test_a_rate_limited_facets_probe_is_never_exact(self):
        facets = bounty.load_keccak().selector('facets()')
        rate_limited = Node.Error(-32005, 'rate limit exceeded')
        result = self.verify(self.big_delegating, self.big_delegating, calls={facets: rate_limited})
        self.assertNotEqual(result['deployment_status'], 'exact')   # failed on 2924bc2: exact
        self.assertEqual(result['proxy_resolution'], 'unresolved')
        self.assertTrue(any('rate limit' in e for e in result['proxy_resolution_errors']))

    def test_control_a_reverting_facets_probe_still_compares_exact(self):
        result = self.verify(self.big_delegating, self.big_delegating)
        self.assertEqual(result['deployment_status'], 'exact')
        self.assertEqual(result['proxy_resolution'], 'not-a-proxy')

    def test_a_null_storage_read_is_refused_not_read_as_empty(self):
        with self.assertRaises(ValueError):                         # 2924bc2 compared exact
            self.verify(self.big_delegating, self.big_delegating,
                        storage={slot: None for slot in bounty.proxy_slots().values()})

    def test_a_null_balance_is_refused_not_read_as_zero(self):
        node = Node({'eth_chainId': '0x1', 'eth_blockNumber': '0x100', 'eth_getCode': '0x',
                     'eth_getBalance': None})
        with self.assertRaises(ValueError):                         # 2924bc2 reported 0 wei
            bounty.value_at_risk('http://node.invalid', [self.address], opener=node)

    def test_executable_bytes_after_a_fake_map_header_are_not_stripped(self):
        def runtime(byte):
            tail = 'a1' + ('60' + byte) * 60 + '00' + b'solc'.hex()
            return '0x600060006000' + tail + format(len(tail) // 2, '04x')
        result = bounty.compare_bytecode(runtime('00'), runtime('ff'))
        self.assertNotEqual(result['status'], 'exact')              # failed on 2924bc2: exact

    def test_control_real_solc_metadata_still_strips(self):
        body = '0x6080604052' + '5b' * 40
        result = bounty.compare_bytecode(body + SOLC_TAIL_A, body + SOLC_TAIL_B)
        self.assertEqual(result['status'], 'exact')
        self.assertEqual(result['metadata_stripped'], [53, 53])

    def test_an_empty_artifact_is_a_mismatch(self):
        result = bounty.compare_bytecode('0x' + '60' * 64, '0x')
        self.assertEqual(result['status'], 'mismatch')              # 2924bc2: partial


# ---------------------------------------------------------------------------------------------
# Group 3: gates that passed when they should not
# ---------------------------------------------------------------------------------------------

def load_test_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tests' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hardening = load_test_module('p1_hardening', 'test_evidence_hardening.py')
fcov_fixture = load_test_module('p1_fcov', 'test_function_coverage.py')
gate = load('p1_gate', 'experiment_gate.py')


class DispatchLensColumnTests(Fixture):
    """B1: a lens named anywhere in a coverage.md row counted as read."""

    def test_only_the_lens_column_marks_a_lens_read(self):
        bounty.bundle(self.repo, self.run, ['privileged-path', 'liveness', 'accounting'])
        with open(self.run / 'coverage.md', 'a', encoding='utf-8') as out:
            out.write('| src/Vault.sol:Vault.f | privileged-path | 1 | read | '
                      'no liveness or accounting issue |\n')
        unread = {row['lens'] for row in bounty._dispatch_state(self.run)['unread']}
        self.assertEqual(unread, {'liveness', 'accounting'})       # 2924bc2: set()


class LexicalSolidityTests(Fixture):
    """B2: a graph holding any Solidity dropped every lexical .sol entry point."""

    def test_solidity_outside_the_graph_is_still_counted(self):
        graph = fcov_fixture.graph_of(self.base)
        bounty.dump(self.run / 'semantic-graph.json', graph)
        (self.repo / 'bridge').mkdir()
        (self.repo / 'bridge/Bridge.sol').write_text(
            'contract Bridge {\n    function lock(uint256 a) external {}\n'
            '    function release(uint256 a) external {}\n}\n')
        commit(self.repo, 'second solc version')
        bounty.function_coverage(self.run, repo=self.repo)
        rows = bounty.read_json(self.run / 'function-coverage.json')['unexamined']
        names = {(row['path'], row['name']) for row in rows}
        self.assertIn(('bridge/Bridge.sol', 'Bridge.lock'), names)     # 2924bc2: missing
        self.assertNotIn('lexical', {row['source'] for row in rows
                                     if row['path'] == 'src/Vault.sol'})


class ConvergeSeparationTests(Fixture):
    """B3/B4: converge merged two functions; a file-only record closed every sibling."""

    def reading(self, name, line):
        folder = self.base / 'readings'
        folder.mkdir(exist_ok=True)
        (folder / name).write_text(line + '\n')
        return folder

    def test_same_function_name_in_two_contracts_is_two_groups(self):
        self.reading('a.md', 'CANDIDATE | lens: a | surface: src/Vault.sol:Token.transfer | '
                             'bug_class: missing-auth')
        folder = self.reading('b.md', 'CANDIDATE | lens: b | surface: '
                                      'src/Vault.sol:WrappedToken.transfer | bug_class: missing-auth')
        result = bounty.converge([str(folder)], self.run)
        self.assertEqual(result['saturated_groups'], 0)               # 2924bc2: 1
        self.assertEqual(result['singletons'], 2)

    def test_underscore_function_is_its_own_group(self):
        self.reading('a.md', 'CANDIDATE | lens: a | surface: src/Vault.sol:Vault.withdraw | '
                             'bug_class: reentrancy')
        folder = self.reading('b.md', 'CANDIDATE | lens: b | surface: src/Vault.sol:Vault._withdraw '
                                      '| bug_class: reentrancy')
        result = bounty.converge([str(folder)], self.run)
        self.assertEqual(result['singletons'], 2)                     # 2924bc2: 0 (merged)

    def test_a_file_only_record_does_not_hide_a_sibling_singleton(self):
        folder = self.reading('a.md', 'LEAD | lens: a | surface: src/Vault.sol:Vault.sweep | '
                                      'bug_class: reentrancy')
        row = bounty.template()
        row.update(id='BP-001', title='t', root_cause='r', bug_class='reentrancy',
                   revision='abc', attacker_capabilities='a', preconditions='p', impact='i',
                   affected_paths=['src/Vault.sol'],
                   next_experiment={'question': 'q', 'method': 'm', 'expected_evidence': 'e',
                                    'blocker': ''})
        bounty.dump(self.run / 'findings.json', [row])
        bounty.converge([str(folder)], self.run)
        queue = bounty.lead_queue(self.run)
        self.assertEqual(queue['unrecorded_singletons']['count'], 1)  # 2924bc2: 0


class BookkeepingEvidenceTests(hardening.SubmissionCase):
    """B7: the run's own mechanical outputs were accepted as a PoC and its log."""

    def test_examined_json_is_not_a_log(self):
        row = self.record()
        hardening.bounty.dump(self.run / 'examined.json', {'surfaces': []})
        hardening.bounty.dump(self.run / 'readings-ledger.json', {'readings': {}})
        row['evidence']['log_path'] = 'examined.json'
        row['evidence']['poc_path'] = 'readings-ledger.json'
        errors = self.gates([row])
        self.assertTrue(any('evidence.log_path names examined.json' in e for e in errors), errors)
        self.assertTrue(any('evidence.poc_path names readings-ledger.json' in e for e in errors))


class DupJoinSpellingTests(Fixture):
    """C1: the dup join compared whole strings by substring."""

    def collisions(self, affected):
        bounty.dump(self.run / 'dup-map.json', [{
            'id': 'KI-1', 'kind': 'program-known-issue', 'source': 'https://example.invalid/known',
            'surfaces': ['src/oracle/PriceOracle.sol:latestAnswer'],
            'bug_classes': ['stale-price'], 'note': 'stale answer accepted'}])
        row = bounty.template()
        row.update(id='BP-001', title='t', root_cause='r', bug_class='stale-price',
                   revision='abc', attacker_capabilities='a', preconditions='p', impact='i',
                   affected_paths=[affected],
                   next_experiment={'question': 'q', 'method': 'm', 'expected_evidence': 'e',
                                    'blocker': ''})
        bounty.dump(self.run / 'findings.json', [row])
        return bounty.dup_check(self.run)['collisions']

    def test_every_documented_spelling_collides(self):
        for affected in ('src/oracle/PriceOracle.sol:PriceOracle.latestAnswer',
                         'src/oracle/PriceOracle.sol (latestAnswer)',
                         'src/oracle/PriceOracle.sol#L42',
                         'oracle/PriceOracle.sol:latestAnswer'):
            self.assertTrue(self.collisions(affected), affected)       # 2924bc2: [] for 3 of 4

    def test_control_another_function_in_the_file_does_not_collide(self):
        self.assertEqual(self.collisions('src/oracle/PriceOracle.sol:PriceOracle.getPrice'), [])


class HarvestTests(Fixture):
    """C2/C3/C10/C8: the closed-issue harvest and the map it is checked against."""

    def item(self, number, repo='org/contracts', labels=('wontfix',)):
        return {'number': number, 'title': f'issue {number}',
                'html_url': f'https://github.com/{repo}/issues/{number}',
                'repository_url': f'https://api.github.com/repos/{repo}',
                'labels': [{'name': name} for name in labels], 'body': ''}

    def harvest(self, payload, repo='org/contracts', labels=('wontfix',)):
        source = self.base / 'search.json'
        source.write_text(json.dumps(payload))
        return bounty.dup_harvest(self.run, repo=repo, labels=list(labels),
                                  from_file=str(source))

    def test_triage_does_not_carry_to_another_repository(self):
        self.harvest({'items': [self.item(12, 'org/frontend')]}, repo='org/frontend')
        data = bounty.read_json(self.run / 'dup-harvest.json')
        data['triage'] = {'#12': {'disposition': 'irrelevant', 'note': 'CI flake'}}
        bounty.dump(self.run / 'dup-harvest.json', data)
        result = self.harvest({'items': [self.item(12)]})
        self.assertEqual(result['untriaged'], ['#12'])                 # 2924bc2: []

    def test_one_number_in_two_repositories_is_two_candidates(self):
        result = self.harvest({'items': [self.item(7, 'org/a'), self.item(7, 'org/b')]},
                              repo='org/a')
        self.assertEqual(result['candidate_count'], 2)                # 2924bc2: 1
        self.assertEqual({c['ref'] for c in result['candidates']}, {'#7', 'org/b#7'})

    def test_a_saved_page_of_a_larger_search_is_truncated(self):
        result = self.harvest({'total_count': 450, 'incomplete_results': False,
                               'items': [self.item(n) for n in range(1, 101)]})
        self.assertTrue(result['truncated'])                           # 2924bc2: False
        result = self.harvest({'total_count': 3, 'incomplete_results': True,
                               'items': [self.item(1)]})
        self.assertTrue(result['truncated'])

    def test_a_label_the_repository_lacks_searches_nothing(self):
        def opener(request, timeout=None):
            if '/labels' in request.full_url:
                return Response([{'name': 'bug'}, {'name': 'enhancement'}])
            return Response({'total_count': 0, 'incomplete_results': False, 'items': []})
        result = bounty.dup_harvest(self.run, repo='org/contracts', labels=['wontfx'],
                                    opener=opener)
        self.assertEqual(result['labels_unknown'], ['wontfx'])
        self.assertTrue(result['vacuous'])                              # 2924bc2: False

    def test_a_label_on_page_four_is_found(self):
        pages = {page: [{'name': f'label-{page}-{i}'} for i in range(100)] for page in (1, 2, 3)}
        pages[4] = [{'name': 'wontfix'}]

        def opener(request, timeout=None):
            if '/labels' in request.full_url:
                page = int(request.full_url.rsplit('page=', 1)[1])
                return Response(pages.get(page, []))
            return Response({'total_count': 0, 'incomplete_results': False, 'items': []})
        result = bounty.dup_harvest(self.run, repo='org/contracts', opener=opener)
        self.assertIn('wontfix', result['labels'])                     # 2924bc2: cut at page 3

    def test_a_dup_map_that_is_not_a_list_is_refused(self):
        bounty.dump(self.run / 'dup-map.json', {})
        errors = []
        bounty._submission_dup_matches(self.run, bounty.read_json(self.run / 'run.json'), [],
                                       errors)
        self.assertTrue(any('must be a JSON array' in e for e in errors), errors)


class RunnerDetectionTests(unittest.TestCase):
    """E1/E8: a fake pytest or a failed import read as a test that ran."""

    def test_the_word_pytest_in_an_argument_is_not_pytest(self):
        argv = ['python3', '-m', 'timeit', '-s', 'print("1 passed in 0.01s")', 'pytest']
        with self.assertRaises(ValueError):                             # 2924bc2: allowed
            scenario_runner._reject_shell(argv)
        status, tool, _ = scenario_runner.read_test_output(argv, 0, '1 passed in 0.01s\n')
        self.assertNotEqual(status, 'ran')                              # 2924bc2: ran/pytest

    def test_launchers_and_long_command_forms_are_refused(self):
        for argv in (['perl', '-MPOSIX;system("id")', 'x.pl'], ['fish', '--command=id'],
                     ['setsid', 'sh', '-c', 'id'], ['xargs', 'sh', '-c', 'id'],
                     ['busybox', 'sh', '-c', 'id'], ['npx', '-c', 'id'],
                     ['uv', 'run', 'sh', '-c', 'id']):
            with self.assertRaises(ValueError, msg=argv):
                scenario_runner._reject_shell(argv)

    def test_control_real_test_commands_still_pass_and_detect(self):
        for argv in (['python3', '-m', 'pytest', '-q'], ['pytest', 'tests/'],
                     ['uv', 'run', 'pytest'], ['perl', '-MTest::More', 't/poc.t']):
            scenario_runner._reject_shell(argv)
        self.assertEqual(scenario_runner.read_test_output(
            ['uv', 'run', 'pytest'], 0, '1 passed in 0.01s\n')[0], 'ran')

    def test_a_unittest_import_error_is_no_test(self):
        output = ('E\n=====\nERROR: test_poc_typo (unittest.loader._FailedTest.test_poc_typo)\n'
                  'ImportError: Failed to import test module: test_poc_typo\n'
                  '-----\nRan 1 test in 0.000s\n\nFAILED (errors=1)\n')
        status, _, _ = scenario_runner.read_test_output(
            ['python3', '-m', 'unittest', 'test_poc_typo'], 1, output)
        self.assertEqual(status, 'no-tests-ran')                        # 2924bc2: ran


class PublishedRevisionTests(unittest.TestCase):
    """E2: a commit made in the target checkout itself passed as a published revision."""

    def test_a_local_commit_is_not_published_when_remote_refs_exist(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp).resolve() / 'repo'
            repo.mkdir()
            git(repo, 'init', '-q')
            (repo / 'Vault.sol').write_text('require(msg.sender == owner);\n')
            commit(repo, 'published')
            published = subprocess.run(['git', '-C', str(repo), 'rev-parse', 'HEAD'],
                                       capture_output=True, text=True).stdout.strip()
            git(repo, 'update-ref', 'refs/remotes/origin/main', published)
            (repo / 'Vault.sol').write_text('\n')
            commit(repo, 'drop the require')
            local = subprocess.run(['git', '-C', str(repo), 'rev-parse', 'HEAD'],
                                   capture_output=True, text=True).stdout.strip()
            self.assertTrue(gate._known_commit(str(repo), published))
            self.assertFalse(gate._known_commit(str(repo), local))      # 2924bc2: True


class BacktestSealTests(unittest.TestCase):
    """D4/D7/D9: the backtest credited findings that were never sealed."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name).resolve()
        self.repo = base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        (self.repo / 'src/Vault.sol').write_text('contract Vault {}\n')
        commit(self.repo)
        self.case = base / 'case'
        bounty.backtest_init('c', str(self.repo), str(self.case), None, None)
        self.run = base / 'run'
        bounty.initialize(self.repo, self.run)

    def finding(self, ident, **fields):
        row = bounty.template()
        row.update(id=ident, title='Oracle staleness', bug_class='stale-price', lens='oracle',
                   root_cause='latestAnswer age is never checked', status='hypothesis',
                   affected_paths=['src/Vault.sol'])
        row.update(fields)
        return row

    def test_a_matches_row_for_an_unsealed_finding_earns_nothing(self):
        bounty.dump(self.run / 'findings.json', [self.finding('BP-001', title='Unrelated',
                                                              bug_class='rounding',
                                                              affected_paths=['src/Other.sol'])])
        bounty.backtest_seal(str(self.case), str(self.run))
        bounty.dump(self.case / 'truth.json', [{'id': 'T-1', 'severity': 'high',
                                                'title': 'Stale oracle price', 'source': 'x'}])
        bounty.dump(self.case / 'matches.json', [{
            'truth_id': 'T-1', 'finding_id': 'BP-999', 'decision': 'same-mechanism',
            'decision_reason': 'added after reading the answers', 'finding_lens': 'oracle'}])
        result = bounty.backtest_score(str(self.case))
        self.assertEqual(result['rediscovered'], [])                    # 2924bc2: found_by BP-999
        self.assertEqual(result['credited_lenses'], {})

    def test_seal_refuses_unusable_ids_and_existing_decisions(self):
        bounty.dump(self.run / 'findings.json', [self.finding(7)])
        with self.assertRaises(ValueError):                              # 2924bc2: sealed
            bounty.backtest_seal(str(self.case), str(self.run))
        bounty.dump(self.run / 'findings.json', [self.finding('BP-001')])
        bounty.dump(self.case / 'matches.json', [])
        with self.assertRaises(ValueError):
            bounty.backtest_seal(str(self.case), str(self.run))

    def test_an_edited_sealed_note_voids_the_case(self):
        (self.run / 'coverage.md').write_text('| a | b | c |\n')
        bounty.dump(self.run / 'findings.json', [self.finding('BP-001')])
        bounty.backtest_seal(str(self.case), str(self.run))
        (self.case / 'sealed-coverage.md').write_text('| rewritten after the answers |\n')
        with self.assertRaises(ValueError):                              # 2924bc2: not checked
            bounty.backtest_score(str(self.case))


# ---------------------------------------------------------------------------------------------
# Group 4: the remaining P1 items
# ---------------------------------------------------------------------------------------------

class HistoryLedgerTests(Fixture):
    """A2/A3/A4: one character or one spelling could brick the ledger or hide a match."""

    def setUp(self):
        super().setUp()
        self.ledger = self.base / 'private' / 'history.jsonl'

    def imported(self, project, root_cause='stale price used'):
        return bounty.history_import(project, 'C4-1', 'stale-price', ['src/Vault.sol:Vault.f'],
                                     root_cause, 'duplicate', self.ledger)

    def test_a_line_separator_in_a_root_cause_does_not_brick_the_ledger(self):
        self.imported('https://github.com/org/vault', 'stale price used after a pause')
        self.imported('https://github.com/org/vault', 'second row')
        bounty.history_summary(self.ledger)                           # 2924bc2: not valid JSON
        self.assertNotIn(' ', self.ledger.read_text(encoding='utf-8'))
        self.assertEqual(len(self.ledger.read_text(encoding='utf-8').strip().split('\n')), 2)

    def test_owner_repo_is_the_github_key_a_remote_gives(self):
        self.assertEqual(bounty.canonical_project('owner/repo'), 'github.com/owner/repo')
        self.assertEqual(bounty.canonical_project('example.invalid/test'), 'example.invalid/test')
        row = bounty.template()
        row.update(id='BP-001', title='t', root_cause='stale price used', bug_class='stale-price',
                   revision='abc', attacker_capabilities='a', preconditions='p', impact='i',
                   affected_paths=['src/Vault.sol:Vault.f'],
                   next_experiment={'question': 'q', 'method': 'm', 'expected_evidence': 'e',
                                    'blocker': ''})
        bounty.dump(self.run / 'findings.json', [row])
        self.imported('https://github.com/Owner/Repo.git')
        result = bounty.history_check(self.run, self.ledger, 'owner/repo')
        self.assertTrue(result['matches'])                              # 2924bc2: no match

    def test_every_accepted_spelling_is_canonical_and_readable(self):
        for project in ('https://github.com/Owner/Repo.GIT', 'https://github.com/o/r/.git',
                        'git@github.com:Owner/Repo.git', 'Owner/Repo'):
            key = bounty.canonical_project(project)
            self.assertEqual(bounty.canonical_project(key), key, project)
            self.imported(project)
        bounty.history_summary(self.ledger)                           # 2924bc2: invalid row


class SubmoduleFixture(Fixture):
    """A target with one dependency submodule, bumped with `ignore = all` in .gitmodules."""

    def setUp(self):
        super().setUp()
        dep = self.base / 'dep'
        (dep / 'src').mkdir(parents=True)
        git(dep, 'init', '-q')
        (dep / 'src/Old.sol').write_text('contract Old {\n  function f() external {\n'
                                         '    require(msg.sender == owner);\n  }\n}\n')
        commit(dep)
        subprocess.run(['git', '-C', str(self.repo), '-c', 'protocol.file.allow=always',
                        'submodule', 'add', '-q', str(dep), 'lib/dep'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        commit(self.repo, 'add dependency')
        self.base_commit = subprocess.run(['git', '-C', str(self.repo), 'rev-parse', 'HEAD'],
                                          capture_output=True, text=True).stdout.strip()
        inner = self.repo / 'lib/dep'
        git(inner, 'mv', 'src/Old.sol', 'src/New.sol')
        (inner / 'src/New.sol').write_text('contract Old {\n  function f() external {\n'
                                           '  }\n}\n')
        commit(inner, 'move and drop the require')
        commit(self.repo, 'bump dependency')
        git(self.repo, 'config', '-f', '.gitmodules', 'submodule.lib/dep.ignore', 'all')
        commit(self.repo, 'quiet the submodule')


class DeltaSubmoduleTests(SubmoduleFixture):
    """C4/C5: delta lost an `ignore = all` bump and a renamed-and-modified dependency file."""

    def test_an_ignored_submodule_bump_is_still_listed(self):
        result = bounty.delta(self.repo, self.base_commit)
        self.assertEqual(result['changed_submodules'], 1)              # 2924bc2: 0
        row = next(r for r in result['ranked'] if r['kind'] == 'submodule')
        self.assertGreaterEqual(row['dependency_diff'].get('changed_source_files', 0), 1)


class AuditInventoryBindingTests(SubmoduleFixture):
    """C6/C7: the inventory gate accepted another run's file and missed common layouts."""

    def test_a_submodule_is_an_entry_to_account_for(self):
        result = bounty.audit_inventory(self.repo, self.run)
        self.assertIn('lib/dep', {row['path'] for row in result['artifacts']})  # 2924bc2: absent

    def test_an_inventory_from_another_run_is_refused(self):
        bounty.audit_inventory(self.repo, self.run)
        data = bounty.read_json(self.run / 'audit-inventory.json')
        data['run_id'] = 'SOME-OTHER-RUN'
        for row in data['artifacts']:
            row['triage'], row['note'] = 'not-applicable', 'vendored'
        bounty.dump(self.run / 'audit-inventory.json', data)
        errors = []
        bounty._check_audit_inventory(self.run, errors)
        self.assertTrue(any('different run' in e for e in errors), errors)  # 2924bc2: []

    def test_review_directories_and_firm_named_reports_are_found(self):
        for rel in ('audit-reports/2024-01-Spearbit.pdf', 'security-reviews/cantina-2025.pdf',
                    'docs/ChainSecurity_Vault_v2.pdf'):
            (self.repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / rel).write_bytes(b'%PDF-1.4\n')
        commit(self.repo, 'reports')
        found = {row['path'] for row in bounty.audit_inventory(self.repo, self.run)['artifacts']}
        for rel in ('audit-reports/2024-01-Spearbit.pdf', 'security-reviews/cantina-2025.pdf',
                    'docs/ChainSecurity_Vault_v2.pdf'):
            self.assertIn(rel, found)                                  # 2924bc2: none found


AUDITOR_TWO_FILES = """FINDING | contract: src/v1/Vault.sol | function: withdraw | bug_class: reentrancy | group_key: Vault | withdraw | reentrancy
confidence: 95
agents: 8
severity: High
description: v1 lets withdraw re-enter.

FINDING | contract: src/v2/Vault.sol | function: withdraw | bug_class: reentrancy | group_key: Vault | withdraw | reentrancy
description: v2 lets withdraw re-enter.
"""


class ImportTests(Fixture):
    """B5/B6/B10: import kept upstream confidence, merged files, and wrote invalid records."""

    def setUp(self):
        super().setUp()
        for version in ('v1', 'v2'):
            (self.repo / 'src' / version).mkdir()
            (self.repo / 'src' / version / 'Vault.sol').write_text(
                'contract Vault { function withdraw() external {} }\n')
        commit(self.repo, 'two versions')

    def source(self, text):
        path = self.base / 'auditor.md'
        path.write_text(text)
        return str(path)

    def test_same_contract_in_two_files_imports_twice_without_confidence(self):
        result = bounty.import_findings(self.run, [self.source(AUDITOR_TWO_FILES)],
                                        repo=self.repo)
        self.assertEqual(result['imported'], 2)                         # 2924bc2: 1
        rows = bounty.read_json(self.run / 'findings.json')
        reported = rows[0]['origin']['reported']
        for name in ('confidence', 'agents', 'severity'):
            self.assertNotIn(name, reported)                             # 2924bc2: carried

    def test_a_bug_class_with_no_place_is_not_imported(self):
        result = bounty.import_findings(
            self.run, [self.source('CANDIDATE | lens: accounting | bug_class: rounding-drift\n')],
            repo=self.repo)
        self.assertEqual(result['imported'], 0)                         # 2924bc2: 1 invalid
        self.assertFalse(any('affected_paths' in e for e in bounty.validate(self.run)))


class AddressChainBindingTests(hardening.SubmissionCase):
    """B8: per-address chain_id in program.json was flattened into one chain set."""

    def test_an_address_read_on_another_listed_chain_is_refused(self):
        row = self.record()
        listed = row['deployment_evidence'][0].split('/')[1][:-5]
        hardening.bounty.dump(self.run / 'program.json', {'in_scope_addresses': [
            {'address': listed, 'chain_id': 8453}, {'address': '0x' + '99' * 20, 'chain_id': 1}]})
        errors = self.gates([row])
        self.assertTrue(any('on chain id(s) 8453 only' in e for e in errors), errors)

    def test_control_the_listed_chain_still_passes(self):
        row = self.record()
        listed = row['deployment_evidence'][0].split('/')[1][:-5]
        hardening.bounty.dump(self.run / 'program.json', {'in_scope_addresses': [
            {'address': listed, 'chain_id': 1}, {'address': '0x' + '99' * 20, 'chain_id': 8453}]})
        self.assertEqual(self.gates([row]), [])


class RunnerOutputTests(unittest.TestCase):
    """E6/E7/E10: cargo -v, a long forge run, and two ids sharing one log."""

    def test_cargo_verbose_compiler_lines_are_not_test_binaries(self):
        output = ('   Compiling poc v0.1.0\n'
                  '     Running `rustc --crate-name poc --edition=2021 src/lib.rs`\n'
                  '     Running `/tmp/target/debug/deps/poc-abc123 test_exploit`\n\n'
                  'running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured;'
                  ' 3 filtered out\n\n   Doc-tests poc\n'
                  '     Running `rustdoc --edition=2021 --test src/lib.rs`\n\n'
                  'running 1 test\ntest src/lib.rs - Vault::withdraw (line 10) ... ok\n\n'
                  'test result: ok. 1 passed; 0 failed; 0 ignored\n')
        self.assertTrue(scenario_runner._cargo_zero(                 # 2924bc2: False
            ['cargo', 'test', '-v', 'test_exploit'], output.lower()))

    def test_a_forge_header_with_only_skips_is_no_test(self):
        text = 'Ran 1 test for test/V.t.sol:VTest\n[SKIP] test_x()\n'
        self.assertEqual(scenario_runner.read_test_output(['forge', 'test'], 0, text)[0],
                         'no-tests-ran')                               # 2924bc2: ran

    def test_detection_reads_the_tail_of_a_long_output(self):
        blob = b'trace line\n' * 10000 + b'Ran 1 test suite: 0 tests passed, 0 failed, 1 skipped'
        text = scenario_runner._detection_text(blob)
        self.assertIn('1 skipped', text)
        self.assertEqual(scenario_runner.read_test_output(['forge', 'test'], 0, text)[0],
                         'no-tests-ran')

    def test_two_ids_that_sanitise_alike_get_two_logs(self):
        with tempfile.TemporaryDirectory() as temp:
            report = {'cases': [{'id': 'poc 1', 'executed': True, 'argv': ['a'], 'stdout': 'A'},
                                {'id': 'poc_1', 'executed': True, 'argv': ['b'], 'stdout': 'B'}]}
            written = scenario_runner.write_case_logs(report, Path(temp) / 'r.json')
            self.assertEqual(len(set(written)), 2)                     # 2924bc2: one file
            first = (Path(temp) / report['cases'][0]['log_file']).read_text()
            self.assertIn('A', first)


if __name__ == '__main__':
    unittest.main()
