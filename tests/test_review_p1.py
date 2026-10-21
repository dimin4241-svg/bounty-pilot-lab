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


if __name__ == '__main__':
    unittest.main()
