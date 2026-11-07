"""The legacy sweep: addresses the repository once deployed and HEAD no longer mentions.

The fixture is a three-commit repository: an OldVault deployment (A) that is later replaced by a
NewVault (B) and deleted, a README that names C, a test file that names D, and the zero address.
A must surface as a removed legacy candidate, B and C as current, D only as an excluded count.
"""
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
import unittest.mock
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = 'skills/bounty-pilot/scripts/legacy_sweep.py'


def load():
    spec = importlib.util.spec_from_file_location('legacy_sweep', ROOT / SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ls = load()
A = '0x' + 'aa' * 19 + 'a1'
B = '0x' + 'bb' * 19 + 'b2'
C = '0x' + 'cc' * 19 + 'c3'
D = '0x' + 'dd' * 19 + 'd4'
ZERO = '0x' + '00' * 20
TOKEN = '0x' + '77' * 20
URL = 'https://rpc.secret-host.example/v2/KEY123456'
ENV = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t', GIT_COMMITTER_NAME='t',
           GIT_COMMITTER_EMAIL='t@t')


def git(repo, *args, date=None):
    env = dict(ENV)
    if date:
        env.update(GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
    subprocess.run(['git', '-C', str(repo), *args], check=True, env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write(repo, rel, text):
    path = Path(repo) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


def make_repo(tmp):
    repo = Path(tmp) / 'target'
    repo.mkdir()
    git(repo, 'init', '-q')
    write(repo, 'deployments/mainnet/OldVault.json', json.dumps({'address': A.upper().replace('0X', '0x')}))
    write(repo, 'test/Vault.t.sol', f'address constant D = {D};\naddress z = {ZERO};\n')
    write(repo, 'README.md', f'Router: {C}\nnull: {ZERO}\n')
    git(repo, 'add', '-A')
    git(repo, 'commit', '-qm', 'deploy old vault', date='2021-03-01T00:00:00+00:00')
    write(repo, 'deployments/mainnet/OldVault.json', json.dumps({'address': A, 'v': 2}))
    git(repo, 'commit', '-qam', 'touch old vault', date='2021-06-01T00:00:00+00:00')
    (repo / 'deployments/mainnet/OldVault.json').unlink()
    write(repo, 'deployments/mainnet/NewVault.json', json.dumps({'address': B}))
    git(repo, 'add', '-A')
    git(repo, 'commit', '-qm', 'replace vault', date='2023-01-01T00:00:00+00:00')
    return repo


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def opener_for(chain_id=1, fail_address=None):
    sent = []

    def opener(request, timeout):
        body = json.loads(request.data.decode('utf-8'))
        method, params = body['method'], body['params']
        sent.append(method)
        if fail_address and params and params[0] == fail_address:
            raise urllib.error.URLError(f'connect to {URL} failed (rpc.secret-host.example)')
        result = {'eth_chainId': hex(chain_id), 'eth_blockNumber': hex(100)}.get(method)
        if method == 'eth_getCode':
            result = '0x6080' if params[0] == A else '0x'
        elif method == 'eth_getBalance':
            result = '0x0'
        elif method == 'eth_call':
            holder = '0x' + params[0]['data'][-40:]
            result = '0x' + format(5000 if holder == A else 0, '064x')
        return FakeResponse(json.dumps({'jsonrpc': '2.0', 'id': 1,
                                        'result': result}).encode('utf-8'))
    opener.sent = sent
    return opener


class LegacySweepTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = make_repo(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def by_address(self, report):
        return {row['address']: row for row in report['addresses']}

    def test_balance_of_selector_is_derived(self):
        self.assertEqual(ls.BALANCE_OF, '0x70a08231')

    def test_history_classification(self):
        report = ls.sweep(self.repo)
        rows = self.by_address(report)
        self.assertEqual(rows[A]['status'], 'removed')
        self.assertFalse(rows[A]['present_at_head'])
        self.assertTrue(rows[A]['first_seen']['date'].startswith('2021-03-01'))
        self.assertTrue(rows[A]['last_seen']['date'].startswith('2023-01-01'))
        self.assertIn('deployments/mainnet/OldVault.json', rows[A]['paths'])
        self.assertEqual(rows[A]['label'], 'OldVault')
        self.assertEqual([r['address'] for r in report['legacy_candidates']], [A])
        self.assertEqual(rows[B]['status'], 'current')
        self.assertEqual(rows[C]['status'], 'current')
        self.assertNotIn(D, rows)
        self.assertNotIn(ZERO, rows)
        self.assertEqual(report['counts']['excluded_test_or_lib_only'], 1)
        self.assertEqual(report['commits_scanned'], 3)
        self.assertFalse(report['truncated'])
        self.assertNotIn('endpoint', report)
        self.assertIn('previous versions', report['notice'])

    def test_program_scope(self):
        program = Path(self.tmp.name) / 'program.json'
        program.write_text(json.dumps({'in_scope_addresses': [B.upper().replace('0X', '0x')],
                                       'chain_ids': [1]}))
        rows = self.by_address(ls.sweep(self.repo, program=program))
        self.assertEqual(rows[B]['scope'], 'in_scope')
        self.assertEqual(rows[A]['scope'], 'not_listed')
        self.assertEqual(rows[C]['scope'], 'not_listed')

    def test_rpc_ranking_and_scrubbing(self):
        # A second removed address with no code, to show ranking and per-address errors.
        E = '0x' + 'ee' * 19 + 'e5'
        F = '0x' + 'ff' * 19 + 'f6'
        write(self.repo, 'deployments/mainnet/Gone.json', json.dumps({'Gone': E, 'Broken': F}))
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-qm', 'gone', date='2023-02-01T00:00:00+00:00')
        (self.repo / 'deployments/mainnet/Gone.json').unlink()
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-qm', 'drop gone', date='2023-03-01T00:00:00+00:00')
        program = Path(self.tmp.name) / 'program.json'
        program.write_text(json.dumps({'in_scope_addresses': [B], 'chain_ids': [10]}))
        opener = opener_for(chain_id=1, fail_address=F)
        report = ls.sweep(self.repo, program=program, rpc=URL, tokens=[TOKEN], opener=opener)
        self.assertEqual(set(opener.sent), {'eth_chainId', 'eth_blockNumber', 'eth_getCode',
                                            'eth_getBalance', 'eth_call'})
        candidates = report['legacy_candidates']
        self.assertEqual(candidates[0]['address'], A)
        self.assertTrue(candidates[0]['onchain']['has_code'])
        self.assertEqual(candidates[0]['onchain']['balances'][TOKEN], '5000')
        self.assertEqual({r['address'] for r in candidates}, {A, E, F})
        broken = next(r for r in candidates if r['address'] == F)
        self.assertTrue(broken['onchain']['errors'])
        self.assertEqual(report['endpoint'], 'not recorded')
        self.assertTrue(report['chain_id_mismatch'])
        self.assertEqual(report['chain_id'], 1)
        text = json.dumps(report)
        self.assertNotIn('secret-host', text)
        self.assertNotIn('KEY123456', text)
        self.assertIn('<endpoint>', text)

    def test_truncation_reported(self):
        report = ls.sweep(self.repo, max_commits=1)
        self.assertTrue(report['truncated'])
        self.assertEqual(report['commits_scanned'], 1)
        self.assertEqual(report['commits_total'], 3)
        self.assertTrue(any('truncated' in n for n in report['notes']))

    def test_target_fsmonitor_never_runs(self):
        marker = Path(self.tmp.name) / 'pwned'
        hook = Path(self.tmp.name) / 'hook.sh'
        hook.write_text(f'#!/bin/sh\ntouch {marker}\n')
        hook.chmod(0o755)
        git(self.repo, 'config', 'core.fsmonitor', str(hook))
        git(self.repo, 'config', 'diff.external', str(hook))
        ls.sweep(self.repo)
        self.assertFalse(marker.exists())

    def test_cli_writes_report(self):
        out = Path(self.tmp.name) / 'legacy.json'
        with unittest.mock.patch('sys.stdout', new=io.StringIO()):
            self.assertEqual(ls.main(['--repo', str(self.repo), '--out', str(out)]), 0)
        report = json.loads(out.read_text())
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(report['counts']['removed'], 1)


if __name__ == '__main__':
    unittest.main()
