"""Local signing-control-plane lens, routing and safety contract."""
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/bounty-pilot/scripts'
LENS = ROOT / 'skills/bounty-pilot/references/hunt-agents/signing-control-plane-agent.md'


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / file)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


bounty = module('signing_bounty', 'bounty.py')
stack_route = module('signing_stack_route', 'stack_route.py')


class SigningControlPlaneTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name) / 'repo'
        self.repo.mkdir()

    def fixture(self, files):
        for path, body in files.items():
            dest = self.repo / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(body, encoding='utf-8')
        subprocess.run(['git', '-C', str(self.repo), 'init', '-q'], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'add', '-A'], check=True)
        subprocess.run(['git', '-C', str(self.repo), '-c', 'user.name=Test',
                        '-c', 'user.email=test@example.invalid',
                        '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture'], check=True)

    def test_group_bundles_instructions_and_source(self):
        self.fixture({'contracts/Vault.sol': 'contract Vault {}\n'})
        self.assertIn('signing-control-plane', bounty.LENSES)
        self.assertEqual(bounty.ATTACK_LENSES[0], 'privileged-path')
        self.assertIn('signing-control-plane', bounty.CROSS_STACK_LENSES)
        run = self.repo.parent / 'run'
        bounty.initialize(self.repo, run)
        result = bounty.bundle(self.repo, run, ['signing'])
        self.assertEqual([entry['lens'] for entry in result['bundles']],
                         ['signing-control-plane'])
        bundle = (run / 'bundles/signing-control-plane-bundle.md').read_text()
        self.assertIn('approved intent versus actual signature', bundle)
        self.assertIn('contract Vault', bundle)

    def test_named_offchain_signer_routes(self):
        self.fixture({
            'package.json': '{"dependencies":{"express":"^4.0.0"}}',
            'services/signing-worker.ts': 'export const sign = (hsm, x) => hsm.sign(x);\n',
        })
        data = stack_route.route(self.repo)
        self.assertTrue(data['signing_signals'])
        self.assertIn('signing-control-plane', data['prioritization']['selected'])
        self.assertIn('signing-control-plane', data['suggested_cross_stack_lenses'])

    def test_generic_api_can_expose_sign_transaction(self):
        self.fixture({
            'package.json': '{"dependencies":{"fastify":"^4.0.0"}}',
            'api/operations.ts':
                'export const run = (signer, tx) => signer.signTransaction(tx);\n',
        })
        data = stack_route.route(self.repo)
        self.assertTrue(data['signing_signals'])
        self.assertIn('signing-control-plane', data['prioritization']['selected'])

    def test_contract_only_signer_not_routed_as_backend(self):
        self.fixture({'foundry.toml': '[profile.default]\nsrc="src"\n',
                      'src/WalletSigner.sol': 'contract WalletSigner {}\n'})
        data = stack_route.route(self.repo)
        self.assertFalse(data['signing_signals'])
        self.assertNotIn('signing-control-plane', data['prioritization']['selected'])

    def test_unrelated_backend_not_routed_as_signer(self):
        self.fixture({'package.json': '{"dependencies":{"express":"^4.0.0"}}',
                      'api/health.ts': 'export const health = () => true;\n'})
        data = stack_route.route(self.repo)
        self.assertFalse(data['signing_signals'])
        self.assertNotIn('signing-control-plane', data['prioritization']['selected'])

    def test_lens_requires_evidence_and_local_controls(self):
        content = LENS.read_text()
        for item in ('lower-privileged', 'negative-control', 'EIP-7702',
                     '50\npre-signed', 'file:line', 'synthetic keys',
                     'no production signer API', 'final post-mortem'):
            self.assertIn(item, content)


if __name__ == '__main__':
    unittest.main()
