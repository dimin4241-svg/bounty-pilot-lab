"""The agent-platform lens: registered, bundlable, documented, and not confusable with the
neighbours it overlaps (agent-wallet, agent-runner, web)."""
import contextlib
import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / 'skills/bounty-pilot'
sys.path.insert(0, str(SKILL / 'scripts'))

spec = importlib.util.spec_from_file_location('bp_platform_bounty',
                                              SKILL / 'scripts/bounty.py')
bounty = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounty)


def git_repo(files):
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    subprocess.run(['git', '-C', str(root), 'add', '-A'], check=True)
    subprocess.run(['git', '-C', str(root), '-c', 'user.name=t', '-c', 'user.email=t@t',
                    'commit', '-qm', 'init'], check=True)
    return root


class AgentPlatformLensTests(unittest.TestCase):
    def test_registered_with_instruction_file(self):
        self.assertEqual(bounty.AGENT_PLATFORM_LENSES, ('agentic-platform',))
        self.assertIn('agentic-platform', bounty.LENSES)
        path = SKILL / 'references/hunt-agents/agentic-platform-agent.md'
        self.assertTrue(path.is_file())
        text = path.read_text(encoding='utf-8')
        for heading in ('## Procedure', '## Where the money is', '## Proof standard',
                        '## What does not pay', '## Self-check'):
            self.assertIn(heading, text, heading)

    def test_group_bundles_the_lens(self):
        repo = git_repo({'app/page.tsx': 'export default function P() { return null }\n'})
        run = Path(tempfile.mkdtemp()) / 'run'
        with contextlib.redirect_stdout(io.StringIO()):
            bounty.initialize(str(repo), str(run))
        result = bounty.bundle(str(repo), str(run), ['agent-platform'])
        self.assertEqual({row['lens'] for row in result['bundles']}, {'agentic-platform'})

    def test_group_is_not_part_of_frontier_or_web(self):
        self.assertNotIn('agentic-platform', bounty.FRONTIER_LENSES)
        self.assertNotIn('agentic-platform', bounty.WEB_LENSES)
        self.assertNotIn('agentic-platform', bounty.WALLET_LENSES)

    def test_documented_in_lens_and_pass_tables(self):
        lenses = (SKILL / 'references/lenses.md').read_text(encoding='utf-8')
        passes = (SKILL / 'references/passes.md').read_text(encoding='utf-8')
        self.assertIn('agentic-platform-agent.md', lenses)
        self.assertIn('--lens agent-platform', lenses)
        self.assertIn('`agentic-platform`', passes)

    def test_unknown_group_message_lists_it(self):
        repo = git_repo({'a.ts': 'x\n'})
        run = Path(tempfile.mkdtemp()) / 'run'
        with contextlib.redirect_stdout(io.StringIO()):
            bounty.initialize(str(repo), str(run))
        with self.assertRaises(ValueError) as ctx:
            bounty.bundle(str(repo), str(run), ['no-such-group'])
        self.assertIn('agent-platform', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
