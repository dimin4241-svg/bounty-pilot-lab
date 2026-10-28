"""Release hygiene: the three version numbers agree, and shipped text carries no invisible bytes.

0.21.0 shipped with `.claude-plugin/plugin.json` still at 0.20.0, and with a literal carriage return
inside `tr -d '…'` in intake.md — rendered and read as `tr -d ''`, a command that deletes nothing.
CI was not running at the time, so neither was caught.
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / 'skills/bounty-pilot'
CONTROL = re.compile(rb'[\x00-\x08\x0b\x0c\x0d\x0e-\x1f\x7f]')


class ReleaseTests(unittest.TestCase):
    def test_version_files_agree(self):
        root = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
        skill = (SKILL / 'VERSION').read_text(encoding='utf-8').strip()
        plugin = json.loads((ROOT / '.claude-plugin/plugin.json').read_text(encoding='utf-8'))['version']
        self.assertEqual(root, skill)
        self.assertEqual(root, plugin)

    def test_lab_skill_and_plugin_names_do_not_collide_with_original(self):
        skill_text = (SKILL / 'SKILL.md').read_text(encoding='utf-8')
        skill_name = re.search(r'^name: (\S+)$', skill_text, re.M).group(1)
        plugin = json.loads((ROOT / '.claude-plugin/plugin.json').read_text(encoding='utf-8'))
        self.assertEqual(skill_name, 'bounty-pilot-lab')
        self.assertEqual(plugin['name'], skill_name)
        self.assertTrue(plugin['homepage'].endswith('/bounty-pilot-lab'))

    def test_marketplace_agrees_with_the_plugin_manifest(self):
        """0.28.0 renamed the skill and plugin but left the marketplace declaring bounty-pilot
        twice, so the README's own /plugin install line could not resolve. Nothing checked it."""
        plugin = json.loads((ROOT / '.claude-plugin/plugin.json').read_text(encoding='utf-8'))
        market = json.loads((ROOT / '.claude-plugin/marketplace.json').read_text(encoding='utf-8'))
        self.assertEqual(market['name'], plugin['name'])
        self.assertEqual([p['name'] for p in market['plugins']], [plugin['name']])

    def test_lab_description_differs_from_the_stable_skill(self):
        """An agent picks a skill from its description alone. While this line was byte-identical to
        the stable bounty-pilot skill's, which of the two ran was arbitrary."""
        head = (SKILL / 'SKILL.md').read_text(encoding='utf-8').split('\n---', 1)[0]
        description = re.search(r'^description: (.+)$', head, re.M).group(1)
        self.assertIn('AVRE', description)
        self.assertIn('bounty-pilot-lab', description)

    def test_changelog_leads_with_the_current_version(self):
        version = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
        first = re.search(r'^## (\S+)', (ROOT / 'CHANGELOG.md').read_text(encoding='utf-8'), re.M)
        self.assertEqual(first.group(1), version)

    def test_shipped_text_has_no_control_bytes(self):
        files = [ROOT / 'CHANGELOG.md', ROOT / 'AGENTS.md', ROOT / 'README.md', ROOT / 'README.ru.md']
        files += [p for p in SKILL.rglob('*') if p.suffix in {'.md', '.py', '.json', '.yaml'}
                  and '__pycache__' not in p.parts]
        dirty = []
        for path in files:
            # split on \n only: bytes.splitlines() would consume a stray \r as a line break
            for number, line in enumerate(path.read_bytes().split(b'\n'), 1):
                if CONTROL.search(line):
                    dirty.append(f'{path.relative_to(ROOT)}:{number}')
        self.assertEqual(dirty, [])

    def test_skill_description_fits_the_frontmatter_limit(self):
        head = (SKILL / 'SKILL.md').read_text(encoding='utf-8').split('\n---', 1)[0]
        description = re.search(r'^description: (.+)$', head, re.M).group(1)
        self.assertLessEqual(len(description), 1024)


if __name__ == '__main__':
    unittest.main()
