"""Release hygiene: the three version numbers agree, and shipped text carries no invisible bytes.

0.21.0 shipped with `.claude-plugin/plugin.json` still at 0.20.0, and with a literal carriage return
inside `tr -d '…'` in intake.md — rendered and read as `tr -d ''`, a command that deletes nothing.
CI was not running at the time, so neither was caught.
"""
import ast
import json
import re
import shutil
import subprocess
import sys
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
        marketplace = json.loads((ROOT / '.claude-plugin/marketplace.json').read_text(encoding='utf-8'))
        self.assertEqual(skill_name, 'bounty-pilot-lab')
        self.assertEqual(plugin['name'], skill_name)
        self.assertTrue(plugin['homepage'].endswith('/bounty-pilot-lab'))
        self.assertEqual(marketplace['name'], skill_name)
        self.assertEqual([entry['name'] for entry in marketplace['plugins']], [skill_name])

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

    def test_nothing_shipped_needs_a_python_newer_than_the_declared_minimum(self):
        """A replacement field spanning a newline is valid only from Python 3.12 (PEP 701).

        `agent_dispatch.py` carried one while both the README ("Python 3.9+") and the CI matrix
        claimed 3.9, so that module did not parse there at all - the `agent-dispatch` command
        was dead for anyone on 3.9, 3.10 or 3.11, and its whole test module was skipped. CI
        would have caught it; CI had not run for days. `ast.parse(feature_version=(3, 9))` does
        NOT reject it, which is why this walks the tree instead.

        Before 3.12 an f-string's inner nodes carry approximate positions, so a legal implicit
        concatenation across two lines also reports `end_lineno > lineno`. The check therefore
        runs on 3.12+, where those positions are exact, and the companion test below compiles
        the scripts with an older interpreter directly.
        """
        if sys.version_info < (3, 12):
            self.skipTest('f-string node positions are approximate before 3.12; the companion '
                          'test compiles with the older interpreter instead')
        offenders = []
        for path in sorted(ROOT.rglob('*.py')):
            if '__pycache__' in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                if isinstance(node, ast.FormattedValue) and node.end_lineno > node.lineno:
                    offenders.append(f'{path.relative_to(ROOT)}:{node.lineno}')
        self.assertEqual(offenders, [])

    def test_every_shipped_script_parses_on_the_oldest_interpreter_present(self):
        """The direct check, when a 3.9-3.11 interpreter happens to be installed."""
        older = None
        for exe in ('python3.9', 'python3.10', 'python3.11', '/usr/bin/python3', 'python3'):
            found = shutil.which(exe) if '/' not in exe else (exe if Path(exe).exists() else None)
            if not found:
                continue
            printed = subprocess.run([found, '--version'], capture_output=True, text=True)
            version = (printed.stdout or printed.stderr).split()[-1].split('.')[:2]
            if version[:1] == ['3'] and version[1:] and int(version[1]) < 12:
                older = found
                break
        if older is None:
            self.skipTest('no 3.9-3.11 interpreter available; the AST check above still applies')
        scripts = sorted(SKILL.rglob('*.py'))
        self.assertTrue(scripts)
        failed = []
        for path in scripts:
            done = subprocess.run([older, '-c', 'import ast,sys;ast.parse(open(sys.argv[1]).read())',
                                   str(path)], capture_output=True, text=True)
            if done.returncode != 0:
                failed.append(f'{path.relative_to(ROOT)}: {done.stderr.strip().splitlines()[-1]}')
        self.assertEqual(failed, [])

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
