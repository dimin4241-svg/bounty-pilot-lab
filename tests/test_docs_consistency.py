"""The prose an agent follows must point at things that exist.

0.52.0 shipped SKILL.md with a dangling "Credentials in bundled" — the rest of the sentence was lost
when a neighbouring line was edited, so the redaction rule silently disappeared from the workflow.
These checks keep paths, commands and paragraph endings honest without reading for meaning.
"""
import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / 'skills/bounty-pilot'
sys.path.insert(0, str(SKILL / 'scripts'))
spec = importlib.util.spec_from_file_location('bounty_docs', SKILL / 'scripts/bounty.py')
bounty = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounty)

PATH_REF = re.compile(r'(?:references|scripts|templates)/[A-Za-z0-9_./-]+\.(?:md|py|json|sol|rs|yaml)')
COMMAND_REF = re.compile(r'(?:\$S|bounty\.py) ([a-z][a-z0-9-]*)')


def skill_docs():
    return [SKILL / 'SKILL.md', *sorted((SKILL / 'references').rglob('*.md')),
            *sorted((SKILL / 'templates').glob('*.md'))]


def prose_lines(path):
    """(number, line, next line) for lines outside fenced code blocks."""
    lines = path.read_text(encoding='utf-8').split('\n')
    fenced = False
    for index, line in enumerate(lines[:-1]):
        if line.lstrip().startswith('```'):
            fenced = not fenced
            continue
        if not fenced:
            yield index + 1, line, lines[index + 1]


class DocsConsistencyTests(unittest.TestCase):
    def test_every_referenced_file_exists(self):
        docs = skill_docs() + [ROOT / 'README.md', ROOT / 'AGENTS.md']
        missing = []
        for doc in docs:
            for ref in sorted(set(PATH_REF.findall(doc.read_text(encoding='utf-8')))):
                ref = ref.rstrip('.')
                if not (SKILL / ref).exists():
                    missing.append(f'{doc.relative_to(ROOT)}: {ref}')
        self.assertEqual(missing, [])

    def test_every_documented_subcommand_is_registered(self):
        parser = bounty.build_parser()
        actions = [a for a in parser._actions if a.__class__.__name__ == '_SubParsersAction']
        registered = set(actions[0].choices)
        unknown = []
        for doc in skill_docs():
            for command in sorted(set(COMMAND_REF.findall(doc.read_text(encoding='utf-8')))):
                if command not in registered:
                    unknown.append(f'{doc.relative_to(ROOT)}: {command}')
        self.assertEqual(unknown, [])

    def test_no_paragraph_ends_mid_sentence(self):
        """A prose paragraph that ends on a bare word lost its ending."""
        cut = []
        for doc in skill_docs():
            for number, line, following in prose_lines(doc):
                text = line.strip()
                if (following.strip() or not text or text[0] in '-*|#>' or text.startswith('<')
                        or re.match(r'\d+\.', text) or re.search(r'https?://\S+$', text)):
                    continue
                if re.search(r'[A-Za-z]$', text):
                    cut.append(f'{doc.relative_to(ROOT)}:{number}: ...{text[-50:]}')
        self.assertEqual(cut, [])

    def test_bundle_redaction_rule_is_a_whole_sentence(self):
        text = (SKILL / 'SKILL.md').read_text(encoding='utf-8')
        self.assertRegex(text, r'Credentials in bundled\s+source are redacted\.')

    def test_lab_release_notes_live_in_their_reference(self):
        skill = (SKILL / 'SKILL.md').read_text(encoding='utf-8')
        notes = (SKILL / 'references/lab-releases.md').read_text(encoding='utf-8')
        self.assertIn('references/lab-releases.md', skill)
        self.assertNotRegex(skill, r'^## Experimental Lab ', 'release notes crept back into SKILL.md')
        for release in ('0.52', '0.51', '0.50', '0.49.5', '0.49', '0.48', '0.47', '0.46', '0.42'):
            self.assertIn(f'Lab {release}', notes)

    def test_codex_metadata_names_the_lab_skill(self):
        text = (SKILL / 'agents/openai.yaml').read_text(encoding='utf-8')
        self.assertIn('$bounty-pilot-lab ', text)
        self.assertIn('display_name: "Bounty Pilot Lab"', text)


class BriefQueueTests(unittest.TestCase):
    def test_brief_drops_glossary_and_empty_sections_only(self):
        full = {'state': 'open', 'open_count': 0, 'gated': False, 'unread_bundles': [{'lens': 'x'}],
                'parked': [], 'audit_gap': None, 'anchors': {}, 'notice': 'x' * 4000}
        brief = bounty.brief_queue(full)
        self.assertEqual(brief['unread_bundles'], [{'lens': 'x'}])
        self.assertEqual((brief['open_count'], brief['gated']), (0, False))
        for dropped in ('parked', 'audit_gap', 'anchors'):
            self.assertNotIn(dropped, brief)
        self.assertLess(len(json.dumps(brief)), 400)
        self.assertEqual(full['notice'], 'x' * 4000, 'brief_queue must not mutate its input')


if __name__ == '__main__':
    unittest.main()
