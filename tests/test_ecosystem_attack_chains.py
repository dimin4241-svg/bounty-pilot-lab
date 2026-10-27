"""Keep the prioritized ecosystem attack-chain playbook complete and evidence-oriented."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / 'skills/bounty-pilot/references/ecosystem-attack-chains.md'
TEMPLATE = ROOT / 'skills/bounty-pilot/templates/attack-chain-review.md'
SKILL = ROOT / 'skills/bounty-pilot/SKILL.md'


class EcosystemAttackChainPlaybookTests(unittest.TestCase):
    def test_twelve_patterns_have_invariant_falsifier_and_safe_validation(self):
        content = PLAYBOOK.read_text(encoding='utf-8')
        headings = re.findall(r'^### EAC-(\d{2}) — .+$', content, re.M)
        self.assertEqual(headings, [f'{index:02d}' for index in range(1, 13)])
        sections = re.split(r'(?=^### EAC-\d{2} — )', content, flags=re.M)
        patterns = [section for section in sections if section.startswith('### EAC-')]
        self.assertEqual(len(patterns), 12)
        for section in patterns:
            for required in ('**Research priority:', '- **Inspect:**', '- **Invariant:**',
                             '- **Disconfirm:**', '- **Safe test:**'):
                with self.subTest(pattern=section.splitlines()[0], field=required):
                    self.assertIn(required, section)
        self.assertIn('do not estimate vulnerability likelihood', content)
        self.assertIn('Do not combine two patterns into one attack chain unless', content)

    def test_review_template_covers_each_pattern_and_blocks_unearned_status(self):
        content = TEMPLATE.read_text(encoding='utf-8')
        rows = re.findall(r'^\| EAC-(\d{2}) \| .+ \| (Very high|High) \| UNASSESSED \|',
                          content, re.M)
        self.assertEqual([row[0] for row in rows], [f'{index:02d}' for index in range(1, 13)])
        self.assertIn('A signal is a research lead, not a finding.', content)
        self.assertIn('Exact command and result (leave `NOT_RUN` until executed)', content)

    def test_skill_routes_mixed_stack_review_to_the_playbook(self):
        content = SKILL.read_text(encoding='utf-8')
        self.assertIn('references/ecosystem-attack-chains.md', content)
        self.assertIn('templates/attack-chain-review.md', content)
        self.assertRegex(content, r'A lexical or\s+source-only review cannot establish')


if __name__ == '__main__':
    unittest.main()
