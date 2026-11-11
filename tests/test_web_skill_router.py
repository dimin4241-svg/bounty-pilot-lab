"""Regression: small lab skill router with preserved full workflow and safe defaults."""
import re
import unittest
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot"
PRIMARY = SKILL / "SKILL.md"
DETAILED = SKILL / "references" / "full-workflow-legacy.md"


class SkillRouterTests(unittest.TestCase):
    def test_router_remains_small_and_routes_only_explicit_lab_requests(self):
        text = PRIMARY.read_text(encoding="utf-8")
        self.assertLessEqual(len(text.splitlines()), 200)
        self.assertLess(len(text.encode("utf-8")), 12000)
        self.assertTrue(text.startswith("---\nname: bounty-pilot-lab\n"))
        self.assertIn("For a generic bug bounty audit use the stable", text)
        self.assertIn("references/full-workflow-legacy.md", text)

    def test_stage_contract_preserved_in_detailed_reference(self):
        self.assertTrue(DETAILED.is_file())
        text = DETAILED.read_text(encoding="utf-8")
        for stage in (
            "Stage 0", "Stage 1", "Stage 2", "Stage 3",
            "Stage 4", "Stage 5", "Stage 6", "Stage 7",
            "Evidence-First", "Lab tools"):
            with self.subTest(stage=stage):
                self.assertIn(stage, text)
        self.assertGreater(len(text.splitlines()), 700)

    def test_phase_references_and_tools_are_present(self):
        text = PRIMARY.read_text(encoding="utf-8")
        names = set(re.findall(r"references/([A-Za-z0-9_.-]+\\.md)", text))
        # Also check explicit direct names; none should be missing.
        names.update((
            "full-workflow-legacy.md", "web-hunt-loop-phase5.md",
            "web-invariants-phase3.md", "agent-dispatch.md"))
        for name in names:
            with self.subTest(name=name):
                self.assertTrue((SKILL / "references" / name).is_file())

    def test_critical_guards_in_immediate_read(self):
        text = PRIMARY.read_text(encoding="utf-8").lower()
        for term in ("official", "authorization", "negative control",
                     "untrusted data", "model", "budget", "scope",
                     "evidence", "unknown", "stable bounty-pilot"):
            with self.subTest(term=term):
                self.assertIn(term, text)


if __name__ == "__main__":
    unittest.main()
