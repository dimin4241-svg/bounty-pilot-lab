"""The severity denominator: what the payout is actually proportional to.

Three consecutive zero-yield runs on one client family produced real, reproduced mechanisms and
nothing payable, because the rubric graded every severity by the client's 1.41% share of the
network. The decisive property is the one asserted in
test_a_share_ceiling_is_not_escapable_by_non_fund_impact: a share denominator multiplies the
non-fund classes too, so `pays_non_fund_impact` must NOT buy an escape from it the way it does from
the value-at-rest ceiling.
"""
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"

spec = importlib.util.spec_from_file_location("test_bp_sd_bounty", SCRIPTS / "bounty.py")
bounty = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounty)


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class SeverityDenominatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / "repo"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "src/Vault.sol").write_text("contract Vault { function f() external {} }\n")
        (self.repo / "test").mkdir()
        (self.repo / "test/Vault.t.sol").write_text("// tests src/Vault.sol\n")
        git(self.repo, "init", "-q")
        git(self.repo, "-c", "user.email=t@e", "-c", "user.name=t", "add", "-A")
        git(self.repo, "-c", "user.email=t@e", "-c", "user.name=t", "commit", "-qm", "fixture")
        self.n = 0

    def score(self, **overrides):
        """A target that would otherwise score well: real value, and it pays non-fund impact."""
        body = {
            "program": "Example", "in_scope_paths": ["src/"],
            "duplicate_policy": "first-to-report", "deposit_required": False,
            "known_issues_count": 7, "payout_max_usd": 50_000,
            "value_at_rest_usd": 50_000_000, "pays_non_fund_impact": True,
            "public_audit_count": 1,
        }
        body.update(overrides)
        self.n += 1
        path = self.base / f"program-{self.n}.json"
        path.write_text(json.dumps(body))
        return bounty.score_target(self.repo, path)

    # --- the field is required, and absence is an unknown, never a pass ---

    def test_absent_denominator_is_an_unknown_that_says_to_measure_first(self):
        result = self.score()
        self.assertEqual(result["severity_denominator_ceiling"], [])
        unknown = [u for u in result["unknowns"] if "severity_denominator unknown" in u]
        self.assertEqual(len(unknown), 1, result["unknowns"])
        self.assertIn("BEFORE reading code", unknown[0])
        # An unknown must not move the band on its own.
        self.assertNotEqual(result["band"], "deprioritise")

    # --- the case that cost three runs ---

    def test_a_share_ceiling_is_not_escapable_by_non_fund_impact(self):
        """pays_non_fund_impact escapes the VALUE ceiling; it must not escape a SHARE ceiling."""
        result = self.score(severity_denominator={
            "kind": "client-share", "measured_fraction": 0.0141,
            "source": "clientdiversity.org, read 2026-10-20", "ceiling_payout_usd": 2_000})
        self.assertTrue(result["pays_non_fund_impact"] if "pays_non_fund_impact" in result else True)
        self.assertEqual(len(result["severity_denominator_ceiling"]), 1)
        ceiling = result["severity_denominator_ceiling"][0]
        self.assertIn("client-share", ceiling)
        self.assertIn("1.41%", ceiling)
        self.assertIn("2,000 USD", ceiling)
        self.assertEqual(result["band"], "deprioritise")
        self.assertTrue(any("severity denominator" in r for r in result["reasons"]),
                        result["reasons"])
        # The value ceiling is a separate list and stays empty: 50M at rest is not the problem.
        self.assertEqual(result["severity_ceiling"], [])

    def test_the_reachable_payout_is_derived_when_only_the_share_is_recorded(self):
        result = self.score(severity_denominator={
            "kind": "usage-share", "measured_fraction": 0.01, "source": "dashboard 2026-10-20"})
        # 1% of a 50,000 USD cap is 500: under the floor, so the band is forced.
        self.assertEqual(len(result["severity_denominator_ceiling"]), 1)
        self.assertIn("500 USD", result["severity_denominator_ceiling"][0])
        self.assertEqual(result["band"], "deprioritise")

    def test_a_share_large_enough_to_pay_is_only_a_reason(self):
        result = self.score(severity_denominator={
            "kind": "market-share", "measured_fraction": 0.8, "source": "dune 2026-10-20"})
        self.assertEqual(result["severity_denominator_ceiling"], [])
        self.assertNotEqual(result["band"], "deprioritise")
        self.assertTrue(any("is still reachable" in r for r in result["reasons"]),
                        result["reasons"])

    def test_a_middling_share_reports_the_gap_without_claiming_it_is_hopeless(self):
        # 10% of 50,000 is 5,000: under the 10,000 floor, so it is forced. Raise the cap so the
        # reachable figure clears the floor but stays under a fifth of what is advertised.
        result = self.score(payout_max_usd=1_000_000, severity_denominator={
            "kind": "client-share", "measured_fraction": 0.1, "source": "x 2026-10-20"})
        self.assertEqual(len(result["severity_denominator_ceiling"]), 1)
        ceiling = result["severity_denominator_ceiling"][0]
        self.assertIn("100,000 USD", ceiling)
        self.assertIn("1,000,000 USD", ceiling)

    # --- the denominators that are not a problem ---

    def test_a_denominator_set_by_the_mechanism_is_not_penalised(self):
        for kind in ("fixed-usd", "value-at-risk", "impact-class"):
            with self.subTest(kind=kind):
                result = self.score(severity_denominator={"kind": kind})
                self.assertEqual(result["severity_denominator_ceiling"], [])
                self.assertNotEqual(result["band"], "deprioritise")
                self.assertTrue(any(kind in r for r in result["reasons"]), result["reasons"])

    def test_a_bare_string_is_read_as_the_kind(self):
        result = self.score(severity_denominator="value-at-risk")
        self.assertEqual(result["severity_denominator_ceiling"], [])
        self.assertTrue(any("value-at-risk" in r for r in result["reasons"]))

    # --- the field has to be measured, not asserted ---

    def test_a_share_without_a_source_is_an_unknown(self):
        result = self.score(severity_denominator={
            "kind": "client-share", "measured_fraction": 0.5})
        self.assertTrue(any("no source" in u for u in result["unknowns"]), result["unknowns"])

    def test_a_share_with_no_numbers_asks_for_the_measurement(self):
        result = self.score(severity_denominator={"kind": "client-share", "source": "docs"})
        self.assertEqual(result["severity_denominator_ceiling"], [])
        unknown = [u for u in result["unknowns"] if "measured_fraction" in u]
        self.assertEqual(len(unknown), 1, result["unknowns"])
        self.assertIn("BEFORE reading code", unknown[0])
        # Without a number it must not force the band either way.
        self.assertNotEqual(result["band"], "deprioritise")

    def test_an_unrecognised_kind_is_reported_rather_than_ignored(self):
        result = self.score(severity_denominator={"kind": "vibes"})
        self.assertTrue(any('"vibes" is not one of' in u for u in result["unknowns"]),
                        result["unknowns"])

    def test_a_nonsense_fraction_is_ignored_not_trusted(self):
        for fraction in (-1, 2, True, "half", None):
            with self.subTest(fraction=fraction):
                result = self.score(severity_denominator={
                    "kind": "client-share", "measured_fraction": fraction, "source": "x"})
                # No usable number, so it asks for one instead of computing from garbage.
                self.assertEqual(result["severity_denominator_ceiling"], [])
                self.assertTrue(any("measured_fraction" in u for u in result["unknowns"]))

    # --- the documentation has to carry it, or nobody fills the field in ---

    def test_the_references_document_the_field(self):
        targets = (ROOT / "skills/bounty-pilot/references/targets.md").read_text(encoding="utf-8")
        self.assertIn("severity_denominator", targets)
        self.assertIn("ceiling_payout_usd", targets)
        self.assertIn("no escape", targets)
        skill = (ROOT / "skills/bounty-pilot/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("severity_denominator", skill)
        misses = (ROOT / "skills/bounty-pilot/references/misses.md").read_text(encoding="utf-8")
        self.assertIn("severity_denominator", misses)

    def test_the_stage_one_published_report_step_is_documented(self):
        intake = (ROOT / "skills/bounty-pilot/references/intake.md").read_text(encoding="utf-8")
        self.assertIn("pdftotext", intake)
        self.assertIn("reportPdfLink", intake)
        self.assertIn("is not a paywall", intake)
        skill = (ROOT / "skills/bounty-pilot/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("published elsewhere", skill)

    def test_the_misses_count_in_passes_matches_the_file(self):
        misses = (ROOT / "skills/bounty-pilot/references/misses.md").read_text(encoding="utf-8")
        import re
        numbers = [int(m) for m in re.findall(r"(?m)^## (\d+)\.", misses)]
        self.assertEqual(sorted(numbers), list(range(1, len(numbers) + 1)),
                         "misses.md item numbers must be contiguous with no duplicates")
        words = {31: "thirty-one", 32: "thirty-two", 33: "thirty-three", 34: "thirty-four"}
        passes = (ROOT / "skills/bounty-pilot/references/passes.md").read_text(encoding="utf-8")
        self.assertIn(f"lists {words[max(numbers)]} ways", passes)


if __name__ == "__main__":
    unittest.main()
