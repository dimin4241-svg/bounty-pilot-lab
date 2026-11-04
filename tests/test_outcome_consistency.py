"""Layered result mismatches must preserve acknowledgement semantics."""
import importlib.util
import unittest
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts/outcome_consistency.py"
spec = importlib.util.spec_from_file_location("outcome_consistency", FILE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OutcomeConsistencyTests(unittest.TestCase):
    def test_submitted_only_is_not_final_settlement(self):
        result = module.analyze({"schema_version": 1, "observations": [{
            "id": "submitted", "ack_semantics": "submitted-only",
            "ack_success": True, "nested_results": ["success", "failure"]}]})
        self.assertEqual(result["leads"], 0)
        self.assertTrue(result["results"][0]["uncertainties"])

    def test_final_ack_and_effect_discrepancy_produce_review_leads(self):
        row = {"id": "final", "ack_semantics": "final-settlement",
               "ack_success": True, "nested_results": ["failure"],
               "expected_asset_delta": "-25", "observed_asset_delta": "0",
               "entitlement_owner": "Alice", "effective_receiver": "Bob",
               "delegation_or_transfer_authorized": False}
        r = module.analyze({"schema_version": 1, "observations": [row]})
        self.assertEqual(r["leads"], 1)
        self.assertEqual(len(r["results"][0]["candidate_signals"]), 3)

    def test_unknown_ownership_cannot_be_fabricated_into_bypass(self):
        row = {"id": "rights", "ack_semantics": "unknown", "ack_success": False,
               "entitlement_owner": "Alice", "effective_receiver": "Bob"}
        r = module.analyze({"schema_version": 1, "observations": [row]})
        self.assertEqual(r["leads"], 0)
        self.assertTrue(r["results"][0]["uncertainties"])


if __name__ == "__main__":
    unittest.main()
