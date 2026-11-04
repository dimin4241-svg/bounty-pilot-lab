"""Economic frontier needs exact numbers, verified preconditions and real control."""
import importlib.util
import unittest
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts/economic_frontier.py"
spec = importlib.util.spec_from_file_location("economic_frontier", FILE)
frontier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(frontier)


def point(id, capital, extraction, loss, restored=True):
    return {"id": id, "capital_required": capital,
            "gross_extraction": extraction, "victim_loss": loss,
            "accessible_liquidity": "1000", "manipulation_cost": "1",
            "protocol_fees": "1", "slippage_cost": "1", "gas_cost": "1",
            "funding_cost": "0", "unrecovered_capital": "0",
            "native_test_executed": True, "paired_control_passed": True,
            "capital_restored": restored, "position_closed": True,
            "unprivileged_reachability_verified": True,
            "real_chain_state_verified": True, "evidence": "local fork receipts"}


class EconomicFrontierTests(unittest.TestCase):
    def test_selects_discrete_min_capital_and_highest_net(self):
        data = {"schema_version": 1, "source_revision": "a"*40,
                "unit": "USDC", "scenarios": [
                    point("high", "300", "100", "50"),
                    point("cheap", "10", "20", "12"),
                    point("bad", "1", "2", "1"),
                ]}
        res = frontier.analyze(data, "400")
        self.assertEqual(res["positive_points_under_supplied_assumptions"], 2)
        self.assertEqual(res["min_capital_positive_point"], "cheap")
        self.assertEqual(res["best_net_positive_point"], "high")

    def test_missing_capital_restoration_disqualifies(self):
        data = {"schema_version": 1, "source_revision": "b"*40,
                "scenarios": [point("borrowed", "500", "100", "20", restored=False)]}
        res = frontier.analyze(data)
        self.assertEqual(res["positive_points_under_supplied_assumptions"], 0)
        self.assertIn("capital restoration not demonstrated", res["points"][0]["flags"])

    def test_decimal_precision_and_budget(self):
        data = {"schema_version": 1, "source_revision": "c"*40,
                "scenarios": [point("wei", "10.000000000000000001",
                                    "4.000000000000000001", "1")]}
        res = frontier.analyze(data, "10")
        self.assertIn("required capital exceeds", " ".join(res["points"][0]["flags"]))
        with self.assertRaisesRegex(ValueError, "finite"):
            frontier.analyze({**data, "scenarios": [{**data["scenarios"][0],
                                                    "capital_required": "NaN"}]})

    def test_unattested_readings_do_not_become_verified_impact(self):
        data = {"schema_version": 1, "source_revision": "d"*40,
                "scenarios": [{**point("unverified", "1", "100", "90"),
                               "native_test_executed": False}]}
        res = frontier.analyze(data)
        self.assertFalse(res["points"][0]["conditions_met_by_supplied_observations"])


if __name__ == "__main__":
    unittest.main()
