"""Synthetic controls for cross-domain impact preflight and explicit OAuth policy."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import business_impact_oracle as impact
import oauth_lifecycle_lab as oauth


class EvidenceAndLifecycleTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.root.joinpath("candidate.json").write_bytes(b'{"candidate":true}')
        self.root.joinpath("control.json").write_bytes(b'{"control":false}')

    @staticmethod
    def h(data):
        return hashlib.sha256(data).hexdigest()

    def receipt(self, name):
        return {"receipt_file": name,
                "receipt_sha256": self.h((self.root / name).read_bytes())}

    def impact_case(self, domain="android"):
        initial = self.h(b"initial")
        changed = self.h(b"changed")
        return {
            "schema_version": 1, "domain": domain, "scenario_id": "fixture-1",
            "scope": {"operator_confirmed": True, "policy_reference": "local-fixture-v1"},
            "expected_policy": {"candidate_effect_permitted": False},
            "candidate": {
                "actor_id": "probe", "before_sha256": initial,
                "after_sha256": changed, **self.receipt("candidate.json"),
            },
            "control": {
                "actor_id": "probe", "before_sha256": initial,
                "after_sha256": initial, **self.receipt("control.json"),
            },
        }

    def test_differential_is_not_verified_impact(self):
        for domain in impact.DOMAINS:
            result = impact.analyze(self.impact_case(domain), self.root)
            self.assertEqual(
                result["status"], "DIFFERENTIAL_UNAUTHORIZED_BY_STATED_POLICY_REVIEW_REQUIRED")
            self.assertTrue(result["receipts_hash_checked"])
            self.assertFalse(result["impact_verified"])

    def test_different_initial_states_not_comparable(self):
        case = self.impact_case()
        case["control"]["before_sha256"] = self.h(b"another")
        result = impact.analyze(case, self.root)
        self.assertEqual(result["status"], "INCOMPARABLE_INITIAL_STATE")

    def test_no_change_not_a_vulnerability(self):
        case = self.impact_case()
        case["candidate"]["after_sha256"] = case["candidate"]["before_sha256"]
        self.assertEqual(impact.analyze(case, self.root)["status"],
                         "NO_UNIQUE_PROTECTED_STATE_CHANGE")

    def test_control_also_changed_not_causally_distinct(self):
        case = self.impact_case()
        case["control"]["after_sha256"] = self.h(b"another")
        self.assertEqual(impact.analyze(case, self.root)["status"],
                         "NO_UNIQUE_PROTECTED_STATE_CHANGE")

    def test_allowed_effect_not_a_violation(self):
        case = self.impact_case()
        case["expected_policy"]["candidate_effect_permitted"] = True
        self.assertEqual(impact.analyze(case, self.root)["status"],
                         "DIFFERENTIAL_BUT_ALLOWED_BY_STATED_POLICY")

    def test_missing_scope_assertion_denies(self):
        case = self.impact_case()
        case["scope"]["operator_confirmed"] = False
        self.assertEqual(impact.analyze(case, self.root)["status"],
                         "UNCONFIRMED_SCOPE_NO_TEST_AUTHORITY")

    def test_tampered_witness_fails(self):
        case = self.impact_case()
        self.root.joinpath("candidate.json").write_bytes(b"tamper")
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            impact.analyze(case, self.root)

    def test_traversal_and_symlink_witness_rejected(self):
        case = self.impact_case()
        case["candidate"]["receipt_file"] = "../secret"
        with self.assertRaises(ValueError):
            impact.analyze(case, self.root)
        case = self.impact_case()
        link = self.root / "link.json"
        link.symlink_to(self.root / "candidate.json")
        case["candidate"]["receipt_file"] = "link.json"
        with self.assertRaisesRegex(ValueError, "symlink"):
            impact.analyze(case, self.root)

    def policy(self, code_invalid=True, refresh_invalid=True):
        return {"invalidate_unredeemed_codes": code_invalid,
                "invalidate_refresh_on_revoke": refresh_invalid,
                "role_actions": {"reader": ["read"], "writer": ["read", "write"]}}

    def trace(self, code_accepted=True, refresh_accepted=False):
        return {"schema_version": 1, "policy": self.policy(), "events": [
            {"id": "e1", "seq": 1, "type": "grant", "actor": "alice", "grant": "g1"},
            {"id": "e2", "seq": 2, "type": "issue_code", "grant": "g1", "code": "c1"},
            {"id": "e3", "seq": 3, "type": "issue_refresh", "grant": "g1", "refresh_id": "r1"},
            {"id": "e4", "seq": 4, "type": "revoke_grant", "grant": "g1"},
            {"id": "e5", "seq": 5, "type": "exchange_code", "grant": "g1", "code": "c1",
             "accepted": code_accepted},
            {"id": "e6", "seq": 6, "type": "refresh", "grant": "g1", "refresh_id": "r1",
             "accepted": refresh_accepted},
        ]}

    def test_revoked_grant_old_code_is_policy_divergence(self):
        report = oauth.analyze(self.trace())
        self.assertEqual(report["divergence_count"], 1)
        self.assertEqual(report["comparisons"][0]["rule"],
                         "CODE_EXCHANGE_ACCEPTANCE_MISMATCH")
        self.assertFalse(report["impact_verified"])

    def test_fixed_behavior_passes_same_trace(self):
        report = oauth.analyze(self.trace(code_accepted=False))
        self.assertEqual(report["divergence_count"], 0)
        self.assertEqual(report["status"], "NO_DECLARED_POLICY_DIVERGENCE")

    def test_permissive_policy_not_reported_as_bug(self):
        case = self.trace()
        case["policy"] = self.policy(code_invalid=False)
        self.assertEqual(oauth.analyze(case)["divergence_count"], 0)

    def test_refresh_after_revoke_detected_when_policy_requires(self):
        self.assertEqual(oauth.analyze(self.trace(False, True))["divergence_count"], 1)

    def test_read_only_role_update_denied(self):
        case = {"schema_version": 1, "policy": self.policy(), "events": [
            {"id": "r1", "seq": 1, "type": "set_role", "actor": "bob", "role": "reader"},
            {"id": "r2", "seq": 2, "type": "action", "actor": "bob",
             "action": "write", "accepted": True},
        ]}
        result = oauth.analyze(case)
        self.assertEqual(result["divergence_count"], 1)
        self.assertEqual(result["comparisons"][0]["rule"],
                         "ROLE_ACTION_ACCEPTANCE_MISMATCH")

    def test_permission_role_change_can_allow_write(self):
        case = {"schema_version": 1, "policy": self.policy(), "events": [
            {"id": "r1", "seq": 1, "type": "set_role", "actor": "bob", "role": "reader"},
            {"id": "r2", "seq": 2, "type": "action", "actor": "bob",
             "action": "write", "accepted": False},
            {"id": "r3", "seq": 3, "type": "set_role", "actor": "bob", "role": "writer"},
            {"id": "r4", "seq": 4, "type": "action", "actor": "bob",
             "action": "write", "accepted": True},
        ]}
        self.assertEqual(oauth.analyze(case)["divergence_count"], 0)

    def test_duplicate_and_out_of_order_events_denied(self):
        case = self.trace()
        case["events"][1]["id"] = case["events"][0]["id"]
        with self.assertRaises(ValueError):
            oauth.analyze(case)

    def test_non_boolean_observed_result_denied(self):
        case = self.trace()
        case["events"][-1]["accepted"] = 200
        with self.assertRaises(ValueError):
            oauth.analyze(case)


if __name__ == "__main__":
    unittest.main()
