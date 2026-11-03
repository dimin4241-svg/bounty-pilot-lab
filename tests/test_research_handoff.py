"""Research task/result handoff validation tests; all evidence is synthetic."""
import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "bounty-pilot" / "scripts"))
import research_handoff


SHA = "a" * 40
LOG_SHA = "b" * 64
POC_SHA = "c" * 64

TASK = {
    "schema_version": "1.0",
    "id": "BP-LAB-TEST-01",
    "task_type": "workflow_smoke_test",
    "status": "READY_FOR_POC",
    "created_at": "2026-11-03T05:00:00Z",
    "target": {
        "name": "Synthetic handoff validation",
        "program_url": None,
        "scope_status": "synthetic",
    },
    "scope": {
        "in_scope": ["skills/bounty-pilot/scripts/research_handoff.py"],
        "out_of_scope": ["production targets", "live networks", "third-party users"],
    },
    "repository": {
        "url": "https://github.com/dimin4241-svg/bounty-pilot-lab",
        "ref": "feat/codex-cloud-handoff",
        "commit_sha": SHA,
    },
    "component": "Task/result validation",
    "hypothesis": "A confirmation without reproducible evidence is rejected.",
    "root_cause": "A status field alone cannot establish that tests ran or that the candidate/control pair differs.",
    "exploit_scenario": "A malformed synthetic result claims CONFIRMED but omits its PoC and test log.",
    "source_basis": [{
        "file": "skills/bounty-pilot/scripts/research_handoff.py",
        "line_start": 1,
        "line_end": 4,
        "excerpt": "Validate private Bounty Pilot task/result JSON with evidence gates.",
    }],
    "attacker": {"capabilities": "Supply synthetic JSON input", "reachable": True},
    "impact": {
        "assets_or_rights": "Integrity of the research workflow",
        "impact_path": "A false status could skip source and PoC review.",
        "estimated_loss": "None; synthetic harness only.",
    },
    "known_issue_review": {
        "status": "not_available",
        "sources": [],
        "rationale": "Synthetic workflow test, not a bounty target.",
    },
    "test_plan": {
        "candidate": "Confirm a result with missing PoC/log evidence.",
        "negative_control": "Confirm a result with matching test log, PoC digest and independent review.",
        "runner": "Python unittest",
        "expected_test_count": 2,
    },
    "expected_test_result": "The incomplete confirmation fails validation and the evidence-complete pair passes.",
    "acceptance_criteria": {
        "confirm": ["Missing PoC and log evidence is rejected."],
        "refute": ["A status-only confirmation passes validation."],
    },
    "execution_constraints": {
        "run_mode": "local_simulation",
        "network_access": "disabled",
        "mainnet": False,
        "live_transactions": False,
        "production_writes": False,
        "third_party_users": False,
    },
}

RESULT = {
    "schema_version": "1.0",
    "task_id": TASK["id"],
    "status": "TESTING",
    "executor": {
        "platform": "codex-cloud",
        "model": "gpt-6-luna",
        "environment": "bounty-pilot-lab",
        "task_url": "https://chatgpt.com/codex/cloud",
    },
    "repository": copy.deepcopy(TASK["repository"]),
    "summary": "Synthetic candidate/control checks ran in Codex Cloud; independent assessment is pending.",
    "execution": {
        "command": "python3 -m unittest discover -s tests -v",
        "exit_code": 0,
        "tests_run": 2,
        "tests_passed": 2,
        "bug_demonstrated": True,
        "assertions": ["Incomplete confirmation rejected.", "Evidence-complete control accepted."],
        "log_path": "research/results/BP-LAB-TEST-01/test.log",
        "log_sha256": LOG_SHA,
    },
    "artifacts": [
        {"kind": "test_log", "path": "research/results/BP-LAB-TEST-01/test.log", "sha256": LOG_SHA},
        {"kind": "proof_of_concept", "path": "research/pocs/BP-LAB-TEST-01/poc.py", "sha256": POC_SHA},
    ],
    "independent_review": {
        "status": "pending",
        "reviewed_by": None,
        "reviewed_at": None,
        "notes": "Awaiting ChatGPT source and assertion review.",
    },
}


class ResearchHandoffTests(unittest.TestCase):
    def test_ready_synthetic_task_validates_for_cloud(self):
        self.assertEqual([], research_handoff.validate_task(TASK, for_cloud=True))

    def test_hypothesis_cannot_be_sent_to_cloud(self):
        task = copy.deepcopy(TASK)
        task["status"] = "HYPOTHESIS"
        self.assertTrue(any("requires READY_FOR_POC" in error
                            for error in research_handoff.validate_task(task, for_cloud=True)))

    def test_security_task_requires_scope_and_known_issue_review(self):
        task = copy.deepcopy(TASK)
        task["task_type"] = "security_hypothesis"
        task["target"]["scope_status"] = "unknown"
        task["status"] = "READY_FOR_POC"
        task["known_issue_review"]["status"] = "pending"
        errors = research_handoff.validate_task(task, for_cloud=True)
        self.assertTrue(any("verified in-scope program" in error for error in errors))
        self.assertTrue(any("known-issue review" in error for error in errors))

    def test_confirmed_result_without_poc_is_rejected(self):
        result = copy.deepcopy(RESULT)
        result["status"] = "CONFIRMED"
        result["independent_review"] = {
            "status": "supports_finding",
            "reviewed_by": "ChatGPT researcher",
            "reviewed_at": "2026-11-03T05:05:00Z",
            "notes": "Synthetic demonstration reviewed.",
        }
        result["artifacts"] = [result["artifacts"][0]]
        self.assertTrue(any("requires a proof_of_concept" in error
                            for error in research_handoff.validate_result(result, TASK)))

    def test_evidence_complete_confirmation_and_commit_binding(self):
        result = copy.deepcopy(RESULT)
        result["status"] = "CONFIRMED"
        result["independent_review"] = {
            "status": "supports_finding",
            "reviewed_by": "ChatGPT researcher",
            "reviewed_at": "2026-11-03T05:05:00Z",
            "notes": "Synthetic demonstration reviewed.",
        }
        self.assertEqual([], research_handoff.validate_result(result, TASK))
        result["repository"]["commit_sha"] = "d" * 40
        self.assertTrue(any("pinned task" in error
                            for error in research_handoff.validate_result(result, TASK)))

    def test_result_requires_exact_luna_and_matching_log_digest(self):
        result = copy.deepcopy(RESULT)
        result["executor"]["model"] = "gpt-6-sol"
        result["artifacts"][0]["sha256"] = "d" * 64
        errors = research_handoff.validate_result(result, TASK)
        self.assertTrue(any("must equal 'gpt-6-luna'" in error for error in errors))
        self.assertTrue(any("log path and digest" in error for error in errors))

    def test_refutation_requires_tested_protection_and_review(self):
        result = copy.deepcopy(RESULT)
        result["status"] = "REFUTED"
        result["execution"]["bug_demonstrated"] = False
        result["independent_review"] = {
            "status": "supports_refutation",
            "reviewed_by": "ChatGPT researcher",
            "reviewed_at": "2026-11-03T05:05:00Z",
            "notes": "The negative control confirms the guard.",
        }
        self.assertEqual([], research_handoff.validate_result(result, TASK))


if __name__ == "__main__":
    unittest.main()
