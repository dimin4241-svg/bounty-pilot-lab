"""Tests for the passive state-transition and trust-handoff heuristic."""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "skills/bounty-pilot/scripts/transition_research.py"
spec = importlib.util.spec_from_file_location("transition_research", HELPER)
research = importlib.util.module_from_spec(spec)
spec.loader.exec_module(research)


def redact(value):
    return value.replace("synthetic-secret-value", "<redacted>")


class TransitionResearchTests(unittest.TestCase):
    def test_alternative_paths_compare_same_write_and_guard_families(self):
        source = """contract Store {
    mapping(bytes32 => address) internal owners;
    function create(bytes32 id, address who) external onlyAdmin {
        owners[id] = who;
    }
    function restore(bytes32 id, address who) external {
        owners[id] = who;
    }
}
"""
        result = research.analyze({"src/Store.sol": source}, redact)
        rows = result["alternative_path_discovery"]["candidates"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["primary_operation"], "create")
        self.assertEqual(rows[0]["alternate_operation"], "restore")
        self.assertEqual(rows[0]["shared_state_symbols"], ["owners"])
        self.assertEqual(rows[0]["missing_guard_families"], ["owner_or_admin"])
        self.assertEqual(rows[0]["operation_paths"][0]["source"]["line"], 3)
        self.assertEqual(rows[0]["confidence"], "low")

    def test_revocation_resurrection_and_deleted_object_lifecycle_are_leads(self):
        source = """contract Lifecycle {
    mapping(bytes32 => bool) internal deviceSessions;
    mapping(bytes32 => bool) internal jobs;
    function revokeDevice(bytes32 id) external onlyAdmin {
        deviceSessions[id] = false;
    }
    function reconnectDevice(bytes32 id) external {
        deviceSessions[id] = true;
    }
    function deleteJob(bytes32 id) external onlyAdmin {
        jobs[id] = false;
    }
    function processJob(bytes32 id) external {
        jobs[id] = true;
    }
}
"""
        result = research.analyze({"src/Lifecycle.sol": source}, redact)
        self.assertEqual(len(result["revocation_resurrection"]["candidates"]), 1)
        self.assertFalse(result["revocation_resurrection"]["candidates"][0][
            "revocation_state_check_in_restore_path"])
        self.assertEqual(len(result["deleted_object_lifecycle"]["candidates"]), 1)
        self.assertEqual(result["deleted_object_lifecycle"]["candidates"][0]["shared_state_symbols"],
                         ["jobs"])

    def test_same_named_cross_file_policy_paths_with_different_guards_are_leads(self):
        files = {
            "workers/RegionA.sol": """contract RegionA {
    uint policyVersion;
    function authorizeJob(bytes32 id) external onlyRole(EXECUTOR_ROLE) {
        require(policyVersion >= 2);
        jobs[id] = true;
    }
}
""",
            "workers/RegionB.sol": """contract RegionB {
    uint policyVersion;
    function authorizeJob(bytes32 id) external {
        jobs[id] = true;
    }
}
""",
        }
        result = research.analyze(files, redact)
        rows = result["security_policy_drift"]["candidates"]
        self.assertEqual(len(rows), 1)
        self.assertIn("RegionA.sol", rows[0]["path"])
        self.assertIn("RegionB.sol", rows[0]["path"])
        self.assertEqual(rows[0]["operation_paths"][0]["name"], "authorizeJob")
        self.assertIn("No call graph", " ".join(rows[0]["disconfirming_evidence"]))

    def test_comments_and_string_literals_do_not_create_function_candidates(self):
        source = '''contract Empty {
    // function create(bytes32 id) external onlyAdmin { owners[id] = msg.sender; }
    string constant NOTE = "function restore(bytes32 id) { owners[id] = msg.sender; }";
}
'''
        result = research.analyze({"src/Empty.sol": source}, redact)
        self.assertEqual(result["alternative_path_discovery"]["functions_parsed"], 0)
        self.assertEqual(result["alternative_path_discovery"]["candidates"], [])

    def test_ci_artifact_and_agent_signals_are_scoped_static_observations(self):
        workflow = """name: fixture
on:
  pull_request_target:
permissions:
  contents: write
jobs:
  build:
    steps:
      - uses: actions/upload-artifact@v4
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "${{ github.event.comment.body }}" # no real credential or action is used
      - uses: actions/download-artifact@v4
      - run: npm publish --dry-run
"""
        result = research.analyze({".github/workflows/agent-release.yml": workflow}, redact)
        self.assertEqual(len(result["ci_release_provenance"]["observations"]), 1)
        self.assertEqual(result["ci_release_provenance"]["observations"][0]["status"],
                         "review_candidate")
        self.assertEqual(len(result["agentic_trust"]["candidates"]), 1)
        self.assertTrue(result["agentic_trust"]["candidates"][0]["untrusted_input_evidence"])
        self.assertTrue(result["agentic_trust"]["candidates"][0]["elevated_capability_evidence"])
        self.assertTrue(any("github.event.comment.body" in row["excerpt"] for row in
                            result["agentic_trust"]["candidates"][0]["untrusted_input_evidence"]))

    def test_architecture_and_lower_layer_are_inventory_not_findings(self):
        files = {
            "src/codec.rs": ('#[cfg(target_pointer_width = "32")]\nfn read(x: u64) -> usize { x as usize }\n'
                              '#[cfg(target_pointer_width = "64")]\nfn read(x: u64) -> usize { usize::try_from(x).unwrap() }\n'),
            "src/sandbox/kernel_boundary.rs": "pub fn run_guest() {}\n",
        }
        result = research.analyze(files, redact)
        self.assertEqual(len(result["architecture_divergence"]["candidates"]), 1)
        self.assertEqual(result["architecture_divergence"]["candidates"][0]["status"], "hypothesis")
        self.assertEqual(len(result["lower_layer_surfaces"]["surfaces"]), 1)
        self.assertTrue(result["lower_layer_surfaces"]["surfaces"][0][
            "requires_component_scope_confirmation"])

    def test_evidence_is_redacted_and_hypothesis_outputs_never_claim_confirmation(self):
        source = """contract Store {
    mapping(bytes32 => address) internal owners;
    function create(bytes32 id) external onlyAdmin {
        owners[id] = address(uint160(uint256(keccak256(abi.encodePacked("synthetic-secret-value")))));
    }
    function restore(bytes32 id) external {
        owners[id] = address(0);
    }
}
"""
        result = research.analyze({"src/Store.sol": source}, redact)
        excerpt = result["alternative_path_discovery"]["candidates"][0][
            "operation_paths"][0]["source"]["excerpt"]
        self.assertNotIn("synthetic-secret-value", excerpt)
        self.assertEqual(result["alternative_path_discovery"]["candidates"][0]["status"],
                         "hypothesis")
        self.assertIn("interprocedural data flow is resolved",
                      result["alternative_path_discovery"]["notice"])


if __name__ == "__main__":
    unittest.main()
