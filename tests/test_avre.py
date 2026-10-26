"""AVRE regression tests: bounded plans, paired measurements, safe scope, and recovery."""
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"
FIXTURE = ROOT / "tests/fixtures/avre/repo"
spec = importlib.util.spec_from_file_location("avre", SCRIPTS / "avre.py")
avre = importlib.util.module_from_spec(spec)
spec.loader.exec_module(avre)
eco = avre._load("ecosystem_intelligence")
sequence = avre.avre_sequence
economics = avre.avre_economics


class AVRETests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        shutil.copytree(FIXTURE, self.repo)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "remote", "add", "origin",
                        "https://github.com/example/protocol.git"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        self._commit("fixture baseline")
        self.scope_path = self.root / "scope.json"
        self.scope = {
            "schema_version": 1,
            "project": "AVRE synthetic fixture",
            "allowed": {
                "domains": ["relay.example.org"], "urls": [],
                "repositories": ["github.com/example/protocol"],
                "contracts": [], "networks": [],
                "methods": ["local_static", "git_history", "provided_archive"],
            },
            "related_out_of_scope": {
                "domains": [], "urls": [], "repositories": [], "contracts": [],
                "networks": [], "methods": [],
            },
        }
        self._write_scope()

    def _write_scope(self):
        self.scope_path.write_text(json.dumps(self.scope, indent=2), encoding="utf-8")

    def _commit(self, message):
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=AVRE Fixture",
                        "-c", "user.email=fixture@example.invalid", "-c",
                        "commit.gpgsign=false", "commit", "-qm", message],
                       check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if subprocess.run(["git", "-C", str(self.repo), "rev-parse", "--verify", "HEAD"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=AVRE Fixture",
                            "-c", "user.email=fixture@example.invalid", "-c",
                            "commit.gpgsign=false", "commit", "-qm", message], check=True)

    def test_scope_is_fail_closed_and_output_must_be_private_and_external(self):
        self.scope["allowed"]["methods"] = ["git_history"]
        self._write_scope()
        with self.assertRaisesRegex(ValueError, "blocked local_static"):
            avre.analyze(self.repo, self.scope_path, self.root / "blocked",
                         modules=["sequence-mutation"])
        self.scope["allowed"]["methods"] = ["local_static", "git_history"]
        self._write_scope()
        with self.assertRaisesRegex(ValueError, "outside the target checkout"):
            avre.analyze(self.repo, self.scope_path, self.repo / "out",
                         modules=["sequence-mutation"])

    def test_local_static_only_scope_does_not_require_history_permissions(self):
        self.scope["allowed"]["methods"] = ["local_static"]
        self._write_scope()
        result = avre.analyze(self.repo, self.scope_path, self.root / "static-only",
                              modules=["sequence-mutation"], budget=5)
        self.assertEqual(result["network_requests"], 0)

    def test_optional_local_plan_remains_dry_run(self):
        plan_path = self.root / "scenario-plan.json"
        plan_path.write_text(json.dumps({"schema_version": 1, "cases": [
            {"id": "candidate", "pair_id": "pair-1", "role": "candidate",
             "argv": ["pytest", "-q", "tests/test_case.py"], "cwd": "."},
            {"id": "control", "pair_id": "pair-1", "role": "negative-control",
             "argv": ["pytest", "-q", "tests/test_case.py", "-k", "negative"], "cwd": "."},
        ]}))
        result = avre.analyze(self.repo, self.scope_path, self.root / "plan-out",
                              modules=["sequence-mutation"], budget=5,
                              local_plan_path=plan_path)
        report = json.loads(Path(result["report"]).read_text())
        run_plan = report["modules"]["local-verification-plan"]
        self.assertEqual(run_plan["result"], "not-executed")
        self.assertTrue(all(not row["executed"] for row in run_plan["cases"]))
        self.assertEqual(report["analysis"]["local_verification"], "dry-run; no command executed")

    def test_impossible_state_and_identity_hypotheses_have_positive_and_negative_controls(self):
        graph = avre._load("state_graph").scan(self.repo, limit=200)
        state_leads = avre._operation_pairs(graph, self.repo, eco,
                                            eco.classify(eco.load_scope(self.scope_path),
                                                         "repository", "github.com/example/protocol"))
        self.assertTrue(any(row["bug_class"] == "state_transition_invariant" for row in state_leads))
        files, _, _ = eco._safe_files(self.repo.resolve())
        scope = eco.classify(eco.load_scope(self.scope_path), "repository",
                             "github.com/example/protocol")
        identity = avre._identity_candidates(self.repo, files, eco, scope)
        self.assertTrue(any(any(path.endswith("UnsafeVerifier.sol") for path in row["affected_paths"])
                            for row in identity))
        self.assertFalse(any(any(path.endswith("SafeVerifier.sol") for path in row["affected_paths"])
                             for row in identity))
        self.assertTrue(all(row["classification"] == "NEEDS_EVIDENCE" for row in identity))

    def test_sequence_search_is_bounded_and_shrinker_uses_supplied_local_predicate(self):
        graph = {"symbols": [
            {"id": "A", "symbol": "deposit", "path": "Pool.sol", "line": 1,
             "reads_approx": ["shares"], "signals": ["asset"]},
            {"id": "B", "symbol": "withdraw", "path": "Pool.sol", "line": 2,
             "reads_approx": ["shares"], "signals": ["asset"]},
            {"id": "C", "symbol": "claim", "path": "Pool.sol", "line": 3,
             "reads_approx": ["claimed"], "signals": ["accounting"]},
        ], "edges": [
            {"from": "A", "to": "B", "token": "shares", "reason": "state", "confidence": "low"},
            {"from": "B", "to": "C", "token": "claimed", "reason": "state", "confidence": "low"},
        ]}
        report = sequence.generate(graph, budget=7, max_length=3, beam_width=2)
        self.assertLessEqual(len(report["sequences"]), 7)
        self.assertTrue(any(len(row["actions"]) == 3 for row in report["sequences"]))
        self.assertEqual(sequence.generate({"symbols": graph["symbols"], "edges": []})["sequences"], [])
        calls = []
        shrunk = sequence.minimize_sequence(["deposit", "delegate", "withdraw", "claim"],
                                             lambda steps: calls.append(list(steps)) or
                                             "withdraw" in steps and "claim" in steps,
                                             max_replays=30)
        self.assertEqual(shrunk["sequence"], ["withdraw", "claim"])
        self.assertGreaterEqual(shrunk["replays"], 1)

    def test_economic_differential_requires_basis_and_distinguishes_tolerance(self):
        plans = economics.generate_plans([
            {"symbol": "deposit", "path": "Pool.sol", "line": 4, "reads_approx": ["shares"]},
            {"symbol": "withdraw", "path": "Pool.sol", "line": 9, "reads_approx": ["assets"]},
        ])
        self.assertEqual({row["family"] for row in plans},
                         {"batch_vs_split", "large_vs_small_exit", "shares_vs_assets"})
        head = avre._head(self.repo)
        fixture = {"schema_version": 1, "source_revision": head, "comparisons": [
            {"id": "difference", "equivalence_basis": "documented same-state route",
             "unit": "wei", "tolerance": 1,
             "candidate": {"before": 100, "after": 89},
             "control": {"before": 100, "after": 95}},
            {"id": "within", "equivalence_basis": "documented same-state route",
             "unit": "wei", "tolerance": 3,
             "candidate": {"before": 100, "after": 98},
             "control": {"before": 100, "after": 100}},
        ]}
        result = economics.compare_measurements(fixture, head, {"classification": "IN_SCOPE"})
        self.assertEqual(result["summary"], {"cases": 2, "exceeds_tolerance": 1, "within_tolerance": 1})
        self.assertIsNone(result["comparisons"][0]["actual_impact"])
        fixture["comparisons"][0]["equivalence_basis"] = " "
        with self.assertRaisesRegex(ValueError, "equivalence_basis"):
            economics.compare_measurements(fixture, head, {"classification": "IN_SCOPE"})

    def test_failure_recovery_and_cross_reality_require_evidence_and_allow_negative_control(self):
        symbols = [{"symbol": "retryMessage", "path": "src/Pool.sol", "line": 20,
                    "reads_approx": ["processed"], "signals": ["asynchronous"]}]
        failures = avre._failure_plans(symbols, {"classification": "IN_SCOPE"})
        self.assertTrue(failures)
        self.assertEqual(failures[0]["classification"], "INVARIANT_ONLY")
        blindspot = avre._load("blindspot_engine")
        gap_model = {"components": [{"id": "api", "kind": "backend"},
                                    {"id": "chain", "kind": "contract"}],
                     "flows": [{"source": "api", "destination": "chain", "data": "amount",
                                "checks": {"parameter_origin": "request body"}}]}
        scope = {"classification": "IN_SCOPE"}
        gap = avre._cross_reality(gap_model, blindspot, scope)
        self.assertEqual(len(gap["candidates"]), 1)
        safe_model = json.loads(json.dumps(gap_model))
        safe_model["flows"][0]["checks"] = {
            "parameter_origin": "request body", "signer_or_authenticator": "EIP-712 signer",
            "validation": "chain and nonce checked", "executed_value": "same decoded amount",
        }
        safe = avre._cross_reality(safe_model, blindspot, scope)
        self.assertEqual(safe["candidates"], [])

    def test_attack_graph_and_historical_leads_keep_unverified_status(self):
        graph = {"symbols": [{"id": "src/Pool.sol:withdraw:10", "symbol": "withdraw",
                              "path": "src/Pool.sol", "line": 10}], "edges": []}
        hypothesis = avre._hypothesis("impossible-state", "candidate", "lexical signal",
                                      ["src/Pool.sol"], [{"type": "source"}],
                                      "invariant", "possible balance impact")
        attack = avre._attack_graph(graph, {}, [hypothesis], {"sequences": []})
        self.assertTrue(any(node["kind"] == "hypothesis" for node in attack["nodes"]))
        history = {"historical_intelligence": {"historical_leads": [{
            "type": "stale_authorization_candidate", "source": {"path": "src/Pool.sol"}}]}}
        leads = avre._historical_candidates(history, {"classification": "IN_SCOPE"})
        self.assertEqual(leads[0]["classification"], "NEEDS_EVIDENCE")
        self.assertIsNone(leads[0]["actual_impact"])

    def test_cli_outputs_ranked_report_mermaid_audit_and_resumes_after_lock_release(self):
        output = self.root / "out"
        trust_model = self.root / "trust-model.json"
        trust_model.write_text(json.dumps({
            "components": [{"id": "api", "kind": "backend"},
                           {"id": "chain", "kind": "contract"}],
            "flows": [{"source": "api", "destination": "chain",
                       "data": {"api_token": "avre-private-fixture-secret"},
                       "checks": {"parameter_origin": "request body"}}],
        }))
        first = avre.analyze(self.repo, self.scope_path, output,
                             budget=30, max_sequence_length=3, beam_width=4,
                             trust_model_path=trust_model)
        self.assertEqual(first["network_requests"], 0)
        self.assertFalse(first["target_execution"])
        report_path = output / "avre-report.json"
        report = json.loads(report_path.read_text())
        self.assertTrue(report["ranking"]["hypotheses"])
        self.assertEqual(report["review"]["status"], "NOT_INDEPENDENTLY_REVIEWED")
        self.assertTrue((output / "attack-graph.mmd").read_text().startswith("flowchart LR"))
        self.assertTrue((output / "avre-report.md").is_file())
        self.assertTrue((output / "audit.jsonl").is_file())
        self.assertTrue((output / "skeptical-review-queue.json").is_file())
        self.assertTrue((output / ".avre.lock").is_file())
        second = avre.analyze(self.repo, self.scope_path, output,
                              modules=report["analysis"]["modules_selected"], budget=30,
                              max_sequence_length=3, beam_width=4, resume=True,
                              trust_model_path=trust_model)
        self.assertEqual(first["commit"], second["commit"])
        self.assertEqual(first["hypotheses"], second["hypotheses"])
        self.assertEqual(report["analysis"]["resource_usage"]["model_or_network_calls"], 0)
        self.assertEqual(report["analysis"]["resource_usage"]["tokens_used"], 0)
        self.assertIn("cross-reality", report["modules"])
        self.assertIn("historical-ecosystem", report["modules"])
        saved = "\n".join(path.read_text(errors="replace") for path in output.rglob("*")
                           if path.is_file())
        self.assertNotIn("avre-private-fixture-secret", saved)

        changed_scope = json.loads(self.scope_path.read_text())
        changed_scope["project"] = "different fingerprint"
        mismatch = self.root / "scope-changed.json"
        mismatch.write_text(json.dumps(changed_scope))
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            avre.analyze(self.repo, mismatch, output, budget=30,
                         max_sequence_length=3, beam_width=4, resume=True,
                         trust_model_path=trust_model)

        cli_out = self.root / "cli-out"
        cli = subprocess.run([
            "python3", str(SCRIPTS / "bounty.py"), "avre", "--repo", str(self.repo),
            "--scope", str(self.scope_path), "--out", str(cli_out),
            "--modules", "sequence-mutation", "--budget", "5",
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        self.assertEqual(json.loads(cli.stdout)["network_requests"], 0)
        self.assertTrue((cli_out / "avre-report.json").is_file())

    def test_output_lock_is_exclusive_and_released_without_deleting_its_inode(self):
        out = self.root / "lock-test"
        path, fd = avre._prepare_out(self.repo.resolve(), out, False)
        with self.assertRaisesRegex(ValueError, "output lock"):
            avre._prepare_out(self.repo.resolve(), out, False)
        import os
        os.close(fd)
        path2, fd2 = avre._prepare_out(self.repo.resolve(), out, False)
        self.assertEqual(path, path2)
        os.close(fd2)


if __name__ == "__main__":
    unittest.main()
