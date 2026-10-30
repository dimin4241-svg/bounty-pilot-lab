"""Regression tests for passive scope, dependency, history, trust-boundary, and ranking analysis."""
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "skills/bounty-pilot/scripts"
FIXTURE = ROOT / "tests/fixtures/ecosystem"
spec = importlib.util.spec_from_file_location(
    "ecosystem_intelligence", SCRIPT_DIR / "ecosystem_intelligence.py")
eco = importlib.util.module_from_spec(spec)
spec.loader.exec_module(eco)


class EcosystemIntelligenceTests(unittest.TestCase):
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
        self._commit("initial fixture")
        self.scope_path = self.root / "scope.json"
        self.scope_path.write_text(json.dumps({
            "schema_version": 1,
            "project": "synthetic fixture",
            "allowed": {
                "domains": ["api.example.org"],
                "urls": ["https://docs.example.org/security/"],
                "repositories": ["github.com/example/protocol"],
                "contracts": [{"address": "0x1111111111111111111111111111111111111111",
                               "chain_id": 1}],
                "networks": [{"name": "Ethereum", "chain_id": 1}],
                "methods": ["local_static", "git_history", "provided_archive"],
            },
            "related_out_of_scope": {
                "domains": ["status.example.org"], "urls": [], "repositories": [],
                "contracts": [], "networks": [], "methods": [],
            },
        }, indent=2))
        self.scope = eco.load_scope(self.scope_path)

    def _commit(self, message):
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "-c",
                        "commit.gpgsign=false", "commit", "-qm", message],
                       check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if subprocess.run(["git", "-C", str(self.repo), "rev-parse", "--verify", "HEAD"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Fixture",
                            "-c", "user.email=fixture@example.invalid", "-c",
                            "commit.gpgsign=false", "commit", "-qm", message], check=True)

    def test_scope_classification_is_exact_and_fail_closed(self):
        self.assertEqual(eco.classify(self.scope, "domain", "api.example.org")["classification"],
                         "IN_SCOPE")
        self.assertEqual(eco.classify(self.scope, "domain", "notexample.org")["classification"],
                         "UNKNOWN")
        self.assertEqual(eco.classify(self.scope, "url", "https://docs.example.org/security/rules")[
            "classification"], "IN_SCOPE")
        self.assertEqual(eco.classify(self.scope, "url", "https://docs.example.org/private")[
            "classification"], "UNKNOWN")
        self.assertEqual(eco.classify(self.scope, "domain", "status.example.org")[
            "classification"], "RELATED_OUT_OF_SCOPE")
        self.assertEqual(eco.classify(self.scope, "repository", "https://github.com/example/protocol.git")[
            "classification"], "IN_SCOPE")

    def test_scope_binds_contract_to_chain_and_disables_active_methods(self):
        address = "0x1111111111111111111111111111111111111111"
        self.assertEqual(eco.classify(self.scope, "contract", address, chain_id=1)[
            "classification"], "IN_SCOPE")
        self.assertEqual(eco.classify(self.scope, "contract", address, chain_id=10)[
            "classification"], "UNKNOWN")
        unapproved_network_address = "0x2222222222222222222222222222222222222222"
        data = json.loads(self.scope_path.read_text())
        data["allowed"]["contracts"].append({"address": unapproved_network_address,
                                               "chain_id": 10})
        self.scope_path.write_text(json.dumps(data))
        restricted = eco.load_scope(self.scope_path)
        self.assertEqual(eco.classify(restricted, "contract", unapproved_network_address,
                                      chain_id=10)["classification"], "UNKNOWN")
        self.assertEqual(eco.classify(self.scope, "method", "http_probe")[
            "classification"], "RELATED_OUT_OF_SCOPE")
        data = json.loads(self.scope_path.read_text())
        data["allowed"]["methods"].append("http_probe")
        self.scope_path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "active methods"):
            eco.load_scope(self.scope_path)

    def test_unauthorized_analysis_method_is_logged_and_stopped_before_read(self):
        data = json.loads(self.scope_path.read_text())
        data["allowed"]["methods"] = ["git_history"]
        self.scope_path.write_text(json.dumps(data))
        out = self.root / "blocked"
        with self.assertRaisesRegex(ValueError, "scope guardian blocked local_static"):
            eco.analyze(self.repo, self.scope_path, out)
        rows = [json.loads(line) for line in (out / "audit.jsonl").read_text().splitlines()]
        self.assertEqual(rows[-1]["event"], "method_scope")
        self.assertEqual(rows[-1]["classification"], "UNKNOWN")
        self.assertEqual(rows[0]["network_requests"], 0)

    def test_redaction_scrubs_credentials_queries_and_provider_keys(self):
        value = ('WEBHOOK_SECRET="fixture-secret" https://api.example.org/v1?q=token '
                 'https://eth-mainnet.g.alchemy.com/v2/abcdefghijklmnopqrstuv '
                 'https://api.example.org/hooks/abcdefghijklmnopqrstuvwx')
        output = eco.redact_text(value)
        self.assertNotIn("fixture-secret", output)
        self.assertNotIn("q=token", output)
        self.assertNotIn("abcdefghijklmnopqrstuv", output)

    def test_secret_named_tracked_files_are_skipped_before_read(self):
        (self.repo / ".env.production").write_text("API_TOKEN=secret-value\n")
        (self.repo / "config").mkdir(exist_ok=True)
        (self.repo / "config/prod-secrets.json").write_text('{"secret":"secret-value"}\n')
        (self.repo / "wallet").mkdir(exist_ok=True)
        (self.repo / "wallet/Wallet.sol").write_text("contract Wallet { function sign() public {} }\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "-f", ".env.production",
                        "config/prod-secrets.json", "wallet/Wallet.sol"], check=True)
        files, skipped, _ = eco._safe_files(self.repo.resolve())
        loaded_paths = {row["path"] for row in files}
        self.assertNotIn(".env.production", loaded_paths)
        self.assertNotIn("config/prod-secrets.json", loaded_paths)
        self.assertIn("wallet/Wallet.sol", loaded_paths)
        self.assertEqual(sum(row["reason"] == "sensitive/generated path" for row in skipped), 2)

    def test_privileged_or_third_party_prerequisites_are_explicit_and_deprioritized(self):
        hypothesis = eco._hypothesis(
            "test hypothesis", "test_class", ["Requires compromise of a trusted signer"],
            ["Attacker submits a request"], "test invariant", "asset loss", "unknown",
            [], [], [], {"classification": "IN_SCOPE"}, "")
        self.assertEqual(hypothesis["privileged_assumption_count"], 1)
        self.assertTrue(hypothesis["privileged_prerequisites"])
        self.assertTrue(any("separate in-scope" in item
                            for item in hypothesis["missing_checks"]))
        self.assertTrue(any("not an acceptable attacker path" in item
                            for item in hypothesis["disconfirming_evidence"]))

    def test_runtime_reality_handoff_does_not_offer_commands_for_unknown_scope(self):
        nodes = [{"id": "contract:unknown", "label": "0x2222222222222222222222222222222222222222",
                  "kind": "contract", "chain_id": None}]
        edges = [{"to": "contract:unknown", "role": "contract_or_deployment_reference",
                  "scope": {"classification": "UNKNOWN", "basis": "not listed"},
                  "source": {"path": "deployments/config.json", "line": 4}}]
        rows = eco._runtime_reality_handoffs(nodes, edges)
        self.assertEqual(rows[0]["status"], "BLOCKED_BY_SCOPE")
        self.assertIsNone(rows[0]["recommended_existing_tool"])
        self.assertIsNone(rows[0]["selector_followup"])
        self.assertEqual(rows[0]["required_checks"], [])

    def test_contract_in_explicit_scope_is_handed_off_even_when_not_in_source(self):
        address = "0x3333333333333333333333333333333333333333"
        scope_data = json.loads(self.scope_path.read_text())
        scope_data["allowed"]["contracts"] = [{"address": address, "chain_id": 10}]
        scope_data["allowed"]["networks"].append({"name": "Optimism", "chain_id": 10})
        self.scope_path.write_text(json.dumps(scope_data))
        scope = eco.load_scope(self.scope_path)
        nodes, edges = {}, []
        count = eco._add_scoped_contract_targets(scope, "github.com/example/protocol",
                                                  "2026-10-27T00:00:00Z", nodes, edges)
        rows = eco._runtime_reality_handoffs(list(nodes.values()), edges)
        self.assertEqual(count, 1)
        self.assertEqual(rows[0]["address"], address)
        self.assertEqual(rows[0]["chain_id"], 10)
        self.assertEqual(rows[0]["status"], "PENDING_EXPLICIT_READ_ONLY_CHECK")
        self.assertIn("verify-deployment", rows[0]["recommended_existing_tool"])

    def test_analysis_writes_provenance_graph_hypotheses_and_no_live_calls(self):
        out = self.root / "out"
        result = eco.analyze(self.repo, self.scope_path, out)
        report = json.loads((out / "ecosystem-intelligence.json").read_text())
        self.assertEqual(result["network_requests"], 0)
        self.assertFalse(report["analysis"]["network_policy"]["enabled"])
        self.assertEqual(report["analysis"]["network_policy"]["requests"], 0)
        self.assertTrue(report["analysis"]["provenance"]["head_commit"])
        edges = report["dependency_intelligence"]["edges"]
        self.assertTrue(any(edge["kind"] == "candidate_data_flow" for edge in edges))
        node_kinds = {node["kind"] for node in report["dependency_intelligence"]["nodes"]}
        self.assertTrue({"asset", "permission", "signed_message"}.issubset(node_kinds))
        self.assertTrue(all("observed_at" in edge and "source" in edge and
                            "trust_boundary" in edge and "confidence" in edge
                            for edge in edges))
        self.assertTrue((out / "ecosystem-report.md").is_file())
        self.assertIn("flowchart LR", (out / "dependency-graph.mmd").read_text())
        sequences = report["trust_boundary_analysis"]["sequence_candidates"]
        self.assertTrue(sequences)
        self.assertEqual(sequences[0]["status"], "unverified_ordering_candidate")
        hypotheses = report["ranking"]["top_hypotheses"]
        self.assertTrue(hypotheses)
        verifier = next(row for row in hypotheses if "OrderVerifier.sol" in row["title"])
        self.assertIn("chain binding", verifier["missing_checks"])
        self.assertEqual(verifier["status"], "hypothesis")
        self.assertEqual(report["safe_verification_plans"][0]["execution_status"], "NOT_EXECUTED")
        self.assertFalse(report["safe_verification_plans"][0]["network_enabled"])
        self.assertEqual(report["independent_review_plans"][0]["review_status"],
                         "NOT_INDEPENDENTLY_REVIEWED")
        self.assertIn("CONFIRMED", report["independent_review_plans"][0]["allowed_verdicts"])
        self.assertIn("patch_variant_analysis", report["historical_intelligence"])
        transition = report["state_transition_research"]
        self.assertTrue(transition["alternative_path_discovery"]["candidates"])
        self.assertTrue(transition["revocation_resurrection"]["candidates"])
        self.assertTrue(transition["deleted_object_lifecycle"]["candidates"])
        self.assertTrue(transition["security_policy_drift"]["candidates"])
        self.assertTrue(transition["ci_release_provenance"]["observations"])
        self.assertTrue(transition["agentic_trust"]["candidates"])
        self.assertTrue(transition["architecture_divergence"]["candidates"])
        self.assertTrue(transition["lower_layer_surfaces"]["surfaces"])
        runtime_handoff = next(row for row in transition["runtime_reality_handoffs"]
                               if row["address"].lower() ==
                               "0x1111111111111111111111111111111111111111")
        self.assertEqual(runtime_handoff["chain_id"], "1")
        self.assertEqual(runtime_handoff["scope"]["classification"], "IN_SCOPE")
        self.assertEqual(runtime_handoff["status"], "PENDING_EXPLICIT_READ_ONLY_CHECK")
        self.assertIn("verify-deployment", runtime_handoff["recommended_existing_tool"])
        self.assertFalse(report["analysis"]["network_policy"]["live_state_reads"])
        audit = [json.loads(line) for line in (out / "audit.jsonl").read_text().splitlines()]
        self.assertTrue(any(row["event"] == "analysis_completed" for row in audit))
        bundle = "\n".join(path.read_text(errors="replace") for path in out.iterdir())
        self.assertNotIn("fixture-secret-must-not-appear-in-output", bundle)
        self.assertNotIn("do-not-export", bundle)

    def test_local_archive_import_is_scoped_and_does_not_fetch(self):
        archive_dir = self.root / "archive"
        archive_dir.mkdir()
        (archive_dir / "saved.html").write_text("local snapshot")
        index = archive_dir / "index.json"
        index.write_text(json.dumps({"captures": [
            {"url": "https://docs.example.org/security/rewards",
             "captured_at": "2026-10-01", "path": "saved.html"},
            {"url": "https://status.example.org/uptime", "path": "saved.html"},
        ]}))
        out = self.root / "archive-out"
        eco.analyze(self.repo, self.scope_path, out, str(index))
        report = json.loads((out / "ecosystem-intelligence.json").read_text())
        self.assertEqual(len(report["historical_intelligence"]["provided_archives"]), 1)
        self.assertEqual(len(report["historical_intelligence"]["archive_skipped"]), 1)
        self.assertEqual(report["analysis"]["network_policy"]["requests"], 0)

    def test_history_patch_lead_is_not_a_finding(self):
        source = self.repo / "contracts/OrderVerifier.sol"
        source.write_text(source.read_text() + "\n// replay guard nonce was added in a patch variant\n")
        admin = self.repo / "stale_auth/Admin.sol"
        admin.write_text(admin.read_text().replace(" onlyRole(DEFAULT_ADMIN_ROLE)", ""))
        relay = self.repo / "config/relay.txt"
        relay.write_text("retired endpoint\n")
        migration = self.repo / "migrations/upgrade.py"
        migration.write_text(migration.read_text() + "\n# security migration review\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "-c",
                        "commit.gpgsign=false", "commit", "-qm",
                        "security fix signature replay #12"], check=True)
        source.write_text(source.read_text().replace(
            "replay guard nonce was added in a patch variant\n", ""))
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "-c",
                        "commit.gpgsign=false", "commit", "-qm",
                        "patch review replay window #13"], check=True)
        result = eco._history(self.repo, {}, {}, self.scope)
        self.assertTrue(result["patch_variant_leads"])
        self.assertEqual(result["patch_variant_leads"][0]["status"], "historical_patch_lead")
        self.assertTrue(any(
            "nonce_or_replay" in change["invariants_added"]
            for lead in result["patch_variant_leads"] for change in lead["changes"]))
        patch_variants = eco._patch_variant_analysis(
            result["patch_variant_leads"],
            {"contracts/OrderVerifier.sol": source.read_text()})
        self.assertTrue(any(row["invariant"] == "nonce_or_replay"
                            and row["function"] == "verifyOrder"
                            for row in patch_variants["candidates"]))
        lead_types = {row["type"] for row in result["historical_leads"]}
        self.assertIn("stale_authorization_candidate", lead_types)
        self.assertIn("ghost_integration_candidate", lead_types)
        self.assertIn("incomplete_migration_candidate", lead_types)
        self.assertIn("historical_replay_window_candidate", lead_types)

    def test_cli_is_exposed_without_changing_old_command_names(self):
        output = subprocess.run(["python3", str(SCRIPT_DIR / "bounty.py"), "--help"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        self.assertIn("ecosystem-intel", output.stdout)
        self.assertIn("bundle", output.stdout)
        self.assertIn("verify-deployment", output.stdout)

    def test_cli_runs_end_to_end_and_writes_private_artifact_bundle(self):
        out = self.root / "cli-out"
        result = subprocess.run([
            "python3", str(SCRIPT_DIR / "bounty.py"), "ecosystem-intel",
            "--repo", str(self.repo), "--scope", str(self.scope_path), "--out", str(out),
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["network_requests"], 0)
        for name in ("ecosystem-intelligence.json", "ecosystem-report.md",
                     "dependency-graph.mmd", "audit.jsonl"):
            self.assertTrue((out / name).is_file(), name)
        report = json.loads((out / "ecosystem-intelligence.json").read_text())
        self.assertTrue(report["ranking"]["top_hypotheses"])
        self.assertTrue(all(row["execution_status"] == "NOT_EXECUTED"
                            for row in report["safe_verification_plans"]))


class MalformedURLTextTests(unittest.TestCase):
    """A target's own text must never abort a passive run.

    urlsplit raises ValueError on a malformed authority. Charon's credential-redaction
    fixtures contain `https://user:s3cret`-shaped strings, where the password parses as
    a port, and bracket-less IPv6 fragments survive URL regexes. Either one aborted the
    whole ecosystem-intel run with "Port could not be cast to integer value" or
    "Invalid IPv6 URL".
    """

    def test_unparsable_authorities_are_not_urls_instead_of_raising(self):
        for value in ("https://user:s3cret", "https://user:s", "http://admin:secret",
                      "http://[::1", "https://host:]", "http://[::1]:notaport/x"):
            with self.subTest(value=value):
                self.assertIsInstance(eco.safe_url(value), str)
                self.assertIsInstance(eco.normalize_url(value), str)

    def test_ordinary_urls_and_ipv6_literals_still_round_trip(self):
        self.assertEqual(eco.safe_url("https://ok.example.org/b"), "https://ok.example.org/b")
        self.assertEqual(eco.normalize_url("https://ok.example.org:8443/a"),
                         "https://ok.example.org:8443/a")
        # hostname drops the IPv6 brackets; a host:port join must put them back or the
        # result ("http://::1:3600") is not a URL at all.
        self.assertEqual(eco.safe_url("http://[::1]:3600/c"), "http://[::1]:3600/c")
        self.assertEqual(eco.normalize_url("http://[::1]/d"), "http://[::1]/d")

    def test_a_full_passive_run_survives_such_text_in_the_target(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        repo = root / "checkout"
        (repo / "src").mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        # Exactly the shape that aborted the run on a real target.
        (repo / "src/redact.go").write_text(
            'package src\n\nvar fixtures = []string{\n'
            '\t"https://user:s3cret@beacon.example.invalid/eth/v1",\n'
            '\t"http://[::1]:3600/eth/v1/node/version",\n'
            '}\n', encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "config", "user.email",
                        "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
        scope = root / "scope.json"
        scope.write_text(json.dumps({
            "schema_version": 1, "project": "fixture",
            "allowed": {"domains": [], "urls": [], "repositories": [], "contracts": [],
                        "networks": [], "methods": ["local_static", "git_history"]},
            "related_out_of_scope": {"domains": [], "urls": [], "repositories": [],
                                     "contracts": [], "networks": []}}), encoding="utf-8")
        out = root / "run"
        result = subprocess.run(
            ["python3", str(SCRIPT_DIR / "bounty.py"), "ecosystem-intel",
             "--repo", str(repo), "--scope", str(scope), "--out", str(out)],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Invalid IPv6 URL", result.stderr)
        self.assertNotIn("cast to integer", result.stderr)
        self.assertTrue((out / "ecosystem-intelligence.json").is_file())


if __name__ == "__main__":
    unittest.main()
