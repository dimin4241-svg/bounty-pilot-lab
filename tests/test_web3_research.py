"""Web3 Security Research Engine: synthetic, local, fail-closed regression cases."""
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/bounty-pilot/scripts"
SPEC = importlib.util.spec_from_file_location("web3_research_test", SCRIPTS / "web3_research.py")
web3 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(web3)
HEX = "a" * 64
REV = "b" * 40


def policy(**changes):
    result = {"schema_version": 1, "network_mode": "offline", "production_requests": False,
              "scope_evidence": "published program scope independently recorded by investigator",
              "in_scope_origins": ["https://app.example.org", "http://127.0.0.1:8080"],
              "excluded_origins": ["https://admin.example.org"],
              "allowed_source_prefixes": ["app", "api"]}
    result.update(changes)
    return result


def obs(a, b):
    return {"schema_version": 1, "source_revision": REV, "environment": "mock-local",
            "cases": [{"id": "BP-501", "invariant": "only owner may mutate a payment",
                       "equivalence_basis": "identical resource and operation on local fixture",
                       "candidate": a, "negative_control": b}]}


def authz(actor, owner="alice", resource="payment-1", result="denied", operation="update"):
    return {"actor": actor, "owner": owner, "resource_id": resource,
            "operation": operation, "result": result, "trace_sha256": HEX}


def wallet(display="A", signed="A", executed="A", perm="valid", status="success"):
    return {"displayed": {"operation_digest": display, "chain_id": "1"},
            "signed": {"operation_digest": signed, "chain_id": "1"},
            "executed": {"operation_digest": executed, "chain_id": "1"},
            "session_permission": perm, "execution_status": status, "trace_sha256": HEX}


def wallet_doc(candidate, control):
    d = obs(candidate, control)
    d["cases"][0]["bound_fields"] = ["operation_digest", "chain_id"]
    return d


class ScopeGateTests(unittest.TestCase):
    def test_exact_origin_and_exclusion_precedence(self):
        self.assertEqual(web3.scope_check(policy(), "https://app.example.org/path?a=1")["classification"],
                         "DECLARED_IN_SCOPE")
        self.assertEqual(web3.scope_check(policy(), "https://admin.example.org/path")["classification"],
                         "EXCLUDED")

    def test_subdomain_and_suffix_do_not_inherit_scope(self):
        for url in ("https://evil.app.example.org/", "https://app.example.org.evil.com/",
                    "http://app.example.org/", "https://another.example.org/"):
            with self.subTest(url=url):
                self.assertNotEqual(web3.scope_check(policy(), url)["classification"],
                                    "DECLARED_IN_SCOPE")

    def test_url_userinfo_and_invalid_origin(self):
        for url in ("https://app.example.org@evil.com/path", "javascript://app.example.org/x",
                    "https://app.example.org:bad/", "https://app.example.org./"):
            with self.subTest(url=url):
                self.assertNotEqual(web3.scope_check(policy(), url)["classification"],
                                    "DECLARED_IN_SCOPE")

    def test_http_requires_loopback(self):
        with self.assertRaises(ValueError):
            web3.validate_policy(policy(in_scope_origins=["http://app.example.org"]))
        self.assertEqual(web3.scope_check(policy(), "http://127.0.0.1:8080/test")["classification"],
                         "DECLARED_IN_SCOPE")

    def test_no_online_mode_and_no_implicit_policy(self):
        for extra in ({"network_mode": "online"}, {"production_requests": True},
                      {"network_mode": "passive"}, {"production_requests": None}):
            with self.subTest(extra=extra):
                with self.assertRaises(ValueError):
                    web3.validate_policy(policy(**extra))

    def test_no_wildcard_schemes_or_directory_traversal(self):
        for extra in ({"in_scope_origins": ["https://*.example.org"]},
                      {"allowed_source_prefixes": ["../src"]},
                      {"allowed_source_prefixes": ["/root"]},
                      {"allowed_source_prefixes": ["."]}):
            with self.subTest(extra=extra):
                with self.assertRaises(ValueError):
                    web3.validate_policy(policy(**extra))

    def test_duplicate_canonical_origin_fails(self):
        with self.assertRaises(ValueError):
            web3.validate_policy(policy(in_scope_origins=["https://app.example.org",
                                                          "https://APP.example.org:443"]))

    def test_bad_policy_input_types(self):
        with self.assertRaises(ValueError):
            web3.validate_policy(policy(schema_version=True))
        with self.assertRaises(ValueError):
            web3.validate_policy(policy(in_scope_origins="app.example.org"))


class ApiMapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "target"
        self.repo.mkdir()

    def git(self):
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid",
                        "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"], check=True)

    def write(self, p, content):
        target = self.repo / p
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def test_express_fastapi_nest_routes_and_security_signals(self):
        self.write("api/server.ts", 'router.post("/withdraw", handler);\nconst key = merchantId;\n')
        self.write("api/accounts.py", '@app.get("/balances/{account_id}")\ndef balances():\n  return accountId\n')
        self.write("app/controller.ts", '@Get("payments")\nfunction list() {}\n')
        self.write("api/dependency.py", 'def sign():\n    verifySiweMessage(x)\n')
        self.git()
        result = web3.api_map(self.repo, policy())
        paths = {(x["method"], x["declared_path"]) for x in result["routes"]}
        self.assertIn(("POST", "/withdraw"), paths)
        self.assertIn(("GET", "/balances/{account_id}"), paths)
        self.assertIn(("GET", "payments"), paths)
        self.assertIn("wallet-login", {x["signal"] for x in result["signals"]})
        self.assertEqual(result["network_requests"], 0)
        self.assertEqual(result["confirmed_vulnerabilities"], 0)

    def test_test_code_and_symlinked_source_ignored(self):
        self.write("api/server.ts", 'app.get("/health", ok);\n')
        self.write("tests/hidden.py", '@app.post("/admin")')
        (self.repo / "api" / "symlink.py").symlink_to(self.repo / "tests" / "hidden.py")
        self.git()
        result = web3.api_map(self.repo, policy())
        self.assertEqual([x["declared_path"] for x in result["routes"]], ["/health"])
        self.assertGreaterEqual(result["skipped_oversized_or_symlinked"], 1)

    def test_requested_scope_cannot_escape_policy(self):
        self.write("api/test.py", '@app.get("/x")')
        self.git()
        with self.assertRaisesRegex(ValueError, "not inside declared scope"):
            web3.api_map(self.repo, policy(), ["contracts"])

    def test_oversized_file_skipped(self):
        self.write("api/oversized.py", "a = 1\n" * 200000)
        self.git()
        result = web3.api_map(self.repo, policy())
        self.assertGreaterEqual(result["skipped_oversized_or_symlinked"], 1)

    def test_subdirectory_not_accepted_as_checkout(self):
        self.write("api/server.ts", 'app.get("/x", f)\n')
        self.git()
        with self.assertRaises(ValueError):
            web3.api_map(self.repo / "api", policy())


class AuthorizationTests(unittest.TestCase):
    def test_cross_owner_allowed_control_owner_allowed(self):
        d = obs(authz("bob", result="allowed"), authz("alice", result="allowed"))
        r = web3.observe(d, "authz")
        self.assertEqual(r["leads"], 1)
        self.assertEqual(r["cases"][0]["signals"], ["CROSS_OWNER_OPERATION_ALLOWED"])
        self.assertEqual(r["confirmed_vulnerabilities"], 0)

    def test_denied_cross_owner_is_not_lead(self):
        d = obs(authz("bob"), authz("alice", result="allowed"))
        self.assertEqual(web3.observe(d, "authz")["cases"][0]["decision"], "NO_DIFFERENTIAL")

    def test_control_denied_blocks_positive(self):
        d = obs(authz("bob", result="allowed"), authz("alice", result="denied"))
        self.assertEqual(web3.observe(d, "authz")["cases"][0]["decision"], "CONTROL_ALSO_VIOLATES")

    def test_different_resource_owner_or_operation_inconclusive(self):
        for change in ({"resource": "payment-2"}, {"owner": "eve"},
                       {"operation": "delete"}):
            candidate = authz("bob", result="allowed", **change)
            control = authz("alice", result="allowed")
            self.assertEqual(web3.observe(obs(candidate, control), "authz")["cases"][0]["decision"],
                             "INCONCLUSIVE")

    def test_unauthenticated_or_same_owner_not_cross_tenant(self):
        d = obs(authz("alice", result="allowed"), authz("alice", result="denied"))
        self.assertEqual(web3.observe(d, "authz")["cases"][0]["decision"], "INCONCLUSIVE")

    def test_unknown_result_is_inconclusive(self):
        d = obs(authz("bob", result="unknown"), authz("alice", result="allowed"))
        self.assertEqual(web3.observe(d, "authz")["cases"][0]["decision"], "INCONCLUSIVE")


class WalletTests(unittest.TestCase):
    def test_signed_and_executed_binding_mismatch(self):
        d = wallet_doc(wallet(executed="B"), wallet())
        r = web3.observe(d, "wallet-intent")
        self.assertEqual(r["leads"], 1)
        self.assertIn("INTENT_FIELD_DIVERGENCE", r["cases"][0]["signals"])
        self.assertNotIn('"B"', json.dumps(r))

    def test_revoked_session_requires_successful_execution(self):
        d = wallet_doc(wallet(perm="revoked"), wallet())
        self.assertEqual(web3.observe(d, "wallet-intent")["leads"], 1)
        d = wallet_doc(wallet(perm="revoked", status="rejected"), wallet())
        self.assertEqual(web3.observe(d, "wallet-intent")["leads"], 0)

    def test_missing_binding_is_inconclusive(self):
        c = wallet(executed="B")
        del c["signed"]["chain_id"]
        self.assertEqual(web3.observe(wallet_doc(c, wallet()), "wallet-intent")["cases"][0]["decision"],
                         "INCONCLUSIVE")

    def test_bad_control_blocks_promotion(self):
        d = wallet_doc(wallet(executed="B"), wallet(executed="C"))
        self.assertEqual(web3.observe(d, "wallet-intent")["cases"][0]["decision"],
                         "CONTROL_ALSO_VIOLATES")

    def test_unknown_execution_is_inconclusive(self):
        d = wallet_doc(wallet(executed="B", status="unknown"), wallet())
        self.assertEqual(web3.observe(d, "wallet-intent")["cases"][0]["decision"],
                         "INCONCLUSIVE")

    def test_duplicate_or_invalid_binding_rejected(self):
        d = wallet_doc(wallet(executed="B"), wallet())
        for fields in (["chain_id", "chain_id"], ["unrecognized"], []):
            with self.subTest(fields=fields):
                d["cases"][0]["bound_fields"] = fields
                with self.assertRaises(ValueError):
                    web3.observe(d, "wallet-intent")


class InputAndCliTests(unittest.TestCase):
    def test_duplicate_json_keys_and_symlink_input_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "input.json"
            source.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                web3.load_json(source)
            link = Path(tmp) / "link"
            link.symlink_to(source)
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                web3.load_json(link)

    def test_output_private_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            web3.write_private(output, {"classification": "TEST"})
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                web3.write_private(output, {"classification": "REPLACED"})

    def test_all_four_modes_in_main_cli_and_direct_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = Path(tmp) / "policy.json"
            scope.write_text(json.dumps(policy()))
            observations = Path(tmp) / "observations.json"
            observations.write_text(json.dumps(obs(authz("bob", result="allowed"),
                                                  authz("alice", result="allowed"))))
            for cmd in ([sys.executable, str(SCRIPTS / "web3_research.py")],
                        [sys.executable, str(SCRIPTS / "bounty.py"), "web3"]):
                for args in (["scope", "--policy", str(scope), "--url", "https://app.example.org/x"],
                             ["authz", "--input", str(observations)]):
                    run = subprocess.run(cmd + args, capture_output=True, text=True, timeout=30)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    self.assertIn("classification", json.loads(run.stdout))
                wallet_input = Path(tmp) / "wallet.json"
                wallet_input.write_text(json.dumps(wallet_doc(wallet(executed="B"), wallet())))
                done = subprocess.run(cmd + ["wallet-intent", "--input", str(wallet_input)],
                                      capture_output=True, text=True, timeout=30)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(json.loads(done.stdout)["leads"], 1)

    def test_bool_schema_and_duplicate_ids_fail_closed(self):
        d = obs(authz("bob", result="allowed"), authz("alice", result="allowed"))
        d["schema_version"] = True
        with self.assertRaises(ValueError):
            web3.observe(d, "authz")
        d["schema_version"] = 1
        d["cases"] *= 2
        with self.assertRaises(ValueError):
            web3.observe(d, "authz")


if __name__ == "__main__":
    unittest.main()
