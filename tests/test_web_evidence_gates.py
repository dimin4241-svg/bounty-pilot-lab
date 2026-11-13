"""Offline evidence gates: paired local synthetic regression tests, no target traffic."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "bounty-pilot" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import web_evidence_gates as gates


def sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class EvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "source"
        self.docs = self.root / "documents"
        self.evidence = self.root / "receipts"
        for path in (self.repo, self.docs, self.evidence):
            path.mkdir()
        self.java = ('interface Api {\n'
                     '  @GET Call<Thing> a(@Header("Cookie") String cookie, @Url String resultUri);\n'
                     '}\n')
        self.call = 'void request() { api.a(cookie, resultUri); }\n'
        (self.repo / "Api.java").write_text(self.java)
        (self.repo / "Call.java").write_text(self.call)
        self.spec = 'Only an authorized decision maker can finalize an appeal.\n'
        (self.docs / "spec.txt").write_text(self.spec)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid",
                        "commit", "-qm", "owned fixture"], check=True)
        self.head = subprocess.check_output(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()

    def anchor(self, name, line, text, root=None, span=None):
        root = root or self.repo
        result = {"path": name, "line": line, "text": text,
                  "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest()}
        if span is not None:
            result["span"] = span
        return result

    def binding(self, examples=None, method_name="a"):
        return {"schema_version": 1, "source_revision": self.head,
                "cases": [{"id": "H-EBS-02", "method": {
                    "name": method_name, "syntax": "java",
                    "declaration": self.anchor("Api.java", 2, "@GET", span=1)},
                    "invocation": self.anchor("Call.java", 1, "api.a", span=1),
                    "claim": {"header": "Cookie"},
                    "url_examples": examples or [
                        {"label": "absolute", "value": "https://server.example/result"},
                        {"label": "root-relative", "value": "/mob/rs/api"},
                        {"label": "empty", "value": ""}]}]}

    def spec_case(self, kind="SPEC_CONFIRMED", with_pair=False):
        case = {"id": "FDO-01", "requirement": {
            "type": kind, "version": "1.5",
            "anchor": self.anchor("spec.txt", 1, "Only an authorized", self.docs)},
            "implementation": {
                "anchor": self.anchor("Api.java", 2, "@GET")}}
        if with_pair:
            (self.evidence / "candidate.txt").write_text("candidate-run\n")
            (self.evidence / "control.txt").write_text("control-run\n")
            case["experiment"] = {"source_revision": self.head,
                                  "candidate": {"file": "candidate.txt",
                                                "sha256": sha("candidate-run\n"),
                                                "executed": True, "exit_code": 0},
                                  "control": {"file": "control.txt",
                                              "sha256": sha("control-run\n"),
                                              "executed": True, "exit_code": 0}}
        return {"schema_version": 1, "source_revision": self.head, "cases": [case]}

    def test_absolute_url_overrides_base_and_is_not_credential_exfil_proof(self):
        result = gates.argument_binding(self.binding(), self.repo)
        case = result["cases"][0]
        self.assertEqual(case["header_parameter_index"], 0)
        self.assertEqual(case["url_parameter_index"], 1)
        self.assertEqual(case["header_argument"], "cookie")
        self.assertEqual(case["url_argument"], "resultUri")
        self.assertEqual([r["route_source"] for r in case["routing"]],
                         ["dynamic", "base", "base"])
        self.assertEqual(case["status"], "CONDITIONAL_ROUTING_ONLY")
        self.assertFalse(result["ready_for_vulnerability_claim"])

    def test_absolute_only_contradicts_claim_not_value_provenance(self):
        data = self.binding([{"label": "absolute", "value": "https://server.example/endpoint"},
                             {"label": "protocol-relative", "value": "//server.example/x"}])
        row = gates.argument_binding(data, self.repo)["cases"][0]
        self.assertEqual(row["status"], "DESTINATION_CLAIM_CONTRADICTED")
        self.assertIn("header value provenance", row["unverified"])

    def test_relative_and_empty_are_only_static_routing_leads(self):
        data = self.binding([{"label": "empty", "value": ""},
                             {"label": "relative", "value": "rs/api"}])
        result = gates.argument_binding(data, self.repo)
        self.assertEqual(result["cases"][0]["status"], "STATIC_ROUTING_ONLY")
        self.assertFalse(result["ready_for_vulnerability_claim"])

    def test_swapped_annotations_change_argument_binding(self):
        self.java = ("interface Api {\n"
                     '  @GET Call<Thing> a(@Url String url, @Header("Cookie") String cookie);\n'
                     "}\n")
        self.call = "void request() { api.a(resultUri, cookie); }\n"
        (self.repo / "Api.java").write_text(self.java)
        (self.repo / "Call.java").write_text(self.call)
        data = self.binding()
        row = gates.argument_binding(data, self.repo)["cases"][0]
        self.assertEqual(row["header_parameter_index"], 1)
        self.assertEqual(row["url_parameter_index"], 0)
        self.assertEqual(row["header_argument"], "cookie")
        self.assertEqual(row["url_argument"], "resultUri")

    def test_broken_annotation_or_arity_fails_closed(self):
        self.java = ("interface Api {\n"
                     "  @GET Call<Thing> a(String cookie, @Url String resultUri);\n"
                     "}\n")
        (self.repo / "Api.java").write_text(self.java)
        row = gates.argument_binding(self.binding(), self.repo)["cases"][0]
        self.assertEqual(row["status"], "BLOCKED_UNRESOLVED_BINDING")
        self.assertNotIn("cookie", json.dumps(row))

    def test_smali_parameter_annotation_mapping(self):
        smali = (".method public abstract a(Ljava/lang/String;Ljava/lang/String;)V\n"
                 "  .annotation runtime Lretrofit2/http/GET;\n"
                 "  .end annotation\n"
                 '  .param p1\n'
                 '    .annotation runtime Lretrofit2/http/Header;\n'
                 '      value = "Cookie"\n'
                 '    .end annotation\n'
                 '  .end param\n'
                 '  .param p2\n'
                 '    .annotation runtime Lretrofit2/http/Url;\n'
                 '    .end annotation\n'
                 '  .end param\n'
                 ".end method\n")
        invoke = ("invoke-interface {v0, v1, v2}, "
                  "Ltest/Api;->a(Ljava/lang/String;Ljava/lang/String;)V\n")
        (self.repo / "Api.smali").write_text(smali)
        (self.repo / "Caller.smali").write_text(invoke)
        data = {"schema_version": 1, "source_revision": self.head, "cases": [{
            "id": "smali", "method": {
                "name": "a", "syntax": "smali",
                "declaration": self.anchor("Api.smali", 1, ".method", span=14)},
            "invocation": self.anchor("Caller.smali", 1, "invoke-interface"),
            "claim": {"header": "Cookie"},
            "url_examples": [{"label": "absolute", "value": "https://server.example/x"}]}]}
        row = gates.argument_binding(data, self.repo)["cases"][0]
        self.assertEqual(row["status"], "DESTINATION_CLAIM_CONTRADICTED")
        self.assertEqual(row["header_argument"], "v1")
        self.assertEqual(row["url_argument"], "v2")

    def test_source_hash_change_rejects_stale_anchor(self):
        data = self.binding()
        (self.repo / "Api.java").write_text(self.java + "// changed\n")
        row = gates.argument_binding(data, self.repo)["cases"][0]
        self.assertEqual(row["status"], "BLOCKED_UNRESOLVED_BINDING")

    def test_spec_anchored_without_native_pair_is_not_proof(self):
        result = gates.spec_implementation(self.spec_case(), self.repo,
                                           self.docs, self.evidence)
        self.assertEqual(result["cases"][0]["status"], "SPEC_SOURCE_LINK_ONLY")
        self.assertFalse(result["ready_for_vulnerability_claim"])

    def test_spec_receipts_distinct_but_untrusted(self):
        result = gates.spec_implementation(self.spec_case(with_pair=True),
                                           self.repo, self.docs, self.evidence)
        self.assertEqual(result["cases"][0]["status"], "REVIEW_PACKET_UNAUTHENTICATED")
        self.assertFalse(result["cases"][0]["ready_for_vulnerability_claim"])

    def test_hypothesis_is_not_upgraded_by_receipts(self):
        result = gates.spec_implementation(
            self.spec_case(kind="RESEARCH_HYPOTHESIS", with_pair=True),
            self.repo, self.docs, self.evidence)
        self.assertEqual(result["cases"][0]["status"], "HYPOTHESIS_WITH_RECEIPTS")

    def test_stale_document_and_same_control_are_blocked(self):
        data = self.spec_case(with_pair=True)
        (self.docs / "spec.txt").write_text(self.spec + "edited\n")
        row = gates.spec_implementation(data, self.repo, self.docs, self.evidence)["cases"][0]
        self.assertEqual(row["status"], "BLOCKED_MISSING_EVIDENCE")
        (self.docs / "spec.txt").write_text(self.spec)
        data["cases"][0]["experiment"]["control"] = (
            data["cases"][0]["experiment"]["candidate"])
        row = gates.spec_implementation(data, self.repo, self.docs, self.evidence)["cases"][0]
        self.assertEqual(row["status"], "BLOCKED_MISSING_EVIDENCE")

    def test_cli_fails_closed_on_wrong_commit_and_never_overwrites(self):
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps(self.binding()))
        out = self.root / "result.json"
        cli = SCRIPTS / "bounty.py"
        cmd = [sys.executable, str(cli), "web-evidence-gates", "argument-binding",
               "--repo", str(self.repo), "--input", str(manifest),
               "--out", str(out), "--gate"]
        outcome = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(outcome.returncode, 1, outcome.stderr)
        self.assertTrue(out.is_file())
        self.assertFalse(json.loads(out.read_text())["ready_for_vulnerability_claim"])
        repeated = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(repeated.returncode, 2)
        wrong = self.binding()
        wrong["source_revision"] = "a" * 40
        manifest.write_text(json.dumps(wrong))
        another = subprocess.run(cmd[:-2] + [str(self.root / "another.json")],
                                 capture_output=True, text=True)
        self.assertEqual(another.returncode, 2)

    def test_no_symlink_source_or_evidence_reads(self):
        data = self.binding()
        (self.repo / "Api.java").rename(self.root / "private.txt")
        (self.repo / "Api.java").symlink_to(self.root / "private.txt")
        row = gates.argument_binding(data, self.repo)["cases"][0]
        self.assertEqual(row["status"], "BLOCKED_UNRESOLVED_BINDING")
        data = self.spec_case(with_pair=True)
        (self.evidence / "candidate.txt").unlink()
        (self.evidence / "candidate.txt").symlink_to(self.root / "private.txt")
        result = gates.spec_implementation(data, self.repo, self.docs, self.evidence)
        self.assertEqual(result["cases"][0]["status"], "BLOCKED_MISSING_EVIDENCE")


if __name__ == "__main__":
    unittest.main()
