"""Synthetic controls for graph variants, Electron, iOS and bounty outcome feedback."""
import json
import plistlib
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import graph_variant_lab as variants
import electron_lab as electron
import ios_trust_lab as ios
import bounty_outcome_feedback as feedback


def graph(guard=True, alternate=False):
    nodes = [
        {"id": "entry", "kind": "entry", "guard_present": False},
        {"id": "auth", "kind": "method", "guard_present": guard},
        {"id": "sink", "kind": "sink", "guard_present": False},
    ]
    edges = [{"from": "entry", "to": "auth"}, {"from": "auth", "to": "sink"}]
    if alternate:
        nodes.append({"id": "other", "kind": "method", "guard_present": False})
        edges += [{"from": "entry", "to": "other"}, {"from": "other", "to": "sink"}]
    return {"nodes": nodes, "edges": edges}


class ExtensionsTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)

    def test_guard_added_does_not_claim_vulnerability(self):
        res = variants.analyze({"schema_version": 1,
                                "before": graph(False), "after": graph(True)})
        self.assertEqual(res["lead_count"], 0)
        self.assertEqual(len(res["guard_deltas"]), 1)

    def test_guard_removed_has_new_guardless_path_candidate(self):
        res = variants.analyze({"schema_version": 1,
                                "before": graph(True), "after": graph(False)})
        self.assertEqual(res["lead_count"], 1)
        self.assertEqual(res["leads"][0]["classification"],
                         "NEW_GUARDLESS_VARIANT_REVIEW")
        self.assertFalse(res["leads"][0]["impact_verified"])

    def test_alternative_path_to_same_sink(self):
        res = variants.analyze({"schema_version": 1,
                                "before": graph(True), "after": graph(True, alternate=True)})
        self.assertEqual(res["lead_count"], 1)
        self.assertTrue(res["leads"][0]["same_sink_has_guarded_path"])

    def test_bad_graph_edge_refused(self):
        doc = {"schema_version": 1, "before": graph(True), "after": graph(True)}
        doc["after"]["edges"].append({"from": "entry", "to": "missing"})
        with self.assertRaisesRegex(ValueError, "edge"):
            variants.analyze(doc)

    def test_duplicate_graph_nodes_refused(self):
        doc = {"schema_version": 1, "before": graph(True), "after": graph(True)}
        doc["before"]["nodes"].append(doc["before"]["nodes"][0].copy())
        with self.assertRaisesRegex(ValueError, "duplicate"):
            variants.analyze(doc)

    def test_electron_cues_are_lexical_only(self):
        source = self.root / "main.js"
        source.write_text("""const win = new BrowserWindow({
webPreferences: { contextIsolation: false, nodeIntegration: true,
preload: __dirname + '/preload.js' }});
ipcMain.handle('screen', async () => desktopCapturer.getSources({types: []}));
session.defaultSession.setPermissionRequestHandler(() => {});
win.loadURL('https://local.test');
""")
        result = electron.analyze(self.root)
        kinds = result["cue_types"]
        for kind in ("browser-window", "context-isolation-disabled",
                     "node-integration-enabled", "preload", "ipc-main",
                     "permission-handler", "desktop-capture", "external-navigation"):
            self.assertIn(kind, kinds)
        self.assertEqual(result["assurance"],
                         "LEXICAL_CUES_NOT_TRUSTED_ORIGIN_REACHABILITY")
        self.assertEqual(len(result["anchors"]), 1)

    def test_electron_comment_and_string_not_cues(self):
        (self.root / "noise.js").write_text(
            '// ipcMain.handle("x", fn)\n'
            'const info = "contextIsolation: false; preload: x";\n')
        result = electron.analyze(self.root)
        self.assertEqual(result["anchors"], [])

    def test_electron_project_wide_co_location_is_only_review(self):
        (self.root / "preload.js").write_text(
            "contextBridge.exposeInMainWorld('api', {}); const preload = {};")
        (self.root / "main.js").write_text(
            "new BrowserWindow({preload: x}); ipcMain.handle('x', fn);")
        result = electron.analyze(self.root)
        self.assertEqual(len(result["review_candidates"]), 1)
        self.assertFalse(result["review_candidates"][0]["ipc_invocation_proven"])

    def _plists(self):
        info = self.root / "Info.plist"
        ent = self.root / "ents.plist"
        info.write_bytes(plistlib.dumps({
            "CFBundleIdentifier": "org.fixture.app",
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["fixtureauth"]}],
        }))
        ent.write_bytes(plistlib.dumps({
            "com.apple.developer.associated-domains": ["applinks:fixture.test"],
            "com.apple.security.application-groups": ["group.fixture"],
            "keychain-access-groups": ["TEAM.fixture"],
        }))
        return info, ent

    def test_ios_trust_sources_are_unverified(self):
        info, ent = self._plists()
        result = ios.analyze(info, ent)
        self.assertEqual(result["bundle_id"], "org.fixture.app")
        self.assertEqual(len(result["review_candidates"]), 3)
        self.assertEqual(result["entitlements_provenance"],
                         "OPERATOR_SUPPLIED_NOT_SIGNATURE_VERIFIED")
        self.assertFalse(result["impact_verified"])

    def test_ios_without_entitlements_no_inferred_domains(self):
        info, ent = self._plists()
        result = ios.analyze(info)
        self.assertEqual(result["associated_domain_claims"], [])
        self.assertEqual(result["entitlements_provenance"], "NOT_PROVIDED")

    def test_ios_non_plist_rejected(self):
        file = self.root / "data.plist"
        file.write_text("not plist")
        with self.assertRaises(Exception):
            ios.analyze(file)

    def feedback_doc(self):
        return {"schema_version": 1, "reports": [
            {"report_id": "a", "method": "mobile", "status": "pending",
             "research_hours": "3.5", "payout_amount": "0", "currency": "USD"},
            {"report_id": "b", "method": "mobile", "status": "duplicate",
             "research_hours": "2", "payout_amount": "0", "currency": "USD"},
            {"report_id": "c", "method": "mobile", "status": "paid",
             "research_hours": "4", "payout_amount": "750", "currency": "USD"},
        ]}

    def test_adjudicated_outcomes_exclude_pending(self):
        result = feedback.analyze(self.feedback_doc())
        row = result["groups"][0]
        self.assertEqual(row["reports"], 3)
        self.assertEqual(row["adjudicated"], 2)
        self.assertEqual(row["duplicate_rate_of_adjudicated"], "0.5000")
        self.assertEqual(row["observed_paid_totals"]["USD"], "750")
        self.assertFalse(result["predicted_future_payout"])

    def test_payout_of_pending_report_denied(self):
        doc = self.feedback_doc()
        doc["reports"][0]["payout_amount"] = "100"
        with self.assertRaisesRegex(ValueError, "only counted"):
            feedback.analyze(doc)

    def test_duplicate_report_id_denied(self):
        doc = self.feedback_doc()
        doc["reports"][1]["report_id"] = doc["reports"][0]["report_id"]
        with self.assertRaises(ValueError):
            feedback.analyze(doc)

    def test_negative_and_nan_cost_denied(self):
        doc = self.feedback_doc()
        doc["reports"][0]["research_hours"] = "-1"
        with self.assertRaises(ValueError):
            feedback.analyze(doc)
        doc["reports"][0]["research_hours"] = "NaN"
        with self.assertRaises(ValueError):
            feedback.analyze(doc)

    def test_feedback_does_not_convert_currencies(self):
        doc = self.feedback_doc()
        doc["reports"].append({
            "report_id": "d", "method": "mobile", "status": "paid",
            "research_hours": "1", "payout_amount": "1000", "currency": "EUR",
        })
        result = feedback.analyze(doc)
        self.assertEqual(result["groups"][0]["observed_paid_totals"],
                         {"EUR": "1000", "USD": "750"})


if __name__ == "__main__":
    unittest.main()
