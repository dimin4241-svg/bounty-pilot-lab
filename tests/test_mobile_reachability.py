"""Synthetic Android Manifest exposure and permission context tests; no target calls."""
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import mobile_reachability

NAMESPACE = "http://schemas.android.com/apk/res/android"


class ManifestReachabilityTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.source("Entry.java", """package fixture;
class Entry {
void open() {
String raw = getIntent().getDataString();
Router.forward(raw);
}
}""")
        self.source("Router.java", """package fixture;
class Router {static void forward(String url) { web.loadUrl(url); }}
""")

    def source(self, path, contents):
        dest = self.root / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(contents, encoding="utf-8")

    def manifest(self, component, target=35, app="", permissions=""):
        self.source("AndroidManifest.xml",
                    '<manifest xmlns:android="' + NAMESPACE + '" package="fixture">'
                    '<uses-sdk android:targetSdkVersion="' + str(target) + '"/>'
                    + permissions + '<application ' + app + '>'
                    + component + '</application></manifest>')

    def check(self):
        return mobile_reachability.analyze(str(self.root))

    def test_exported_no_permission_is_possible_not_proven(self):
        self.manifest('<activity android:name=".Entry" android:exported="true"/>')
        report = self.check()
        self.assertEqual(report["lead_count"], 1, report)
        lead = report["leads"][0]
        self.assertEqual(lead["entrypoint_context"], "POSSIBLE_EXTERNAL_STATIC_ENTRY")
        self.assertEqual(lead["entrypoint_assessments"][0]
                         ["static_exposure_assessment"], "EXPORTED_NO_MANIFEST_PERMISSION")
        self.assertFalse(lead["entrypoint_assessments"][0]["specific_handler_path_observed"])
        self.assertEqual(report["summary"]["vulnerabilities_proven"], 0)

    def test_exported_false_not_external(self):
        self.manifest('<activity android:name=".Entry" android:exported="false"/>')
        report = self.check()
        self.assertEqual(report["leads"][0]["entrypoint_context"],
                         "STATIC_NONEXPORTED_OR_CONDITIONAL_ENTRY")

    def test_application_permission_is_inherited(self):
        self.manifest('<activity android:name=".Entry" android:exported="true"/>',
                      app='android:permission="fixture.SIGNATURE"')
        lead = self.check()["leads"][0]
        self.assertEqual(lead["entrypoint_context"],
                         "STATIC_EXPORTED_ENTRY_PERMISSION_GATED")
        self.assertEqual(lead["entrypoint_assessments"][0]["permission"]
                         ["requirements"][0]["name"], "fixture.SIGNATURE")

    def test_custom_signature_protection_level(self):
        self.manifest('<activity android:name=".Entry" android:exported="true"'
                      ' android:permission="fixture.SIGNATURE"/>',
                      permissions='<permission android:name="fixture.SIGNATURE" '
                      'android:protectionLevel="signature"/>')
        req = self.check()["leads"][0]["entrypoint_assessments"][0]["permission"]
        self.assertEqual(req["requirements"][0]["protection_level"], "signature")
        self.assertEqual(req["requirements"][0]["definition"], "APP_DECLARED")
        self.assertEqual(req["caller_has_required_permission"], "NOT_EVALUATED")

    def test_absent_exported_sdk31_filter_not_installable_on_12(self):
        self.manifest('<activity android:name=".Entry"><intent-filter>'
                      '<action android:name="android.intent.action.VIEW"/>'
                      '</intent-filter></activity>', target=35)
        lead = self.check()["leads"][0]
        self.assertEqual(lead["entrypoint_assessments"][0]
                         ["static_exposure_assessment"],
                         "MISSING_EXPORTED_INSTALL_INVALID_ON_ANDROID_12_PLUS")
        self.assertEqual(lead["entrypoint_context"],
                         "STATIC_NONEXPORTED_OR_CONDITIONAL_ENTRY")

    def test_legacy_implicit_export_depends_on_target(self):
        self.manifest('<activity android:name=".Entry"><intent-filter>'
                      '<action android:name="android.intent.action.VIEW"/>'
                      '</intent-filter></activity>', target=29)
        lead = self.check()["leads"][0]
        self.assertEqual(lead["entrypoint_assessments"][0]
                         ["static_exposure_assessment"], "LEGACY_FILTER_IMPLICIT_EXPORT")

    def test_no_manifest_explicitly_rejected(self):
        with self.assertRaisesRegex(ValueError, "AndroidManifest"):
            self.check()

    def test_unrelated_manifest_class_has_no_entry(self):
        self.manifest('<activity android:name=".Other" android:exported="true"/>')
        report = self.check()
        self.assertEqual(report["leads"][0]["entrypoint_context"],
                         "NO_MATCHING_MANIFEST_ENTRY_CLASS")

    def test_alias_carries_independent_exposure(self):
        self.manifest(
            '<activity android:name=".Entry" android:exported="false"/>'
            '<activity-alias android:name=".PublicAlias"'
            ' android:targetActivity=".Entry" android:exported="true"/>')
        result = self.check()
        evaluations = result["leads"][0]["entrypoint_assessments"]
        self.assertEqual(len(evaluations), 2, evaluations)
        self.assertTrue(any(e["source_binding"] == "ALIAS_TARGET_CLASS_STRING"
                            for e in evaluations))
        self.assertEqual(result["leads"][0]["entrypoint_context"],
                         "POSSIBLE_EXTERNAL_STATIC_ENTRY")

    def test_manifest_report_deterministic(self):
        self.manifest('<activity android:name=".Entry" android:exported="true"/>')
        self.assertEqual(self.check(), self.check())


if __name__ == "__main__":
    unittest.main()
