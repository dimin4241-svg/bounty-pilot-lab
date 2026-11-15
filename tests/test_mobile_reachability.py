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


    def test_arbitrary_helper_not_mistaken_for_framework_entry(self):
        self.manifest('<activity android:name=".Entry" android:exported="true"/>')
        lead = self.check()["leads"][0]
        self.assertEqual(lead["framework_callback_review_priority"],
                         "UNLINKED_TO_FRAMEWORK_CALLBACK_REVIEW_ONLY")
        ctx = lead["entrypoint_assessments"][0]["entry_method"]
        self.assertEqual(ctx["source_method"], "open")
        self.assertEqual(ctx["method_assessment"],
                         "NO_DIRECT_FRAMEWORK_CALLBACK_NAME_MATCH")
        self.assertFalse(ctx["framework_dispatch_proven"])

    def test_activity_oncreate_callback_name_is_tentative(self):
        self.source("Entry.java", """package fixture;
class Entry {
void onCreate(Bundle saved) {
String raw=getIntent().getDataString();
Router.forward(raw);
}
}""")
        self.manifest('<activity android:name=".Entry" android:exported="true"/>')
        lead = self.check()["leads"][0]
        self.assertEqual(lead["framework_callback_review_priority"],
                         "REVIEW_FIRST_STATIC_CALLBACK_CANDIDATE")
        ctx = lead["entrypoint_assessments"][0]["entry_method"]
        self.assertEqual(ctx["method_assessment"],
                         "FRAMEWORK_CALLBACK_NAME_CANDIDATE")
        self.assertFalse(ctx["framework_dispatch_proven"])
        self.assertEqual(self.check()["summary"]
                         ["leads_with_framework_callback_name_candidate"], 1)

    def test_receiver_wrong_callback_rejected(self):
        self.source("Entry.java", """package fixture;
class Entry {
void onCreate(Bundle b) {
String raw=getIntent().getDataString();
Router.forward(raw);
}
}""")
        self.manifest('<receiver android:name=".Entry" android:exported="true"/>')
        lead = self.check()["leads"][0]
        self.assertEqual(lead["framework_callback_review_priority"],
                         "UNLINKED_TO_FRAMEWORK_CALLBACK_REVIEW_ONLY")

    def test_disabled_component_remains_blocked_for_priority(self):
        self.source("Entry.java", """package fixture;
class Entry {void onNewIntent(Intent intent) {
String raw=getIntent().getDataString();
Router.forward(raw);
}}""")
        self.manifest('<activity android:name=".Entry" android:exported="true" '
                      'android:enabled="false"/>')
        ctx = self.check()["leads"][0]["entrypoint_assessments"][0]
        self.assertEqual(ctx["enabled_assessment"],
                         "COMPONENT_DISABLED_IN_MANIFEST")
        self.assertEqual(self.check()["leads"][0]["framework_callback_review_priority"],
                         "REVIEW_CONDITIONAL_FRAMEWORK_CALLBACK")

    def test_disabled_application_overrides_component_enabled(self):
        self.manifest('<activity android:name=".Entry" android:exported="true" '
                      'android:enabled="true"/>',
                      app='android:enabled="false"')
        assessment = self.check()["leads"][0]["entrypoint_assessments"][0]
        self.assertEqual(assessment["enabled_assessment"],
                         "APPLICATION_DISABLED_IN_MANIFEST")
        self.assertEqual(self.check()["android_manifest"]
                         ["application_enabled"], "false")

    def test_provider_read_write_and_path_permissions_are_separate(self):
        self.source("Entry.java", """package fixture;
class Entry {void query(Uri uri) {
String raw=getIntent().getDataString();
Router.forward(raw);
}}""")
        self.manifest(
            '<provider android:name=".Entry" android:authorities="fixture.data" '
            'android:exported="true" android:permission="fixture.BASE" '
            'android:readPermission="fixture.READ" '
            'android:writePermission="fixture.WRITE" '
            'android:grantUriPermissions="true">'
            '<path-permission android:pathPrefix="/secured" '
            'android:readPermission="fixture.PATH"/>'
            '</provider>')
        lead = self.check()["leads"][0]
        ctx = lead["entrypoint_assessments"][0]
        self.assertEqual(ctx["entry_method"]["method_assessment"],
                         "FRAMEWORK_CALLBACK_NAME_CANDIDATE")
        gates = ctx["provider_operation_gates"]
        self.assertEqual(gates["read_permission_name"], "fixture.READ")
        self.assertEqual(gates["write_permission_name"], "fixture.WRITE")
        self.assertEqual(gates["path_permission_count"], 1)
        self.assertTrue(gates["uri_grant_overrides_possible"])
        self.assertEqual(gates["effective_access"],
                         "OPERATION_AND_PATH_DEPENDENT_NOT_EVALUATED")

    def test_alias_entry_callback_is_context_only(self):
        self.source("Entry.java", """package fixture;
class Entry {void onNewIntent(Intent x) {
String raw=getIntent().getDataString();
Router.forward(raw);
}}""")
        self.manifest(
            '<activity android:name=".Entry" android:exported="false"/>'
            '<activity-alias android:name=".PublicAlias" '
            'android:targetActivity=".Entry" android:exported="true"/>')
        assessments = self.check()["leads"][0]["entrypoint_assessments"]
        alias = [p for p in assessments if p["component_kind"] ==
                 "activity-alias"][0]
        self.assertEqual(alias["entry_method"]["method_assessment"],
                         "FRAMEWORK_CALLBACK_NAME_CANDIDATE")
        self.assertFalse(alias["entry_method"]["framework_dispatch_proven"])

    def test_manifest_report_deterministic(self):
        self.manifest('<activity android:name=".Entry" android:exported="true"/>')
        self.assertEqual(self.check(), self.check())


if __name__ == "__main__":
    unittest.main()
