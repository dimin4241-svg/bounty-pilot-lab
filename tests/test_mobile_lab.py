"""Synthetic Mobile Lab regression: artifact parsing, provenance and false-positive controls."""
import json
import plistlib
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "bounty-pilot" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import mobile_lab
import mobile_axml


def android_xml(exposed="true"):
    return ('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="fixture">'
            '<uses-sdk android:targetSdkVersion="33"/>'
            '<application><activity android:name=".Entry" android:exported="' + exposed + '">'
            '<intent-filter><action android:name="android.intent.action.VIEW"/></intent-filter>'
            '</activity></application></manifest>').encode()


def axml_string_pool(strings):
    blob = b""
    offsets = []
    for value in strings:
        encoded = value.encode("utf-8")
        if len(encoded) >= 128:
            raise ValueError("fixture too long")
        offsets.append(len(blob))
        blob += bytes([len(value), len(encoded)]) + encoded + b"\x00"
    size = 28 + 4 * len(strings) + len(blob)
    header = struct.pack("<HHIIIII", 1, 28, size, len(strings), 0, 0x100, 28 + 4 * len(strings))
    return header + b"".join(struct.pack("<I", x) for x in offsets) + blob


def axml_node(chunk_type, name, attrs=()):
    data = struct.pack("<IIHHHHHH", 0xffffffff, name, 20, 20, len(attrs), 0, 0, 0)
    for namespace, key, value in attrs:
        data += struct.pack("<IIIHBBI", namespace, key, value, 8, 0, 3, value)
    size = 16 + len(data)
    return struct.pack("<HHIII", chunk_type, 16, size, 1, 0xffffffff) + data


def axml_end(name):
    return (struct.pack("<HHIII", 0x0103, 16, 24, 1, 0xffffffff)
            + struct.pack("<II", 0xffffffff, name))


def compiled_axml():
    strings = ["manifest", "application", "activity", "package", "fixture", "name",
               ".Entry", "exported", "true", "http://schemas.android.com/apk/res/android"]
    android = 9
    payload = (axml_string_pool(strings)
               + axml_node(0x0102, 0, [(0xffffffff, 3, 4)])
               + axml_node(0x0102, 1)
               + axml_node(0x0102, 2, [(android, 5, 6), (android, 7, 8)])
               + axml_end(2) + axml_end(1) + axml_end(0))
    return struct.pack("<HHI", 3, 8, len(payload) + 8) + payload


class MobileLabTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.src = self.root / "src"
        self.src.mkdir()
        (self.src / "AndroidManifest.xml").write_bytes(android_xml())

    def test_android_decoded_manifest_and_trust_chain_are_unverified(self):
        code = self.src / "Entry.java"
        code.write_text(
            "class Entry { void execute() { getIntent(); loadUrl(url);\n"
            "addJavascriptInterface(br, name); setResult(code, intent); } }\n")
        report = mobile_lab.analyze(sources=str(self.src), platform="android")
        self.assertEqual(report["inventory"]["target_sdk"], "33")
        self.assertEqual(report["inventory"]["components"][0]["name"], "fixture.Entry")
        self.assertEqual(report["lead_count"], 3)
        self.assertEqual(report["leads"][0]["status"], "STATIC_COLOCATION_UNVERIFIED")
        self.assertEqual(report["leads"][0]["severity"], "unassessed")
        self.assertTrue(all(x["impact"] == "NOT_ESTABLISHED" for x in report["leads"]))
        self.assertTrue(any(edge["relation"] == "filename-class-match"
                            for edge in report["graph"]["edges"]))
        self.assertNotIn("addJavascriptInterface(br, name)", json.dumps(report))

    def test_android_control_does_not_invent_chain(self):
        (self.src / "Entry.java").write_text(
            "class Entry { void open() { getIntent(); renderSafeText(); } }\n")
        report = mobile_lab.analyze(sources=str(self.src), platform="android")
        self.assertEqual(report["lead_count"], 0)

    def test_unexported_component_is_not_external_entrypoint(self):
        (self.src / "AndroidManifest.xml").write_bytes(android_xml("false"))
        (self.src / "Entry.java").write_text(
            "class Entry { void open() { getIntent(); loadUrl(url); } }\n")
        report = mobile_lab.analyze(sources=str(self.src), platform="android")
        self.assertEqual(report["leads"][0]["entrypoints"], [])

    def test_compiled_binary_axml_is_decoded(self):
        data = compiled_axml()
        root = mobile_axml.decode_manifest(data)
        inv = mobile_lab._manifest_android(data)
        self.assertEqual(root.tag, "manifest")
        self.assertEqual(inv["components"][0]["exposure"], "explicit-exported")
        self.assertEqual(inv["components"][0]["name"], "fixture.Entry")

    def test_invalid_axml_fails_closed(self):
        with self.assertRaises(ValueError):
            mobile_axml.decode_manifest(b"\x03\x00\x08\x00\x08\x00\x00\x00")
        with self.assertRaises(ValueError):
            mobile_axml.decode_manifest(compiled_axml()[:-1])

    def test_real_apk_container_metadata_not_dex_claim(self):
        apk = self.root / "fixture.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("META-INF/", "")
            archive.writestr("AndroidManifest.xml", android_xml())
            archive.writestr("classes.dex", b"dex\n")
        report = mobile_lab.analyze(artifact=str(apk))
        self.assertEqual(report["artifact"]["dex_entries"], 1)
        self.assertFalse(report["artifact"]["binary_code_inspected"])
        self.assertEqual(report["lead_count"], 0)

    def test_zip_traversal_and_duplicates_rejected(self):
        for index, entries in enumerate([
            [("../outside", b"x"), ("AndroidManifest.xml", android_xml())],
            [("AndroidManifest.xml", android_xml()), ("AndroidManifest.xml", android_xml())],
        ]):
            apk = self.root / ("bad-%d.apk" % index)
            with zipfile.ZipFile(apk, "w") as archive:
                for path, payload in entries:
                    archive.writestr(path, payload)
            with self.assertRaisesRegex(ValueError, "unsafe|duplicate"):
                mobile_lab.analyze(artifact=str(apk))

    def test_ipa_plist_and_url_schemes(self):
        ipa = self.root / "sample.ipa"
        info = {"CFBundleIdentifier": "example.fixture",
                "CFBundleURLTypes": [{"CFBundleURLSchemes": ["fixtureauth"]}],
                "CFBundleDocumentTypes": [{"CFBundleTypeName": "Document"}]}
        with zipfile.ZipFile(ipa, "w") as archive:
            archive.writestr("Payload/Sample.app/Info.plist", plistlib.dumps(info))
        report = mobile_lab.analyze(artifact=str(ipa))
        self.assertEqual(report["inventory"]["url_schemes"], ["fixtureauth"])
        self.assertFalse(report["inventory"]["entitlements_available"])
        self.assertEqual(report["lead_count"], 0)
        self.assertFalse(report["artifact"]["mach_o_inspected"])

    def test_ios_oauth_callback_review_not_ato(self):
        (self.src / "Flow.swift").write_text(
            "func application(_ app: Application) { ASWebAuthenticationSession() }\n")
        report = mobile_lab.analyze(sources=str(self.src), platform="ios")
        self.assertEqual(report["leads"][0]["family"], "IOS_CALLBACK_BINDING_REVIEW")
        self.assertEqual(report["leads"][0]["impact"], "NOT_ESTABLISHED")

    def test_source_artifact_platform_conflict(self):
        ipa = self.root / "sample.ipa"
        with zipfile.ZipFile(ipa, "w") as archive:
            archive.writestr("Payload/Sample.app/Info.plist", plistlib.dumps({}))
        with self.assertRaisesRegex(ValueError, "disagrees"):
            mobile_lab.analyze(artifact=str(ipa), platform="android")

    def test_private_output_new_only_not_inside_source(self):
        out = self.root / "out.json"
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "bounty.py"), "mobile-lab", "analyze",
             "--sources", str(self.src), "--platform", "android", "--out", str(out)],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(out.read_text())["tool"], "mobile-lab")
        repeated = subprocess.run(
            [sys.executable, str(SCRIPTS / "bounty.py"), "mobile-lab", "analyze",
             "--sources", str(self.src), "--platform", "android", "--out", str(out)],
            capture_output=True, text=True)
        self.assertNotEqual(repeated.returncode, 0)
        with self.assertRaisesRegex(ValueError, "inside source"):
            mobile_lab._write_private(self.src / "bad.json", {}, str(self.src))

    def test_synthetic_benchmark_is_not_claimed_historical(self):
        report = mobile_lab.benchmark()
        self.assertEqual(report["pairs"], 2)
        self.assertEqual(report["historical_case_count"], 0)
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["negative_false_positives"], 0)


if __name__ == "__main__":
    unittest.main()
