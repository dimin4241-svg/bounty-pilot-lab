#!/usr/bin/env python3
"""Offline Mobile Lab: bounded APK/IPA inventory and source-anchored trust-boundary leads.

No decompiler installation, execution, remote traffic, agent invocation or severity
attestation. Code-co-location and API calls are NEVER treated as proven flow.
"""
import argparse
import hashlib
import json
import os
import plistlib
import re
import stat
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from collections import defaultdict
from pathlib import Path

import mobile_axml

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
SOURCE_SUFFIXES = {".java", ".kt", ".kts", ".smali", ".swift", ".m", ".mm", ".dart"}
ANDROID_SOURCE = {".java", ".kt", ".kts", ".smali", ".dart"}
IOS_SOURCE = {".swift", ".m", ".mm"}
MAX_ARCHIVE = 200 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
MAX_ENTRIES = 40000
MAX_FILES = 1500
MAX_SOURCE_BYTES = 12 * 1024 * 1024
MAX_SINGLE_SOURCE = 512 * 1024
MAX_LINES = 50000
MAX_ANCHORS = 2000
MAX_LEADS = 150
VALID_PLATFORMS = {"android", "ios"}
# Lexical clues are *not* dataflow. Pairs must be reviewed in real functions.
RULES = {
    "android": {
        "ipc-intent": r"\b(?:getIntent|startActivity|startService|sendBroadcast|Intent\.parseUri|startActivityForResult)\s*\(",
        "ipc-result": r"\b(?:setResult|onActivityResult|ActivityResultLauncher|registerForActivityResult)\s*\(",
        "ipc-parcel": r"\b(?:getParcelableExtra|putParcelable|Parcelable|Bundle|ClipData)\b",
        "webview-load": r"\b(?:loadUrl|loadDataWithBaseURL|shouldOverrideUrlLoading)\s*\(",
        "webview-bridge": r"\b(?:addJavascriptInterface|JavascriptInterface|WebMessageListener|postWebMessage)\b",
        "file-input": r"\b(?:ContentResolver|OpenableColumns\.DISPLAY_NAME|openInputStream|FileProvider|content://)\b",
        "file-output": r"\b(?:FileOutputStream|openFileOutput|Files\.copy|copyTo|openOutputStream)\s*\(",
        "api-operation": r"\b(?:Retrofit|@POST|@PUT|@PATCH|@DELETE|enqueue|execute)\b",
        "oauth-flow": r"\b(?:AuthorizationRequest|CustomTabsIntent|redirect_uri|code_verifier|OAuth)\b",
        "guard-cue": r"\b(?:checkCallingPermission|enforceCallingPermission|checkPermission|requireNotNull|isAllowed|isAuthorized)\b",
        "dynamic-code": r"\b(?:DexClassLoader|PathClassLoader|System\.loadLibrary|loadDex)\b",
    },
    "ios": {
        "url-entry": r"\b(?:application\s*\(|continueUserActivity|openURLContexts|onOpenURL|NSUserActivityTypeBrowsingWeb)\b",
        "webview-load": r"\b(?:WKWebView|loadHTMLString|loadRequest|loadFileURL)\b",
        "webview-bridge": r"\b(?:WKScriptMessageHandler|addScriptMessageHandler|evaluateJavaScript|userContentController)\b",
        "oauth-flow": r"\b(?:ASWebAuthenticationSession|authorizationCode|codeVerifier|redirectURI|OAuth)\b",
        "file-input": r"\b(?:NSItemProvider|UIDocumentPickerViewController|startAccessingSecurityScopedResource)\b",
        "file-output": r"\b(?:writeToURL|writeToFile|FileManager\.default\.copyItem|createFile)\b",
        "ui-gate": r"\b(?:LAContext|evaluatePolicy|biometryCurrentSet|LocalAuthentication)\b",
        "app-intent": r"\b(?:AppIntent|AppShortcutsProvider|perform\s*\()\b",
        "api-operation": r"\b(?:URLSession|dataTask|uploadTask|HTTPMethod)\b",
        "guard-cue": r"\b(?:guard\b|precondition\b|verify\b|isAuthorized|validate)\b",
    },
}
COMPOSITIONS = {
    "android": (
        ("ipc-intent", "ipc-parcel", "NESTED_IPC_REVIEW"),
        ("ipc-intent", "ipc-result", "EXTERNAL_RESULT_REVIEW"),
        ("ipc-intent", "webview-load", "IPC_TO_WEBVIEW_REVIEW"),
        ("webview-load", "webview-bridge", "WEBVIEW_BRIDGE_REVIEW"),
        ("file-input", "file-output", "UNTRUSTED_FILENAME_REVIEW"),
        ("ipc-intent", "api-operation", "IPC_TO_API_REVIEW"),
        ("oauth-flow", "api-operation", "MOBILE_AUTH_REVIEW"),
        ("file-output", "dynamic-code", "FILE_TO_CODE_REVIEW"),
    ),
    "ios": (
        ("url-entry", "oauth-flow", "IOS_CALLBACK_BINDING_REVIEW"),
        ("url-entry", "webview-load", "IOS_LINK_TO_WEBVIEW_REVIEW"),
        ("webview-load", "webview-bridge", "IOS_WEBVIEW_BRIDGE_REVIEW"),
        ("file-input", "file-output", "IOS_FILE_IMPORT_REVIEW"),
        ("app-intent", "api-operation", "IOS_APP_INTENT_GUARD_REVIEW"),
        ("ui-gate", "app-intent", "IOS_ALTERNATE_UI_GUARD_REVIEW"),
    ),
}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _regular_file(path, size_limit):
    path = Path(path)
    item = path.lstat()
    if not stat.S_ISREG(item.st_mode) or item.st_size > size_limit:
        raise ValueError("input must be a regular non-symlink file within size limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags)
    try:
        with os.fdopen(fd, "rb") as stream:
            data = stream.read(size_limit + 1)
    except Exception:
        raise
    if len(data) > size_limit:
        raise ValueError("input is too large")
    return data


def _name_safe(name):
    parts = name.replace("\\", "/").split("/")
    return not (name.startswith("/") or any(p in ("", ".", "..") for p in parts)
                or "\x00" in name or ":" in parts[0])


def _zip_index(path):
    # Read only whitelisted small metadata members. Never extract untrusted bytes.
    if not zipfile.is_zipfile(path):
        raise ValueError("expected ZIP-based APK/AAB/IPA artifact")
    archive = zipfile.ZipFile(path)
    try:
        entries = archive.infolist()
        if len(entries) > MAX_ENTRIES:
            raise ValueError("archive has too many entries")
        found = set()
        for item in entries:
            if not _name_safe(item.filename):
                raise ValueError("unsafe archive member path")
            if item.filename in found:
                raise ValueError("duplicate archive member path")
            found.add(item.filename)
            mode = item.external_attr >> 16
            if stat.S_IFMT(mode) == stat.S_IFLNK:
                raise ValueError("archive contains a symlink")
        return archive
    except Exception:
        archive.close()
        raise


def _read_member(archive, name):
    item = archive.getinfo(name)
    if item.file_size > MAX_MANIFEST:
        raise ValueError("metadata member exceeds maximum")
    with archive.open(item) as stream:
        data = stream.read(MAX_MANIFEST + 1)
    if len(data) > MAX_MANIFEST:
        raise ValueError("metadata member decompression exceeds maximum")
    return data


def _android_attr(node, key):
    return node.attrib.get(ANDROID_NS + key, node.attrib.get(key))


def _manifest_android(raw):
    try:
        if raw.lstrip().startswith(b"<"):
            root = ET.fromstring(raw)
        else:
            root = mobile_axml.decode_manifest(raw)
    except (ET.ParseError, ValueError) as exc:
        raise ValueError("Android manifest cannot be decoded: " + str(exc)) from exc
    if root.tag != "manifest":
        raise ValueError("Android manifest root is not <manifest>")
    package = root.attrib.get("package", "")
    app = root.find("application")
    components = []
    if app is not None:
        for kind in ("activity", "activity-alias", "receiver", "service", "provider"):
            for item in app.findall(kind):
                name = _android_attr(item, "name") or ""
                if name.startswith("."):
                    name = package + name
                elif "." not in name:
                    name = package + "." + name
                exported = _android_attr(item, "exported")
                filters = item.findall("intent-filter")
                if exported in ("true", "false"):
                    exposure = "explicit-exported" if exported == "true" else "explicit-internal"
                elif kind == "provider":
                    exposure = "platform-dependent"
                elif filters:
                    exposure = "implicit-exported-legacy-or-install-error"
                else:
                    exposure = "implicit-internal-legacy"
                components.append({
                    "kind": kind, "name": name, "exposure": exposure,
                    "permission": _android_attr(item, "permission"),
                    "read_permission": _android_attr(item, "readPermission"),
                    "write_permission": _android_attr(item, "writePermission"),
                    "grant_uri_permissions": _android_attr(item, "grantUriPermissions"),
                    "authorities": _android_attr(item, "authorities"),
                    "target_activity": _android_attr(item, "targetActivity"),
                    "intent_filters": [
                        {"actions": [_android_attr(c, "name") for c in f.findall("action")],
                         "categories": [_android_attr(c, "name") for c in f.findall("category")],
                         "data_schemes": [_android_attr(c, "scheme") for c in f.findall("data")]}
                        for f in filters][:20],
                })
    sdk = root.find("uses-sdk")
    return {
        "platform": "android", "package": package,
        "target_sdk": _android_attr(sdk, "targetSdkVersion") if sdk is not None else None,
        "min_sdk": _android_attr(sdk, "minSdkVersion") if sdk is not None else None,
        "permissions": sorted({_android_attr(x, "name") for x in root.findall("uses-permission")
                               if _android_attr(x, "name")}),
        "components": sorted(components, key=lambda x: (x["kind"], x["name"])),
        "limitations": ["manifest metadata does not prove runtime reachability",
                        "intent filters, default provider export and permission behavior depend on OS/targetSdk"],
    }


def _manifest_ios(info, entitlements=None):
    bundle = info.get("CFBundleIdentifier", "")
    if not isinstance(bundle, str):
        bundle = ""
    schemes = []
    for obj in info.get("CFBundleURLTypes", []):
        if isinstance(obj, dict):
            schemes.extend(v for v in obj.get("CFBundleURLSchemes", []) if isinstance(v, str))
    associated = []
    if isinstance(entitlements, dict):
        associated = [x for x in entitlements.get("com.apple.developer.associated-domains", [])
                      if isinstance(x, str)]
    ext = info.get("NSExtension")
    return {
        "platform": "ios", "bundle_id": bundle,
        "url_schemes": sorted(set(schemes)),
        "associated_domains": sorted(set(associated)),
        "extension_point": ext.get("NSExtensionPointIdentifier") if isinstance(ext, dict) else None,
        "document_types_count": len(info.get("CFBundleDocumentTypes", [])),
        "transport_security": bool(info.get("NSAppTransportSecurity")),
        "entitlements_available": entitlements is not None,
        "limitations": ["Info.plist does not expose effective signed entitlements",
                        "App Store IPA executable may be encrypted; no Mach-O dataflow inferred"],
    }


def _platform_from_file(path):
    ext = path.suffix.lower()
    if ext in (".apk", ".aab"):
        return "android"
    if ext == ".ipa":
        return "ios"
    raise ValueError("artifact suffix must be .apk, .aab, or .ipa")


def _inspect_artifact(path):
    platform = _platform_from_file(path)
    raw = _regular_file(path, MAX_ARCHIVE)
    meta = {"artifact_sha256": _sha(raw), "artifact_bytes": len(raw),
            "platform": platform, "binary_code_inspected": False}
    with _zip_index(path) as archive:
        names = set(archive.namelist())
        if platform == "android":
            target = ("AndroidManifest.xml" if path.suffix.lower() == ".apk"
                      else "base/manifest/AndroidManifest.xml")
            if target not in names:
                raise ValueError("Android manifest missing from artifact")
            try:
                inventory = _manifest_android(_read_member(archive, target))
            except ValueError as exc:
                if path.suffix.lower() == ".aab":
                    inventory = {"platform": platform, "components": [],
                                 "limitations": ["AAB protobuf manifest unsupported; supply a decoded manifest source"],
                                 "manifest_error": str(exc)}
                else:
                    raise
            meta["dex_entries"] = sum(name.endswith(".dex") for name in names)
            meta["native_library_entries"] = sum(name.endswith(".so") for name in names)
        else:
            plist_names = sorted(name for name in names
                                 if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", name))
            if len(plist_names) != 1:
                raise ValueError("IPA must contain one top-level App Info.plist")
            try:
                info = plistlib.loads(_read_member(archive, plist_names[0]))
            except (ValueError, TypeError) as exc:
                raise ValueError("invalid IPA Info.plist") from exc
            entitlements = None
            ent_name = plist_names[0].replace("Info.plist", "archived-expanded-entitlements.xcent")
            if ent_name in names:
                try:
                    entitlements = plistlib.loads(_read_member(archive, ent_name))
                except (ValueError, TypeError):
                    pass
            inventory = _manifest_ios(info, entitlements)
            meta["mach_o_inspected"] = False
    return inventory, meta


def _inspect_decoded_manifest(root, platform):
    # For researcher-owned decoded projects when no mobile package is available.
    if platform == "android":
        for candidate in ("AndroidManifest.xml", "app/src/main/AndroidManifest.xml"):
            path = root / candidate
            if path.is_file() and not path.is_symlink():
                return _manifest_android(_regular_file(path, MAX_MANIFEST))
        return {"platform": platform, "components": [], "limitations": ["manifest not provided"]}
    for candidate in ("Info.plist", "Runner/Info.plist"):
        path = root / candidate
        if path.is_file() and not path.is_symlink():
            return _manifest_ios(plistlib.loads(_regular_file(path, MAX_MANIFEST)))
    return {"platform": platform, "limitations": ["Info.plist not provided"]}


def _sources(root, platform):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("sources must be a real directory, not symlink")
    regex = {key: re.compile(value, re.I) for key, value in RULES[platform].items()}
    extensions = ANDROID_SOURCE if platform == "android" else IOS_SOURCE
    found = []
    files = 0
    scanned = 0
    truncated = False
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in extensions or not path.is_file():
            continue
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root):
            continue
        if files >= MAX_FILES or scanned >= MAX_SOURCE_BYTES or len(found) >= MAX_ANCHORS:
            truncated = True
            break
        item = path.stat()
        if item.st_size > MAX_SINGLE_SOURCE or item.st_size + scanned > MAX_SOURCE_BYTES:
            truncated = True
            continue
        data = _regular_file(path, MAX_SINGLE_SOURCE)
        scanned += len(data)
        files += 1
        try:
            lines = data.decode("utf-8").splitlines()[:MAX_LINES]
        except UnicodeDecodeError:
            continue
        digest = _sha(data)
        relative = path.relative_to(root).as_posix()
        for line_no, line in enumerate(lines, 1):
            if len(found) >= MAX_ANCHORS:
                truncated = True
                break
            if len(line) > 10000:
                continue
            for kind, pattern in regex.items():
                if pattern.search(line):
                    found.append({"path": relative, "line": line_no, "sha256": digest,
                                  "kind": kind, "platform": platform})
    return found, {"files_scanned": files, "bytes_scanned": scanned,
                   "anchors_truncated": truncated, "raw_source_content_retained": False}


def _graph_and_leads(inventory, anchors, platform):
    components = inventory.get("components", []) if platform == "android" else []
    nodes = []
    edges = []
    leads = []
    for i, component in enumerate(components):
        nodes.append({"id": "component:%d" % i, "kind": "component",
                      "name": component["name"], "exposure": component["exposure"]})
    by_file = defaultdict(list)
    for anchor in anchors:
        by_file[anchor["path"]].append(anchor)
    if platform == "android":
        for index, component in enumerate(components):
            # Class/file-name alignment only. Not a verified receiver->handler edge.
            simple = component["name"].rsplit(".", 1)[-1]
            matches = [path for path in by_file
                       if Path(path).stem == simple or Path(path).stem == simple + "Kt"]
            for path in matches[:5]:
                edges.append({"from": "component:%d" % index, "to": "source:" + path,
                              "relation": "filename-class-match", "verified": False})
    for path, group in sorted(by_file.items()):
        nodes.append({"id": "source:" + path, "kind": "source-file"})
        kinds = {a["kind"] for a in group}
        attached = [e["from"] for e in edges if e["to"] == "source:" + path]
        exposed = [components[int(x.split(":")[1])] for x in attached
                   if components[int(x.split(":")[1])]["exposure"] in
                   ("explicit-exported", "implicit-exported-legacy-or-install-error")]
        for left, right, category in COMPOSITIONS[platform]:
            if not {left, right}.issubset(kinds):
                continue
            selected = [a for a in group if a["kind"] in (left, right)][:8]
            if len(leads) >= MAX_LEADS:
                break
            # Do not claim external trigger on generic file-only or iOS metadata.
            id_value = _sha((platform + path + category + ",".join(
                str(a["line"]) for a in selected)).encode("utf-8"))[:14]
            leads.append({
                "id": "MOB-" + id_value, "family": category,
                "status": "STATIC_COLOCATION_UNVERIFIED", "severity": "unassessed",
                "path": path, "source_anchors": selected,
                "entrypoints": [x["name"] for x in exposed],
                "reachability": "UNVERIFIED",
                "impact": "NOT_ESTABLISHED",
                "guard_cue_present_in_file": "guard-cue" in kinds,
                "missing_evidence": ["function-level dataflow", "actual entrypoint permissions",
                                     "paired native observation", "negative control",
                                     "independent review"],
            })
    return nodes, edges, leads


def analyze(artifact=None, sources=None, platform=None):
    if not artifact and not sources:
        raise ValueError("--artifact and/or --sources required")
    if artifact:
        inferred = _platform_from_file(Path(artifact))
        if platform and platform != inferred:
            raise ValueError("declared platform disagrees with artifact")
        platform = inferred
        inventory, meta = _inspect_artifact(Path(artifact))
    else:
        if platform not in VALID_PLATFORMS:
            raise ValueError("--platform android|ios required for source-only analysis")
        inventory = _inspect_decoded_manifest(Path(sources).resolve(), platform)
        meta = {"platform": platform, "binary_code_inspected": False}
    anchors = []
    scan = {"files_scanned": 0, "bytes_scanned": 0, "anchors_truncated": False,
            "raw_source_content_retained": False}
    if sources:
        anchors, scan = _sources(Path(sources).resolve(), platform)
    nodes, edges, leads = _graph_and_leads(inventory, anchors, platform)
    if len(leads) >= MAX_LEADS:
        scan["leads_truncated"] = True
    return {
        "schema_version": 1,
        "tool": "mobile-lab", "mode": "offline-static",
        "platform": platform, "artifact": meta, "inventory": inventory,
        "scan": scan, "graph": {"nodes": nodes, "edges": edges},
        "leads": leads, "lead_count": len(leads),
        "assurance": "STATIC_LEADS_ONLY_NO_NATIVE_REPRODUCTION",
        "limitations": ["regex co-location does not prove taint flow, call graph or exploitability",
                        "executable DEX/Mach-O was not decompiled by this tool",
                        "no application, device, network or model was executed",
                        "severity, authorization, runtime guards and business impact remain unverified"],
    }


def _write_private(path, obj, sources=None, artifact=None):
    output = Path(path).expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("output must be a NEW private file")
    if sources and (output == Path(sources).resolve() or
                    Path(sources).resolve() in output.parents):
        raise ValueError("output cannot be written inside source checkout")
    if artifact and output == Path(artifact).resolve():
        raise ValueError("output cannot overwrite artifact")
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise ValueError("output parent directory must exist and not be symlink")
    payload = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    fd = os.open(str(output), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload + b"\n")
    except Exception:
        output.unlink(missing_ok=True)
        raise


def benchmark():
    """Small synthetic regression only: not independent CVEs or AI discoveries."""
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        android = root / "android"
        android.mkdir()
        (android / "AndroidManifest.xml").write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="sample">'
            '<application><activity android:name=".Entry" android:exported="true"/>'
            '</application></manifest>', encoding="utf-8")
        target = android / "Entry.java"
        candidate = "class Entry { void open(){ getIntent(); loadUrl(url); addJavascriptInterface(obj, name); } }"
        control = "class Entry { void open(){ getIntent(); renderSafeText(); } }"
        target.write_text(candidate, encoding="utf-8")
        positive = analyze(sources=str(android), platform="android")
        target.write_text(control, encoding="utf-8")
        negative = analyze(sources=str(android), platform="android")
        ios = root / "ios"
        ios.mkdir()
        sample = ios / "Callback.swift"
        sample.write_text("func application(_ app: App) { ASWebAuthenticationSession() }", encoding="utf-8")
        ios_positive = analyze(sources=str(ios), platform="ios")
        sample.write_text("func appDidBecomeActive() { return }", encoding="utf-8")
        ios_negative = analyze(sources=str(ios), platform="ios")
    ok = bool(positive["leads"]) and not negative["leads"] and bool(ios_positive["leads"]) and not ios_negative["leads"]
    return {"kind": "synthetic-co-location-regression", "pairs": 2, "observations": 4,
            "positive_detected": int(bool(positive["leads"])) + int(bool(ios_positive["leads"])),
            "negative_false_positives": int(bool(negative["leads"])) + int(bool(ios_negative["leads"])),
            "passed": ok, "historical_case_count": 0, "real_vulnerabilities_found": 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    cmds = parser.add_subparsers(dest="action", required=True)
    inspect = cmds.add_parser("analyze", help="offline APK/AAB/IPA metadata and source co-location leads")
    inspect.add_argument("--artifact")
    inspect.add_argument("--sources")
    inspect.add_argument("--platform", choices=sorted(VALID_PLATFORMS))
    inspect.add_argument("--out", required=True)
    bench = cmds.add_parser("benchmark", help="run 2 synthetic positive/control pairs")
    bench.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "analyze":
            report = analyze(args.artifact, args.sources, args.platform)
            _write_private(args.out, report, args.sources, args.artifact)
        else:
            report = benchmark()
            _write_private(args.out, report)
        print(json.dumps({"status": report.get("assurance", "SYNTHETIC_REGRESSION"),
                          "out": str(Path(args.out).absolute()),
                          "count": report.get("lead_count", report.get("pairs"))}, sort_keys=True))
        return 0 if report.get("passed", True) else 1
    except (OSError, ValueError, zipfile.BadZipFile, plistlib.InvalidFileException) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
