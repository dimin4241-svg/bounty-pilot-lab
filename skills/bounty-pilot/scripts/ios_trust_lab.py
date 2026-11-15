#!/usr/bin/env python3
"""Offline iOS URL-scheme, app-group and entitlements trust-boundary inventory.

Entitlements supplied as a file are NOT verified as signed or effective. The
tool never inspects user Keychain data, installs apps, or launches an IPA.
"""
import argparse
import hashlib
import json
import os
import plistlib
import sys
from pathlib import Path

MAX_PLIST = 2 * 1024 * 1024


def _read(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_PLIST:
        raise ValueError("bounded regular plist required")
    data = p.read_bytes()
    value = plistlib.loads(data)
    if not isinstance(value, dict):
        raise ValueError("top-level plist must be a dictionary")
    return value, hashlib.sha256(data).hexdigest()


def _strings(value):
    if not isinstance(value, list) or len(value) > 300:
        return []
    return sorted({x for x in value if isinstance(x, str) and len(x) <= 256})


def analyze(info_path, entitlements_path=None):
    info, info_sha = _read(info_path)
    entitlements = None
    entitlement_sha = None
    if entitlements_path:
        entitlements, entitlement_sha = _read(entitlements_path)
    bundle = info.get("CFBundleIdentifier", "")
    if not isinstance(bundle, str) or len(bundle) > 256:
        raise ValueError("invalid bundle id")
    schemes = []
    for item in info.get("CFBundleURLTypes", []):
        if isinstance(item, dict):
            schemes.extend(_strings(item.get("CFBundleURLSchemes", [])))
    schemes = sorted(set(schemes))
    associated = _strings((entitlements or {}).get(
        "com.apple.developer.associated-domains", []))
    app_groups = _strings((entitlements or {}).get(
        "com.apple.security.application-groups", []))
    keychain_groups = _strings((entitlements or {}).get(
        "keychain-access-groups", []))
    queries = []
    if schemes:
        queries.append({
            "kind": "CUSTOM_URL_SCHEME_ENTRY_REVIEW",
            "count": len(schemes),
            "unverified": ["which app receives URL on installed device",
                           "callback session and state binding"],
        })
    if associated:
        queries.append({
            "kind": "UNIVERSAL_LINK_ENTITLEMENT_REVIEW",
            "count": len(associated),
            "unverified": ["AASA hosted content and CDN result",
                           "effective signed entitlements", "user approval"],
        })
    if app_groups or keychain_groups:
        queries.append({
            "kind": "SHARED_CONTAINER_TRUST_REVIEW",
            "count": len(app_groups) + len(keychain_groups),
            "unverified": ["signing team", "members sharing access groups",
                           "runtime authorization and data exposure"],
        })
    return {
        "schema_version": 1, "engine": "ios-trust-boundary-review",
        "bundle_id": bundle, "info_plist_sha256": info_sha,
        "entitlements_plist_sha256": entitlement_sha,
        "entitlements_provenance": (
            "OPERATOR_SUPPLIED_NOT_SIGNATURE_VERIFIED"
            if entitlements is not None else "NOT_PROVIDED"),
        "url_schemes": schemes, "associated_domain_claims": associated,
        "app_groups": app_groups, "keychain_access_groups": keychain_groups,
        "review_candidates": queries,
        "assurance": "PLIST_INVENTORY_NOT_EFFECTIVE_OS_CAPABILITY",
        "native_executed": False, "impact_verified": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--info-plist", required=True)
    ap.add_argument("--entitlements-plist")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        report = analyze(a.info_plist, a.entitlements_plist)
        path = Path(a.out)
        if path.is_symlink() or path.exists() or not path.parent.is_dir():
            raise ValueError("output must be a new file in existing directory")
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(report, out, sort_keys=True, indent=2)
            out.write("\n")
        print(json.dumps({"review_candidates": len(report["review_candidates"]),
                          "impact_verified": False}))
        return 0
    except (OSError, ValueError, plistlib.InvalidFileException) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
