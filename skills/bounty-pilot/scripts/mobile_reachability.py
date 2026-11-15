#!/usr/bin/env python3
"""Android Manifest permission/exposure context for bounded mobile cross-file leads.

This module never claims an intent is externally triggerable. Android lifecycle,
enabled state, caller permissions, dynamic handlers, application installation,
and runtime control-flow remain independent questions.
"""
from pathlib import Path

import mobile_crossfile
import mobile_lab


def _target_sdk(value):
    if isinstance(value, str) and value.isascii() and value.isdecimal():
        return int(value) if int(value) <= 1000 else None
    return None


def _permission(component, manifest):
    kind = component["kind"]
    app = manifest.get("application_permission")
    base = component.get("permission") or app
    read = component.get("read_permission")
    write = component.get("write_permission")
    if kind == "provider":
        # A provider may have different gates depending on the operation;
        # absence of a gate is not sufficient to establish readable content.
        names = sorted(set(p for p in (base, read, write) if p))
        operation_specific = bool(read or write)
    else:
        names = [base] if base else []
        operation_specific = False
    declared = {p["name"]: p["protection_level"]
                for p in manifest.get("declared_permissions", [])}
    return {
        "manifest_gate": (
            "DECLARED_PERMISSION_REQUIRED" if names
            else "NO_MANIFEST_PERMISSION_DECLARED"
        ),
        "requirements": [
            {"name": name, "protection_level": declared.get(name, "UNKNOWN"),
             "definition": ("APP_DECLARED" if name in declared
                            else "EXTERNAL_OR_MISSING_DEFINITION")}
            for name in names
        ],
        "provider_read_write_may_differ": operation_specific,
        "caller_has_required_permission": "NOT_EVALUATED",
        "runtime_authorization": "NOT_EVALUATED",
    }


def _status(component, target_sdk, permission):
    exposure = component["exposure"]
    has_gate = permission["manifest_gate"] == "DECLARED_PERMISSION_REQUIRED"
    if exposure in ("explicit-internal", "implicit-internal-legacy"):
        return "NOT_EXPORTED_BY_MANIFEST"
    if exposure == "explicit-exported":
        return ("EXPORTED_WITH_MANIFEST_PERMISSION"
                if has_gate else "EXPORTED_NO_MANIFEST_PERMISSION")
    if exposure == "implicit-exported-legacy-or-install-error":
        if target_sdk is None:
            return "UNKNOWN_LEGACY_OR_INSTALL_DEPENDENCY"
        if target_sdk >= 31:
            return "MISSING_EXPORTED_INSTALL_INVALID_ON_ANDROID_12_PLUS"
        return ("LEGACY_FILTER_IMPLICIT_EXPORT_WITH_PERMISSION"
                if has_gate else "LEGACY_FILTER_IMPLICIT_EXPORT")
    if exposure == "platform-dependent" and component["kind"] == "provider":
        if target_sdk is None:
            return "UNKNOWN_PROVIDER_DEFAULT_TARGET_DEPENDENT"
        if target_sdk <= 16:
            return ("LEGACY_PROVIDER_DEFAULT_EXPORTED_WITH_PERMISSION"
                    if has_gate else "LEGACY_PROVIDER_DEFAULT_EXPORTED")
        return "PROVIDER_DEFAULT_NOT_EXPORTED_TARGET_17_PLUS"
    return "UNKNOWN_MANIFEST_EXPOSURE"


def _binding(entry, component):
    symbol = entry["symbol"]
    if component["name"] == symbol:
        return "EXACT_PACKAGE_AND_CLASS_STRING"
    if (component["kind"] == "activity-alias"
            and component.get("target_activity") == symbol):
        return "ALIAS_TARGET_CLASS_STRING"
    return None


def analyze(sources, max_leads=120):
    if type(max_leads) is not int or not 1 <= max_leads <= 120:
        raise ValueError("max_leads must be between 1 and 120")
    given = Path(sources).expanduser().absolute()
    if not given.is_dir() or given.is_symlink():
        raise ValueError("sources must be a non-symlink directory")
    root = given.resolve(strict=True)
    inventory = mobile_lab._inspect_decoded_manifest(root, "android")
    manifest_present = any((root / filename).is_file()
                           for filename in ("AndroidManifest.xml",
                                            "app/src/main/AndroidManifest.xml"))
    if not manifest_present:
        raise ValueError("decoded AndroidManifest.xml required for reachability review")
    report = mobile_crossfile.analyze(str(root), "android", max_leads)
    indexed, _, index_coverage = mobile_crossfile._index(root, "android")
    by_file = {e["path"]: e for e in indexed}
    sdk = _target_sdk(inventory.get("target_sdk"))
    matched = 0
    potential = 0
    protected = 0
    for lead in report["leads"]:
        entry = by_file.get(lead["source"]["file"])
        assessments = []
        if entry:
            for component in inventory.get("components", []):
                binding = _binding(entry, component)
                if not binding:
                    continue
                permission = _permission(component, inventory)
                status = _status(component, sdk, permission)
                assessments.append({
                    "component_name": component["name"],
                    "component_kind": component["kind"],
                    "source_binding": binding,
                    "manifest_exposure": component["exposure"],
                    "static_exposure_assessment": status,
                    "permission": permission,
                    "filter_count": len(component["intent_filters"]),
                    "specific_handler_path_observed": False,
                })
        assessments.sort(key=lambda e: (e["component_name"], e["component_kind"]))
        statuses = {p["static_exposure_assessment"] for p in assessments}
        if assessments:
            matched += 1
        if "EXPORTED_NO_MANIFEST_PERMISSION" in statuses:
            lead["entrypoint_context"] = "POSSIBLE_EXTERNAL_STATIC_ENTRY"
            potential += 1
        elif any(s.endswith("_WITH_PERMISSION") for s in statuses):
            lead["entrypoint_context"] = "STATIC_EXPORTED_ENTRY_PERMISSION_GATED"
            protected += 1
        elif assessments:
            lead["entrypoint_context"] = "STATIC_NONEXPORTED_OR_CONDITIONAL_ENTRY"
        else:
            lead["entrypoint_context"] = "NO_MATCHING_MANIFEST_ENTRY_CLASS"
        lead["entrypoint_assessments"] = assessments
        lead["still_unproven"] = [
            "application installed on selected Android OS",
            "component enabled and accepted user action",
            "source method is called by actual entrypoint lifecycle",
            "caller has permission or can reach caller-owned activity",
            "dynamic intent routing/validation and runtime control flow",
            "sink executed and effect observable in a controlled run",
        ]
    report["engine"] = "mobile-manifest-reachability"
    report["assurance"] = "MANIFEST_CLASS_MATCH_NOT_VERIFIED_CALLER_REACHABILITY"
    report["android_manifest"] = {
        "package": inventory.get("package"),
        "target_sdk": inventory.get("target_sdk"),
        "application_permission": inventory.get("application_permission"),
        "components_considered": len(inventory.get("components", [])),
        "component_defaults_target_dependent": True,
        "intent_filter_presence_is_not_a_caller_proof": True,
        "runtime_permission_checks_not_inferred": True,
    }
    report["coverage"]["crossfile_index_files"] = index_coverage["files_indexed"]
    report["summary"] = {
        "leads_with_manifest_class_or_alias_match": matched,
        "leads_with_possible_static_external_entry": potential,
        "leads_with_manifest_permission_gated_entry": protected,
        "vulnerabilities_proven": 0,
        "runtime_tests_executed": 0,
    }
    return report
