#!/usr/bin/env python3
"""Read-only triage of why a local Bounty Pilot run appears to find nothing.

No provider calls, source execution, RPC calls, network access or file writes.
Only counts and classifications are emitted; hypothesis text stays private.
"""
import argparse
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bounty_doctor_core", ROOT / "bounty.py")
bounty = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounty)

BUNDLE_WARNING_BYTES = 400_000


def _json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 5_000_000:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return None


def diagnose(run_dir, opus_output=None):
    run = Path(run_dir).expanduser().resolve()
    if not (run / "run.json").is_file():
        raise ValueError("--run must name an existing private Bounty Pilot run (run.json absent)")
    report = {"schema_version": 1, "classification": "READ_ONLY_DISCOVERY_DIAGNOSTIC",
              "confirmed_findings": "not evaluated by this command", "warnings": []}
    findings = _json(run / "findings.json")
    report["recorded_hypotheses"] = sum(
        isinstance(row, dict) and row.get("status") in ("hypothesis", "needs-evidence")
        for row in findings) if isinstance(findings, list) else None
    manifest = _json(run / "bundles" / "manifest.json")
    bundles = {}
    if isinstance(manifest, dict):
        for event in manifest.get("dispatches", []):
            if not isinstance(event, dict):
                continue
            for item in event.get("bundles", []):
                if isinstance(item, dict) and isinstance(item.get("lens"), str):
                    bundles[item["lens"]] = item
    report["bundle_lenses"] = sorted(bundles)
    report["oversized_bundles"] = [
        {"lens": lens, "bytes": item["bytes"]}
        for lens, item in sorted(bundles.items())
        if type(item.get("bytes")) is int and item["bytes"] > BUNDLE_WARNING_BYTES
    ]
    report["backend_bundle_present"] = (
        "web-api-boundary" not in bundles or
        (run / "bundles" / "web-api-source.md").is_file()
    )
    reading_paths = []
    folder = run / "readings"
    if folder.is_dir() and not folder.is_symlink():
        reading_paths.extend(sorted(folder.glob("*.md")))
    if opus_output:
        opus = Path(opus_output).expanduser().resolve()
        if not (opus / "manifest.json").is_file():
            raise ValueError("--opus-output must contain a Charon Opus manifest.json")
        opus_folder = opus / "readings"
        if opus_folder.is_dir() and not opus_folder.is_symlink():
            reading_paths.extend(sorted(opus_folder.glob("*.md")))
        opus_manifest = _json(opus / "manifest.json") or {}
        report["opus_api_responses"] = opus_manifest.get("api_responses_received")
        report["opus_passes_completed"] = opus_manifest.get("passes_completed")
        report["opus_status"] = opus_manifest.get("status")
        if not opus_folder.is_dir() or not list(opus_folder.glob("*.md")):
            report["warnings"].append("Opus produced no importable Markdown readings; inspect its private JSON responses.")
    counts = Counter()
    unparsed_headers = Counter()
    for path in reading_paths:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > bounty.READING_MAX_BYTES:
            counts["unreadable_readings"] += 1
            continue
        raw = path.read_text(encoding="utf-8", errors="replace")
        parsed = bounty._parse_reading(raw, str(path))
        counts["readings"] += 1
        counts["candidate_or_lead_blocks"] += len(parsed["blocks"])
        counts["examined_lines"] += len(parsed["examined"])
        counts["not_reached_lines"] += len(parsed["not_reached"])
        for skipped in parsed["skipped"]:
            reason = skipped.get("reason", "")
            if "format example" not in reason and "looks like a block header" in reason:
                counts["unparsed_candidate_headers"] += 1
                unparsed_headers[reason] += 1
    report["reading_counts"] = dict(counts)
    report["unparsed_header_reasons"] = dict(unparsed_headers)
    dispatch = _json(run / "agents" / "dispatch.json")
    jobs = dispatch.get("jobs", {}) if isinstance(dispatch, dict) else {}
    if isinstance(jobs, dict):
        report["agent_jobs"] = dict(Counter(
            j.get("status", "unknown") for j in jobs.values() if isinstance(j, dict)))
    else:
        report["agent_jobs"] = {}
    if not bundles:
        report["warnings"].append("No bundle dispatch manifest: check that bounty.py bundle actually ran.")
    if report["oversized_bundles"]:
        report["warnings"].append("Some prompts exceed 400 KB; run smaller explicit --scope groups. No complete review can be inferred.")
    if bundles and not report["backend_bundle_present"]:
        report["warnings"].append("Web API bundle predates backend coverage fix; rebuild the scoped bundle.")
    if not counts["readings"]:
        report["warnings"].append("No model reading files found; check agent_dispatch status, provider output and Opus output path.")
    if counts["unparsed_candidate_headers"]:
        report["warnings"].append("Some candidate-like headers were not parsed; review raw readings before discarding.")
    if counts["candidate_or_lead_blocks"] and report["recorded_hypotheses"] == 0:
        report["warnings"].append("Model produced parsable candidates, but findings.json has no open records. Run import-findings with the reading directory.")
    if report["agent_jobs"].get("queued") or report["agent_jobs"].get("failed"):
        report["warnings"].append("Some model jobs never completed; inspect agent_dispatch status and retry failed jobs.")
    report["notice"] = ("This reports pipeline state, not bug validity or a recall benchmark. "
                        "Zero reportable findings is not the same as zero model hypotheses.")
    return report


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", required=True)
    p.add_argument("--opus-output", help="optional separate private Charon Opus output directory")
    args = p.parse_args(argv)
    try:
        report = diagnose(args.run, args.opus_output)
    except (OSError, ValueError) as exc:
        p.error(str(exc))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
