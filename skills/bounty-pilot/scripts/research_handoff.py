#!/usr/bin/env python3
"""Validate Bounty Pilot Lab task/result JSON using only the Python standard library."""
import argparse
import datetime
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"


def _matches_type(value, expected):
    names = expected if isinstance(expected, list) else [expected]
    for name in names:
        if name == "object" and isinstance(value, dict):
            return True
        if name == "array" and isinstance(value, list):
            return True
        if name == "string" and isinstance(value, str):
            return True
        if name == "boolean" and isinstance(value, bool):
            return True
        if name == "integer" and isinstance(value, int) and not isinstance(value, bool):
            return True
        if name == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
            return True
        if name == "null" and value is None:
            return True
    return False


def _valid_format(value, name):
    if not isinstance(value, str):
        return True
    if name == "uri":
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    if name == "date-time":
        try:
            parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.tzinfo is not None and parsed.utcoffset() is not None
        except ValueError:
            return False
    return True


def _validate_schema(value, schema, location="$"):
    errors = []
    if "const" in schema and value != schema["const"]:
        errors.append("%s: must equal %r" % (location, schema["const"]))
    if "enum" in schema and value not in schema["enum"]:
        errors.append("%s: must be one of %s" % (location, ", ".join(map(str, schema["enum"]))))
    expected = schema.get("type")
    if expected is not None and not _matches_type(value, expected):
        errors.append("%s: expected %s" % (location, expected))
        return errors
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append("%s.%s: required property is missing" % (location, key))
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    errors.append("%s.%s: additional property is not allowed" % (location, key))
        for key, child_schema in properties.items():
            if key in value:
                errors.extend(_validate_schema(value[key], child_schema, "%s.%s" % (location, key)))
    if isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            errors.extend(_validate_schema(item, schema["items"], "%s[%d]" % (location, index)))
    if "pattern" in schema and isinstance(value, str):
        if re.search(schema["pattern"], value) is None:
            errors.append("%s: does not match required pattern" % location)
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append("%s: shorter than minLength" % location)
        if len(value) > schema.get("maxLength", float("inf")):
            errors.append("%s: longer than maxLength" % location)
        if "format" in schema and not _valid_format(value, schema["format"]):
            errors.append("%s: invalid %s value" % (location, schema["format"]))
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append("%s: fewer than minItems" % location)
        if len(value) > schema.get("maxItems", float("inf")):
            errors.append("%s: more than maxItems" % location)
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True, ensure_ascii=False) for item in value]
            if len(encoded) != len(set(encoded)):
                errors.append("%s: items must be unique" % location)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < schema.get("minimum", float("-inf")):
            errors.append("%s: below minimum" % location)
        if value > schema.get("maximum", float("inf")):
            errors.append("%s: above maximum" % location)
    return errors


def _load_schema(kind):
    filename = "research-task.schema.json" if kind == "task" else "research-result.schema.json"
    with (SCHEMA_DIR / filename).open(encoding="utf-8") as stream:
        return json.load(stream)


def validate_task(data, for_cloud=False):
    errors = _validate_schema(data, _load_schema("task"))
    if not isinstance(data, dict):
        return errors
    task_type = data.get("task_type")
    status = data.get("status")
    if for_cloud and status != "READY_FOR_POC":
        errors.append("$.status: Cloud submission requires READY_FOR_POC")
    if task_type == "security_hypothesis" and status in ("READY_FOR_POC", "TESTING", "CONFIRMED", "REFUTED", "INCONCLUSIVE"):
        target = data.get("target", {})
        if target.get("scope_status") != "in_scope" or not target.get("program_url"):
            errors.append("$.target: a runnable security task needs a verified in-scope program")
        attacker = data.get("attacker", {})
        if attacker.get("reachable") is not True:
            errors.append("$.attacker.reachable: must be true before PoC dispatch")
        review = data.get("known_issue_review", {})
        if review.get("status") not in ("complete", "not_available"):
            errors.append("$.known_issue_review.status: known-issue review must be complete")
        if review.get("status") == "complete" and not review.get("sources"):
            errors.append("$.known_issue_review.sources: completed review needs sources")
        if review.get("status") == "not_available" and not review.get("rationale"):
            errors.append("$.known_issue_review.rationale: explain why review sources were unavailable")
    if for_cloud and task_type == "workflow_smoke_test":
        if data.get("target", {}).get("scope_status") != "synthetic":
            errors.append("$.target.scope_status: workflow smoke tasks must stay synthetic")
    if isinstance(data.get("source_basis"), list):
        for index, anchor in enumerate(data["source_basis"]):
            if isinstance(anchor, dict) and isinstance(anchor.get("line_start"), int) and isinstance(anchor.get("line_end"), int):
                if anchor["line_end"] < anchor["line_start"]:
                    errors.append("$.source_basis[%d]: line_end precedes line_start" % index)
    return errors


def validate_result(data, task=None):
    errors = _validate_schema(data, _load_schema("result"))
    if not isinstance(data, dict):
        return errors
    status = data.get("status")
    execution = data.get("execution", {})
    review = data.get("independent_review", {})
    artifacts = data.get("artifacts", [])
    kinds = {item.get("kind"): item for item in artifacts if isinstance(item, dict)}
    if status in ("CONFIRMED", "REFUTED"):
        if execution.get("exit_code") != 0:
            errors.append("$.execution.exit_code: adjudicated results need a successful test command")
        if execution.get("tests_run", 0) < 1 or execution.get("tests_passed", 0) < 1:
            errors.append("$.execution: adjudicated results need at least one passing test")
        if status == "CONFIRMED" and execution.get("bug_demonstrated") is not True:
            errors.append("$.execution.bug_demonstrated: CONFIRMED requires a demonstrated behavior")
        if status == "REFUTED" and execution.get("bug_demonstrated") is not False:
            errors.append("$.execution.bug_demonstrated: REFUTED requires the protection to hold")
        expected_review = "supports_finding" if status == "CONFIRMED" else "supports_refutation"
        reviewer = str(review.get("reviewed_by") or "").strip().casefold()
        executor = data.get("executor", {})
        executor_names = {str(executor.get("platform", "")).casefold(), str(executor.get("model", "")).casefold()}
        if review.get("status") != expected_review or not reviewer or reviewer in executor_names or "codex" in reviewer:
            errors.append("$.independent_review: adjudicated result needs a distinct researcher review")
        log = kinds.get("test_log")
        if not log:
            errors.append("$.artifacts: adjudicated result needs a test_log artifact")
        if status == "CONFIRMED" and not kinds.get("proof_of_concept"):
            errors.append("$.artifacts: CONFIRMED requires a proof_of_concept artifact")
        if execution.get("tests_passed", 0) > execution.get("tests_run", 0):
            errors.append("$.execution.tests_passed: cannot exceed tests_run")
    log = kinds.get("test_log")
    if log and (log.get("path") != execution.get("log_path") or log.get("sha256") != execution.get("log_sha256")):
        errors.append("$.execution: log path and digest must match the test_log artifact")
    if status == "INCONCLUSIVE":
        blocker = data.get("blocker")
        if not isinstance(blocker, dict):
            errors.append("$.blocker: INCONCLUSIVE needs a reproduced blocker")
    if status == "OUT_OF_SCOPE" and not data.get("out_of_scope_reason"):
        errors.append("$.out_of_scope_reason: OUT_OF_SCOPE needs a reason")
    if task is not None and isinstance(task, dict):
        if data.get("task_id") != task.get("id"):
            errors.append("$.task_id: does not match the supplied task")
        task_repo = task.get("repository", {})
        result_repo = data.get("repository", {})
        for key in ("url", "ref", "commit_sha"):
            if task_repo.get(key) != result_repo.get(key):
                errors.append("$.repository.%s: does not match the pinned task" % key)
    return errors


def _read_json(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate private Bounty Pilot task/result JSON.")
    commands = parser.add_subparsers(dest="command", required=True)
    task_parser = commands.add_parser("validate-task")
    task_parser.add_argument("path")
    task_parser.add_argument("--for-cloud", action="store_true")
    result_parser = commands.add_parser("validate-result")
    result_parser.add_argument("path")
    result_parser.add_argument("--task")
    args = parser.parse_args(argv)
    try:
        data = _read_json(args.path)
        if args.command == "validate-task":
            errors = validate_task(data, for_cloud=args.for_cloud)
        else:
            task = _read_json(args.task) if args.task else None
            errors = validate_result(data, task=task)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print("invalid JSON input: %s" % error, file=sys.stderr)
        return 2
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("valid: %s" % args.path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
