#!/usr/bin/env python3
"""Validate and render explicitly supplied local runtime observations for AVRE.

This importer does not execute the target or attest to the trace producer. It checks that an
investigator-supplied local trace is pinned to the exact checkout and that every reported call
has exact source anchors. The output therefore labels every edge as reported and unverified.
"""
import hashlib
import json
import re
from pathlib import Path

MAX_TRACE_BYTES = 8_000_000
REVISION = re.compile(r"[0-9a-fA-F]{40,64}\Z")
ENVIRONMENTS = {"anvil-local", "mock-local"}
EFFECTS = {"call", "delegatecall", "staticcall", "http", "webhook", "event",
           "state-transition"}
OUTCOMES = {"success", "failed", "reverted", "unknown"}


def _source_anchor(root, anchor, label):
    if not isinstance(anchor, dict):
        raise ValueError(label + " source_anchor must be an object")
    relative, line, quote = anchor.get("path"), anchor.get("line"), anchor.get("quote")
    if (not isinstance(relative, str) or not relative or Path(relative).is_absolute() or
            ".." in Path(relative).parts or "\\" in relative):
        raise ValueError(label + " source anchor path must be repository-relative")
    target = root / relative
    try:
        resolved = target.resolve(strict=True)
        if target.is_symlink() or root not in resolved.parents or not resolved.is_file():
            raise ValueError(label + " source anchor escapes the target checkout")
        if type(line) is not int or line < 1 or not isinstance(quote, str) or not quote.strip():
            raise ValueError(label + " source anchor needs a positive line and exact quote")
        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise ValueError(label + " source anchor could not be read") from exc
    if line > len(lines):
        raise ValueError(label + " source anchor line is outside the file")
    excerpt = "\n".join(lines[max(0, line - 2):min(len(lines), line + 1)])
    if quote not in excerpt:
        raise ValueError(label + " exact source quote does not match the pinned checkout")
    return {"path": relative, "line": line, "quote": quote}


def load_trace(path, root, expected_revision):
    """Load a bounded local trace and return review-labeled graph nodes and edges."""
    source = Path(path).expanduser()
    if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_TRACE_BYTES:
        raise ValueError("runtime trace must be a regular, non-symlink local file under the size cap")
    raw = source.read_bytes()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("runtime trace must be valid UTF-8 JSON") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("runtime trace schema_version must be 1")
    if data.get("environment") not in ENVIRONMENTS:
        raise ValueError("runtime trace environment must be an explicitly local anvil-local or mock-local")
    revision = data.get("source_revision")
    if not isinstance(revision, str) or not REVISION.fullmatch(revision):
        raise ValueError("runtime trace source_revision must be a full Git revision")
    if revision.lower() != expected_revision.lower():
        raise ValueError("runtime trace source_revision does not match the current checkout")
    execution_id = data.get("execution_id")
    if not isinstance(execution_id, str) or not execution_id.strip() or len(execution_id) > 160:
        raise ValueError("runtime trace execution_id must be non-empty and at most 160 characters")
    seed = data.get("seed")
    if not isinstance(seed, str) or not seed.strip() or len(seed) > 160:
        raise ValueError("runtime trace seed must be a non-empty string of at most 160 characters")
    if data["environment"] == "anvil-local":
        if type(data.get("chain_id")) is not int or data["chain_id"] < 1:
            raise ValueError("anvil-local traces require a positive integer chain_id")
        if type(data.get("block_number")) is not int or data["block_number"] < 0:
            raise ValueError("anvil-local traces require a non-negative integer block_number")
    elif data.get("chain_id") is not None or data.get("block_number") is not None:
        raise ValueError("mock-local traces must not claim a chain_id or block_number")
    versions = data.get("tool_versions")
    if not isinstance(versions, dict) or not versions or any(
            not isinstance(k, str) or not k.strip() or not isinstance(v, str) or not v.strip()
            for k, v in versions.items()):
        raise ValueError("runtime trace tool_versions must map tool names to version strings")
    actions = data.get("actions")
    if not isinstance(actions, list) or not actions or len(actions) > 10000:
        raise ValueError("runtime trace actions must be a non-empty array of at most 10000 rows")

    digest = hashlib.sha256(raw).hexdigest()
    prefix = "runtime:" + digest[:12]
    nodes, edges = [], []
    for index, action in enumerate(actions, 1):
        if not isinstance(action, dict) or action.get("step") != index:
            raise ValueError("runtime trace action steps must be ordered integers starting at 1")
        caller, callee = action.get("caller"), action.get("callee")
        if any(not isinstance(value, str) or not value.strip() or len(value) > 240
               for value in (caller, callee)):
            raise ValueError("runtime trace caller and callee must be non-empty labels under 240 characters")
        effect, outcome = action.get("effect"), action.get("outcome")
        if effect not in EFFECTS or outcome not in OUTCOMES:
            raise ValueError("runtime trace action effect or outcome is not supported")
        left = _source_anchor(root, action.get("caller_anchor"), "caller")
        right = _source_anchor(root, action.get("callee_anchor"), "callee")
        caller_id, callee_id = prefix + ":" + str(index) + ":caller", prefix + ":" + str(index) + ":callee"
        nodes.extend([
            {"id": caller_id, "kind": "reported_runtime_site", "label": caller,
             "source_anchor": left, "trace_sha256": digest},
            {"id": callee_id, "kind": "reported_runtime_site", "label": callee,
             "source_anchor": right, "trace_sha256": digest},
        ])
        edges.append({"from": caller_id, "to": callee_id, "kind": "reported_runtime_edge",
                      "role": effect, "outcome": outcome, "sequence": index,
                      "confidence": "unverified_artifact", "evidence": digest})
    return {
        "schema_version": 1,
        "status": "IMPORTED_UNVERIFIED",
        "provenance": {"source_revision": revision, "environment": data["environment"],
                       "execution_id": execution_id, "chain_id": data.get("chain_id"),
                       "block_number": data.get("block_number"), "tool_versions": versions,
                       "seed": seed, "artifact_sha256": digest, "artifact_name": source.name,
                       "actions": len(actions)},
        "nodes": nodes,
        "edges": edges,
        "notice": "The artifact and its local-execution claims were supplied by the caller. "
                  "AVRE did not execute the target or authenticate the trace producer; an "
                  "independent reviewer must verify the logs and execution environment.",
    }
