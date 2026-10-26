#!/usr/bin/env python3
"""Advanced Vulnerability Research Engine: bounded orchestration of existing and new leads.

AVRE is an opt-in research workflow. It reuses Bounty Pilot's local state graph, ecosystem
inventory, blind-spot queues, differential test planner, scenario runner, and evidence verifier.
Static candidates remain hypotheses. AVRE does not contact targets or execute target code.
"""
import argparse
import errno
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback is exercised by import/CLI tests.
    fcntl = None
try:
    import msvcrt
except ImportError:  # pragma: no cover - POSIX uses fcntl.
    msvcrt = None

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import avre_economics
import avre_sequence

SCHEMA_VERSION = 1
MAX_INPUT_BYTES = 8_000_000
MODULES = ("impossible-state", "sequence-mutation", "economic-differential",
           "failure-recovery", "cross-reality", "identity-context",
           "historical-ecosystem", "attack-graph", "hypothesis-ranking")
GIT_HARDENING = ("--no-optional-locks", "-c", "core.fsmonitor=false", "-c",
                 "core.hooksPath=/dev/null", "-c", "core.pager=cat")
PRIVILEGED = re.compile(r"(?i)(admin|administrator|owner-only|privileged|trusted signer|"
                        r"compromised (?:admin|provider|service|oracle|relayer))")


def _load(name):
    path = SCRIPTS / (name + ".py")
    spec = importlib.util.spec_from_file_location("bp_avre_" + name, path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load existing Pilot module " + name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _json(path):
    raw = Path(path).expanduser()
    if raw.is_symlink() or not raw.is_file() or raw.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("input must be a regular, non-symlink local file under the size cap")
    return json.loads(raw.read_text(encoding="utf-8"))


def _local_input(path, label, max_bytes=MAX_INPUT_BYTES):
    if path is None:
        return None
    raw = Path(path).expanduser()
    if raw.is_symlink() or not raw.is_file() or raw.stat().st_size > max_bytes:
        raise ValueError(label + " must be a regular, non-symlink local file under the size cap")
    return str(raw.resolve())


def _sanitize(value, eco):
    if isinstance(value, str):
        return eco.redact_text(value)
    if isinstance(value, list):
        return [_sanitize(item, eco) for item in value]
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            if eco.SENSITIVE_PATH.search(str(key)):
                output[key] = "<redacted>"
            else:
                output[key] = _sanitize(item, eco)
        return output
    return value


def _git(root, *args):
    result = subprocess.run(["git", *GIT_HARDENING, "-C", str(root), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
                            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat"},
                            check=False)
    return result


def _head(root):
    result = _git(root, "rev-parse", "HEAD")
    value = result.stdout.decode("utf-8", "replace").strip()
    if result.returncode or not re.fullmatch(r"[0-9a-fA-F]{40,64}", value):
        raise ValueError("AVRE requires a local checkout with a resolvable HEAD commit")
    return value


def _file_digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _input_fingerprint(root, scope_path, options, extra_paths):
    eco = _load("ecosystem_intelligence")
    files, skipped, stats = eco._safe_files(root)
    payload = {"head": _head(root), "scope": _file_digest(scope_path),
               "options": options, "files": [(row["path"], hashlib.sha256(
                   row["text"].encode("utf-8", "replace")).hexdigest()) for row in files],
               "skipped_paths": [row["path"] for row in skipped], "stats": stats,
               "extras": {key: _file_digest(path) if path else None
                          for key, path in sorted(extra_paths.items())}}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(), files, stats


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_name = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.chmod(tmp_name, 0o600)
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def _read_checkpoint(path):
    try:
        value = _json(path)
        return value if isinstance(value, dict) and value.get("schema_version") == 1 else None
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def _source_anchor(root, path, line, eco):
    target = root / path
    try:
        if target.is_symlink() or not target.is_file() or target.stat().st_size > 1_000_000:
            return {"path": path, "line": line, "quote": ""}
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        if not 1 <= line <= len(lines):
            return {"path": path, "line": line, "quote": ""}
        quote = " ".join(lines[line - 1].split())
        return {"path": path, "line": line, "quote": eco.redact_text(quote)[:240]}
    except OSError:
        return {"path": path, "line": line, "quote": ""}


def _hypothesis(module, title, root_cause, paths, evidence, invariant, impact,
                prerequisites=None, attacker=None, disconfirming=None,
                classification="NEEDS_EVIDENCE", scope=None, bug_class=None):
    paths = sorted(set(x for x in paths if isinstance(x, str)))
    evidence = evidence if isinstance(evidence, list) else []
    prerequisites = prerequisites or []
    attacker = attacker or "Unknown; establish a low-privilege path before escalation."
    disconfirming = disconfirming or []
    key = module + "|" + title + "|" + "|".join(paths)
    return {
        "id": "AVRE-" + hashlib.sha256(key.encode()).hexdigest()[:12].upper(),
        "module": module, "title": title, "root_cause": root_cause,
        "classification": classification, "status": "unverified_research_candidate",
        "scope": scope or {"classification": "UNKNOWN"},
        "assumptions": prerequisites,
        "attacker_capabilities": attacker,
        "attacker_privileged_assumptions": [x for x in prerequisites if PRIVILEGED.search(x)],
        "reachable_path": "not established; source or model evidence below is only a lead",
        "invariant": invariant, "possible_impact": impact, "actual_impact": None,
        "minimal_reproduction": {"candidate": "not yet written; use local native test",
                                 "negative_control": "required; preserve the same setup and restore the suspected guard"},
        "evidence": evidence, "affected_paths": paths,
        "disconfirming_evidence": disconfirming,
        "bug_class": bug_class or module,
        "confidence": "low", "duplicate_risk": "unknown without local known-issue comparison",
        "review_status": "NOT_INDEPENDENTLY_REVIEWED",
        "reviewer_verdict": None,
    }


def _operation_pairs(graph, root, eco, scope):
    symbols = {row["id"]: row for row in graph.get("symbols", [])}
    patterns = (
        (r"withdraw|unstake|exit|redeem|burn", r"claim|reward|harvest|distribut|checkpoint",
         "post-exit reward weight must follow the documented snapshot and become zero when due"),
        (r"repay|settle|liquidat", r"debt|borrow|withdraw|redeem|claim",
         "successful repayment must reduce the same authoritative debt used by later checks"),
        (r"revoke|disable|transfer|cancel|upgrade|remove", r"authorize|execute|claim|settle|finaliz|withdraw",
         "revoked or superseded authority must not authorize a later execution path"),
        (r"claim|process|finaliz|redeem|execute|relay|callback", r"claim|process|finaliz|redeem|execute|relay|callback",
         "a logical operation identifier must produce at most one economic effect"),
        (r"deposit|stake|mint|supply", r"withdraw|unstake|redeem|burn|total|balance|share",
         "aggregate asset, share and liability deltas must conserve the documented accounting relation"),
    )
    candidates, seen = [], set()
    for edge in graph.get("edges", []):
        if edge.get("reason") != "qualified-or-indexed-write / lexical-read overlap":
            continue
        writer, reader = symbols.get(edge.get("from")), symbols.get(edge.get("to"))
        if not writer or not reader:
            continue
        left = writer["symbol"] + " " + " ".join(writer.get("reads_approx", []))
        right = reader["symbol"] + " " + " ".join(reader.get("reads_approx", []))
        pair = next((row for row in patterns if re.search(row[0], left, re.I) and
                     re.search(row[1], right, re.I)), None)
        if not pair:
            continue
        key = (pair[2], writer["id"], reader["id"], edge.get("token"))
        if key in seen:
            continue
        seen.add(key)
        anchors = [_source_anchor(root, row["path"], row["line"], eco)
                   for row in (writer, reader)]
        candidates.append(_hypothesis(
            "impossible-state", "Check invariant across %s → %s" % (writer["symbol"], reader["symbol"]),
            "A write/read relationship shares lexical state token %r across operations." % edge.get("token"),
            [writer["path"], reader["path"]],
            [{"type": "lexical_state_edge", "shared_state": edge.get("token"),
              "confidence": "low", "anchors": anchors}], pair[2],
            "Possible stale authorization, accounting drift, duplicate credit, or reward/debt mismatch; no loss measured.",
            ["Confirm the functions address the same storage instance and lifecycle.",
             "Confirm protocol specifications and snapshots do not intentionally preserve this value."],
            "Unprivileged only if the named entry points are public and caller-controlled.",
            ["The state graph is lexical and path-insensitive.",
             "A library, caller, checkpoint, or documented snapshot may enforce the invariant."],
            "INVARIANT_ONLY", scope, "state_transition_invariant"))
    return candidates


def _failure_plans(symbols, scope):
    profiles = (
        ("retry|resume|process|relay|callback|ack|event|message|queue",
         "duplicate_message_and_out_of_order_delivery",
         "Exactly-once economic effects and monotonic message consumption."),
        ("upgrade|migrate|initialize|reinitializer|version",
         "interrupted_migration_and_restart",
         "Migration is atomic or safely resumable; recovery cannot restore revoked authority."),
        ("cache|oracle|registry|setconfig|disable|fallback",
         "stale_cache_and_reconciliation",
         "A stale cached value cannot authorize irreversible credit after source state changes."),
        ("claim|withdraw|settle|repay|redeem|transfer",
         "partial_failure_and_rollback",
         "A failed operation leaves either the full prior state or a recoverable consistent state."),
    )
    rows, seen = [], set()
    for symbol in symbols:
        text = (symbol["symbol"] + " " + " ".join(symbol.get("reads_approx", []))).lower()
        for pattern, family, invariant in profiles:
            if not re.search(pattern, text):
                continue
            key = (family, symbol["path"], symbol["symbol"])
            if key in seen:
                continue
            seen.add(key)
            fault = ("duplicate delivery, retry after partial write, restart at the saved checkpoint, "
                     "or out-of-order event" if family.startswith("duplicate") else
                     "inject failure before and after state writes, then restart/reconcile")
            rows.append(_hypothesis(
                "failure-recovery", "Exercise %s around %s" % (family.replace("_", " "), symbol["symbol"]),
                "The source operation names a fault-sensitive lifecycle; no failure handling defect is established.",
                [symbol["path"]], [{"type": "source_symbol", "path": symbol["path"],
                                     "line": symbol["line"], "symbol": symbol["symbol"],
                                     "signals": symbol.get("signals", [])}], invariant,
                "Possible duplicate/lost state or liveness impact; requires a local recovery test.",
                ["Run candidate and negative-control fault injections in an isolated native test.",
                 "Record state before failure, after restart, and after reconciliation."],
                "Caller capability is unknown; do not assume compromised admin or third-party services.",
                ["The function name may be unrelated to asynchronous or recovery behavior.",
                 "The existing transaction or queue layer may provide atomicity/idempotency."],
                "INVARIANT_ONLY", scope, family))
            break
    return rows


def _identity_candidates(root, files, eco, scope):
    rows = []
    for row in files:
        path, body = row["path"], row["text"]
        if not re.search(r"(?i)(ecrecover|ECDSA\.recover|isValidSignature|personal_sign|"
                         r"signTypedData|tx\.origin|delegatecall|nonce|verifyingContract)", body):
            continue
        checks = {
            "contract and chain domain": bool(re.search(r"(?i)(DOMAIN_SEPARATOR|EIP712Domain|"
                                                          r"verifyingContract|chainId|chainid)", body)),
            "one-time or lifecycle binding": bool(re.search(r"(?i)(nonce|usedDigest|consumed|"
                                                             r"orderStatus|cancelled|filled)", body)),
            "explicit account context": bool(re.search(r"(?i)(msg\.sender|owner|operator|"
                                                          r"payer|receiver|spender|account)", body)),
        }
        missing = [name for name, exists in checks.items() if not exists]
        if not missing:
            continue
        for match in list(re.finditer(r"(?i)(ecrecover|ECDSA\.recover|isValidSignature|"
                                      r"personal_sign|signTypedData|tx\.origin|delegatecall|nonce|"
                                      r"verifyingContract)", body))[:4]:
            line = body.count("\n", 0, match.start()) + 1
            rows.append(_hypothesis(
                "identity-context", "Review signed identity/context binding in " + path,
                "One or more identity/domain/replay signals are not visible in this file.", [path],
                [{"type": "identity_context_signal", "signal": match.group(0),
                  "anchor": _source_anchor(root, path, line, eco), "missing_checks": missing}],
                "Authority must bind the intended account, action, chain, verifier, recipient, amount, and nonce.",
                "Possible unauthorized action or replay; no state transition or loss measured.",
                ["Trace the decoded fields from signature through the final authorization check.",
                 "Inspect inherited libraries, proxy implementation and alternate entry points."],
                "Unknown; a signature alone does not establish attacker control or authorization.",
                ["The missing property may be supplied by a caller, library, wallet validator, or outer account-abstraction layer.",
                 "Lexical absence is not proof of missing runtime validation."],
                "NEEDS_EVIDENCE", scope, "identity_or_domain_binding"))
    return rows


def _cross_reality(model, blindspot, scope):
    if model is None:
        return {"flows": [], "candidates": [], "notice":
                "Existing ecosystem path edges are lexical; supply a human-built trust-flow model before making cross-reality hypotheses."}
    result = blindspot.trust_boundary_review(model)
    candidates = []
    by_index = {index: flow for index, flow in enumerate(model.get("flows", []))}
    for gap in result["unverified_flows"]:
        flow = by_index[gap["flow_index"]]
        candidates.append(_hypothesis(
            "cross-reality", "Resolve trust checks on %s → %s" % (gap["source"], gap["destination"]),
            "The supplied flow inventory omits one or more source/authentication/validation/executed-value fields.",
            [], [{"type": "provided_trust_flow", "flow_index": gap["flow_index"],
                  "source": gap["source"], "destination": gap["destination"],
                  "data": flow.get("data"), "missing_checks": gap["missing"],
                  "provenance": flow.get("evidence", [])}],
            "The exact value validated must be the value executed at the final financial or authority decision.",
            "Possible state disagreement or authorization gap; no runtime mismatch measured.",
            ["Anchor the flow to source code and a native integration test.",
             "Inspect cache invalidation, reorg/finality policy and canonical serialization."],
            "Attacker-controlled inputs and trust assumptions must be established from the flow source.",
            ["The model is investigator-supplied and may omit middleware or a trusted validation component."],
            "NEEDS_EVIDENCE", scope, "cross_component_mismatch"))
    return {**result, "candidates": candidates}


def _historical_candidates(eco_report, scope):
    history = eco_report.get("historical_intelligence", {})
    candidates = []
    for lead in history.get("historical_leads", []):
        candidates.append(_hypothesis(
            "historical-ecosystem", "Review historical %s" % lead.get("type", "security change"),
            "Local Git history contains a security-shaped change that may affect current behavior.",
            [lead.get("source", {}).get("path", "")],
            [{"type": "local_history_lead", "lead": lead}],
            "Current authorization, migration, endpoint and replay behavior must preserve the intended invariant.",
            "Possible stale permission, incomplete migration, or replay window; deployment impact unknown.",
            ["Trace all affected versions and deployments.",
             "Check live roles/allowances only through a separately authorized, read-only procedure."],
            "No attacker capability established from local history alone.",
            ["A removal may be intentional; code may have moved; deployments and roles were not queried."],
            "NEEDS_EVIDENCE", scope, lead.get("type")))
    variants = history.get("patch_variant_analysis", {}).get("candidates", [])
    for lead in variants[:100]:
        candidates.append(_hypothesis(
            "historical-ecosystem", "Review %s invariant in %s" %
            (lead.get("invariant"), lead.get("function")),
            "A historical patch added an invariant token not found by lexical scan in this function.",
            [lead.get("current_path", "")], [{"type": "patch_variant_candidate", "lead": lead}],
            "Equivalent paths and versions must retain the patched invariant.",
            "Possible incomplete fix; exploitability and deployment are unknown.",
            ["Compare semantic behavior across all sibling functions, versions and deployments."],
            "No attacker capability established from the patch-token comparison alone.",
            lead.get("disconfirming_evidence", []), "NEEDS_EVIDENCE", scope,
            "patch_variant:" + str(lead.get("invariant"))))
    return candidates


def _deduplicate(rows):
    unique, kept = set(), []
    for row in rows:
        anchor_paths = sorted(set(row.get("affected_paths", [])))
        support_key = tuple(sorted((item.get("type", ""), item.get("path", ""),
                                    item.get("symbol", ""), item.get("shared_state", ""))
                                   for item in row.get("evidence", []) if isinstance(item, dict)))
        key = (row["module"], row["bug_class"], tuple(anchor_paths), support_key)
        if key in unique:
            continue
        unique.add(key)
        kept.append(row)
    return kept


def _score(rows, known_issues, scope):
    corpus = re.findall(r"[a-z0-9_]{4,}", str(known_issues or "").lower())
    corpus_set = set(corpus)
    for row in rows:
        title_tokens = set(re.findall(r"[a-z0-9_]{4,}",
                                      (row["title"] + " " + row["bug_class"]).lower()))
        overlap = len(title_tokens & corpus_set) / max(1, len(title_tokens)) if corpus_set else 0.0
        scope_class = row.get("scope", {}).get("classification", scope.get("classification", "UNKNOWN"))
        scope_score = {"IN_SCOPE": 1.0, "RELATED_OUT_OF_SCOPE": 0.0, "UNKNOWN": 0.2}.get(scope_class, 0.2)
        privileged = len(row.get("attacker_privileged_assumptions", []))
        public_evidence = any(re.search(r"(?i)(public|external|entry|endpoint|handler)",
                                        json.dumps(item)) for item in row.get("evidence", []))
        attacker = 0.65 if public_evidence else (0.25 if not privileged else 0.05)
        reachable = 0.15 if row["classification"] == "INVARIANT_ONLY" else 0.25
        evidence = min(0.6, 0.15 * len(row.get("evidence", [])))
        impact = 0.35 if re.search(r"(?i)(asset|balance|debt|reward|claim|payment|economic)",
                                   row.get("possible_impact", "")) else 0.15
        verification_cost = 0.3 if row.get("module") in ("economic-differential", "sequence-mutation") else 0.5
        assumptions = len(row.get("assumptions", [])) + privileged + (0 if public_evidence else 1)
        burden = min(1.0, assumptions / 6.0)
        values = {"scope_confidence": round(scope_score, 3),
                  "attacker_control": round(max(0.0, attacker - privileged * 0.2), 3),
                  "reachability": reachable, "evidence_strength": evidence,
                  "financial_impact": impact, "novelty": round(1.0 - overlap, 3),
                  "duplicate_risk": round(overlap, 3),
                  "verification_cost": verification_cost,
                  "assumption_burden": round(burden, 3)}
        row["scores"] = {key: {"value": value, "basis": "heuristic; inspect source and artifacts"}
                         for key, value in values.items()}
        row["scores"]["priority"] = round(
            0.16 * scope_score + 0.16 * values["attacker_control"] +
            0.13 * reachable + 0.15 * evidence + 0.13 * impact +
            0.10 * values["novelty"] + 0.07 * (1.0 - verification_cost) -
            0.10 * burden, 4)
        row["duplicate_risk"] = "high" if overlap >= 0.75 else (
            "medium" if overlap >= 0.45 else ("low" if corpus_set else "unknown"))
        row["score_notice"] = "Heuristic prioritization only; no confirmed exploit, payout, or report status."
    rows.sort(key=lambda row: (-row["scores"]["priority"], row["id"]))
    for rank, row in enumerate(rows, 1):
        row["rank"] = rank
    return rows


def _attack_graph(state_graph, ecosystem_report, hypotheses, sequences):
    nodes, edges = {}, []
    for symbol in state_graph.get("symbols", []):
        ident = "symbol:" + symbol["id"]
        nodes[ident] = {"id": ident, "kind": "operation", "label": symbol["symbol"],
                        "path": symbol["path"], "line": symbol["line"]}
    for edge in state_graph.get("edges", []):
        source, destination = "symbol:" + edge["from"], "symbol:" + edge["to"]
        if source in nodes and destination in nodes:
            edges.append({"from": source, "to": destination,
                          "kind": "references_or_may_read_state", "role": edge.get("reason"),
                          "confidence": "low", "evidence": edge.get("token")})
    dep = ecosystem_report.get("dependency_intelligence", {})
    for node in dep.get("nodes", []):
        nodes.setdefault("ecosystem:" + node["id"], {**node, "id": "ecosystem:" + node["id"]})
    for edge in dep.get("edges", []):
        src, dst = "ecosystem:" + edge["from"], "ecosystem:" + edge["to"]
        if src in nodes and dst in nodes:
            edges.append({"from": src, "to": dst, "kind": edge.get("kind"),
                          "role": edge.get("role"), "confidence": edge.get("confidence", "low"),
                          "evidence": edge.get("source")})
    for hypothesis in hypotheses:
        hid = "hypothesis:" + hypothesis["id"]
        nodes[hid] = {"id": hid, "kind": "hypothesis", "label": hypothesis["title"],
                      "classification": hypothesis["classification"]}
        for path in hypothesis.get("affected_paths", []):
            source = next((ident for ident, node in nodes.items()
                           if ident.startswith("symbol:") and node.get("path") == path), None)
            if source:
                edges.append({"from": source, "to": hid, "kind": "supports_hypothesis",
                              "role": hypothesis["module"], "confidence": "low",
                              "evidence": path})
    chains = []
    for index, sequence in enumerate(sequences.get("sequences", [])):
        actions = sequence.get("actions", [])
        if len(actions) < 3:
            continue
        chains.append({"id": "CHAIN-%04d" % (index + 1),
                       "steps": ["symbol:" + row["symbol_id"] for row in actions],
                       "mutation": sequence.get("mutation"), "status": "unverified_chain_candidate",
                       "compatibility": "only lexical state links; runtime permissions and execution order unproven"})
    return {"schema_version": 1, "nodes": list(nodes.values()), "edges": edges,
            "candidate_chains": chains,
            "notice": "Graph edges are evidence-carrying but lexical or investigator-supplied. No chain is a finding."}


def _mermaid(graph):
    aliases = {node["id"]: "n" + hashlib.sha256(node["id"].encode()).hexdigest()[:16]
               for node in graph["nodes"]}
    lines = ["flowchart LR"]
    for node in graph["nodes"][:2500]:
        ident = aliases[node["id"]]
        label = str(node.get("label", ident)).replace('"', "'").replace("\n", " ")[:100]
        lines.append('  %s["%s<br/>%s"]' % (ident, label, node.get("kind", "entity")))
    for edge in graph["edges"][:5000]:
        left, right = aliases.get(edge["from"]), aliases.get(edge["to"])
        if not left or not right:
            continue
        label = (str(edge.get("role", edge.get("kind", "edge"))) + " / " +
                 str(edge.get("confidence", "unknown"))).replace('"', "'")[:80]
        lines.append('  %s -->|"%s"| %s' % (left, label, right))
    return "\n".join(lines) + "\n"


def _markdown(report):
    lines = ["# Advanced Vulnerability Research Engine", "",
             "> Static and artifact-driven research candidates only. This report does not confirm a vulnerability.",
             "", "## Run provenance", "",
             "- Commit: `%s`" % report["analysis"]["head_commit"],
             "- Scope: **%s**" % report["scope"]["repository_decision"]["classification"],
             "- Network requests: 0", "- Target execution: false", "",
             "## Ranked candidates", ""]
    for row in report["ranking"]["hypotheses"][:100]:
        lines.extend(["### %s. %s" % (row["rank"], row["title"]), "",
                      "- Classification: `%s`; module: `%s`; review: `%s`." %
                      (row["classification"], row["module"], row["review_status"]),
                      "- Root cause lead: %s" % row["root_cause"],
                      "- Invariant: %s" % row["invariant"],
                      "- Possible impact: %s; actual impact: not established." % row["possible_impact"],
                      "- Attacker capabilities: %s" % row["attacker_capabilities"],
                      "- Assumptions: %s" % ("; ".join(row["assumptions"]) or "none recorded"),
                      "- Affected paths: %s" % (", ".join(row["affected_paths"]) or "not anchored to source"),
                      "- Minimal reproduction: candidate: %s; negative control: %s." %
                      (row["minimal_reproduction"]["candidate"],
                       row["minimal_reproduction"]["negative_control"]),
                      "- Evidence: %s" % json.dumps(row["evidence"], ensure_ascii=False),
                      "- Disconfirming evidence: %s" % ("; ".join(row["disconfirming_evidence"]) or "not supplied"),
                      "- Confidence: `%s`; duplicate risk: `%s`; score dimensions: `%s`." %
                      (row["confidence"], row["duplicate_risk"],
                       ", ".join("%s=%s" % (key, value["value"])
                                 for key, value in row.get("scores", {}).items()
                                 if isinstance(value, dict) and "value" in value)), ""])
    lines.extend(["## Candidate and control plans", "",
                  "- Sequence plans: %d" % len(report["modules"].get("sequence-mutation", {}).get("sequences", [])),
                  "- Economic metamorphic plans: %d" % len(report["modules"].get("economic-differential", {}).get("plans", [])),
                  "- Failure/recovery plans: %d" % len(report["modules"].get("failure-recovery", {}).get("candidates", [])),
                  "- Local plan execution: %s" % report["analysis"].get("local_verification", "not requested"),
                  "", "## Limits", "",
                  "- Source graphs and static leads are heuristic; no arbitrary target code was executed.",
                  "- Historical public services and on-chain state are not fetched. Local-only archives and explicit trust models are optional inputs.",
                  "- No historical benchmark corpus was supplied; effectiveness and uplift are unmeasured.",
                  "- Review queue is a handoff packet; it is not an independent review or verdict."])
    return "\n".join(lines) + "\n"


def _prepare_out(root, out, resume):
    requested = Path(out).expanduser()
    if requested.is_symlink():
        raise ValueError("AVRE output directory must not be a symlink")
    path = requested.resolve()
    if root == path or root in path.parents:
        raise ValueError("AVRE output must be outside the target checkout")
    if path.exists() and path.is_symlink():
        raise ValueError("AVRE output directory must not be a symlink")
    if path.exists() and any(item.name != ".avre.lock" for item in path.iterdir()) and not resume:
        raise ValueError("output directory is not empty; use --resume only for the matching checkpoint")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    lock = path / ".avre.lock"
    fd = None
    try:
        if fcntl is None and msvcrt is None:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        else:
            flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(lock, flags, 0o600)
            os.chmod(lock, 0o600)
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        os.ftruncate(fd, 0)
        os.write(fd, (str(os.getpid()) + "\n").encode())
        os.fsync(fd)
    except (BlockingIOError, FileExistsError) as exc:
        if fd is not None:
            os.close(fd)
        raise ValueError("another AVRE run holds the output lock") from exc
    except OSError as exc:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
            raise ValueError("another AVRE run holds the output lock") from exc
        raise
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        raise
    return path, fd


def _safe_plan(repo, plan_path, runner):
    plan = _json(plan_path)
    return runner.execute(plan, repo, allow_exec=False)


def analyze(repo, scope_path, out, modules=None, budget=200, max_sequence_length=5,
            beam_width=16, resume=False, trust_model_path=None, measurements_path=None,
            known_issues_path=None, local_plan_path=None, baseline_path=None,
            archive_index_path=None):
    wall_started, cpu_started = time.perf_counter(), time.process_time()
    root = Path(repo).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("--repo must be an existing local directory")
    scope_path = _local_input(scope_path, "--scope")
    scope_file = Path(scope_path)
    scope_path = str(scope_file)
    scope = _load("ecosystem_intelligence").load_scope(scope_file)
    eco = _load("ecosystem_intelligence")
    for method in ("local_static",):
        eco._require_method(scope, method)
    key = eco._repo_key(root)
    repository_decision = eco.classify(scope, "repository", key)
    if repository_decision["classification"] != "IN_SCOPE":
        raise ValueError("scope guardian requires an explicit IN_SCOPE repository rule")
    selected = list(modules or MODULES)
    if not selected or len(set(selected)) != len(selected) or any(name not in MODULES for name in selected):
        raise ValueError("--modules must be a nonempty, duplicate-free selection from: " + ", ".join(MODULES))
    if not set(selected) - {"attack-graph", "hypothesis-ranking"}:
        raise ValueError("select at least one candidate-generating module")
    need_eco = bool(set(selected) & {"historical-ecosystem", "attack-graph"}) or bool(archive_index_path)
    if need_eco:
        eco._require_method(scope, "git_history")
    if archive_index_path:
        eco._require_method(scope, "provided_archive")
    if type(budget) is not int or not 1 <= budget <= 5000:
        raise ValueError("--budget must be between 1 and 5000")
    if type(max_sequence_length) is not int or not 2 <= max_sequence_length <= 8:
        raise ValueError("--max-sequence-length must be between 2 and 8")
    if type(beam_width) is not int or not 1 <= beam_width <= 100:
        raise ValueError("--beam-width must be between 1 and 100")
    options = {"modules": selected, "budget": budget,
               "max_sequence_length": max_sequence_length, "beam_width": beam_width}
    extras = {"trust_model": trust_model_path, "measurements": measurements_path,
              "known_issues": known_issues_path, "local_plan": local_plan_path,
              "baseline": baseline_path, "archive_index": archive_index_path}
    extras = {key: _local_input(path, "--" + key.replace("_", "-")) if path else None
              for key, path in extras.items()}
    trust_model_path, measurements_path = extras["trust_model"], extras["measurements"]
    known_issues_path, local_plan_path = extras["known_issues"], extras["local_plan"]
    baseline_path, archive_index_path = extras["baseline"], extras["archive_index"]
    fingerprint, safe_file_rows, file_stats = _input_fingerprint(root, scope_file, options, extras)
    output, lock_fd = _prepare_out(root, out, resume)
    try:
        checkpoint_path = output / "checkpoint.json"
        checkpoint = _read_checkpoint(checkpoint_path) if resume else None
        payload_entries = [path for path in output.iterdir() if path.name != ".avre.lock"]
        if resume and payload_entries and (not checkpoint or checkpoint.get("fingerprint") != fingerprint):
            raise ValueError("checkpoint fingerprint does not match current commit, inputs, scope, modules, or budgets")
        if not checkpoint:
            checkpoint = {"schema_version": 1, "fingerprint": fingerprint,
                          "completed_modules": [], "module_results": {}, "updated_at": _now()}
            _write_json(checkpoint_path, checkpoint)
        done = checkpoint.get("module_results", {}) if checkpoint else {}
        def audit(event, **values):
            row = {"timestamp": _now(), "event": event, **values}
            with open(output / "audit.jsonl", "a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            os.chmod(output / "audit.jsonl", 0o600)

        audit("analysis_started", repository=key, modules=selected, fingerprint=fingerprint,
              network_requests=0, target_execution=False)
        need_graph = bool(set(selected) & {"impossible-state", "sequence-mutation",
                                           "economic-differential", "failure-recovery",
                                           "identity-context", "attack-graph"})
        state_graph = None
        if need_graph:
            cached_graph = output / "state-graph.json"
            if checkpoint and cached_graph.is_file():
                state_graph = _json(cached_graph)
            else:
                state_graph = _load("state_graph").scan(root, limit=min(2000, max(100, budget * 3)))
                _write_json(cached_graph, state_graph)
        need_eco = bool(set(selected) & {"historical-ecosystem", "attack-graph"}) or bool(archive_index_path)
        eco_report = None
        if need_eco:
            eco_out = output / "ecosystem"
            eco_json = eco_out / "ecosystem-intelligence.json"
            if checkpoint and eco_json.is_file():
                eco_report = _json(eco_json)
            else:
                build_out = output / ".ecosystem-building"
                if build_out.exists():
                    shutil.rmtree(build_out)
                if eco_out.exists():
                    raise ValueError("incomplete nested ecosystem output exists; inspect it before resuming: " + str(eco_out))
                eco.analyze(root, scope_file, build_out, archive_index=archive_index_path,
                            known_issues=known_issues_path)
                os.replace(build_out, eco_out)
                eco_report = _json(eco_json)
        symbols = state_graph.get("symbols", []) if state_graph else []
        results = dict(done)
        module_order = [name for name in MODULES if name in selected]
        for name in module_order:
            if name in results:
                continue
            if name == "impossible-state":
                results[name] = {"hypotheses": _operation_pairs(
                    state_graph, root, eco, repository_decision)}
            elif name == "sequence-mutation":
                results[name] = avre_sequence.generate(
                    state_graph, budget=budget, max_length=max_sequence_length, beam_width=beam_width)
            elif name == "economic-differential":
                econ = {"plans": avre_economics.generate_plans(symbols, min(1000, budget * 2)),
                        "measurements": None}
                if measurements_path:
                    measurements = _json(measurements_path)
                    econ["measurements"] = avre_economics.compare_measurements(
                        measurements, _head(root), repository_decision)
                results[name] = econ
            elif name == "failure-recovery":
                results[name] = {"candidates": _failure_plans(symbols, repository_decision)[:budget]}
            elif name == "cross-reality":
                model = _json(trust_model_path) if trust_model_path else None
                if model is not None and not isinstance(model, dict):
                    raise ValueError("trust model must be a JSON object")
                results[name] = _cross_reality(model, _load("blindspot_engine"), repository_decision)
            elif name == "identity-context":
                results[name] = {"hypotheses": _identity_candidates(
                    root, safe_file_rows, eco, repository_decision)[:budget]}
            elif name == "historical-ecosystem":
                results[name] = {"hypotheses": _historical_candidates(
                    eco_report or {}, repository_decision)[:budget]}
            elif name == "attack-graph":
                seq = results.get("sequence-mutation") or {"sequences": []}
                all_before_graph = []
                for prior in module_order:
                    item = results.get(prior, {})
                    all_before_graph.extend(item.get("hypotheses", []))
                    all_before_graph.extend(item.get("candidates", []))
                results[name] = _attack_graph(state_graph or {"symbols": [], "edges": []},
                                              eco_report or {}, all_before_graph, seq)
            elif name == "hypothesis-ranking":
                results[name] = {"state": "computed_after_candidate_collection"}
            checkpoint_state = {"schema_version": 1, "fingerprint": fingerprint,
                                "completed_modules": [module for module in module_order
                                                      if module in results],
                                "module_results": results, "updated_at": _now()}
            _write_json(checkpoint_path, _sanitize(checkpoint_state, eco))
            audit("module_completed", module=name)
        hypotheses = []
        for name, item in results.items():
            if name in ("attack-graph", "hypothesis-ranking") or not isinstance(item, dict):
                continue
            hypotheses.extend(item.get("hypotheses", []))
            hypotheses.extend(item.get("candidates", []))
            measurements = item.get("measurements")
            if isinstance(measurements, dict):
                for row in measurements.get("comparisons", []):
                    if row["measurement_result"] != "exceeds_declared_tolerance":
                        continue
                    hypotheses.append(_hypothesis(
                        "economic-differential", "Measured differential: " + row["id"],
                        "Candidate/control balance deltas differ beyond the supplied tolerance.", [],
                        [{"type": "paired_measurement", "measurement": row}],
                        "Candidate and control should be economically equivalent under the cited basis.",
                        "Observed delta difference is %s %s; attribution to an attacker or victim is not established." %
                        (row["absolute_difference"], row["unit"]),
                        ["Verify measurement logs and identical initial state.",
                         "Confirm fees, intended rounding, attacker cost and third-party loss."],
                        row.get("attacker_control", "not supplied"),
                        row["missing_checks"], row["classification"], repository_decision,
                        "economic_differential"))
        hypotheses = _deduplicate(hypotheses)
        hypotheses_before_cap = len(hypotheses)
        hypotheses = hypotheses[:budget]
        if known_issues_path:
            known_path = Path(known_issues_path).expanduser()
            if known_path.is_symlink() or not known_path.is_file() or known_path.stat().st_size > MAX_INPUT_BYTES:
                raise ValueError("known-issues corpus must be a regular local file under the size cap")
            known = eco.redact_text(known_path.read_text(encoding="utf-8", errors="replace"))
        else:
            known = ""
        ranked = _score(hypotheses, known, repository_decision)
        results["hypothesis-ranking"] = {"hypotheses": ranked, "budget": budget,
                                        "candidates_before_cap": hypotheses_before_cap,
                                        "notice": "Priority is a queue, not a severity or payout prediction."}
        if "attack-graph" in selected:
            sequences = results.get("sequence-mutation") or {"sequences": []}
            results["attack-graph"] = _attack_graph(state_graph or {"symbols": [], "edges": []},
                                                      eco_report or {}, ranked, sequences)
        if "hypothesis-ranking" in selected:
            _write_json(checkpoint_path, {"schema_version": 1, "fingerprint": fingerprint,
                                          "completed_modules": sorted(set(selected) | {"hypothesis-ranking"}),
                                          "module_results": _sanitize(results, eco), "updated_at": _now()})
        revision = _head(root)
        review_queue = {
            "schema_version": 1, "source_revision": revision,
            "status": "AWAITING_INDEPENDENT_REVIEW",
            "reviewer_requirements": [
                "Use a separate reviewer session and bind it to a completed dispatch invocation.",
                "Attempt to disprove low-privilege reachability, scope, intended behavior, duplicate status and impact.",
                "Do not treat AVRE lexical edges, plans, or heuristic scores as reproduction evidence.",
                "Record confirming and disconfirming anchors and retain rejected candidates with rationale.",
            ],
            "candidates": [{"hypothesis": row,
                            "review_questions": [
                                "Can an ordinary in-scope user reach the proposed path on this exact revision?",
                                "Does a native candidate test fail while its paired negative control passes?",
                                "Is the behavior contrary to documented design, and is there measurable third-party impact?",
                                "Can a duplicate or excluded-scope explanation account for the evidence?",
                            ]} for row in ranked],
            "notice": "This queue is generated by AVRE and is not an independent reviewer verdict.",
        }
        verification = "not requested"
        if local_plan_path:
            decision = eco.classify(scope, "method", "local_static")
            if decision["classification"] != "IN_SCOPE":
                raise ValueError("scope guardian blocked local plan inspection")
            result = _safe_plan(root, local_plan_path, _load("scenario_runner"))
            results["local-verification-plan"] = result
            verification = "dry-run; no command executed"
        comparison = None
        if baseline_path:
            baseline = _json(baseline_path)
            if not isinstance(baseline, dict):
                raise ValueError("baseline must be a JSON object")
            ranking = baseline.get("ranking", {})
            if not isinstance(ranking, dict):
                raise ValueError("baseline ranking must be an object")
            baseline_rows = baseline.get("hypotheses", ranking.get("hypotheses", []))
            if not isinstance(baseline_rows, list):
                raise ValueError("baseline hypotheses must be an array")
            baseline_keys = {(row.get("bug_class"), tuple(row.get("affected_paths", [])))
                             for row in baseline_rows if isinstance(row, dict)}
            current_keys = {(row.get("bug_class"), tuple(row.get("affected_paths", []))) for row in ranked}
            comparison = {"baseline_candidate_count": len(baseline_keys),
                          "avre_candidate_count": len(current_keys),
                          "overlap_count": len(baseline_keys & current_keys),
                          "notice": "Structural overlap only; no true/false-positive labels or efficiency uplift are inferred."}
        results = _sanitize(results, eco)
        ranked = results["hypothesis-ranking"]["hypotheses"]
        graph = results.get("attack-graph") or {"schema_version": 1, "nodes": [], "edges": [],
                                                 "candidate_chains": [], "notice": "attack-graph module not selected"}
        report = {
            "schema_version": SCHEMA_VERSION,
            "analysis": {"observed_at": _now(), "head_commit": _head(root),
                         "input_fingerprint": fingerprint, "repository_key": key,
                         "working_tree_dirty": bool(_git(root, "status", "--porcelain").stdout.strip()),
                         "files_read": file_stats["files_read"], "tracked_files_seen": file_stats["tracked_files_seen"],
                         "modules_selected": selected,
                         "resource_usage": {"wall_seconds_before_report_write": round(time.perf_counter() - wall_started, 4),
                                            "process_cpu_seconds_before_report_write": round(time.process_time() - cpu_started, 4),
                                            "model_or_network_calls": 0, "tokens_used": 0,
                                            "budget_unit": "bounded hypotheses/sequences; not tokens",
                                            "files_read": file_stats["files_read"],
                                            "symbols_scanned": len(symbols),
                                            "sequence_paths_explored": (results.get("sequence-mutation", {}).get("paths_explored", 0)),
                                            "ranked_hypotheses": len(ranked)},
                         "network_policy": {"enabled": False, "requests": 0,
                                            "credential_validation": False,
                                            "active_or_destructive_checks": False},
                         "target_execution": False, "local_verification": verification,
                         "budget": {"candidate_cap": budget, "max_sequence_length": max_sequence_length,
                                    "beam_width": beam_width, "parallelism": 1}},
            "scope": {"project": scope["project"], "repository_decision": repository_decision,
                      "allowed_methods": scope["allowed"]["methods"]},
            "modules": results,
            "ranking": {"hypotheses": ranked,
                        "dimensions": ["scope_confidence", "attacker_control", "reachability",
                                      "evidence_strength", "financial_impact", "novelty",
                                      "duplicate_risk", "verification_cost", "assumption_burden"]},
            "attack_graph": graph, "benchmark_comparison": comparison,
            "review": {"status": "NOT_INDEPENDENTLY_REVIEWED",
                       "integration": "Use existing Bounty Pilot dispatch + evidence_verifier for a bound independent review; AVRE never self-confirms.",
                       "queue_artifact": "skeptical-review-queue.json"},
            "limits": ["Static candidates and dependency edges are heuristic; no runtime reachability is inferred.",
                       "The scenario runner is called in dry-run mode only; run approved tests separately in an isolated environment.",
                       "No historical public benchmark corpus or truth labels were supplied; no recall or uplift is claimed."],
        }
        _write_json(output / "avre-report.json", report)
        _write_json(output / "skeptical-review-queue.json", _sanitize(review_queue, eco))
        (output / "avre-report.md").write_text(_markdown(report), encoding="utf-8")
        os.chmod(output / "avre-report.md", 0o600)
        (output / "attack-graph.mmd").write_text(_mermaid(graph), encoding="utf-8")
        os.chmod(output / "attack-graph.mmd", 0o600)
        audit("analysis_completed", hypotheses=len(ranked), chains=len(graph.get("candidate_chains", [])),
              network_requests=0, target_execution=False,
              wall_seconds=round(time.perf_counter() - wall_started, 4),
              process_cpu_seconds=round(time.process_time() - cpu_started, 4))
        return {"status": "completed", "report": str(output / "avre-report.json"),
                "markdown": str(output / "avre-report.md"), "graph": str(output / "attack-graph.mmd"),
                "audit": str(output / "audit.jsonl"), "commit": report["analysis"]["head_commit"],
                "modules": selected, "hypotheses": len(ranked), "network_requests": 0,
                "target_execution": False}
    finally:
        try:
            if fcntl is not None:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            elif msvcrt is not None:
                os.lseek(lock_fd, 0, os.SEEK_SET)
                msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
            os.close(lock_fd)
            if fcntl is None and msvcrt is None:
                (output / ".avre.lock").unlink(missing_ok=True)
        except OSError:
            pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="local target checkout")
    parser.add_argument("--scope", required=True, help="explicit scope JSON, schema version 1")
    parser.add_argument("--out", required=True, help="private output directory outside target checkout")
    parser.add_argument("--modules", default=",".join(MODULES), help="comma-separated module names")
    parser.add_argument("--budget", type=int, default=200, help="maximum ranked hypothesis count")
    parser.add_argument("--max-sequence-length", type=int, default=5)
    parser.add_argument("--beam-width", type=int, default=16)
    parser.add_argument("--resume", action="store_true", help="resume only a matching fingerprint checkpoint")
    parser.add_argument("--trust-model", help="local human-built cross-component flow JSON")
    parser.add_argument("--measurements", help="local paired economic measurement JSON")
    parser.add_argument("--known-issues", help="local known-issue corpus for duplicate/novelty heuristics")
    parser.add_argument("--local-plan", help="local candidate/control plan to validate in scenario-runner dry-run")
    parser.add_argument("--baseline", help="prior Pilot/AVRE JSON report for structural overlap comparison")
    parser.add_argument("--archive-index", help="local index of previously saved in-scope archives")
    args = parser.parse_args(argv)
    modules = [name.strip() for name in args.modules.split(",") if name.strip()]
    try:
        result = analyze(args.repo, args.scope, args.out, modules, args.budget,
                         args.max_sequence_length, args.beam_width, args.resume,
                         args.trust_model, args.measurements, args.known_issues,
                         args.local_plan, args.baseline, args.archive_index)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError,
            subprocess.SubprocessError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
