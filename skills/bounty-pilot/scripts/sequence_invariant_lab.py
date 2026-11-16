#!/usr/bin/env python3
"""Offline, evidence-first inter-operation security invariant review.

This tool reads researcher-supplied, source-pinned observations. It never
contacts a target, runs a PoC, or asserts that a model violation is exploitable.
Python stdlib only. See references/sequence-invariant-lab.md.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path

REV = re.compile(r"^[0-9a-f]{40}$")
ALLOWED = {"transfer_isolation", "obligation_coverage", "callback_stack",
           "trigger_integrity", "lifecycle_authority", "temporal_accrual",
           "asset_identity"}
PATTERNS = {
    "shared-context-accounting": [r"currencyDelta\s*\(", r"TAKE_PAIR|_sweepableBalance|balanceOf\s*\(\s*address\s*\(\s*this\s*\)"],
    "callback-interleaving": [r"\.call\s*\{|\.call\s*\(", r"\.transfer\s*\(|safeTransfer|\.swap\s*\("],
    "trigger-lifecycle": [r"(?:remove|delete|pop|_remove)[A-Za-z_]*Trigger|delete\s+[A-Za-z_]*trigger", r"_dispatchAutomationAction|try\s+this\.|catch\s*\("],
    "configuration-composition": [r"modeFlags|MODE_AUTO_|hasAuto", r"ticks\s*\[[012]\]|_computeTriggerTicks|_validateModeFlags"],
    "approval-migration": [r"_mint\s*\(|\.mint\s*\(|nextTokenId", r"approval|setApproval|positionConfigs|tokenId"],
    "temporal-pricing": [r"lastAccrual|lastUpdate|accrue|interestRate|utilization", r"totalAssets|balanceOf|totalDebt|block\.timestamp"],
    "asset-alias": [r"weth|WETH|address\s*\(\s*0\s*\)", r"asset\s*\(\)|currency0|currency1|unwrap|wrap"],
}
MAX_BYTES = 512_000


def _read(path, limit=MAX_BYTES):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > limit:
        raise ValueError("input missing, symlink or exceeds size limit")
    return p.read_text(encoding="utf-8")


def _read_json(path):
    return json.loads(_read(path), parse_float=Decimal)


def _dec(x):
    if isinstance(x, bool) or not isinstance(x, (str, int, Decimal)):
        raise ValueError("amounts must be exact decimal strings/integers (not floats/bools)")
    try:
        v = Decimal(str(x))
    except InvalidOperation as e:
        raise ValueError("invalid exact decimal") from e
    if not v.is_finite() or abs(v) > Decimal("1e80"):
        raise ValueError("non-finite or extreme amount")
    return v


def _sum(values):
    return sum((_dec(v) for v in values), Decimal(0))


def _asmap(x, name):
    if not isinstance(x, dict):
        raise ValueError(name + " must be an object")
    return x


def _revision(obj):
    v = obj.get("source_revision")
    if not isinstance(v, str) or not REV.fullmatch(v):
        raise ValueError("source_revision must be a pinned 40-char lowercase Git SHA")
    return v


def _witness(check_id, kind, step, status, issue, evidence, requirement):
    return {"id": check_id, "kind": kind, "step": step, "status": status,
            "observation": issue, "evidence": evidence, "native_requirement": requirement}


def _check_transfer(rule, steps):
    """Check that protected funds attributed to an owner are not spent elsewhere.

    outflow `fund_owner` denotes the whose funds the observation attributed to
    that transfer, not msg.sender. A single actor's self-transfer is allowed.
    """
    res = []
    for i, step in enumerate(steps):
        for j, move in enumerate(step.get("transfers", [])):
            if not isinstance(move, dict):
                raise ValueError("transfers entries must be objects")
            amt = _dec(move["amount"])
            if amt < 0:
                raise ValueError("transfers cannot have negative amounts")
            owner = move.get("fund_owner")
            recipient = move.get("recipient")
            if not all(isinstance(v, str) and v for v in (owner, recipient)):
                raise ValueError("transfer owner/recipient required")
            if owner != recipient and move.get("authorized_by_owner") is not True and amt > 0:
                res.append(_witness(rule["id"], "transfer_isolation", i, "MODEL_VIOLATION",
                    "value attributed to one owner paid to a different actor without recorded authorization",
                    {"transfer_index": j, "amount": str(amt), "fund_owner": owner,
                     "recipient": recipient},
                    "Independently establish provenance, actual permissions, receipt and control."))
    return res


def _check_coverage(rule, steps):
    res = []
    for i, step in enumerate(steps):
        accounts = step.get("accounting")
        if accounts is None:
            continue
        _asmap(accounts, "accounting")
        for asset, ledger in accounts.items():
            _asmap(ledger, "asset ledger")
            held = _dec(ledger["held_assets"])
            receivable = _dec(ledger.get("collectible_receivables", "0"))
            liabilities = _sum(_asmap(ledger["claims_by_owner"], "claims_by_owner").values())
            reserved = _dec(ledger.get("external_reservations", "0"))
            if min(held, receivable, liabilities, reserved) < 0:
                raise ValueError("negative financial input")
            if held + receivable < liabilities + reserved:
                res.append(_witness(rule["id"], "obligation_coverage", i,
                    "MODEL_VIOLATION", "supplied backing is below supplied claims and reservations",
                    {"asset": asset, "backing": str(held + receivable),
                     "obligations": str(liabilities + reserved)},
                    "Confirm real vault accounting, recoverability, units and native traces."))
    return res


def _check_stack(rule, steps):
    stack, res = [], []
    for i, step in enumerate(steps):
        t = step.get("event")
        if t not in ("enter", "exit", "revert", "observe"):
            raise ValueError("callback_stack requires enter/exit/revert/observe events")
        actor = step.get("actor")
        operation = step.get("operation")
        if t == "enter":
            if not actor or not operation:
                raise ValueError("enter requires actor and operation")
            if stack and actor != stack[-1][0] and rule.get("disallow_cross_actor_nested", False):
                res.append(_witness(rule["id"], "callback_stack", i,
                    "REVIEW_NEEDED", "cross-actor nested entry observed",
                    {"outer_actor": stack[-1][0], "inner_actor": actor},
                    "Cross-actor nesting alone is not a vulnerability; test invariant break."))
            stack.append((actor, operation))
        elif t in ("exit", "revert"):
            if not stack or stack[-1] != (actor, operation):
                raise ValueError("unbalanced callback trace at step " + str(i))
            stack.pop()
    if stack:
        raise ValueError("callback trace ended with open call frames")
    return res


def _check_triggers(rule, steps):
    res = []
    for i, step in enumerate(steps):
        t = step.get("trigger")
        if not t:
            continue
        _asmap(t, "trigger")
        if t.get("active") is not True:
            continue
        required = set(t.get("required", []))
        armed = set(t.get("armed", []))
        disabled = set(t.get("disabled", []))
        if not all(isinstance(k, str) for k in required | armed | disabled):
            raise ValueError("trigger labels must be strings")
        if required - armed:
            res.append(_witness(rule["id"], "trigger_integrity", i, "MODEL_VIOLATION",
                "active configuration is missing required trigger labels",
                {"missing": sorted(required - armed)},
                "Prove thresholds from actual native trigger state and documented config."))
        if disabled & armed:
            res.append(_witness(rule["id"], "trigger_integrity", i, "MODEL_VIOLATION",
                "explicitly disabled trigger is armed", {"armed_disabled": sorted(disabled & armed)},
                "Prove trigger activation and corresponding unauthorized native action."))
        expected_ticks = _asmap(t.get("expected_ticks", {}), "expected_ticks")
        armed_ticks = _asmap(t.get("armed_ticks", {}), "armed_ticks")
        for name, expected in expected_ticks.items():
            if not isinstance(name, str) or not name or name in disabled:
                raise ValueError("expected ticks must have valid enabled labels")
            if name in armed_ticks and _dec(expected) != _dec(armed_ticks[name]):
                res.append(_witness(rule["id"], "trigger_integrity", i, "MODEL_VIOLATION",
                    "armed trigger tick differs from accepted configuration",
                    {"trigger": name, "expected_tick": str(_dec(expected)),
                     "actual_tick": str(_dec(armed_ticks[name]))},
                    "Prove the on-chain trigger slot/owner, the configured limit and resulting native action."))
        action = t.get("executed_mode")
        if action and action not in set(t.get("allowed_actions", [])):
            res.append(_witness(rule["id"], "trigger_integrity", i, "MODEL_VIOLATION",
                "dispatched mode differs from configured acceptable actions",
                {"mode": action}, "Reproduce the dispatched call and actual state effect."))
        if t.get("action_failed") is True and t.get("consumed") and not t.get("rearmed") and t.get("must_survive_failure") is True:
            res.append(_witness(rule["id"], "trigger_integrity", i, "MODEL_VIOLATION",
                "failed automation consumed a trigger without rearming it",
                {"consumed": sorted(t["consumed"])},
                "Confirm no normal fallback or re-arm in native tests."))
    return res


def _check_lifecycle(rule, steps):
    res = []
    for i, step in enumerate(steps):
        m = step.get("migration")
        if not m:
            continue
        _asmap(m, "migration")
        if m.get("automation_active") is not True:
            continue
        required = set(m.get("required_capabilities", []))
        new = set(m.get("successor_capabilities", []))
        if not all(isinstance(v, str) for v in required | new):
            raise ValueError("capability names must be strings")
        if required - new:
            res.append(_witness(rule["id"], "lifecycle_authority", i, "MODEL_VIOLATION",
                "successor advertises automation without the old required capability",
                {"old_id": str(m.get("old_id", "")), "new_id": str(m.get("new_id", "")),
                 "missing": sorted(required - new)},
                "Reproduce remint/migration, actual approvals and failed subsequent action."))
    return res


def _check_temporal(rule, steps):
    res = []
    for i, step in enumerate(steps):
        e = step.get("accrual")
        if not e:
            continue
        _asmap(e, "accrual")
        # Observed segments have already established rates and time units;
        # this does not derive real interest-rate curves from a vault.
        intervals = e.get("intervals", [])
        if not isinstance(intervals, list) or not intervals:
            raise ValueError("accrual needs rate/time segments")
        prev, expected = None, Decimal(0)
        for seg in intervals:
            a,b,rate = _dec(seg["start"]),_dec(seg["end"]),_dec(seg["rate_per_unit"])
            if b < a or (prev is not None and a != prev):
                raise ValueError("accrual intervals must be contiguous and ordered")
            expected += (b-a)*rate
            prev = b
        observed = _dec(e["observed_accrual"])
        tolerance = _dec(e.get("absolute_tolerance", "0"))
        if tolerance < 0:
            raise ValueError("negative tolerance")
        if abs(observed-expected) > tolerance:
            res.append(_witness(rule["id"], "temporal_accrual", i, "MODEL_VIOLATION",
                "accrued amount differs from supplied time-weighted baseline",
                {"expected": str(expected), "observed": str(observed),
                 "difference": str(observed-expected)},
                "Verify protocol's intended accrual semantics, rounding and native balance deltas."))
    return res


def _check_identity(rule, steps):
    aliases = _asmap(rule.get("canonical_assets", {}), "canonical_assets")
    res = []
    for i, step in enumerate(steps):
        for j, link in enumerate(step.get("asset_links", [])):
            _asmap(link, "asset link")
            left, right = link["left"], link["right"]
            if left not in aliases or right not in aliases:
                raise ValueError("asset aliases require explicit mappings, never infer ETH/WETH")
            should_equal = aliases[left] == aliases[right]
            admitted = link.get("admitted_as_same")
            if not isinstance(admitted, bool):
                raise ValueError("admitted_as_same must be boolean")
            if should_equal != admitted:
                res.append(_witness(rule["id"], "asset_identity", i, "MODEL_VIOLATION",
                    "observed asset identity check disagrees with operator-supplied alias policy",
                    {"link_index": j, "left": left, "right": right,
                     "expected_equivalent": should_equal, "admitted_as_same": admitted},
                    "Confirm whether wrap/unwrap is permitted in this exact operation."))
    return res


DISPATCH = {"transfer_isolation": _check_transfer,
            "obligation_coverage": _check_coverage,
            "callback_stack": _check_stack,
            "trigger_integrity": _check_triggers,
            "lifecycle_authority": _check_lifecycle,
            "temporal_accrual": _check_temporal,
            "asset_identity": _check_identity}


def _pair(pair):
    if not pair:
        return {"status": "NO_NATIVE_PAIR", "reason": "candidate/control receipts were not supplied"}
    _asmap(pair, "native_pair")
    if set(pair) - {"candidate", "control"}:
        raise ValueError("native_pair has unexpected keys")
    if not all(key in pair for key in ("candidate", "control")):
        raise ValueError("native_pair requires candidate and control")
    a, b = pair["candidate"], pair["control"]
    for v in (a, b):
        _asmap(v, "native receipt")
        for k in ("source_revision", "starting_state_digest", "command", "log_sha256", "exit_code", "invariant_holds"):
            if k not in v:
                raise ValueError("native receipt missing " + k)
        _revision(v)
        if not re.fullmatch(r"[0-9a-f]{64}", str(v["starting_state_digest"])):
            raise ValueError("invalid initial state digest")
        if not re.fullmatch(r"[0-9a-f]{64}", str(v["log_sha256"])):
            raise ValueError("invalid native log SHA256")
        if not isinstance(v["command"], str) or not v["command"].strip() or len(v["command"]) > 1024:
            raise ValueError("native command missing/too long")
        if type(v["exit_code"]) is not int or type(v["invariant_holds"]) is not bool:
            raise ValueError("native receipt has invalid exit/status")
    same_state = a["starting_state_digest"] == b["starting_state_digest"]
    same_revision = a["source_revision"] == b["source_revision"]
    meaningful = a["exit_code"] == b["exit_code"] == 0 and a["invariant_holds"] is False and b["invariant_holds"] is True
    return {"status": "NATIVE_PAIR_RECEIPTS_NEED_INDEPENDENT_VERIFICATION" if same_state and same_revision and meaningful else "NATIVE_PAIR_INSUFFICIENT",
            "same_initial_state": same_state, "same_revision": same_revision,
            "candidate_break_control_holds": meaningful,
            "reason": "Receipt fields are supplied, not authenticated; source, logs, traces and scope require external validation."}


def review(doc):
    _asmap(doc, "review input")
    rev = _revision(doc)
    rules, steps = doc.get("checks"), doc.get("steps")
    if not isinstance(rules, list) or not rules or len(rules) > 64:
        raise ValueError("checks must contain 1..64 entries")
    if not isinstance(steps, list) or not steps or len(steps) > 250:
        raise ValueError("steps must contain 1..250 entries")
    seen, findings = set(), []
    for item in rules:
        _asmap(item, "check")
        kind, ident = item.get("kind"), item.get("id")
        if kind not in ALLOWED or not isinstance(ident, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,50}", ident) or ident in seen:
            raise ValueError("unsupported kind, duplicate or invalid check ID")
        seen.add(ident)
        findings.extend(DISPATCH[kind](item, steps))
    n = _pair(doc.get("native_pair"))
    if doc.get("native_pair"):
        if any(v["source_revision"] != rev for v in doc["native_pair"].values()):
            n["status"] = "NATIVE_PAIR_INSUFFICIENT"
            n["reason"] = "native receipts disagree with reviewed source revision"
    return {"schema_version": 1, "source_revision": rev,
            "classification": "OFFLINE_MODEL_REVIEW_NOT_A_DEPLOYED_FINDING",
            "checks": len(rules), "steps": len(steps), "witnesses": findings,
            "witness_count": len(findings), "native_evidence": n,
            "next_action": "Reproduce each witness against the unmodified pinned target with an independently reviewed protected negative control and real balance/permission effects."}


def scan(repo, revision, limit=120):
    if not REV.fullmatch(revision):
        raise ValueError("revision must be 40 lowercase hex")
    root = Path(repo)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("repo must be a directory, not a symlink")
    verified = False
    # `rev-parse` is read-only and offline. Do not silently trust a claimed
    # source SHA when a real Git checkout is available.
    try:
        git = subprocess.run(["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
                             capture_output=True, text=True, timeout=4, check=False)
    except (OSError, subprocess.TimeoutExpired):
        git = None
    if git is not None and git.returncode == 0:
        actual = git.stdout.strip().lower()
        if actual != revision:
            raise ValueError("pinned checkout HEAD differs from requested source_revision")
        verified = True
    out, inspected = [], 0
    for path in sorted(root.rglob("*.sol")):
        if inspected >= limit:
            break
        if path.is_symlink() or not path.is_file() or any(x in path.parts for x in ("lib", "node_modules", ".git", "out", "cache")):
            continue
        if path.stat().st_size > 200_000:
            continue
        inspected += 1
        src = path.read_text(encoding="utf-8", errors="replace")
        # Preserve line breaks when removing comments for stable approximate
        # source anchors. String literals can still mislead this lexer.
        src = re.sub(r"/\*.*?\*/|//[^\n]*", lambda m: "\n" * m.group(0).count("\n"), src, flags=re.S)
        for kind, pats in PATTERNS.items():
            hits = [list(re.finditer(p, src, re.I)) for p in pats]
            if not all(hits):
                continue
            # Match two distinct signals locally (within 80 lines), not just across a file.
            for match in hits[0][:15]:
                line = src[:match.start()].count("\n") + 1
                nearest = min((abs(line - (src[:m.start()].count("\n") + 1)) for m in hits[1]), default=10000)
                if nearest <= 80:
                    out.append({"file": str(path.relative_to(root)), "line_approx": line,
                                "pattern": kind, "status": "UNVERIFIED_SOURCE_CUE",
                                "review": "Read both operations, authorization, asset owner and failure path; generate native candidate/control."})
                    break
    return {"schema_version": 1, "revision_claim": revision,
            "revision_verified_by_tool": verified, "files_inspected": inspected,
            "findings": out[:300], "truncated": inspected == limit,
            "notice": "Bounded lexical source cues; no dataflow, runtime reachability, source pin validation or vulnerability proof."}


def mode_matrix(doc):
    """Enumerate all combinations of user-defined flag bits as test tasks.

    The matrix does not infer protocol intent or call real contracts. The user
    supplies documented acceptance and expected dispatch rules in review.
    """
    _asmap(doc, "mode matrix")
    rev = _revision(doc)
    modes = doc.get("modes", [])
    if not isinstance(modes, list) or not 1 <= len(modes) <= 8:
        raise ValueError("mode matrix requires 1..8 flag definitions")
    known, bits = set(), set()
    for m in modes:
        _asmap(m, "mode")
        name, bit = m.get("name"), m.get("bit")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Z0-9_]{2,40}", name):
            raise ValueError("mode names must be uppercase identifiers")
        if type(bit) is not int or bit < 1 or bit > (1 << 30) or bit & (bit - 1):
            raise ValueError("each bit must be a distinct power of two")
        if name in known or bit in bits:
            raise ValueError("duplicate flag name/bit")
        known.add(name)
        bits.add(bit)
    combos = []
    for idx in range(1, 1 << len(modes)):
        selected = [m for j, m in enumerate(modes) if idx & (1 << j)]
        mask = sum(m["bit"] for m in selected)
        labels = [m["name"] for m in selected]
        combos.append({"mode_mask": mask, "modes": labels,
                       "reviewed_acceptance": "UNKNOWN",
                       "native_tests": ["config validation for combined flags",
                                        "arm triggers before and after price movement",
                                        "dispatch to intended mode owner",
                                        "failed action: preserve or rearm protection",
                                        "actual balance and permission effects",
                                        "protected single-mode negative controls"]})
    return {"schema_version": 1, "source_revision": rev,
            "classification": "PLANNED_FLAG_COMBINATIONS_NOT_EXECUTED",
            "cases": sorted(combos, key=lambda c: (len(c["modes"]), c["mode_mask"])),
            "count": len(combos), "notice": "No valid/invalid modes inferred; consult code and documented intent for each case."}


def proof_plan(doc):
    base = review(doc)
    instructions = []
    for w in base["witnesses"]:
        instructions.append({"witness_id": w["id"], "step": w["step"], "kind": w["kind"],
            "candidate": "Use unmodified pinned source and a minimal native end-to-end trace exhibiting this model observation.",
            "negative_control": "Same initial native state, change only the suspected enabling condition, assert the protected invariant holds.",
            "required_observables": ["actual before/after protected balances or rights", "relevant events", "external-call outcomes", "trigger/guard decisions", "gas/capital/fees if economic"],
            "source_revision": doc["source_revision"]})
    return {"classification": "NATIVE_POC_TASKS_NOT_EXECUTED", "source_revision": doc["source_revision"],
            "tasks": instructions, "candidate_count": len(instructions),
            "suggestion": "Use existing harness-gen, sandbox-run and experimenter; import actual candidate/control receipts into native_pair before judging."}


def _write_new(path, payload):
    dest = Path(path)
    if dest.is_symlink() or dest.exists():
        raise ValueError("output already exists or is a symlink")
    dest.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(str(dest), flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, default=str)
        f.write("\n")


def _caseforge(source, action, predictions=None):
    corpus = _read_json(source)
    cases = corpus.get("cases", [])
    if not isinstance(cases, list) or len(cases) > 200:
        raise ValueError("corpus must have up to 200 entries")
    for c in cases:
        _asmap(c, "case")
        if c.get("status") not in {"Confirmed", "Duplicate", "Rejected", "Withdrawn"} or c.get("severity") not in {"Critical", "High", "Medium", "Low", "Informational"}:
            raise ValueError("invalid adjudication")
    if action == "inventory":
        return {"classification": "PUBLIC_KNOWN_ANSWER_CALIBRATION_ONLY",
                "count": len(cases), "by_status": {st: sum(c["status"]==st for c in cases) for st in ("Confirmed", "Duplicate", "Rejected", "Withdrawn")},
                "patterns": sorted(set(c["pattern"] for c in cases)),
                "caveat": "Public reports are contaminated for blind evaluation; never report a discovery lift based on these cases."}
    if action == "tasks":
        return {"classification": "KNOWN_CASE_TRAINING_NOT_BLIND",
                "cases": [{"case_id": c["id"], "snapshot": c.get("source_revision"), "public_report_url": c["url"], "purpose": "create independently controlled native regression for this known case"} for c in cases]}
    if action == "score":
        p = _read_json(predictions)
        rows = p.get("predictions", [])
        if not isinstance(rows, list):
            raise ValueError("predictions must be an array")
        truth = {c["id"]: c for c in cases}
        scored = []
        seen = set()
        for row in rows:
            ident = row.get("case_id")
            if ident not in truth or ident in seen:
                raise ValueError("unknown or duplicate case ID")
            seen.add(ident)
            c = truth[ident]
            scored.append({"case_id": ident, "predicted_pattern": row.get("pattern"),
                "pattern_match": row.get("pattern") == c["pattern"],
                "predicted_status": row.get("status"), "status_match": row.get("status") == c["status"],
                "native_pair_evidence_supplied": row.get("native_pair_evidence_supplied") is True})
        return {"classification": "SELF_REPORTED_KNOWN_CASE_CALIBRATION_NOT_BLIND_REDISCOVERY",
                "scored": scored, "total": len(scored),
                "pattern_matches": sum(r["pattern_match"] for r in scored),
                "no_claim": "No independent native test, real novelty or improvement metric established."}
    raise ValueError("unknown caseforge action")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    a = sub.add_parser("scan", help="bounded lexical source leads (offline)")
    a.add_argument("--repo", required=True)
    a.add_argument("--revision", required=True)
    a.add_argument("--max-files", type=int, default=120)
    a.add_argument("--out", help="new private output file")
    a = sub.add_parser("mode-matrix", help="bounded manual flag-combination coverage plan")
    a.add_argument("--input", required=True)
    a.add_argument("--out", help="new private output file")
    for k in ("review", "proof-plan"):
        a = sub.add_parser(k, help="review pinned JSON observations or prepare native test plan")
        a.add_argument("--input", required=True)
        a.add_argument("--out", help="new private output file")
    a = sub.add_parser("caseforge", help="known Cantina cases for calibration, not blind benchmark")
    a.add_argument("--corpus", required=True)
    a.add_argument("--mode", choices=("inventory", "tasks", "score"), required=True)
    a.add_argument("--predictions")
    a.add_argument("--out", help="new private output file")
    args = p.parse_args(argv)
    try:
        if args.action == "scan":
            if not 1 <= args.max_files <= 500:
                raise ValueError("max-files must be 1..500")
            result = scan(args.repo, args.revision, args.max_files)
        elif args.action in ("review", "proof-plan", "mode-matrix"):
            doc = _read_json(args.input)
            result = (review(doc) if args.action == "review" else
                      proof_plan(doc) if args.action == "proof-plan" else mode_matrix(doc))
        else:
            if args.mode == "score" and not args.predictions:
                raise ValueError("score requires --predictions")
            result = _caseforge(args.corpus, args.mode, args.predictions)
        if args.out:
            _write_new(args.out, result)
        else:
            print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return 0
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
