#!/usr/bin/env python3
"""Three offline Web3 integrity checks. Research leads only; no target execution/network.

- business: paired trade/deposit/fee business-invariant observations
- intent-mirror: complete multi-leg displayed/decoded/actual intent comparison
- runtime: locally pinned, tracked-artifact SHA-256 / source cue inventory

Python 3.9+ standard library. Never claim that provided observations, source
baseline or program scope are independently authenticated.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

MAX_INPUT = 300_000
MAX_CASES = 100
MAX_ENTRIES = 150
MAX_FILE = 2_000_000
SHA = re.compile(r"[a-fA-F0-9]{64}\Z")
REV = re.compile(r"[a-fA-F0-9]{40}\Z")
ATOMIC = re.compile(r"0|[1-9][0-9]{0,77}\Z")
SIGNED_ATOMIC = re.compile(r"-?(?:0|[1-9][0-9]{0,77})\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z")
BINDINGS = {"chain_id", "contract", "recipient", "spender", "asset",
            "amount_atomic", "nonce", "domain", "function_selector",
            "operator", "account", "calldata_sha256", "authorization_id"}
LOCAL = {"mock-local", "anvil-local", "native-local"}
GIT_FLAGS = ("--no-optional-locks", "-c", "core.fsmonitor=false",
             "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat")
SOURCE_CUES = {
    "wallet-request": re.compile(r"\b(?:eth_sendTransaction|sendTransaction|signTypedData|writeContract|personal_sign)\b"),
    "dynamic-script": re.compile(r"\b(?:document\.write|createElement\s*\(\s*['\"]script|importScripts|eval\s*\()\b"),
    "address-mutation": re.compile(r"\b(?:clipboard\.writeText|navigator\.clipboard|replaceAll|setAttribute)\b"),
}
EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".json", ".map"}


def pairs_unique(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate JSON key")
        result[k] = v
    return result


def json_file(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_INPUT:
        raise ValueError("JSON input must be a regular non-symlink file under 300kB")
    try:
        return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=pairs_unique,
                          parse_constant=lambda x: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("invalid Unicode or excessive JSON nesting") from exc


def obj(value, label, fields=None):
    if not isinstance(value, dict):
        raise ValueError(label + " must be an object")
    if fields is not None and set(value) - set(fields):
        raise ValueError(label + " contains unsupported fields")
    return value


def txt(value, label, maximum=300, regex=None):
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(label + " must be bounded nonempty text")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(label + " has control characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(label + " has invalid Unicode") from exc
    if regex and not regex.fullmatch(value):
        raise ValueError(label + " has invalid format")
    return value


def amount(value, label, negative=False):
    return int(txt(value, label, 79, SIGNED_ATOMIC if negative else ATOMIC))


def bounded(values, label, maximum=MAX_CASES):
    if not isinstance(values, list) or not 1 <= len(values) <= maximum:
        raise ValueError(label + " must contain 1.." + str(maximum) + " entries")
    return values


def document(data):
    x = obj(data, "observations", ("schema_version", "source_revision", "environment", "cases"))
    if type(x.get("schema_version")) is not int or x["schema_version"] != 1:
        raise ValueError("schema_version must be integer 1")
    txt(x.get("source_revision"), "source_revision", 40, REV)
    if x.get("environment") not in LOCAL:
        raise ValueError("environment must be local")
    return x, bounded(x.get("cases"), "cases")


def sha(value, label):
    return txt(value, label, 64, SHA).lower()


def common_case(item, seen, scenario=None):
    x = obj(item, "case", ("id", "invariant", "equivalence_basis", "scenario",
                           "candidate", "negative_control", "bound_fields"))
    name = txt(x.get("id"), "case.id", 96, IDENT)
    if name in seen:
        raise ValueError("duplicate case ID")
    seen.add(name)
    txt(x.get("invariant"), "case.invariant", 500)
    txt(x.get("equivalence_basis"), "case.equivalence_basis", 500)
    c = obj(x.get("candidate"), "candidate")
    n = obj(x.get("negative_control"), "negative_control")
    if c == n:
        raise ValueError("identical candidate and control")
    if scenario is not None and x.get("scenario") not in scenario:
        raise ValueError("unsupported scenario")
    return name, x, c, n


def business_side(side, scenario):
    defaults = {"trade-asset": ("order_id", "actor", "order_asset", "debit_asset", "status", "trace_sha256"),
                "fee-sign": ("order_id", "actor", "fee_atomic", "status", "trace_sha256"),
                "deposit-finality": ("order_id", "actor", "deposit_status", "credit_status",
                                     "received_atomic", "credited_atomic", "trace_sha256")}
    obj(side, "business observation", defaults[scenario])
    shared = (txt(side.get("order_id"), "order_id", 120),
              txt(side.get("actor"), "actor", 120))
    sha(side.get("trace_sha256"), "trace_sha256")
    result = {"shared": shared, "inconclusive": False, "failure": False, "details": {}}
    if scenario == "trade-asset":
        order_asset = txt(side.get("order_asset"), "order_asset", 120)
        debit_asset = txt(side.get("debit_asset"), "debit_asset", 120)
        state = side.get("status")
        if state not in ("completed", "rejected", "pending", "unknown"):
            raise ValueError("invalid trade status")
        result["shared"] += (order_asset,)
        result["inconclusive"] = state in ("pending", "unknown")
        result["failure"] = state == "completed" and debit_asset != order_asset
        result["details"] = {"settled": state == "completed", "asset_mismatch": debit_asset != order_asset}
    elif scenario == "fee-sign":
        fee = amount(side.get("fee_atomic"), "fee_atomic", True)
        state = side.get("status")
        if state not in ("accepted", "rejected", "unknown"):
            raise ValueError("invalid fee status")
        result["inconclusive"] = state == "unknown"
        result["failure"] = state == "accepted" and fee < 0
        result["details"] = {"fee_negative": fee < 0, "accepted": state == "accepted"}
    else:
        dep, credit = side.get("deposit_status"), side.get("credit_status")
        if dep not in ("finalized", "pending", "failed", "unknown"):
            raise ValueError("invalid deposit status")
        if credit not in ("finalized", "pending", "none", "unknown"):
            raise ValueError("invalid credit status")
        got = amount(side.get("received_atomic"), "received_atomic")
        owed = amount(side.get("credited_atomic"), "credited_atomic")
        result["inconclusive"] = "unknown" in (dep, credit)
        result["failure"] = credit == "finalized" and owed > 0 and (dep != "finalized" or got < owed)
        result["details"] = {"deposit_finalized": dep == "finalized",
                             "credit_finalized": credit == "finalized",
                             "unbacked_atomic": str(max(0, owed-got))}
    return result


def compare_business(data):
    doc, cases = document(data)
    seen, rows = set(), []
    for item in cases:
        name, x, candidate, control = common_case(item, seen,
                                                    {"trade-asset", "fee-sign", "deposit-finality"})
        if "bound_fields" in x:
            raise ValueError("bound_fields is an intent-mirror field")
        mode = x["scenario"]
        a, b = business_side(candidate, mode), business_side(control, mode)
        equivalent = a["shared"] == b["shared"]
        # A legitimate, successful control is essential; a control that was
        # rejected/pending cannot establish the intended good operation.
        control_good = {"trade-asset": b["details"].get("settled"),
                        "fee-sign": b["details"].get("accepted"),
                        "deposit-finality": b["details"].get("credit_finalized")
                        and b["details"].get("deposit_finalized")}[mode]
        if not equivalent or a["inconclusive"] or b["inconclusive"]:
            decision = "INCONCLUSIVE"
        elif b["failure"] or not control_good:
            decision = "CONTROL_ALSO_VIOLATES"
        elif a["failure"]:
            decision = "DIFFERENTIAL_LEAD"
        else:
            decision = "NO_DIFFERENTIAL"
        rows.append({"id": name, "scenario": mode, "decision": decision,
                     "candidate_signals": a["details"], "control_signals": b["details"],
                     "candidate_trace_sha256_supplied": sha(candidate["trace_sha256"], "trace"),
                     "control_trace_sha256_supplied": sha(control["trace_sha256"], "trace")})
    return summary("business-invariants", doc, rows)


def legs(side, bound_fields):
    obj(side, "intent observation", ("displayed_legs", "decoded_signed_legs", "executed_legs",
                                     "display_coverage", "decoder", "approval_status",
                                     "execution_status", "trace_sha256"))
    sha(side.get("trace_sha256"), "trace_sha256")
    if side.get("display_coverage") not in ("complete", "partial", "unknown"):
        raise ValueError("invalid display coverage")
    if side.get("decoder") not in ("native-abi", "native-eip712", "independent-local"):
        raise ValueError("decoder must be declared explicitly")
    if side.get("approval_status") not in ("approved", "rejected", "unknown"):
        raise ValueError("invalid approval")
    if side.get("execution_status") not in ("success", "rejected", "unknown"):
        raise ValueError("invalid execution")
    stage_list = []
    for stage in ("displayed_legs", "decoded_signed_legs", "executed_legs"):
        values = bounded(side.get(stage), stage, 24)
        normalized = []
        for item in values:
            o = obj(item, stage, BINDINGS)
            if any(f not in o for f in bound_fields):
                return {"missing": True, "violation": False, "details": {}}
            normalized.append(tuple(txt(o[f], stage + "." + f, 256)
                                    for f in bound_fields))
        stage_list.append(normalized)
    disagree = stage_list[0] != stage_list[1] or stage_list[1] != stage_list[2]
    counts = [len(x) for x in stage_list]
    unknown = ("unknown" in (side["display_coverage"], side["approval_status"],
                             side["execution_status"]))
    ready = (side["display_coverage"] == "complete" and
             side["approval_status"] == "approved" and
             side["execution_status"] == "success")
    return {"missing": False, "violation": disagree and ready,
            "ready": ready, "unknown": unknown,
            "details": {"leg_counts": counts, "binding_disagreement": disagree,
                        "decoder_declared": side["decoder"]}}


def compare_intent(data):
    doc, cases = document(data)
    seen, rows = set(), []
    for item in cases:
        name, x, candidate, control = common_case(item, seen)
        if "scenario" in x:
            raise ValueError("scenario belongs to business-invariants")
        fields = bounded(x.get("bound_fields"), "bound_fields", len(BINDINGS))
        if len(fields) != len(set(fields)) or any(not isinstance(z, str) or z not in BINDINGS for z in fields):
            raise ValueError("bound_fields contain unsupported or repeated names")
        a, b = legs(candidate, fields), legs(control, fields)
        if a["missing"] or b["missing"] or a.get("unknown") or b.get("unknown") or not a.get("ready"):
            decision = "INCONCLUSIVE"
        elif not b.get("ready") or b["details"]["binding_disagreement"]:
            decision = "CONTROL_ALSO_VIOLATES"
        elif a["violation"]:
            decision = "DIFFERENTIAL_LEAD"
        else:
            decision = "NO_DIFFERENTIAL"
        rows.append({"id": name, "decision": decision, "bound_fields": fields,
                     "candidate_signals": a["details"], "control_signals": b["details"],
                     "candidate_trace_sha256_supplied": sha(candidate["trace_sha256"], "trace"),
                     "control_trace_sha256_supplied": sha(control["trace_sha256"], "trace")})
    return summary("signed-intent-mirror", doc, rows)


def summary(mode, doc, rows):
    return {"schema_version": 1, "engine": "web3-advanced", "mode": mode,
            "classification": "UNAUTHENTICATED_LOCAL_OBSERVATIONS",
            "source_revision_supplied_not_verified": doc["source_revision"],
            "environment_supplied_not_verified": doc["environment"],
            "cases": rows, "leads": sum(z["decision"] == "DIFFERENTIAL_LEAD" for z in rows),
            "confirmed_vulnerabilities": 0, "network_requests": 0,
            "notice": "Candidate and negative-control data, local decoder identity, digests "
                      "and source revision are supplied by the researcher. This does not "
                      "prove deployed exploit reachability, harm or bug bounty eligibility."}


def _git(root, *arguments):
    done = subprocess.run(["git", *GIT_FLAGS, "-C", str(root), *arguments],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=False, timeout=15)
    if done.returncode:
        raise ValueError("git read failed")
    return done.stdout


def local_checkout(repo):
    p = Path(repo)
    if p.is_symlink() or not p.is_dir():
        raise ValueError("repo must be a non-symlink checkout root")
    p = p.resolve()
    top = Path(_git(p, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve()
    if p != top:
        raise ValueError("repo must be checkout root")
    revision = _git(p, "rev-parse", "HEAD").decode("ascii").strip()
    txt(revision, "checkout revision", 40, REV)
    tracked = set(z for z in _git(p, "ls-files", "-z").decode("utf-8", "replace").split("\0") if z)
    return p, revision, tracked


def _relative(value):
    value = txt(value, "artifact path", 250)
    p = PurePosixPath(value)
    if (p.is_absolute() or any(part in ("..", ".") for part in value.split("/"))
            or "\\" in value or value.startswith("~") or ":" in value
            or not p.parts or value.startswith("//")):
        raise ValueError("artifact path must be relative and traversal-free")
    return value


def runtime_provenance(repo, policy, data):
    # Shared scope contract: explicit source prefixes and exact origins,
    # no implicit broad source traversal or live HTTP requests.
    spec = importlib.util.spec_from_file_location(
        "web3_policy_for_advanced", Path(__file__).with_name("web3_research.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rules = module.validate_policy(policy)
    doc = obj(data, "manifest", ("schema_version", "baseline_id", "baseline_revision",
                                  "artifacts"))
    if type(doc.get("schema_version")) is not int or doc["schema_version"] != 1:
        raise ValueError("schema_version must be integer 1")
    txt(doc.get("baseline_id"), "baseline_id", 200)
    txt(doc.get("baseline_revision"), "baseline_revision", 40, REV)
    artifacts = bounded(doc.get("artifacts"), "artifacts", MAX_ENTRIES)
    root, revision, tracked = local_checkout(repo)
    seen, results = set(), []
    for entry in artifacts:
        item = obj(entry, "artifact", ("path", "expected_sha256", "origin", "role"))
        rel = _relative(item.get("path"))
        if rel in seen:
            raise ValueError("duplicate artifact path")
        seen.add(rel)
        expected = sha(item.get("expected_sha256"), "expected_sha256")
        if rel not in tracked:
            raise ValueError("artifact not tracked by target checkout: " + rel)
        if not any(rel.startswith(prefix) for prefix in rules["prefixes"]):
            raise ValueError("artifact is outside policy source prefixes: " + rel)
        if PurePosixPath(rel).suffix.lower() not in EXTENSIONS:
            raise ValueError("unsupported artifact extension")
        origin = item.get("origin")
        if origin not in ("first-party", "third-party"):
            raise ValueError("origin must be first-party or third-party")
        role = item.get("role")
        if role not in ("script", "worker", "manifest", "other"):
            raise ValueError("unsupported artifact role")
        components = PurePosixPath(rel).parts
        if any(root.joinpath(*components[:idx]).is_symlink()
               for idx in range(1, len(components)+1)):
            raise ValueError("symlinked artifact/path is not allowed")
        path = root / rel
        if not path.is_file() or path.stat().st_size > MAX_FILE:
            raise ValueError("artifact must be a regular file under 2MB")
        raw = path.read_bytes()
        actual = hashlib.sha256(raw).hexdigest()
        match = expected == actual
        cues = []
        if (not match and path.suffix.lower() in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}):
            lines = raw.decode("utf-8", "replace").splitlines()
            for no, line in enumerate(lines, 1):
                if len(line) > 5000:
                    continue
                for kind, rx in SOURCE_CUES.items():
                    if rx.search(line):
                        cues.append({"line": no, "kind": kind})
                        if len(cues) >= 24:
                            break
                if len(cues) >= 24:
                    break
        results.append({"path": rel, "origin_claimed": origin, "role": role,
                        "decision": "BASELINE_MATCH" if match else "ARTIFACT_DRIFT",
                        "expected_sha256_supplied": expected,
                        "actual_sha256_local": actual,
                        "source_cues_not_vulnerabilities": cues})
    return {"schema_version": 1, "mode": "runtime-provenance",
            "classification": "INVESTIGATOR_SUPPLIED_BASELINE",
            "checkout_revision": revision,
            "baseline_revision_supplied_not_verified": doc["baseline_revision"],
            "baseline_id_supplied_not_verified": doc["baseline_id"],
            "artifacts": results, "drift_count": sum(z["decision"] == "ARTIFACT_DRIFT" for z in results),
            "confirmed_vulnerabilities": 0, "network_requests": 0,
            "notice": "Only local tracked artifacts are hashed. Source baseline is investigator-supplied, "
                      "not an independent deployment attestation. Drift is not malware or a vulnerability "
                      "verdict; package provenance, actual deployed bytes and scope need independent review."}


def private_write(destination, result):
    p = Path(destination).expanduser()
    if p.is_symlink() or not p.parent.is_dir():
        raise ValueError("output cannot be symlink and parent must exist")
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, ensure_ascii=True)
        handle.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="mode", required=True)
    for mode in ("business-invariants", "signed-intent-mirror", "runtime-provenance"):
        p = subs.add_parser(mode)
        p.add_argument("--input", required=True)
        p.add_argument("--out")
        if mode == "runtime-provenance":
            p.add_argument("--repo", required=True)
            p.add_argument("--policy", required=True)
    a = parser.parse_args(argv)
    try:
        if a.mode == "runtime-provenance":
            result = runtime_provenance(a.repo, json_file(a.policy), json_file(a.input))
        elif a.mode == "business-invariants":
            result = compare_business(json_file(a.input))
        else:
            result = compare_intent(json_file(a.input))
        if a.out:
            private_write(a.out, result)
            print(json.dumps({"saved_to": a.out, "classification": result["classification"]}))
        else:
            print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
