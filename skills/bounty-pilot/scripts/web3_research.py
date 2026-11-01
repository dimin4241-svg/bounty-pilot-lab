#!/usr/bin/env python3
"""Offline Web3 API/authorization/wallet-intent research from explicitly scoped local inputs.

No HTTP client, socket, DNS lookup, target-code execution, or production requests.
Source scans and researcher-provided observations are leads, not exploit proofs.
Python 3.9+ standard library only.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

MAX_JSON = 300_000
MAX_CASES = 100
MAX_FILES = 3000
MAX_ROUTES = 300
MAX_SIGNALS = 200
MAX_SOURCE_BYTES = 200_000
SOURCE_EXT = {".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".go", ".rs"}
SKIP = {"node_modules", "vendor", "dist", "build", "target", ".next", "tests",
        "test", "fixtures", "__pycache__", ".git", "coverage", "generated"}
HEX40 = re.compile(r"[0-9a-fA-F]{40}\Z")
HEX64 = re.compile(r"[0-9a-fA-F]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z")
FIELD = {"account", "address", "amount_atomic", "asset", "chain_id", "contract",
         "deadline", "delegate", "domain", "nonce", "operation_digest",
         "recipient", "session_id", "signer", "spender"}
MODES = ("scope", "api-map", "authz", "wallet-intent")
ROUTES = (
    re.compile(r"""\b(?:app|router|server|fastify|api)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*['"]([^'"]{1,160})['"]""", re.I),
    re.compile(r"""@\s*(?:app|router|bp|api)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['"]([^'"]{1,160})['"]""", re.I),
    re.compile(r"""@\s*(Get|Post|Put|Patch|Delete)\s*\(\s*['"]([^'"]{0,160})['"]"""),
    re.compile(r"""\b(?:HandleFunc|handleFunc)\s*\(\s*['"]([^'"]{1,160})['"]"""),
)
SIGNALS = {
    "wallet-signing": re.compile(r"\b(?:signTypedData|signMessage|eth_sendTransaction|sendTransaction|writeContract|sign_typed_data)\b"),
    "wallet-login": re.compile(r"\b(?:siwe|SignInWithEthereum|verifyMessage|verifySiweMessage|isValidSignature|ERC1271)\b", re.I),
    "money-operation": re.compile(r"\b(?:withdraw|withdrawal|refund|settle|deposit|payout|transferFrom)\b", re.I),
    "tenant-boundary": re.compile(r"\b(?:tenantId|merchantId|organizationId|accountId|ownerId|workspaceId)\b"),
    "authorization-check": re.compile(r"\b(?:authorize|requireAuth|hasPermission|checkPermission|isOwner|canAccess|policyGuard)\b", re.I),
    "webhook": re.compile(r"\b(?:webhook|signatureHeader|idempotencyKey|eventId)\b", re.I),
    "async-queue": re.compile(r"\b(?:BullMQ|queue\.add|enqueue|acknowledge|job\.complete)\b"),
    "graphql": re.compile(r"\b(?:resolver|GraphQL|typeDefs|Mutation)\b"),
    "websocket": re.compile(r"\b(?:WebSocket|socket\.on|subscribe|SocketIO)\b"),
}
GIT_FLAGS = ("--no-optional-locks", "-c", "core.fsmonitor=false",
             "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat")


def unique_dict(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def load_json(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_JSON:
        raise ValueError("input JSON must be a regular non-symlink file under 300kB")
    try:
        return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=unique_dict,
                          parse_constant=lambda x: (_ for _ in ()).throw(ValueError("non-finite JSON")))
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("invalid Unicode or excessive JSON nesting") from exc


def _object(value, label, allowed=None):
    if not isinstance(value, dict):
        raise ValueError(label + " must be an object")
    if allowed is not None and set(value) - set(allowed):
        raise ValueError(label + " has unsupported properties")
    return value


def _string(value, label, maximum=300, pattern=None):
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(label + " must be bounded nonempty text")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(label + " contains control characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(label + " has invalid Unicode") from exc
    if pattern and not pattern.fullmatch(value):
        raise ValueError(label + " has invalid format")
    return value


def _list(value, label, limit=100):
    if not isinstance(value, list) or not 1 <= len(value) <= limit:
        raise ValueError(label + " must be a nonempty bounded array")
    return value


def _sha(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode("ascii")).hexdigest()


def _prefix(path):
    text = _string(path, "source prefix", 140)
    p = PurePosixPath(text)
    if (p.is_absolute() or not p.parts or any(x in ("..", ".") for x in text.split("/"))
            or "\\" in text or "\x00" in text or ":" in text or text.startswith("~")
            or text.startswith("//")):
        raise ValueError("source prefix must be an explicit relative directory")
    return str(p).rstrip("/") + "/"


def _origin(url):
    value = _string(url, "origin", 300)
    # An origin is not a URL prefix; slash, userinfo, wildcard, query and
    # fragments would make a superficially valid scope declaration ambiguous.
    try:
        parsed = urlsplit(value)
        if (parsed.username is not None or parsed.password is not None or parsed.path
                or parsed.query or parsed.fragment or "*" in value or value.endswith(".")
                or not parsed.hostname or parsed.hostname.endswith(".")):
            raise ValueError("ambiguous origin")
        scheme = parsed.scheme.lower()
        host = parsed.hostname.lower().encode("idna").decode("ascii")
        port = parsed.port
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid exact origin") from exc
    if scheme not in ("https", "http"):
        raise ValueError("only http(s) origins are supported")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    # HTTP allowed only for explicitly scoped loopback development origins.
    if scheme == "http" and (ip is None or not ip.is_loopback):
        raise ValueError("cleartext origin accepted only on loopback")
    if not (ip or ("." in host and re.fullmatch(r"[a-z0-9.-]+", host))):
        raise ValueError("invalid host")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("invalid port")
    if port in (443 if scheme == "https" else 80, None):
        port = None
    netloc = "[" + host + "]" if ":" in host else host
    return scheme + "://" + netloc + (":" + str(port) if port else "")


def validate_policy(data):
    x = _object(data, "policy",
                ("schema_version", "network_mode", "production_requests", "in_scope_origins",
                 "excluded_origins", "allowed_source_prefixes", "scope_evidence"))
    if type(x.get("schema_version")) is not int or x["schema_version"] != 1:
        raise ValueError("policy schema_version must equal 1")
    if x.get("network_mode") != "offline" or x.get("production_requests") is not False:
        raise ValueError("engine operates only offline with production_requests=false")
    _string(x.get("scope_evidence"), "scope_evidence", 500)
    included = [_origin(z) for z in _list(x.get("in_scope_origins"), "in_scope_origins", 80)]
    excluded_raw = x.get("excluded_origins", [])
    if not isinstance(excluded_raw, list) or len(excluded_raw) > 80:
        raise ValueError("excluded_origins must be a bounded array")
    excluded = [_origin(z) for z in excluded_raw]
    prefixes = [_prefix(z) for z in _list(x.get("allowed_source_prefixes"),
                                            "allowed_source_prefixes", 80)]
    for label, values in (("origins", included), ("excluded", excluded), ("prefixes", prefixes)):
        if len(values) != len(set(values)):
            raise ValueError("duplicate " + label)
    return {"included": included, "excluded": excluded, "prefixes": prefixes,
            "scope_evidence_supplied_not_verified": x["scope_evidence"]}


def scope_check(policy, url):
    trusted = validate_policy(policy)
    # urlsplit accepts paths, but policy never attempts network operations.
    raw = _string(url, "candidate URL", 1000)
    p = urlsplit(raw)
    hostpart = p.scheme + "://" + p.netloc
    try:
        norm = _origin(hostpart)
    except ValueError:
        return {"classification": "INVALID_URL", "note": "URL cannot be assessed"}
    result = ("EXCLUDED" if norm in trusted["excluded"] else
              "DECLARED_IN_SCOPE" if norm in trusted["included"] else "UNKNOWN_ORIGIN")
    return {"classification": result, "origin": norm,
            "notice": "Declaration is investigator-supplied, not proof of active bounty authorization."}


def _git(repo, *args):
    done = subprocess.run(["git", *GIT_FLAGS, "-C", str(repo), *args],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
                          check=False)
    if done.returncode:
        raise ValueError("git inspection failed")
    return done.stdout


def api_map(repo, policy, scope_prefixes=None):
    p = validate_policy(policy)
    root = Path(repo)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("checkout must be a non-symlink directory")
    root = root.resolve()
    top = Path(_git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve()
    if top != root:
        raise ValueError("repo must be the checkout root, not a subdirectory")
    rev = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    if not HEX40.fullmatch(rev):
        raise ValueError("checkout must have a pinned Git revision")
    chosen = p["prefixes"]
    if scope_prefixes:
        wanted = [_prefix(k) for k in scope_prefixes]
        # An operator cannot override the policy with a broader prefix.
        if any(not any(w.startswith(a) for a in chosen) for w in wanted):
            raise ValueError("requested prefix is not inside declared scope")
        chosen = wanted
    listed = _git(root, "ls-files", "-z").decode("utf-8", "replace").split("\0")
    entries = sorted({name for name in listed if name})
    routes, signals, skipped, inspected = [], [], 0, 0
    for rel in entries:
        if not any(rel.startswith(pre) for pre in chosen):
            continue
        if len(routes) >= MAX_ROUTES or len(signals) >= MAX_SIGNALS or inspected >= MAX_FILES:
            break
        parts = PurePosixPath(rel).parts
        if (not parts or any(q in (".", "..") for q in parts) or any(q in SKIP for q in parts)
                or PurePosixPath(rel).suffix.lower() not in SOURCE_EXT):
            continue
        src = root / rel
        # No symlink target is followed, including symlinked parent directories.
        if any((root.joinpath(*parts[:i])).is_symlink() for i in range(1, len(parts)+1)):
            skipped += 1
            continue
        if not src.is_file() or src.stat().st_size > MAX_SOURCE_BYTES:
            skipped += 1
            continue
        inspected += 1
        content = src.read_text(encoding="utf-8", errors="replace")
        for no, line in enumerate(content.splitlines(), 1):
            if len(line) > 5000:
                skipped += 1
                continue
            for pat in ROUTES:
                if len(routes) >= MAX_ROUTES:
                    break
                match = pat.search(line)
                if not match:
                    continue
                method, endpoint = ((match.group(1), match.group(2))
                                    if len(match.groups()) == 2 else ("UNSPECIFIED", match.group(1)))
                routes.append({"file": rel, "line": no, "method": method.upper(),
                               "declared_path": endpoint, "classification": "LEXICAL_ROUTE"})
            for label, pattern in SIGNALS.items():
                if len(signals) >= MAX_SIGNALS:
                    break
                if pattern.search(line):
                    signals.append({"file": rel, "line": no, "signal": label,
                                    "classification": "LEXICAL_CUE"})
    return {
        "schema_version": 1, "mode": "api-map",
        "classification": "PASSIVE_SOURCE_INVENTORY", "source_revision": rev,
        "source_prefixes": chosen, "files_inspected": inspected,
        "skipped_oversized_or_symlinked": skipped, "routes": routes, "signals": signals,
        "truncated": inspected >= MAX_FILES or len(routes) >= MAX_ROUTES or len(signals) >= MAX_SIGNALS,
        "network_requests": 0, "executed_target_code": False,
        "confirmed_vulnerabilities": 0,
        "notice": "Lexical discovery only: missing routes/guards is not proof of absence; "
                  "the scope declaration is not verified and no target is contacted.",
    }


def _base_observation(data, mode):
    x = _object(data, "observations", ("schema_version", "source_revision", "environment", "cases"))
    if type(x.get("schema_version")) is not int or x["schema_version"] != 1:
        raise ValueError("schema_version must be integer 1")
    _string(x.get("source_revision"), "source_revision", 40, HEX40)
    if x.get("environment") not in ("mock-local", "native-local", "anvil-local"):
        raise ValueError("only local environments supported")
    cases = _list(x.get("cases"), "cases", MAX_CASES)
    return x, cases


def _trace(side):
    obj = _object(side, "observation")
    _string(obj.get("trace_sha256"), "trace_sha256", 64, HEX64)
    return obj


def _access(side):
    _object(side, "authz observation",
            ("actor", "owner", "resource_id", "operation", "result", "trace_sha256"))
    _trace(side)
    for field in ("actor", "owner", "resource_id", "operation"):
        _string(side.get(field), field)
    if side.get("result") not in ("allowed", "denied", "unknown"):
        raise ValueError("authz result invalid")
    return side


def _wallet(side, bound_fields):
    _object(side, "wallet observation",
            ("displayed", "signed", "executed", "session_permission", "execution_status", "trace_sha256"))
    _trace(side)
    if side.get("session_permission") not in ("valid", "revoked", "unknown"):
        raise ValueError("session_permission must be valid, revoked or unknown")
    if side.get("execution_status") not in ("success", "rejected", "unknown"):
        raise ValueError("wallet execution_status must be success, rejected or unknown")
    stages = {}
    for name in ("displayed", "signed", "executed"):
        value = _object(side.get(name), name)
        if set(value) - FIELD:
            raise ValueError("wallet stage contains unsupported fields")
        for field, data in value.items():
            _string(data, name + "." + field, 200)
        stages[name] = value
    if any(not all(key in stages[stage] for key in bound_fields) for stage in stages):
        return None
    different = sorted(key for key in bound_fields if
                       len({stages[stage][key] for stage in stages}) > 1)
    return different


def observe(data, mode):
    if mode not in ("authz", "wallet-intent"):
        raise ValueError("unsupported observations mode")
    doc, cases = _base_observation(data, mode)
    seen, records = set(), []
    for case in cases:
        case = _object(case, "case",
                       ("id", "invariant", "equivalence_basis", "candidate",
                        "negative_control", "bound_fields"))
        ident = _string(case.get("id"), "case.id", 96, IDENT)
        if ident in seen:
            raise ValueError("duplicate case ID")
        seen.add(ident)
        _string(case.get("invariant"), "invariant", 500)
        _string(case.get("equivalence_basis"), "equivalence_basis", 500)
        cand = _object(case.get("candidate"), "candidate")
        ctl = _object(case.get("negative_control"), "negative_control")
        if cand == ctl:
            raise ValueError("candidate and negative control must differ")
        reasons = []
        if mode == "authz":
            if "bound_fields" in case:
                raise ValueError("bound_fields is wallet-only")
            a, b = _access(cand), _access(ctl)
            comparable = (a["resource_id"] == b["resource_id"] and
                          a["operation"] == b["operation"] and a["owner"] == b["owner"])
            valid_actors = a["actor"] != a["owner"] and b["actor"] == b["owner"]
            a_bad = a["result"] == "allowed" and valid_actors
            b_bad = b["result"] != "allowed"
            unknown = "unknown" in (a["result"], b["result"])
            if not comparable:
                reasons.append("different operation or resource")
            if not valid_actors:
                reasons.append("actors do not represent nonowner versus owner")
        else:
            fields = _list(case.get("bound_fields"), "bound_fields", 20)
            if (len(fields) != len(set(fields)) or any(not isinstance(f, str) or f not in FIELD for f in fields)):
                raise ValueError("invalid wallet-intent binding fields")
            a, b = _wallet(cand, fields), _wallet(ctl, fields)
            unknown = a is None or b is None or "unknown" in (
                cand["session_permission"], ctl["session_permission"],
                cand["execution_status"], ctl["execution_status"])
            # A revoked candidate still executing is a possible session drift.
            a_bad = cand["execution_status"] == "success" and (
                bool(a) or cand["session_permission"] == "revoked")
            b_bad = (bool(b) or ctl["session_permission"] != "valid" or
                     ctl["execution_status"] != "success")
            comparable = True
            valid_actors = True
            if a is None or b is None:
                reasons.append("required bound fields missing")
        if not comparable or not valid_actors or unknown:
            decision = "INCONCLUSIVE"
        elif b_bad:
            decision = "CONTROL_ALSO_VIOLATES"
        elif a_bad:
            decision = "DIFFERENTIAL_LEAD"
        else:
            decision = "NO_DIFFERENTIAL"
        record = {"id": ident, "decision": decision, "reasons": reasons,
                  "candidate_trace_sha256_supplied": cand["trace_sha256"],
                  "control_trace_sha256_supplied": ctl["trace_sha256"],
                  "signals": []}
        if decision == "DIFFERENTIAL_LEAD":
            record["signals"] = (["CROSS_OWNER_OPERATION_ALLOWED"] if mode == "authz" else
                (["INTENT_FIELD_DIVERGENCE"] if a else []) +
                (["REVOKED_SESSION_EXECUTION_OBSERVED"] if cand["session_permission"] == "revoked"
                 and cand["execution_status"] == "success" else []))
        records.append(record)
    return {"schema_version": 1, "mode": mode,
            "classification": "RESEARCHER_SUPPLIED_LOCAL_OBSERVATIONS",
            "source_revision_supplied_not_verified": doc["source_revision"],
            "cases": records,
            "leads": sum(x["decision"] == "DIFFERENTIAL_LEAD" for x in records),
            "confirmed_vulnerabilities": 0, "network_requests": 0,
            "notice": "Researcher-supplied values, identities and digests are not authenticated. "
                      "A differential is not proof of actual reachability, financial harm or bug bounty eligibility."}


def write_private(path, data):
    target = Path(path).expanduser()
    if target.is_symlink() or not target.parent.is_dir():
        raise ValueError("output parent must exist and output cannot be symlink")
    fd = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=True)
        file.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    for name in MODES:
        cmd = sub.add_parser(name)
        cmd.add_argument("--out")
        if name in ("scope", "api-map"):
            cmd.add_argument("--policy", required=True, help="explicit offline scope declaration")
        if name == "scope":
            cmd.add_argument("--url", required=True, help="classify URL only; NEVER request it")
        elif name == "api-map":
            cmd.add_argument("--repo", required=True, help="local git checkout")
            cmd.add_argument("--scope", action="append", default=None)
        else:
            cmd.add_argument("--input", required=True, help="paired local observations")
    args = parser.parse_args(argv)
    try:
        if args.operation == "scope":
            output = scope_check(load_json(args.policy), args.url)
        elif args.operation == "api-map":
            output = api_map(args.repo, load_json(args.policy), args.scope)
        else:
            output = observe(load_json(args.input), args.operation)
        if args.out:
            write_private(args.out, output)
            print(json.dumps({"saved_to": args.out, "classification": output["classification"]}))
        else:
            print(json.dumps(output, indent=2, ensure_ascii=True))
        return 0
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    sys.exit(main())
