#!/usr/bin/env python3
"""Passive, scope-bound ecosystem inventory and hypothesis ranking.

Reads a local checkout and optional locally supplied archive metadata. It never makes network
requests, probes services, validates credentials, executes target code, or proves bugs.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

SCHEMA_VERSION = 1
GIT_HARDENING = ("--no-optional-locks", "-c", "core.fsmonitor=false",
                 "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat")
MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, MAX_COMMITS = 5000, 1_000_000, 80_000_000, 400
SENSITIVE_DIRS = {"secret", "secrets", "credential", "credentials", "keystore",
                  "mnemonic", "mnemonics", "private-key", "private_key"}
SENSITIVE_PATH = re.compile(
    r"(?i)(?:\.env(?:\..*)?|(?:api|access|auth)[_-]?token|api[_-]?key|"
    r"secrets?|credentials?|private[_-]?key|mnemonic|seed[_-]?phrase|keystore)")
SOURCE_SUFFIXES = {".sol", ".vy", ".rs", ".move", ".cairo", ".go", ".ts", ".tsx",
                   ".js", ".jsx", ".py", ".java", ".kt", ".swift", ".php", ".rb",
                   ".c", ".h", ".cc", ".cpp", ".hpp", ".cs"}
GENERATED = {".git", "node_modules", "vendor", "third_party", "thirdparty", "dist",
             "build", "target", "out", "cache", "artifacts", "__pycache__", ".venv",
             "venv", "coverage"}
URL_RE = re.compile(r"(?i)\b(?:https?|wss?)://[^\s\"'<>]+")
ADDRESS_RE = re.compile(r"(?i)\b0x[a-f0-9]{40}\b")
SECRET_ASSIGN = re.compile(
    r"""(?ix)(["']?[A-Za-z0-9_.-]*(?:private[_-]?key|api[_-]?key|secret(?:[_-]?key)?|
    access[_-]?token|auth[_-]?token|bearer[_-]?token|password|passwd|mnemonic|
    seed[_-]?phrase|client[_-]?secret|webhook[_-]?secret)["']?\s*[:=]\s*)
    (["'])(.*?)(\2)""")
UNQUOTED_SECRET = re.compile(
    r"(?i)([A-Za-z0-9_.-]*(?:private[_-]?key|api[_-]?key|secret(?:[_-]?key)?|"
    r"access[_-]?token|auth[_-]?token|bearer[_-]?token|password|passwd|mnemonic|"
    r"seed[_-]?phrase|client[_-]?secret|webhook[_-]?secret)[A-Za-z0-9_.-]*\s*[:=]\s*)"
    r"(?![\"'])([^,\s}\]]+)")
BEARER = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
HEX_KEY = re.compile(r"(?i)(\b[\w$]*(?:private|priv|secret|signing)[\w$]*\s*[:=]\s*)"
                     r"(0x[0-9a-f]{64})")
RPC_HOST = re.compile(r"(?i)(alchemy\.com|alchemyapi\.io|infura\.io|quiknode\.pro|"
                      r"quicknode\.com|ankr\.com|blastapi\.io|chainstack\.com|getblock\.io|"
                      r"drpc\.org|nodereal\.io|tenderly\.co|blockpi\.network|nodies\.app|p2pify\.com)")
ROLES = [
    ("bridge", r"\b(bridge|wormhole|layerzero|hyperlane|axelar|ccip|cctp|ibc|xcm)\b"),
    ("relayer", r"\b(relayer|relay|keeper|messenger)\b"),
    ("oracle", r"\b(oracle|price.?feed|aggregatorv3|twap)\b"),
    ("payment_processor", r"\b(stripe|paypal|checkout|payment.?processor)\b"),
    ("auth_provider", r"\b(oauth|oidc|firebase.?auth|auth0|cognito|clerk)\b"),
    ("webhook", r"\b(webhook|callback.?url|event.?hook)\b"),
    ("indexer", r"\b(indexer|subgraph|thegraph|graphql.?client)\b"),
    ("signer", r"\b(signer|signing.?service|kms|hsm|ecrecover|signature)\b"),
    ("rpc", r"\b(rpc|json.?rpc|provider|alchemy|infura|quicknode|ankr)\b"),
    ("external_api", r"\b(external.?api|api.?client|rest.?client|fetch\s*\(|axios)\b"),
]
COMPONENTS = {
    "frontend": re.compile(r"(?i)(^|/)(web|frontend|client|app|ui|dapp)(/|$)|\.(tsx|jsx|vue|svelte)$"),
    "backend": re.compile(r"(?i)(^|/)(api|backend|server|service)(/|$)|routes?\.|controller"),
    "relayer": re.compile(r"(?i)(^|/)(relayer|relay|keeper|messenger)(/|$)"),
    "indexer": re.compile(r"(?i)(^|/)(indexer|subgraph|graphql)(/|$)"),
    "oracle": re.compile(r"(?i)(^|/)(oracle|price-feed|feeds?)(/|$)"),
    "contract": re.compile(r"(?i)\.(sol|vy|move|cairo)$|(^|/)(contracts?|programs?)(/|$)"),
    "signer": re.compile(r"(?i)(^|/)(signer|signing|kms|hsm)(/|$)"),
}
INVARIANTS = {
    "signature_domain": ("DOMAIN_SEPARATOR", "domainSeparator", "EIP712Domain", "domain_typehash"),
    "chain_binding": ("chainId", "chain_id", "chainid"),
    "contract_binding": ("verifyingContract", "verifying_contract", "address(this)"),
    "nonce_or_replay": ("nonce", "usedDigest", "consumed", "replay"),
    "order_lifecycle": ("cancelled", "filled", "executed", "pending", "orderStatus"),
    "finality": ("finalized", "finality", "confirmations", "safeBlock", "finalizedBlock"),
    "auth_or_roles": ("onlyOwner", "onlyRole", "hasRole", "AccessControl", "authorize"),
    "migration_or_upgrade": ("initializer", "reinitializer", "upgradeTo", "migrate", "migration"),
    "allowance": ("approve(", "allowance(", "permit(", "safeApprove"),
    "webhook_auth": ("hmac", "signature", "timestamp", "idempotency", "event_id"),
}
SECURITY_COMMIT = re.compile(r"(?i)\b(security|vuln|exploit|fix|patch|auth|replay|nonce|"
                             r"signature|access.?control|upgrade|migration|hotfix)\b")
ACTIVE_METHODS = {"http_probe", "api_probe", "port_scan", "fuzz_live", "transaction",
                  "write_rpc", "credential_validation", "exploit", "bruteforce", "active_scan"}
PASSIVE_METHODS = {"local_static", "git_history", "provided_archive"}


def now_utc():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_domain(value):
    text = str(value or "").strip().lower().rstrip(".")
    if "://" in text:
        text = urlsplit(text).hostname or ""
    return text[4:] if text.startswith("www.") else text


def normalize_repo(value):
    text = str(value or "").strip()
    if "://" in text:
        parsed = urlsplit(text)
        path = parsed.path.strip("/").removesuffix(".git")
        return (parsed.hostname or "").lower() + "/" + path.lower()
    if text.startswith("git@") and ":" in text:
        host, path = text[4:].split(":", 1)
        return host.lower() + "/" + path.removesuffix(".git").strip("/").lower()
    text = text.removesuffix(".git").strip("/")
    return "github.com/" + text.lower() if text.count("/") == 1 else text.lower()


def normalize_url(value):
    parsed = urlsplit(str(value).strip())
    if parsed.scheme.lower() not in ("http", "https", "ws", "wss") or not parsed.hostname:
        return ""
    host = parsed.hostname.lower()
    if parsed.port and parsed.port not in (80, 443):
        host += ":" + str(parsed.port)
    path = re.sub(r"/{2,}", "/", parsed.path or "/").rstrip("/") or "/"
    return urlunsplit((parsed.scheme.lower(), host, path, "", ""))


def safe_url(value):
    parsed = urlsplit(str(value).rstrip(".,;:!?)\"]}"))
    if not parsed.scheme or not parsed.hostname:
        return ""
    host = parsed.hostname.lower()
    if parsed.port and parsed.port not in (80, 443):
        host += ":" + str(parsed.port)
    parts = [p for p in parsed.path.split("/") if p]
    parts = ["<redacted>" if (SENSITIVE_PATH.search(p) or
             len(p) >= 24 and re.fullmatch(r"[A-Za-z0-9._~-]+", p) or
             RPC_HOST.search(host) and len(p) >= 16 and
             re.fullmatch(r"[A-Za-z0-9_-]+", p)) else p for p in parts]
    return urlunsplit((parsed.scheme.lower(), host, "/" + "/".join(parts) if parts else "", "", ""))


def redact_text(text):
    value = URL_RE.sub(lambda m: safe_url(m.group(0)), str(text))
    value = SECRET_ASSIGN.sub(lambda m: m.group(1) + m.group(2) + "<redacted>" + m.group(4), value)
    value = UNQUOTED_SECRET.sub(lambda m: m.group(1) + "<redacted>", value)
    value = BEARER.sub(r"\1<redacted>", value)
    return HEX_KEY.sub(r"\1<redacted>", value)


def git(repo, *args, check=True):
    result = subprocess.run(["git", *GIT_HARDENING, "-C", str(repo), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check, timeout=30)
    return result.stdout.decode("utf-8", "replace")


def load_scope(path):
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("scope file must be a JSON object with schema_version: 1")
    allowed, related = raw.get("allowed", {}), raw.get("related_out_of_scope", {})
    if not isinstance(allowed, dict) or not isinstance(related, dict):
        raise ValueError("allowed and related_out_of_scope must be objects")
    keys = ("domains", "urls", "repositories", "contracts", "networks", "methods")
    result = {"schema_version": 1,
              "project": redact_text(str(raw.get("project", "unnamed project")))[:160],
              "allowed": {}, "related_out_of_scope": {}, "limits": raw.get("limits", {})}
    for group, source in (("allowed", allowed), ("related_out_of_scope", related)):
        for key in keys:
            value = source.get(key, [])
            if not isinstance(value, list):
                raise ValueError("scope field %s.%s must be an array" % (group, key))
            result[group][key] = value
        result[group]["methods"] = [str(x).lower().replace("-", "_")
                                    for x in result[group]["methods"]]
        for key in keys[:-1]:
            for item in result[group][key]:
                if not (isinstance(item, str) and item.strip()) and not (
                        isinstance(item, dict) and item):
                    raise ValueError("scope entries in %s.%s must be strings or objects" % (group, key))
    methods = set(result["allowed"]["methods"])
    if methods & ACTIVE_METHODS:
        raise ValueError("active methods are unsupported; this tool is passive-only")
    unknown = methods - PASSIVE_METHODS
    if unknown:
        raise ValueError("unknown allowed method(s): " + ", ".join(sorted(unknown)))
    return result


def _domain_matches(rule, host):
    domain, candidate = normalize_domain(rule), normalize_domain(host)
    return bool(domain and candidate and (candidate == domain or candidate.endswith("." + domain)))


def _url_matches(target, rule):
    candidate, pattern = normalize_url(target), normalize_url(rule)
    if not candidate or not pattern:
        return False
    left, right = urlsplit(candidate), urlsplit(pattern)
    root = right.path.rstrip("/") or "/"
    return left.scheme == right.scheme and left.netloc == right.netloc and (
        root == "/" or left.path == root or left.path.startswith(root + "/"))


def classify(scope, kind, value, network=None, chain_id=None):
    kind, value = str(kind).lower().replace("-", "_"), str(value or "").strip()
    # More-specific exclusions must win over a broader allowed parent domain or repository.
    groups = (("related_out_of_scope", "RELATED_OUT_OF_SCOPE"), ("allowed", "IN_SCOPE"))
    if kind in ("domain", "url"):
        host = urlsplit(value).hostname if "://" in value else value
        safe = safe_url(value) if "://" in value else normalize_domain(value)
        for group, label in groups:
            data = scope[group]
            if kind == "url" and any(_url_matches(value, x) for x in data["urls"]):
                return {"classification": label, "basis": "explicit URL rule", "value": safe}
            if host and any(_domain_matches(x, host) for x in data["domains"]):
                return {"classification": label, "basis": "explicit domain rule", "value": safe}
        return {"classification": "UNKNOWN", "basis": "no explicit domain or URL match", "value": safe}
    if kind in ("repo", "repository"):
        normalized = normalize_repo(value)
        for group, label in groups:
            rules = [normalize_repo(x if isinstance(x, str) else x.get("url", x.get("name", "")))
                     for x in scope[group]["repositories"]]
            if normalized and normalized in rules:
                return {"classification": label, "basis": "explicit repository rule", "value": normalized}
        return {"classification": "UNKNOWN", "basis": "no explicit repository match", "value": normalized}
    if kind in ("contract", "address"):
        address = value.lower()
        for group, label in groups:
            for row in scope[group]["contracts"]:
                candidate, net, cid = ((str(row.get("address", "")).lower(), row.get("network"),
                                        row.get("chain_id", row.get("chainId")))
                                       if isinstance(row, dict) else (str(row).lower(), None, None))
                if candidate != address:
                    continue
                if net is not None and (network is None or str(net).lower() != str(network).lower()):
                    continue
                if cid is not None and (chain_id is None or str(cid) != str(chain_id)):
                    continue
                return {"classification": label, "basis": "explicit contract/network rule", "value": address}
        return {"classification": "UNKNOWN", "basis": "no explicit contract/network match", "value": address}
    if kind in ("network", "chain"):
        for group, label in groups:
            for row in scope[group]["networks"]:
                if isinstance(row, str) and row.lower() in (value.lower(), str(chain_id or "").lower()):
                    return {"classification": label, "basis": "explicit network rule", "value": value}
                if isinstance(row, dict):
                    names = {str(row.get("name", "")).lower(), str(row.get("chain_id", "")).lower()}
                    if value.lower() in names or (chain_id is not None and str(chain_id).lower() in names):
                        return {"classification": label, "basis": "explicit network rule", "value": value}
        return {"classification": "UNKNOWN", "basis": "no explicit network match", "value": value}
    if kind == "method":
        method = value.lower().replace("-", "_")
        if method in ACTIVE_METHODS:
            return {"classification": "RELATED_OUT_OF_SCOPE", "basis": "active method disabled", "value": method}
        if method in scope["allowed"]["methods"]:
            return {"classification": "IN_SCOPE", "basis": "method explicitly allowed", "value": method}
        if method in scope["related_out_of_scope"]["methods"]:
            return {"classification": "RELATED_OUT_OF_SCOPE", "basis": "method explicitly excluded", "value": method}
        return {"classification": "UNKNOWN", "basis": "method not explicitly allowed", "value": method}
    return {"classification": "UNKNOWN", "basis": "unsupported entity kind", "value": value}


def _require_method(scope, method):
    result = classify(scope, "method", method)
    if result["classification"] != "IN_SCOPE":
        raise ValueError("scope guardian blocked %s: %s" % (method, result["classification"]))


def _repo_key(root):
    remote = git(root, "remote", "get-url", "origin", check=False).strip()
    return redact_text(normalize_repo(remote))[:220] if remote else root.name.lower()


def _safe_files(root):
    names = [x for x in git(root, "ls-files", "-z").split("\0") if x][:MAX_FILES]
    files, skipped, total = [], [], 0
    for name in names:
        path = root / name
        parts = [p.lower() for p in Path(name).parts]
        basename, suffix = Path(name).name.lower(), Path(name).suffix.lower()
        sensitive_data_file = (SENSITIVE_PATH.search(basename) and
                               (suffix not in SOURCE_SUFFIXES or basename.startswith(".env")))
        sensitive_directory = (suffix not in SOURCE_SUFFIXES and
                               any(part in SENSITIVE_DIRS for part in parts[:-1]))
        if (set(parts) & GENERATED or sensitive_data_file or sensitive_directory or
                basename in {"id_rsa", "id_ed25519", "authorized_keys", "known_hosts"}):
            skipped.append({"path": name, "reason": "sensitive/generated path"})
            continue
        try:
            if path.is_symlink() or not path.is_file():
                raise ValueError()
            path.resolve().relative_to(root)
            size = path.stat().st_size
            if size > MAX_FILE_BYTES or total + size > MAX_TOTAL_BYTES:
                skipped.append({"path": name, "reason": "size cap"})
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            skipped.append({"path": name, "reason": "unsafe/unreadable path"})
            continue
        total += size
        files.append({"path": name, "text": text, "size": size})
    return files, skipped, {"tracked_files_seen": len(names), "files_read": len(files),
                            "bytes_read": total, "file_list_truncated": len(names) == MAX_FILES}


def _path_times(root):
    raw = git(root, "log", "--all", "--format=%ct", "--name-only", "-n", str(MAX_COMMITS),
              check=False)
    times, current = {}, None
    for line in raw.splitlines():
        if line.isdigit():
            current = datetime.fromtimestamp(int(line), timezone.utc).replace(
                microsecond=0).isoformat().replace("+00:00", "Z")
        elif line and current:
            times.setdefault(line, current)
    return times


def _component(path, text=""):
    combined = path + "\n" + text[:1500]
    return next((name for name, pattern in COMPONENTS.items() if pattern.search(combined)), "repository")


def _evidence(path, text, start, end, timestamp=None):
    line = text.count("\n", 0, start) + 1
    excerpt = " ".join(text[max(0, start - 80):min(len(text), end + 100)].split())
    result = {"path": path, "line": line, "excerpt": redact_text(excerpt)[:220]}
    if timestamp:
        result["source_timestamp"] = timestamp
    return result


def _id(kind, value):
    return kind + ":" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def _role(text, pos):
    near = text[max(0, pos - 180):pos + 180]
    for role, pattern in ROLES:
        if re.search(pattern, near, re.I):
            return role
    return "external_service"


def _dependency_graph(files, path_times, observed, repo_key, scope):
    nodes, edges, evidence, by_component = {}, [], [], {}
    repo_id = _id("repository", repo_key)
    repo_scope = classify(scope, "repository", repo_key)
    nodes[repo_id] = {"id": repo_id, "kind": "repository", "label": repo_key,
                      "scope": repo_scope["classification"]}
    for row in files:
        path, text = row["path"], row["text"]
        component = _component(path, text)
        if component != "repository":
            by_component.setdefault(component, []).append(row)
            cid = _id("component", path)
            nodes[cid] = {"id": cid, "kind": "component", "label": path,
                          "component": component, "scope": "IN_SCOPE"}
        for match in URL_RE.finditer(text):
            url = safe_url(match.group(0))
            if not url:
                continue
            decision, role = classify(scope, "url", url), _role(text, match.start())
            nid = _id("service", url)
            nodes[nid] = {"id": nid, "kind": "service_or_endpoint", "label": url,
                          "host": urlsplit(url).hostname, "scope": decision["classification"]}
            source = _evidence(path, text, match.start(), match.end(), path_times.get(path))
            edges.append({"from": repo_id, "to": nid, "kind": "references", "role": role,
                          "trust_boundary": "repository to external endpoint", "observed_at": observed,
                          "confidence": "medium" if role != "external_service" else "low",
                          "source": source, "scope": decision, "interaction": "none"})
            evidence.append({"kind": "url_reference", "role": role, "scope": decision, "source": source})
        for match in ADDRESS_RE.finditer(text):
            nearby = text[max(0, match.start() - 250):match.end() + 250]
            if not re.search(r"(?i)(address|contract|proxy|implementation|deploy)", path + nearby):
                continue
            chain = re.search(r"(?i)(?:chainid|chain_id|chain-id)\s*[:=]\s*[\"']?(\d+)", nearby)
            chain_id = chain.group(1) if chain else None
            decision = classify(scope, "contract", match.group(0), network=chain_id, chain_id=chain_id)
            nid = _id("contract", match.group(0).lower() + ":" + str(chain_id))
            nodes[nid] = {"id": nid, "kind": "contract", "label": match.group(0),
                          "chain_id": chain_id, "scope": decision["classification"]}
            source = _evidence(path, text, match.start(), match.end(), path_times.get(path))
            edges.append({"from": repo_id, "to": nid, "kind": "references",
                          "role": "contract_or_deployment_reference",
                          "trust_boundary": "repository to deployed-system identifier",
                          "observed_at": observed, "confidence": "low", "source": source,
                          "scope": decision, "interaction": "none; no chain query"})
            evidence.append({"kind": "contract_reference", "scope": decision, "source": source})
        if Path(path).name.lower() in ("package.json", "cargo.toml", "go.mod", "requirements.txt",
                                       "pyproject.toml", "foundry.toml", "docker-compose.yml",
                                       "compose.yml"):
            for role, pattern in ROLES:
                for match in re.finditer(pattern, text, re.I):
                    source = _evidence(path, text, match.start(), match.end(), path_times.get(path))
                    label = match.group(0).lower()
                    nid = _id("integration", role + ":" + label)
                    nodes[nid] = {"id": nid, "kind": "integration", "label": label, "scope": "UNKNOWN"}
                    edges.append({"from": repo_id, "to": nid, "kind": "declares_or_mentions",
                                  "role": role, "trust_boundary": "repository to external dependency",
                                  "observed_at": observed, "confidence": "low", "source": source,
                                  "scope": {"classification": "UNKNOWN",
                                            "basis": "dependency name is not an authorized endpoint",
                                            "value": label}, "interaction": "none"})
                    evidence.append({"kind": "integration_term", "role": role,
                                     "scope": {"classification": "UNKNOWN"}, "source": source})
    pairs = (("frontend", "backend"), ("frontend", "contract"), ("backend", "contract"),
             ("relayer", "contract"), ("indexer", "backend"), ("oracle", "contract"),
             ("signer", "relayer"))
    for left, right in pairs:
        if left in by_component and right in by_component:
            a, b = by_component[left][0], by_component[right][0]
            edges.append({"from": _id("component", a["path"]), "to": _id("component", b["path"]),
                          "kind": "candidate_data_flow", "role": left + "_to_" + right,
                          "trust_boundary": left + " to " + right, "observed_at": observed,
                          "confidence": "low", "source": {"paths": [a["path"], b["path"]],
                          "basis": "component path labels only"},
                          "scope": {"classification": "IN_SCOPE", "basis": "local repository components"},
                          "interaction": "inferred; runtime flow unverified"})
    entity_patterns = {
        "asset": (re.compile(r"(?i)\b(token|vault|treasury|collateral|shares|balance|funds?)\b"),
                  "references_asset"),
        "identity": (re.compile(r"(?i)\b(owner|admin|guardian|signer|keeper|relayer)\b"),
                     "names_identity_or_actor"),
        "permission": (re.compile(r"(?i)\b(onlyOwner|onlyRole|hasRole|AccessControl|adminRole|"
                                  r"upgradeRole|pauserRole)\b"), "checks_or_grants_permission"),
        "signed_message": (re.compile(r"(?i)\b(EIP712|signTypedData|signature|permit|ecrecover)\b"),
                           "signs_or_validates_message"),
    }
    for row in files:
        parent_id = _id("component", row["path"]) if _component(
            row["path"], row["text"]) != "repository" else repo_id
        for kind, (pattern, relation) in entity_patterns.items():
            count = 0
            for match in pattern.finditer(row["text"]):
                label = match.group(0)
                nid = _id(kind, label.lower())
                nodes[nid] = {"id": nid, "kind": kind, "label": label,
                              "scope": "UNKNOWN"}
                edges.append({"from": parent_id, "to": nid, "kind": relation,
                              "role": kind, "trust_boundary": "source-code reference to " + kind,
                              "observed_at": observed, "confidence": "low",
                              "source": _evidence(row["path"], row["text"], match.start(),
                                                  match.end(), path_times.get(row["path"])),
                              "scope": {"classification": "UNKNOWN",
                                        "basis": "lexical entity; no separate scope rule",
                                        "value": label},
                              "interaction": "none; lexical reference"})
                count += 1
                if count >= 5:
                    break
    return nodes, edges, evidence


def _history(root, files, path_times, scope):
    head = git(root, "rev-parse", "HEAD", check=False).strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", head):
        raise ValueError("repository has no resolvable HEAD commit")
    dirty = bool(git(root, "status", "--porcelain", check=False).strip())
    log = git(root, "log", "--all", "--format=%H%x09%ct%x09%s", "-n", str(MAX_COMMITS),
              check=False)
    commits, candidate = [], []
    for line in log.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3 or not re.fullmatch(r"[0-9a-fA-F]{40,64}", parts[0]):
            continue
        commit, stamp, subject = parts
        row = {"commit": commit,
               "timestamp": datetime.fromtimestamp(int(stamp), timezone.utc).replace(
                   microsecond=0).isoformat().replace("+00:00", "Z"),
               "subject": redact_text(subject)[:180],
               "paths": sorted({p.strip() for p in git(
                   root, "show", "--format=", "--name-only", commit, check=False).splitlines()
                                if p.strip()})[:80]}
        row["pull_request_refs"] = sorted(set(re.findall(r"(?i)(?:#|pull/)(\d{1,8})\b",
                                                         row["subject"])))
        commits.append(row)
        if SECURITY_COMMIT.search(subject):
            candidate.append(row)
    tags = [redact_text(x)[:100] for x in git(
        root, "tag", "--list", "--sort=-creatordate", check=False).splitlines()[:100]]
    tag_map = {}
    for tag in tags:
        target = git(root, "rev-list", "-n", "1", tag, check=False).strip()
        if target:
            tag_map.setdefault(target, []).append(tag)
    for row in commits:
        if row["commit"] in tag_map:
            row["tags"] = tag_map[row["commit"]]
    patch_leads = []
    for row in candidate[:40]:
        parent = git(root, "rev-parse", row["commit"] + "^", check=False).strip()
        if not re.fullmatch(r"[0-9a-fA-F]{40,64}", parent):
            continue
        changes = []
        for path in row["paths"][:30]:
            diff = git(root, "diff", "--no-ext-diff", "--no-textconv", "--unified=0",
                       parent, row["commit"], "--", path, check=False)
            added = "\n".join(x[1:] for x in diff.splitlines() if x.startswith("+") and not x.startswith("+++"))
            removed = "\n".join(x[1:] for x in diff.splitlines() if x.startswith("-") and not x.startswith("---"))
            plus = [name for name, terms in INVARIANTS.items()
                    if any(term.lower() in added.lower() for term in terms)]
            minus = [name for name, terms in INVARIANTS.items()
                     if any(term.lower() in removed.lower() for term in terms)]
            removed_urls = sorted({safe_url(match.group(0)) for match in URL_RE.finditer(removed)
                                   if safe_url(match.group(0))})
            if plus or minus or removed_urls:
                changes.append({"path": path, "invariants_added": plus,
                                "invariants_removed": minus, "removed_urls": removed_urls,
                                "diff_summary_only": True})
        if changes:
            patch_leads.append({"commit": row["commit"], "timestamp": row["timestamp"],
                                "subject": row["subject"], "changes": changes,
                                "status": "historical_patch_lead",
                                "notice": "Token changes do not prove a complete security patch."})
    migrations = sorted(p for p in files if re.search(
        r"(?i)(migration|deploy|upgrade|proxy|initializer)", p))
    addresses = []
    for path, text in files.items():
        if re.search(r"(?i)(deploy|migration|address|proxy|contract)", path):
            for match in ADDRESS_RE.finditer(text):
                addresses.append({"address": match.group(0),
                                  "source": _evidence(path, text, match.start(), match.end(),
                                                      path_times.get(path))})
    leads = []
    current_hosts = {urlsplit(safe_url(match.group(0))).hostname
                     for text in files.values() for match in URL_RE.finditer(text)
                     if safe_url(match.group(0))}
    for patch in patch_leads:
        for change in patch["changes"]:
            source = {"commit": patch["commit"], "timestamp": patch["timestamp"],
                      "subject": patch["subject"], "path": change["path"]}
            removed = set(change["invariants_removed"])
            added = set(change["invariants_added"])
            if "auth_or_roles" in removed or "allowance" in removed:
                leads.append({
                    "type": "stale_authorization_candidate", "status": "hypothesis",
                    "source": source, "removed_invariants": sorted(removed),
                    "supporting_evidence": ["historical patch removed an authorization/allowance token"],
                    "disconfirming_evidence": [
                        "The token may have moved to an equivalent guard or the old path may have been retired.",
                        "Live roles, allowances, callers, and deployed revision were not checked.",
                    ],
                })
            if "nonce_or_replay" in removed or "signature_domain" in removed:
                leads.append({
                    "type": "historical_replay_window_candidate", "status": "hypothesis",
                    "source": source, "removed_invariants": sorted(removed),
                    "supporting_evidence": ["historical patch removed a signature/replay-related token"],
                    "disconfirming_evidence": [
                        "The token may have moved to another verifier or the path may no longer be active.",
                        "No message was replayed and no live deployment was inspected.",
                    ],
                })
            for url in change.get("removed_urls", []):
                host = urlsplit(url).hostname
                if host and host not in current_hosts:
                    decision = classify(scope, "url", url)
                    leads.append({
                        "type": "ghost_integration_candidate", "status": "hypothesis",
                        "source": source, "historical_endpoint": url, "scope": decision,
                        "supporting_evidence": ["historical diff removed this URL; no current tracked URL uses its host"],
                        "disconfirming_evidence": [
                            "Removal may be intentional; runtime configuration or a replacement endpoint may be external.",
                            "No remote service or deployment configuration was queried.",
                        ],
                    })
    for row in candidate[:30]:
        if any(re.search(r"(?i)(migration|upgrade|proxy)", p) for p in row["paths"]):
            leads.append({
                "type": "incomplete_migration_candidate", "status": "hypothesis",
                "source": {"commit": row["commit"], "timestamp": row["timestamp"],
                           "subject": row["subject"], "paths": row["paths"][:20]},
                "supporting_evidence": ["local commit changes a migration/upgrade/proxy path"],
                "disconfirming_evidence": [
                    "No deployment sequence, proxy state, or live storage was queried.",
                    "The migration may already be complete or intentionally superseded.",
                ],
            })
    return {"head_commit": head, "working_tree_dirty": dirty,
            "commit_count_read": len(commits), "commits": commits[:200], "tags": tags,
            "pull_request_refs_are_local_commit_text_only": True,
            "patch_variant_leads": patch_leads, "migration_deployment_paths": migrations,
        "historical_contract_references": addresses[:500], "historical_leads": leads,
            "source_timestamps": path_times,
            "notice": "Local Git refs/objects only. PR bodies, advisories, public archives and historical "
                      "on-chain proxies, admins, allowances, roles or events are not queried."}


def _patch_variant_analysis(patches, files):
    """Compare security-shaped patch invariants with lexical sibling execution paths."""
    triggers = {
        "signature_domain": re.compile(r"(?i)(ecrecover|signature|signTypedData|typed.?data|permit)"),
        "chain_binding": re.compile(r"(?i)(ecrecover|signature|signTypedData|typed.?data|permit)"),
        "contract_binding": re.compile(r"(?i)(ecrecover|signature|signTypedData|typed.?data|permit)"),
        "nonce_or_replay": re.compile(r"(?i)(ecrecover|signature|signTypedData|typed.?data|permit|order)"),
        "auth_or_roles": re.compile(r"(?i)(upgrade|admin|owner|role|authorize|grant)"),
        "allowance": re.compile(r"(?i)(approve|allowance|transferFrom|permit)"),
        "finality": re.compile(r"(?i)(bridge|relay|message|finaliz|confirm)"),
    }
    function_re = re.compile(
        r"(?m)^\s*(?:(?:export|public|private|async|pub|unsafe)\s+)*"
        r"(?:function|fn|def|func)\s+([A-Za-z_]\w*)[^\n]*")
    candidates, checked = [], 0
    for patch in patches:
        added = {name for change in patch["changes"] for name in change["invariants_added"]}
        patch_paths = {change["path"] for change in patch["changes"]}
        for family in sorted(added):
            trigger = triggers.get(family)
            if not trigger:
                continue
            markers = INVARIANTS.get(family, ())
            for path, body in files.items():
                if Path(path).suffix.lower() not in {
                        ".sol", ".vy", ".rs", ".move", ".cairo", ".go", ".ts",
                        ".tsx", ".js", ".py"}:
                    continue
                if not trigger.search(body):
                    continue
                matches = list(function_re.finditer(body))
                if not matches:
                    matches = [None]
                for index, match in enumerate(matches):
                    start = match.start() if match else 0
                    end = matches[index + 1].start() if match and index + 1 < len(matches) and matches[index + 1] else min(
                        len(body), start + 8000)
                    chunk = body[start:end]
                    if not trigger.search(chunk):
                        continue
                    checked += 1
                    if any(marker.lower() in chunk.lower() for marker in markers):
                        continue
                    if match:
                        ev = _evidence(path, body, match.start(), match.end())
                        function_name = match.group(1)
                    else:
                        ev = {"path": path, "line": 1, "excerpt": redact_text(body[:160])}
                        function_name = "unresolved"
                    candidates.append({
                        "patch_commit": patch["commit"], "patch_subject": patch["subject"],
                        "invariant": family, "current_path": path,
                        "function": function_name,
                        "relation": "same_path" if path in patch_paths else "alternate_path_or_version",
                        "supporting_evidence": [ev],
                        "disconfirming_evidence": [
                            "This is a lexical candidate; the patch may be path-specific or a shared library may enforce the property.",
                            "No deployment, inheritance, generated code, or runtime call path was resolved.",
                        ],
                        "status": "hypothesis", "confidence": "low",
                    })
                    if len(candidates) >= 200:
                        break
                if len(candidates) >= 200:
                    break
            if len(candidates) >= 200:
                break
    return {
        "patches_reviewed": len(patches), "function_or_file_chunks_checked": checked,
        "candidates": candidates,
        "notice": "Patch-token propagation review is lexical. It does not prove a fix was correct, incomplete, or exploitable.",
    }


def _trust(files, repo_scope, known):
    inventory = {}
    signal_evidence = []
    for path, text in files.items():
        component = _component(path, text)
        row = inventory.setdefault(component, {"component": component, "files": [], "signals": {}})
        row["files"].append(path)
        for family, variants in INVARIANTS.items():
            found = [term for term in variants if re.search(re.escape(term), text, re.I)]
            if found:
                row["signals"].setdefault(family, []).extend(found[:8])
                term = found[0]
                match = re.search(re.escape(term), text, re.I)
                signal_evidence.append({"invariant": family, "term": term,
                                        "source": _evidence(path, text, match.start(), match.end())})
    present = set(inventory)
    boundaries = []
    for left, right in (("frontend", "backend"), ("frontend", "contract"),
                        ("backend", "contract"), ("relayer", "contract"),
                        ("indexer", "backend"), ("oracle", "contract"), ("signer", "relayer")):
        if left in present and right in present:
            boundaries.append({"from_component": left, "to_component": right,
                               "kind": "candidate_data_or_authority_boundary",
                               "source_paths": [inventory[left]["files"][0], inventory[right]["files"][0]],
                               "confidence": "low",
                               "notice": "Path/text heuristic; actual runtime flow is unverified."})
    hypotheses = []
    signature_files = [(path, body) for path, body in files.items()
                       if re.search(r"(?i)\b(ecrecover|signature|signTypedData|verifyTypedData|personal_sign|permit|typed.?data)\b", body)]
    for path, signature_text in signature_files:
        checks = {
            "domain separation": bool(re.search(r"(?i)(DOMAIN_SEPARATOR|EIP712Domain|domainSeparator)", signature_text)),
            "chain binding": bool(re.search(r"(?i)(chainId|chain_id|chainid)", signature_text)),
            "contract binding": bool(re.search(r"(?i)(verifyingContract|verifying_contract|address\(this\))", signature_text)),
            "nonce/replay control": bool(re.search(r"(?i)(nonce|usedDigest|consumed)", signature_text)),
        }
        missing = [name for name, found in checks.items() if not found]
        if missing:
            hypotheses.append(_hypothesis(
                "Verify signed-message domain and replay controls in " + path,
                "signed_message_replay_or_cross_domain",
                ["A public or low-privilege path accepts a signed message.",
                 "Equivalent checks are not supplied by an imported library or caller."],
                ["A captured signature or attacker-chosen fields, only if the acceptance path permits it."],
                "Authorization is bound to the intended chain, verifier, and one-time/order lifecycle.",
                "Possible unauthorized state transition or asset action; loss is unmeasured.",
                "Unknown: signature terms exist in " + path + "; runtime reachability is not established.",
                [x for x in signal_evidence if x["invariant"] in
                 ("signature_domain", "chain_binding", "contract_binding", "nonce_or_replay")
                 and x["source"]["path"] == path][:12]
                 or [{"signal": "signature term found in " + path}],
                ["An imported/generated verifier may supply missing properties.",
                 "No signature was submitted and no state transition was executed."],
                missing, repo_scope, known))
    bridge_files = [(path, body) for path, body in files.items()
                    if _component(path, body) in ("relayer", "contract", "backend")
                    and re.search(r"(?i)\b(bridge|relayer|relay|messenger|wormhole|layerzero|hyperlane|axelar|ccip|ibc)\b", body)]
    for path, bridge_text in bridge_files:
        checks = {
            "source-chain binding": bool(re.search(r"(?i)(sourceChain|srcChain|source_chain|originChain)", bridge_text)),
            "message replay tracking": bool(re.search(r"(?i)(nonce|messageId|message_id|consumed|processed)", bridge_text)),
            "finality/verifier proof": bool(re.search(r"(?i)(finality|finalized|confirmations|proof|quorum|validator)", bridge_text)),
        }
        missing = [name for name, found in checks.items() if not found]
        if missing:
            hypotheses.append(_hypothesis(
                "Compare cross-chain origin, replay, and finality checks in " + path,
                "cross_chain_trust_boundary",
                ["A message-delivery path exists between source and destination.",
                 "Affected deployment/network is in the explicit program scope."],
                ["Only message fields or delivery timing a public caller/relayer can influence."],
                "Destination authenticates source domain, unique message identity, and required finality.",
                "Possible unauthorized destination transition; asset impact is unmeasured.",
                "Unknown: bridge terms exist in " + path + "; endpoint and verifier wiring are unproven.",
                [x for x in signal_evidence if x["invariant"] in
                 ("chain_binding", "nonce_or_replay", "finality")
                 and x["source"]["path"] == path][:12]
                 or [{"signal": "bridge/relayer term found in " + path}],
                ["A third-party verifier may enforce properties outside this checkout.",
                 "No cross-chain message was submitted or replayed."],
                missing, repo_scope, known))
    webhook_files = [(path, body) for path, body in files.items()
                     if _component(path, body) == "backend" and
                     re.search(r"(?i)\bwebhook\b", body)]
    for path, webhook_text in webhook_files:
        checks = {
            "request authentication": bool(re.search(r"(?i)(hmac|webhook.?signature|verifySignature|signatureHeader)", webhook_text)),
            "freshness/replay defense": bool(re.search(r"(?i)(timestamp|idempotency|event_id|replay|dedup)", webhook_text)),
        }
        missing = [name for name, found in checks.items() if not found]
        if missing:
            hypotheses.append(_hypothesis(
                "Check webhook authentication and duplicate-event handling in " + path,
                "webhook_auth_or_replay",
                ["An in-scope externally reachable handler processes the event.",
                 "Provider guarantees are not enforced by middleware or gateway."],
                ["Request body and delivery timing only if the endpoint is public and unauthenticated."],
                "Events are authenticated, fresh, and applied at most once where required.",
                "Possible unauthorized or repeated business transition; loss is unmeasured.",
                "Unknown: webhook term exists in " + path + "; handler exposure and middleware are unverified.",
                [{"signal": "webhook term found in " + path}],
                ["Gateway middleware may enforce authentication outside this checkout.",
                 "No HTTP request was sent and no account was used."],
                missing, repo_scope, known))
    sequence_candidates = []
    states = re.compile(r"(?i)\b(pending|signed|submitted|validated|confirmed|finalized|"
                        r"settled|cancelled|canceled|filled|executed|refunded|processed)\b")
    for path, body in files.items():
        found = []
        for match in states.finditer(body):
            state = match.group(0).lower()
            if not found or found[-1]["state"] != state:
                found.append({"state": state, "line": body.count("\n", 0, match.start()) + 1})
        if len(found) >= 2:
            sequence_candidates.append({
                "path": path, "states_in_source_order": found[:20],
                "candidate_transitions": [{"from": left["state"], "to": right["state"],
                                           "lines": [left["line"], right["line"]]}
                                          for left, right in zip(found, found[1:20])],
                "confidence": "low", "status": "unverified_ordering_candidate",
                "notice": "Textual order is not a runtime state transition or an execution sequence.",
            })
    return {"components": list(inventory.values()), "candidate_boundaries": boundaries,
            "invariant_signals": signal_evidence[:300],
            "sequence_candidates": sequence_candidates[:100],
            "hypotheses": hypotheses[:20],
            "notice": "Lexical analysis only; no flow, reachability, attacker control, exploit, or impact is confirmed."}


def _hypothesis(title, bug_class, prereq, attacker, invariant, impact, path, support,
                against, missing, scope, known):
    privileged_prerequisites = [item for item in prereq + attacker if re.search(
        r"(?i)(?:requires?|assumes?|depends on).{0,50}(?:admin|administrator|owner|privileged|"
        r"compromis.{0,24}(?:provider|service|signer)|third.party)", item)]
    if privileged_prerequisites:
        against = list(against) + [
            "A privileged or third-party compromise is not an acceptable attacker path without a separate in-scope vector."
        ]
        missing = list(missing) + [
            "Establish a separate in-scope, low-privilege attacker path for any privileged prerequisite."
        ]
    terms = set(re.findall(r"[a-z0-9_]{4,}", (title + " " + bug_class).lower()))
    corpus = set(re.findall(r"[a-z0-9_]{4,}", known.lower()))
    novelty = (max(0.0, 1.0 - len(terms & corpus) / max(1, len(terms)))
               if known else 0.5)
    novelty_basis = ("lexical overlap against supplied known-issue corpus; manual check required"
                     if known else "neutral, unmeasured; no known-issue corpus supplied")
    state = scope.get("classification", "UNKNOWN")
    scope_score = {"IN_SCOPE": 1.0, "RELATED_OUT_OF_SCOPE": 0.0, "UNKNOWN": 0.25}.get(state, 0.25)
    exploit = 0.15 if path.lower().startswith("unknown") else 0.25
    impact_score = 0.35 if re.search(r"(?i)(asset|fund|token|balance|withdraw|payment)", impact) else 0.15
    proof = min(0.25, 0.05 + 0.025 * min(len(support), 8))
    assumptions = len(prereq) + len(missing)
    priority = round(0.18 * novelty + 0.25 * scope_score + 0.18 * exploit +
                     0.18 * impact_score + 0.21 * proof - min(0.12, assumptions * 0.005), 4)
    return {
        "id": "ECO-" + hashlib.sha256((bug_class + title).encode()).hexdigest()[:10].upper(),
        "title": title, "bug_class": bug_class, "status": "hypothesis",
        "review_status": "NOT_INDEPENDENTLY_REVIEWED", "prerequisites": prereq,
        "attacker_control": attacker,
        "attacker_privileges_assumed": "unprivileged, unless a prerequisite explicitly says otherwise",
        "privileged_prerequisites": privileged_prerequisites,
        "privileged_assumption_count": len(privileged_prerequisites), "assumption_count": assumptions,
        "invariant": invariant, "possible_impact": impact, "reachable_path": path,
        "supporting_evidence": support, "disconfirming_evidence": against,
        "missing_checks": missing, "scope": scope,
        "scores": {
            "novelty": {"value": round(novelty, 3), "basis": novelty_basis},
            "scope_confidence": {"value": round(scope_score, 3), "basis": state},
            "exploitability": {"value": exploit, "basis": "lexical only; reachability unverified"},
            "impact": {"value": impact_score, "basis": "asset-word heuristic; no loss measured"},
            "proof_strength": {"value": proof, "basis": "local static/history only; capped below reproduction"},
            "priority": priority,
        },
        "notice": "Hypothesis only; not a vulnerability finding or payout prediction.",
    }


def _verification_plan(hypothesis, commit):
    kind = hypothesis["bug_class"]
    if kind == "signed_message_replay_or_cross_domain":
        backend = "Foundry/Anvil local fork pinned to a reviewed block, or a fully local EVM test"
        candidate = "Submit one valid signed payload, then replay it or change one domain field; record each state and balance delta."
        control = "Submit a fresh valid payload once, then replay it; compare against documented nonce/domain behavior."
        assertions = ["Record unauthorized state transitions and token/native balance deltas.",
                      "Compare the same verifier path against a fresh-nonce/domain negative control."]
    elif kind == "cross_chain_trust_boundary":
        backend = "Foundry/Anvil local fork with local verifier mock, or a fully local EVM test"
        candidate = "Deliver a duplicate message or mismatched source identity through the local harness."
        control = "Deliver one valid, unique message with the expected source and verifier proof."
        assertions = ["Record accepted/rejected transitions, replay state, and asset balance deltas.",
                      "Do not use a public exploit transaction or live bridge/relayer."]
    else:
        backend = "Local API test with mock provider, mock service, and investigator-owned test data"
        candidate = "Send an invalidly authenticated webhook and repeated event to the local mock handler."
        control = "Send one valid mock-provider event, then repeat it and compare state changes."
        assertions = ["Record response status, persisted state, idempotency, and test-account balance delta.",
                      "Do not validate credentials or contact a live provider."]
    return {
        "hypothesis_id": hypothesis["id"], "backend": backend,
        "candidate_case": candidate, "negative_control": control,
        "assertions": assertions, "execution_status": "NOT_EXECUTED",
        "network_enabled": False, "target_side_effects_performed": False,
        "requires_separate_confirmation_for_any_target_side_effect": True,
        "provenance_required": {"commit": commit, "chain_id": "required for EVM fork",
                                "block_number": "required for EVM fork",
                                "test_command": "record exact argv and exit code",
                                "logs": "preserve candidate and control output"},
        "notice": "Plan only. It is not a PoC, test result, or impact proof.",
    }


def _skeptical_review_plan(hypothesis):
    return {
        "hypothesis_id": hypothesis["id"],
        "review_status": "NOT_INDEPENDENTLY_REVIEWED",
        "allowed_verdicts": ["CONFIRMED", "NEEDS_EVIDENCE", "REJECTED"],
        "reviewer_must_check": [
            "Trace a low-privilege attacker path from a public entry point; reject admin or third-party compromise as an unsupported prerequisite.",
            "Separate code defects from deployment, feature-flag, middleware, and configuration assumptions.",
            "Quantify reproducible effects on other users or protocol assets; distinguish self-harm and theoretical impact.",
            "Re-check explicit program scope and historical/public/private duplicate evidence.",
            "Try to disprove the claim with guards, libraries, alternate paths, lifecycle rules, and deployment evidence.",
        ],
        "required_record_fields": [
            "attacker_reachable_path", "configuration_assumptions", "impact_evidence",
            "scope_decision", "duplicate_search", "disconfirming_evidence", "verdict",
        ],
        "independence_requirement": "Run as a separate reviewer pass. This module does not manufacture or attest reviewer identity.",
    }


def _archives(index_path, scope):
    if not index_path:
        return [], []
    raw = json.loads(Path(index_path).read_text(encoding="utf-8"))
    entries = raw.get("captures", []) if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ValueError("archive index must be an array or an object with captures[]")
    _require_method(scope, "provided_archive")
    base, accepted, skipped = Path(index_path).resolve().parent, [], []
    for row in entries[:500]:
        if not isinstance(row, dict) or not row.get("url") or not row.get("path"):
            skipped.append({"reason": "entry requires url and local path"})
            continue
        decision = classify(scope, "url", row["url"])
        if decision["classification"] != "IN_SCOPE":
            skipped.append({"url": safe_url(row["url"]), "scope": decision,
                            "reason": "archive URL is not explicitly in scope"})
            continue
        path = (base / str(row["path"])).resolve()
        try:
            path.relative_to(base)
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
                raise ValueError()
            body = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            skipped.append({"url": safe_url(row["url"]), "reason": "unsafe/unreadable archive path"})
            continue
        accepted.append({"url": safe_url(row["url"]),
                         "captured_at": redact_text(str(row.get("captured_at", "")))[:80],
                         "kind": redact_text(str(row.get("kind", "document")))[:80],
                         "local_path": redact_text(str(path.relative_to(base))),
                         "sha256": hashlib.sha256(body.encode()).hexdigest()})
    return accepted, skipped


def _markdown(report):
    lines = [
        "# Ecosystem Intelligence report", "",
        "> Passive local analysis only. Hypotheses are unverified leads, not findings.", "",
        "## Run provenance", "", "- Project: " + report["scope"]["project"],
        "- Commit: " + report["analysis"]["provenance"]["head_commit"],
        "- Working tree dirty: " + str(report["analysis"]["provenance"]["working_tree_dirty"]).lower(),
        "- Files read: " + str(report["analysis"]["provenance"]["files_read"]),
        "- Network requests: 0",
        "- Repository scope: " + report["scope"]["repository_decision"]["classification"],
        "", "## Dependency inventory", "", "| Role | Target | Scope | Evidence |",
        "|---|---|---|---|",
    ]
    by_id = {x["id"]: x for x in report["dependency_intelligence"]["nodes"]}
    for edge in report["dependency_intelligence"]["edges"][:200]:
        target = by_id.get(edge["to"], {}).get("label", edge["to"]).replace("|", "\\|")
        source = edge["source"]
        path = source.get("path", ", ".join(source.get("paths", [])))
        lines.append("| %s | %s | %s | %s:%s |" %
                     (edge["role"], target, edge["scope"]["classification"], path, source.get("line", "")))
    if not report["dependency_intelligence"]["edges"]:
        lines.append("| — | no external references observed | — | — |")
    lines.extend(["", "## Candidate trust boundaries", ""])
    for edge in report["trust_boundary_analysis"]["candidate_boundaries"]:
        lines.append("- %s → %s: %s (low-confidence path heuristic)" %
                     (edge["from_component"], edge["to_component"], edge["kind"]))
    if not report["trust_boundary_analysis"]["candidate_boundaries"]:
        lines.append("- No multi-component boundary was identified by path heuristics.")
    lines.extend(["", "## Ranked hypotheses", ""])
    hypotheses = report["ranking"]["top_hypotheses"]
    if not hypotheses:
        lines.append("No hypotheses were generated from the current lexical indicators.")
    for row in hypotheses:
        scores = row["scores"]
        lines.extend([
            "### %s. %s" % (row["rank"], row["title"]), "",
            "- Status: %s; review: %s." % (row["status"], row["review_status"]),
            "- Privilege assumption: %s; reachability: %s." %
            (row["attacker_privileges_assumed"], row["reachable_path"]),
            "- Invariant: %s" % row["invariant"], "- Possible impact: %s" % row["possible_impact"],
            "- Scope: %s (confidence %.3f)." % (row["scope"]["classification"],
                                                scores["scope_confidence"]["value"]),
            "- Scores: novelty %.3f; exploitability %.3f; impact %.3f; proof %.3f; priority %.4f." %
            (scores["novelty"]["value"], scores["exploitability"]["value"], scores["impact"]["value"],
             scores["proof_strength"]["value"], scores["priority"]),
            "- Prerequisites: " + "; ".join(row["prerequisites"]),
            "- Disconfirming evidence: " + "; ".join(row["disconfirming_evidence"]), "",
        ])
    lines.extend(["## Local verification plans", "",
                  "These are unexecuted plans; they are not PoCs or impact evidence."])
    for plan in report["safe_verification_plans"]:
        lines.extend(["", "- %s: **%s**. Network enabled: %s; target side effects: %s." %
                      (plan["hypothesis_id"], plan["execution_status"],
                       str(plan["network_enabled"]).lower(),
                       str(plan["target_side_effects_performed"]).lower())])
    lines.extend(["", "## Skeptical review status", "",
                  "Independent review is not performed by this module. Each checklist is a handoff plan."])
    for review in report["independent_review_plans"]:
        lines.append("- %s: %s; verdict options: %s." %
                     (review["hypothesis_id"], review["review_status"],
                      ", ".join(review["allowed_verdicts"])))
    hist = report["historical_intelligence"]
    lines.extend(["## Historical review limits", "",
                  "- Local commits: %s; tags: %s; patch leads: %s." %
                  (hist["commit_count_read"], len(hist["tags"]), len(hist["patch_variant_leads"])),
                  "- Patch-variant lexical candidates: %s." %
                  len(hist["patch_variant_analysis"]["candidates"]),
                  "- " + hist["notice"], "", "## Evidence limits", "",
                  "- Lexical leads are not a call graph, exploit proof, deployment check, or payout prediction.",
                  "- No benchmark was run; no recall or false-positive rate is claimed."])
    return "\n".join(lines) + "\n"


def _mermaid(nodes, edges):
    lines = ["flowchart LR"]
    for node in nodes:
        label = str(node.get("label", node["id"])).replace('"', "'").replace("\n", " ")[:100]
        lines.append('  "%s"["%s<br/>%s"]' % (node["id"], label, node.get("kind", "entity")))
    for edge in edges:
        label = (edge.get("role", "edge") + " / " +
                 edge.get("scope", {}).get("classification", "UNKNOWN")).replace('"', "'")
        lines.append('  "%s" -->|"%s"| "%s"' % (edge["from"], label, edge["to"]))
    return "\n".join(lines) + "\n"


def analyze(repo, scope_path, out, archive_index=None, known_issues=None):
    root = Path(repo).resolve()
    if not root.is_dir():
        raise ValueError("repo must be an existing local directory")
    scope = load_scope(scope_path)
    output = Path(out).expanduser().resolve()
    try:
        output.relative_to(root)
    except ValueError:
        pass
    else:
        raise ValueError("output must be outside target checkout")
    if output.exists() and any(output.iterdir()):
        raise ValueError("output directory is not empty")
    output.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        os.chmod(output, 0o700)
    except OSError:
        pass
    started, audit_rows = now_utc(), []
    audit_path = output / "audit.jsonl"

    def audit(event, **fields):
        audit_rows.append({"timestamp": now_utc(), "event": event, **fields})
        audit_path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n"
                                      for row in audit_rows), encoding="utf-8")

    key = _repo_key(root)
    repo_scope = classify(scope, "repository", key)
    audit("analysis_started", target=key, methods=["local_static", "git_history"],
          network_requests=0, credential_validation=False)
    audit("scope_classified", kind="repository", classification=repo_scope["classification"],
          basis=repo_scope["basis"], value=repo_scope["value"])
    for method in ("local_static", "git_history"):
        decision = classify(scope, "method", method)
        audit("method_scope", method=method, classification=decision["classification"],
              basis=decision["basis"])
        _require_method(scope, method)
    if archive_index:
        decision = classify(scope, "method", "provided_archive")
        audit("method_scope", method="provided_archive",
              classification=decision["classification"], basis=decision["basis"])
        _require_method(scope, "provided_archive")
    files, skipped, stats = _safe_files(root)
    times = _path_times(root)
    nodes, edges, dep_evidence = _dependency_graph(files, times, started, key, scope)
    files_by_path = {row["path"]: row["text"] for row in files}
    history = _history(root, files_by_path, times, scope)
    patch_variants = _patch_variant_analysis(history["patch_variant_leads"], files_by_path)
    archives, archive_skipped = _archives(archive_index, scope) if archive_index else ([], [])
    if archive_index:
        audit("provided_archive_read", accepted=len(archives), skipped=len(archive_skipped),
              network_requests=0)
    known = ""
    if known_issues:
        path = Path(known_issues).resolve()
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("known-issues corpus must be a local file under the size cap")
        known = redact_text(path.read_text(encoding="utf-8", errors="replace"))
    trust = _trust(files_by_path, repo_scope, known)
    hypotheses = trust["hypotheses"]
    hypotheses.sort(key=lambda row: (row["privileged_assumption_count"],
                                     -row["scores"]["priority"], row["id"]))
    for index, row in enumerate(hypotheses, 1):
        row["rank"] = index
    report = {
        "schema_version": SCHEMA_VERSION,
        "analysis": {
            "project": scope["project"], "observed_at": started,
            "repository": {"key": key, "scope": repo_scope},
            "provenance": {"head_commit": history["head_commit"],
                           "working_tree_dirty": history["working_tree_dirty"],
                           "tracked_files_seen": stats["tracked_files_seen"],
                           "files_read": stats["files_read"], "bytes_read": stats["bytes_read"],
                           "file_listing": "git-tracked files only"},
            "methods": ["local_static", "git_history"] + (["provided_archive"] if archive_index else []),
            "network_policy": {"enabled": False, "requests": 0, "rate_limit_per_minute": 0,
                               "credential_validation": False, "live_state_reads": False,
                               "active_or_destructive_checks": False},
            "limitations": [
                "No network request, active probe, credential validation, transaction, target-code execution or live-chain read was performed.",
                "Only git-tracked files and local Git metadata were read; ignored/untracked files are outside this run.",
                "Lexical results do not establish deployment, runtime flow, reachability, exploitability, or impact.",
                "Public URLs are classified but never contacted; archives must be supplied locally and be in scope.",
            ],
        },
        "scope": {"schema_version": 1, "project": scope["project"],
                  "repository_decision": repo_scope, "allowed_methods": scope["allowed"]["methods"],
                  "rate_limits": {"outbound_requests_per_minute": 0, "file_count_cap": MAX_FILES,
                                  "file_bytes_cap": MAX_FILE_BYTES, "aggregate_bytes_cap": MAX_TOTAL_BYTES}},
        "dependency_intelligence": {"nodes": list(nodes.values()), "edges": edges,
                                    "evidence": dep_evidence, "file_stats": stats,
                                    "skipped": skipped,
                                    "notice": "Endpoints, addresses and manifest terms are candidates; nothing was contacted."},
        "historical_intelligence": {**history, "provided_archives": archives,
                                   "archive_skipped": archive_skipped,
                                   "patch_variant_analysis": patch_variants},
        "trust_boundary_analysis": trust,
        "ranking": {"top_hypotheses": hypotheses,
                    "formula": "weighted novelty, scope confidence, exploitability, impact and proof strength minus assumption penalty; privilege assumptions sort first",
                    "benchmark": "not measured; no verified paired corpus supplied"},
        "safe_verification_plans": [_verification_plan(row, history["head_commit"])
                                     for row in hypotheses],
        "independent_review_plans": [_skeptical_review_plan(row) for row in hypotheses],
    }
    audit("analysis_completed", hypotheses=len(hypotheses), nodes=len(nodes), edges=len(edges),
          network_requests=0, result="hypotheses_only")
    (output / "ecosystem-intelligence.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "ecosystem-report.md").write_text(_markdown(report), encoding="utf-8")
    (output / "dependency-graph.mmd").write_text(_mermaid(report["dependency_intelligence"]["nodes"],
                                                           edges), encoding="utf-8")
    try:
        for artifact in output.iterdir():
            if artifact.is_file():
                os.chmod(artifact, 0o600)
    except OSError:
        pass
    return {"result": "completed", "json": str(output / "ecosystem-intelligence.json"),
            "markdown": str(output / "ecosystem-report.md"),
            "graph": str(output / "dependency-graph.mmd"), "audit": str(output / "audit.jsonl"),
            "head": history["head_commit"], "scope": repo_scope["classification"],
            "files_read": stats["files_read"], "hypotheses": len(hypotheses), "network_requests": 0,
            "notice": "Research leads only; no vulnerability is confirmed."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="local target checkout")
    parser.add_argument("--scope", required=True, help="explicit scope JSON, schema version 1")
    parser.add_argument("--out", required=True, help="private output directory outside checkout")
    parser.add_argument("--archive-index", help="local index of previously saved in-scope public archives")
    parser.add_argument("--known-issues", help="local known-issue corpus for lexical novelty baseline")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(analyze(args.repo, args.scope, args.out, args.archive_index,
                                 args.known_issues), ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError,
            subprocess.SubprocessError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2
if __name__ == "__main__":
    sys.exit(main())
