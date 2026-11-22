#!/usr/bin/env python3
"""Fast Hunt: bounded source cue queue, shared anomaly ledger, explicit read-only HTTP probes.

This is not an autonomous vulnerability verdict, scanner, report-submitter or OS egress sandbox.
All target content is untrusted data. Real network I/O requires a reviewed exact-origin plan
and an explicit --execute flag. No credentials, cookies, redirects or writes are supported.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import urllib.parse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import web_program_policy as policy  # noqa: E402

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")
SOURCE_TYPES = {".sol", ".vy", ".rs", ".go", ".ts", ".tsx", ".js",
                ".py", ".java", ".kt", ".swift", ".move"}
MAX_SOURCE_BYTES = 200_000
MAX_INPUT_BYTES = 512_000
BLOCK_DIRS = {"vendor", "node_modules", ".git", "dist", "build", "target",
              "coverage", "generated", ".next", "__pycache__"}
RISK = re.compile(r"withdraw|transfer|refund|claim|mint|burn|settle|credit|"
                  r"balance|withdrawal|create.?order|invoice|authorization|"
                  r"role|owner|tenant|session|callback|approve|admin|"
                  r"delete|download|report|credential", re.I)
ENTRY = re.compile(r"\b(public|external|function|func|def|pub fn|router|"
                   r"@(?:Get|Post|Patch|Delete|Put)|app\.(?:get|post|put|delete)|"
                   r"express\.|handler|endpoint)\b", re.I)
EFFECT = re.compile(r"\b(transfer|withdraw|refund|mint|burn|settle|credit|"
                    r"approve|authorize|delete|update|execute|save|claim|"
                    r"create|distribute|send|write)\b|\.update\(|\.delete\(", re.I)
GUARD = re.compile(r"onlyOwner|require\(|hasRole|auth|access.?control|"
                   r"permission|tenant.?id|owner.?id|is.?signer|verify\(|"
                   r"validate\(|check.?role|assert\(", re.I)
KINDS = {"AUTHZ", "ACCOUNTING", "TRUST", "STATE", "OTHER"}


def read_json(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("regular non-symlink JSON input <=512KB required")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=policy._unique)


def write_new(path, result, repo=None):
    p = Path(path).expanduser()
    if p.is_symlink() or p.exists():
        raise ValueError("output exists or is symlink")
    if repo and (p.resolve() == repo.resolve() or repo.resolve() in p.resolve().parents):
        raise ValueError("private output must be outside target checkout")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(result, f, sort_keys=True, indent=2, ensure_ascii=False)
        f.write("\n")


def git(repo, *args):
    p = subprocess.run(["git", "-C", str(repo), *args], check=True,
                       text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.stdout.strip()


def _scope(value):
    if (not isinstance(value, str) or not value or len(value) > 160 or
            value.startswith("/") or "\\" in value or
            any(x in (".", "..", "") for x in value.strip("/").split("/"))):
        raise ValueError("scope must be a bounded relative source prefix")
    return value.strip("/")


def _source_paths(repo, scope):
    listing = git(repo, "ls-files", "-z").split("\0")
    result = []
    for name in listing:
        if not name or (name != scope and not name.startswith(scope + "/")):
            continue
        if any(part in BLOCK_DIRS for part in Path(name).parts):
            continue
        if Path(name).suffix.lower() not in SOURCE_TYPES:
            continue
        target = repo / name
        if target.is_symlink() or not target.is_file() or repo not in target.resolve().parents:
            continue
        if target.stat().st_size > MAX_SOURCE_BYTES:
            continue
        result.append(name)
    return sorted(result)


def _cue_kind(line):
    lower = line.lower()
    if any(x in lower for x in ("owner", "tenant", "role", "auth", "permission", "admin")):
        return "AUTHZ"
    if any(x in lower for x in ("balance", "fee", "refund", "claim", "settle", "credit", "transfer")):
        return "ACCOUNTING"
    if any(x in lower for x in ("callback", "token", "signature", "session", "credential")):
        return "TRUST"
    return "STATE"


def plan(repo_path, scope, max_files=80, max_leads=24, anomalies=None):
    repo = Path(repo_path).resolve()
    if not repo.is_dir() or not (repo / ".git").exists():
        raise ValueError("checked-out git repository required")
    scope = _scope(scope)
    revision = git(repo, "rev-parse", "HEAD")
    if not SHA40.fullmatch(revision):
        raise ValueError("40-hex pinned git revision required")
    files = _source_paths(repo, scope)
    if not files:
        raise ValueError("no tracked source files under requested scope")
    if type(max_files) is not int or not 1 <= max_files <= 400:
        raise ValueError("max_files out of range")
    if type(max_leads) is not int or not 1 <= max_leads <= 50:
        raise ValueError("max_leads out of range")
    candidates = []
    for name in files[:max_files]:
        raw = (repo / name).read_bytes()
        lines = raw.decode("utf-8", "replace").splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "#", "*", "/*")):
                continue
            if not RISK.search(line) or not (EFFECT.search(line) or ENTRY.search(line)):
                continue
            adjacent = "\n".join(lines[max(0, i-10):min(len(lines), i+11)])
            cue = _cue_kind(line)
            guard = bool(GUARD.search(adjacent))
            context = bool(ENTRY.search(adjacent))
            score = 4 + (2 if EFFECT.search(line) else 0) + (2 if context else 0)
            if not guard:
                score += 2
            if cue == "ACCOUNTING":
                score += 1
            # Source hash anchors the observation without copying arbitrary source/secret lines.
            anchor = hashlib.sha256((name + ":" + str(i+1) + ":" + line).encode()).hexdigest()
            candidates.append({"id": "FH-" + anchor[:12], "path": name, "line": i+1,
                               "kind": cue, "score": score,
                               "source_line_sha256": hashlib.sha256(line.encode()).hexdigest(),
                               "entry_cue_in_20_lines": context,
                               "guard_cue_in_20_lines": guard,
                               "classification": "UNVERIFIED_SOURCE_READING_LEAD"})
    candidates.sort(key=lambda x: (-x["score"], x["path"], x["line"]))
    seen = set()
    ranked = []
    for item in candidates:
        if item["id"] not in seen:
            ranked.append(item)
            seen.add(item["id"])
        if len(ranked) >= max_leads:
            break
    retained = []
    if anomalies:
        ledger = read_json(anomalies)
        if ledger.get("schema_version") != 1 or ledger.get("revision") != revision:
            raise ValueError("anomaly ledger must match source revision")
        retained = ledger.get("anomalies", [])
        if not isinstance(retained, list) or len(retained) > 250:
            raise ValueError("invalid anomaly ledger")
    return {"schema_version": 1, "mode": "fast-hunt-offline-source-queue",
            "revision": revision, "scope": scope, "tracked_source_files": len(files),
            "inspected_source_files": min(max_files, len(files)),
            "uninspected_source_files": max(len(files)-max_files, 0),
            "candidates": ranked, "shared_anomalies": retained,
            "recommended_next": ["review pinned lines and code paths",
                                 "merge weak leads into shared anomaly ledger",
                                 "test only owned/approved candidate-control fixtures"],
            "real_model_calls": 0, "network_requests": 0,
            "confirmed_vulnerabilities": 0, "ready_to_submit": False}


def merge_anomalies(revision, observations, previous=None):
    if not isinstance(revision, str) or not SHA40.fullmatch(revision):
        raise ValueError("pinned revision required")
    incoming = read_json(observations)
    if not isinstance(incoming, list) or len(incoming) > 100:
        raise ValueError("observations must be a list of <=100 entries")
    old = []
    if previous:
        ledger = read_json(previous)
        if ledger.get("schema_version") != 1 or ledger.get("revision") != revision:
            raise ValueError("different-revision anomaly ledger")
        old = ledger.get("anomalies")
        if not isinstance(old, list) or len(old) > 250:
            raise ValueError("invalid anomaly ledger")
    output = {}
    for row in old + incoming:
        if not isinstance(row, dict) or set(row).difference({"id"}) != {
                "path", "line", "kind", "note", "evidence_sha256", "observed_by"} or (
                "id" in row and not isinstance(row["id"], str)):
            raise ValueError("anomaly requires exact path/line/kind/note/evidence/observer")
        if (not isinstance(row["path"], str) or len(row["path"]) > 280 or
                not row["path"] or row["path"].startswith("/") or
                any(x in ("", ".", "..") for x in row["path"].split("/")) or
                "\\" in row["path"]):
            raise ValueError("invalid source path")
        if type(row["line"]) is not int or row["line"] < 1 or row["line"] > 10_000_000:
            raise ValueError("invalid line")
        if row["kind"] not in KINDS:
            raise ValueError("invalid kind")
        if not isinstance(row["note"], str) or not 10 <= len(row["note"]) <= 240:
            raise ValueError("bounded observation note required")
        if not isinstance(row["evidence_sha256"], str) or not SHA64.fullmatch(row["evidence_sha256"]):
            raise ValueError("evidence hash required")
        if not isinstance(row["observed_by"], str) or not ID.fullmatch(row["observed_by"]):
            raise ValueError("observer ID required")
        digest = hashlib.sha256((revision + row["path"] + str(row["line"]) +
                                 row["kind"] + row["evidence_sha256"]).encode()).hexdigest()
        clean = {k: v for k, v in row.items() if k != "id"}
        if "id" in row and row["id"] != "AN-" + digest[:16]:
            raise ValueError("stored anomaly ID does not match evidence")
        output["AN-" + digest[:16]] = clean
    if len(output) > 250:
        raise ValueError("too many shared anomalies")
    entries = [{"id": id_, **v} for id_, v in sorted(output.items())]
    # Adjacent notes from different lenses stay visible even when neither lens finds a PoC.
    cross = []
    for i, left in enumerate(entries):
        for right in entries[i+1:]:
            if (left["observed_by"] != right["observed_by"] and
                    left["path"] == right["path"] and
                    abs(left["line"] - right["line"]) <= 30):
                cross.append({"left": left["id"], "right": right["id"],
                              "reason": "CROSS_LENS_NEARBY_NOT_PROOF"})
                if len(cross) >= 60:
                    break
        if len(cross) >= 60:
            break
    return {"schema_version": 1, "revision": revision, "anomalies": entries,
            "cross_lens_review": cross, "confirmed_vulnerabilities": 0,
            "network_requests": 0}


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to operator-reviewed IPv4; TLS certificate and SNI check real hostname."""
    def __init__(self, hostname, address, timeout):
        super().__init__(hostname, port=443, timeout=timeout,
                         context=ssl.create_default_context())
        self._address = address

    def connect(self):
        raw = socket.create_connection((self._address, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class LocalHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.create_connection(("127.0.0.1", self.port),
                                             timeout=self.timeout)


def validate_probe(doc, now=None):
    required = {"schema_version", "environment", "acknowledgement", "origin",
                "pinned_ip", "program_policy", "requests", "timeout_seconds",
                "max_response_bytes"}
    if not isinstance(doc, dict) or set(doc) != required or doc["schema_version"] != 1:
        raise ValueError("exact bounded probe manifest schema required")
    env = doc["environment"]
    if env not in ("owned-loopback", "approved-public"):
        raise ValueError("unsupported environment")
    url = doc["origin"]
    if not isinstance(url, str) or any(x in url for x in ("?", "#", "@")):
        raise ValueError("exact canonical origin required")
    parts = urllib.parse.urlsplit(url)
    if parts.path or parts.query or parts.fragment or parts.username or parts.password:
        raise ValueError("origin must contain only scheme/host/port")
    if env == "owned-loopback":
        if (doc["acknowledgement"] != "I_CONTROL_THIS_LOCAL_FIXTURE" or
                parts.scheme != "http" or parts.hostname != "127.0.0.1" or
                not isinstance(parts.port, int) or not 1024 <= parts.port <= 65535 or
                doc["pinned_ip"] != "127.0.0.1" or doc["program_policy"] is not None):
            raise ValueError("owned-loopback requires literal own 127.0.0.1 service")
        if url != "http://127.0.0.1:" + str(parts.port):
            raise ValueError("canonical local origin required")
    else:
        if doc["acknowledgement"] != "I_HAVE_REVIEWED_CURRENT_RULES_AND_TARGET_IP":
            raise ValueError("explicit current operator review required")
        policy._origin(url)
        ip = ipaddress.ip_address(doc["pinned_ip"])
        if not isinstance(ip, ipaddress.IPv4Address) or not ip.is_global:
            raise ValueError("public IPv4 pin required, not private, DNS or loopback")
        if doc["program_policy"] is None:
            raise ValueError("current operator-supplied program policy required")
    timeout = doc["timeout_seconds"]
    max_body = doc["max_response_bytes"]
    if type(timeout) not in (int, float) or not 0.5 <= timeout <= 10:
        raise ValueError("bounded per-request timeout required")
    if type(max_body) is not int or not 1 <= max_body <= 131072:
        raise ValueError("bounded response size required")
    requests = doc["requests"]
    if not isinstance(requests, list) or not 1 <= len(requests) <= 8:
        raise ValueError("1..8 exact requests only")
    seen = set()
    preflights = []
    validated = []
    for row in requests:
        if not isinstance(row, dict) or set(row) != {"id", "method", "url", "headers"}:
            raise ValueError("exact request record required")
        if not isinstance(row["id"], str) or not ID.fullmatch(row["id"]) or row["id"] in seen:
            raise ValueError("unique request ID required")
        seen.add(row["id"])
        if row["method"] not in ("GET", "HEAD"):
            raise ValueError("read-only GET/HEAD only")
        parsed = urllib.parse.urlsplit(row["url"])
        if (parsed.scheme + "://" + parsed.netloc != url or
                parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("request must target exact origin without userinfo/query/fragment")
        path = policy._path(parsed.path or "/")
        if not isinstance(row["headers"], dict):
            raise ValueError("headers must be object")
        headers = {}
        header_names = set()
        for name, val in row["headers"].items():
            if (not isinstance(name, str) or name.lower() not in ("accept", "x-bug-bounty") or
                    name.lower() in header_names):
                raise ValueError("only Accept and X-Bug-Bounty headers allowed")
            if (not isinstance(val, str) or not val or len(val) > 128 or
                    any(ord(c) < 33 or ord(c) > 126 for c in val)):
                raise ValueError("header must be a bounded printable value")
            if name.lower() == "x-bug-bounty" and not ID.fullmatch(val):
                raise ValueError("X-Bug-Bounty requires simple researcher handle")
            header_names.add(name.lower())
            headers[name] = val
        preflights.append({"id": row["id"], "url": row["url"], "action": "read-only",
                           "provided_header_names": list(headers)})
        validated.append((row["id"], row["method"], path, headers))
    if env == "approved-public":
        checks = policy.evaluate(doc["program_policy"], preflights, now=now)["checks"]
        if not all(x["allowed_by_saved_preflight"] for x in checks):
            raise ValueError("saved program policy preflight denied one or more requests")
    return validated


def probe(doc, execute=False, now=None, connector=None):
    validated = validate_probe(doc, now=now)
    if not execute:
        return {"schema_version": 1, "state": "DRY_RUN_NOT_AUTHORIZATION",
                "requests_planned": len(validated), "network_requests": 0,
                "confirmed_vulnerabilities": 0}
    env = doc["environment"]
    host = urllib.parse.urlsplit(doc["origin"]).hostname
    results = []
    for id_, method, path, headers in validated:
        if connector:
            connection = connector(doc, host)
        elif env == "approved-public":
            connection = PinnedHTTPSConnection(host, doc["pinned_ip"], doc["timeout_seconds"])
        else:
            connection = LocalHTTPConnection(host, port=urllib.parse.urlsplit(
                doc["origin"]).port, timeout=doc["timeout_seconds"])
        try:
            request_headers = {"Accept": "application/json", "Accept-Encoding": "identity",
                               "User-Agent": "BountyPilot-FastHunt/1.0"}
            request_headers.update(headers)
            connection.request(method, path, headers=request_headers)
            response = connection.getresponse()
            body = response.read(doc["max_response_bytes"] + 1)
            # Body is never saved, echoed, parsed into suggestions, or fed to the agent.
            results.append({"id": id_, "method": method, "path_sha256":
                            hashlib.sha256(path.encode()).hexdigest(),
                            "status": response.status,
                            "content_sha256": hashlib.sha256(body).hexdigest(),
                            "body_bytes_observed": len(body),
                            "truncated": len(body) > doc["max_response_bytes"],
                            "redirect_blocked": 300 <= response.status <= 399,
                            "classification": "UNVERIFIED_HTTP_OBSERVATION"})
        except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError):
            results.append({"id": id_, "method": method, "path_sha256":
                            hashlib.sha256(path.encode()).hexdigest(),
                            "state": "TRANSPORT_ERROR_NO_RESPONSE", "classification":
                            "NO_FINDING"})
        finally:
            connection.close()
    return {"schema_version": 1, "state": "EXECUTED_READ_ONLY_UNVERIFIED",
            "requests_planned": len(validated), "network_requests": len(results),
            "results": results, "confirmed_vulnerabilities": 0, "ready_to_submit": False,
            "limitations": ["GET endpoints can have side effects; operator must review each path",
                            "not an OS-level network egress sandbox",
                            "no authenticated cross-account exploitation or automatic triage"]}


def run_cycle(repo_path, scope, manifest=None, execute=False,
              max_files=80, max_leads=24, anomalies=None, now=None):
    """One opt-in bounded pass: static triage first, then only an approved exact request plan."""
    source = plan(repo_path, scope, max_files, max_leads, anomalies)
    observation = (probe(read_json(manifest), execute=execute, now=now)
                   if manifest else None)
    if execute and manifest is None:
        raise ValueError("--execute requires an explicit pre-reviewed probe manifest")
    return {"schema_version": 1, "mode": "fast-hunt-bounded-cycle",
            "source_revision": source["revision"],
            "source_queue": source, "http_observations": observation,
            "network_requests": observation["network_requests"] if observation else 0,
            "real_model_calls": 0, "confirmed_vulnerabilities": 0,
            "ready_to_submit": False,
            "next_step": "independent triage and native candidate/control PoC"}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("plan", help="quickly rank bounded pinned source cues, offline")
    p.add_argument("--repo", required=True)
    p.add_argument("--scope", required=True)
    p.add_argument("--max-files", type=int, default=80)
    p.add_argument("--max-leads", type=int, default=24)
    p.add_argument("--anomalies")
    p.add_argument("--out", required=True)
    m = sub.add_parser("merge", help="carry weak observations across independent lenses")
    m.add_argument("--revision", required=True)
    m.add_argument("--observations", required=True)
    m.add_argument("--previous")
    m.add_argument("--out", required=True)
    q = sub.add_parser("probe", help="explicitly approved, exact-origin bounded HTTP GET/HEAD")
    q.add_argument("--manifest", required=True)
    q.add_argument("--out", required=True)
    q.add_argument("--execute", action="store_true")
    c = sub.add_parser("run", help="one bounded source-to-reviewed-HTTP cycle")
    c.add_argument("--repo", required=True)
    c.add_argument("--scope", required=True)
    c.add_argument("--max-files", type=int, default=80)
    c.add_argument("--max-leads", type=int, default=24)
    c.add_argument("--anomalies")
    c.add_argument("--manifest", help="explicit approved read-only HTTP plan")
    c.add_argument("--execute", action="store_true")
    c.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    try:
        if args.command == "plan":
            target = Path(args.repo).resolve()
            result = plan(args.repo, args.scope, args.max_files, args.max_leads, args.anomalies)
            write_new(args.out, result, repo=target)
        elif args.command == "merge":
            result = merge_anomalies(args.revision, args.observations, args.previous)
            write_new(args.out, result)
        elif args.command == "run":
            result = run_cycle(args.repo, args.scope, args.manifest, args.execute,
                               args.max_files, args.max_leads, args.anomalies)
            write_new(args.out, result, repo=Path(args.repo).resolve())
        else:
            result = probe(read_json(args.manifest), execute=args.execute)
            write_new(args.out, result)
    except (ValueError, TypeError, KeyError, OSError, subprocess.CalledProcessError,
            json.JSONDecodeError) as exc:
        ap.error(str(exc))
    print(json.dumps({"out": args.out, "state": result.get("state", result.get("mode", "LEDGER")),
                      "network_requests": result.get("network_requests", 0),
                      "confirmed_vulnerabilities": 0}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
