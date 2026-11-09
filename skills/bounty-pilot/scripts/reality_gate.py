#!/usr/bin/env python3
"""Classify advertised components as live, gated, broken or unbuilt from saved probes.

Reads a researcher-supplied JSON file of **observations** (page, API, auth,
chain, bundle and DNS probes plus bundle-scan signals) and sorts every claimed
component into one of six states so a hunt knows where a payable surface can
even exist. It makes no network request, executes nothing, and does not read
target code. Classification is a reading of the supplied probes, never proof
that an absent surface can never exist.
"""
import argparse
import json
import sys
from pathlib import Path

KINDS = {"onchain", "client-app", "api-backend", "marketplace", "game", "infra"}
PROBE_KINDS = {"page", "api", "auth", "chain", "bundle", "dns", "repo", "asset"}
STATES = {"LIVE", "AUTH_ONLY", "BACKEND_BROKEN", "MARKETING_ONLY",
          "NOT_DEPLOYED", "UNKNOWN"}
SIGNAL_KEYS = {"assets_scanned", "addresses_found", "addresses_verified",
               "client_api_calls", "client_crypto_libs", "download_links",
               "source_repository"}
INIT_FAILURE = ("prismaclientinitializationerror", "enotfound", "econnrefused",
                "connection refused", "could not connect", "database is down",
                "tenant/user", "no such host")
AUTH_MARKERS = ("unauthorized", "forbidden", "not authenticated", "sign in",
                "login required")
NEXT = {
    "LIVE": "Review the live entry points named by the probes; establish actor, "
            "reachability and money impact before writing anything up.",
    "AUTH_ONLY": "Enumerate the authenticated roles. Test authorization (role checks, "
                 "object ownership, IDOR) with one owned account before calling the API safe.",
    "BACKEND_BROKEN": "Record the exact failing probe. Re-run the same paths when the "
                      "backend responds; a dead backend is a blocker, not a finding.",
    "MARKETING_ONLY": "Only a rendered page exists. Do not spend hunt passes on UI mockups.",
    "NOT_DEPLOYED": "No deployed artifact was observed. Keep the claim out of the hunt until "
                    "an address, repository or release exists.",
    "UNKNOWN": "Collect the missing probe type before drawing any conclusion about this component.",
}


def _merge_signals(component):
    out = {"assets_scanned": 0, "addresses_found": 0, "addresses_verified": 0,
           "client_api_calls": 0, "client_crypto_libs": [],
           "download_links": {"total": 0, "resolving": 0},
           "source_repository": False}
    raw = component.get("signals", {})
    if not isinstance(raw, dict):
        raise ValueError("signals must be an object")
    for key, value in raw.items():
        if key not in SIGNAL_KEYS:
            raise ValueError("unknown signal %r" % key)
    for key in ("assets_scanned", "addresses_found", "addresses_verified",
                "client_api_calls"):
        value = raw.get(key, 0)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 10_000_000:
            raise ValueError("signal %s must be a non-negative integer" % key)
        out[key] = value
    if out["addresses_verified"] > out["addresses_found"]:
        raise ValueError("addresses_verified cannot exceed addresses_found")
    libs = raw.get("client_crypto_libs", [])
    if not isinstance(libs, list) or len(libs) > 100 or not all(
            isinstance(x, str) and 1 <= len(x) <= 60 for x in libs):
        raise ValueError("client_crypto_libs must be a short string list")
    out["client_crypto_libs"] = sorted(set(libs))
    links = raw.get("download_links", {"total": 0, "resolving": 0})
    if not isinstance(links, dict) or set(links) - {"total", "resolving"}:
        raise ValueError("download_links must contain total and resolving")
    total, resolving = links.get("total", 0), links.get("resolving", 0)
    for name, value in (("total", total), ("resolving", resolving)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError("download_links.%s must be a non-negative integer" % name)
    if resolving > total:
        raise ValueError("download_links.resolving cannot exceed total")
    out["download_links"] = {"total": total, "resolving": resolving}
    repo = raw.get("source_repository", False)
    if not isinstance(repo, bool):
        raise ValueError("source_repository must be boolean")
    out["source_repository"] = repo
    return out


def _probe(component):
    probes = component.get("probes", [])
    if not isinstance(probes, list) or len(probes) > 500:
        raise ValueError("probes must be an array of at most 500")
    out = []
    for pos, raw in enumerate(probes):
        if not isinstance(raw, dict):
            raise ValueError("probe %d must be an object" % pos)
        kind = raw.get("kind")
        if kind not in PROBE_KINDS:
            raise ValueError("probe %d has an invalid kind" % pos)
        status = raw.get("status")
        if status is not None and (not isinstance(status, int) or isinstance(status, bool)
                                   or not 100 <= status <= 599):
            raise ValueError("probe %d status must be 100..599 or null" % pos)
        excerpt = raw.get("body_excerpt", "")
        if not isinstance(excerpt, str) or len(excerpt) > 2000:
            raise ValueError("probe %d body_excerpt must be a string <=2000" % pos)
        target = raw.get("target", "")
        if not isinstance(target, str) or len(target) > 500:
            raise ValueError("probe %d target must be a string <=500" % pos)
        out.append({"index": pos, "kind": kind, "status": status,
                    "excerpt": excerpt, "target": target})
    return out


def classify(component):
    signals = _merge_signals(component)
    probes = _probe(component)
    kind = component["kind"]
    pages = [p for p in probes if p["kind"] == "page"]
    apis = [p for p in probes if p["kind"] in ("api", "auth")]
    chains = [p for p in probes if p["kind"] == "chain"]
    page_ok = any(p["status"] == 200 for p in pages)
    api_data = [p for p in apis
                if p["status"] == 200 and p["excerpt"].strip() not in ("", "{}", "[]", "null")
                and not any(m in p["excerpt"].lower() for m in AUTH_MARKERS)]
    backend_error = any(
        (p["status"] or 0) >= 500
        or any(token in p["excerpt"].lower() for token in INIT_FAILURE)
        for p in apis)
    gated = [p for p in apis if p["status"] in (401, 403)
             or (p["status"] in (301, 302, 307, 308) and "login" in p["target"].lower())]
    chain_live = bool(signals["addresses_verified"]) and bool(chains)
    client_live = bool(signals["client_crypto_libs"]) and signals["client_api_calls"] > 0
    release_live = signals["download_links"]["resolving"] > 0
    chain_searched = bool(chains) or signals["assets_scanned"] > 0
    inert_page = page_ok and signals["download_links"]["total"] > 0 and not release_live
    basis = []
    warnings = []

    if not probes and not any(signals[k] for k in
                              ("assets_scanned", "addresses_found", "client_api_calls")) \
            and not signals["download_links"]["resolving"] and not signals["client_crypto_libs"]:
        state = "UNKNOWN"
        basis.append("no probes or scan signals supplied")
        warnings.append("unprobed-component")
    elif backend_error:
        state = "BACKEND_BROKEN"
        basis.append("an api/auth probe failed inside the backend (5xx or init failure)")
    elif api_data:
        state = "LIVE"
        basis.append("api probe returned data without an auth challenge: %s"
                     % ", ".join(p["target"] for p in api_data[:3]))
    elif chain_live:
        state = "LIVE"
        basis.append("chain probe verified %d deployed address(es)"
                     % signals["addresses_verified"])
    elif client_live or (release_live and kind in ("client-app", "marketplace", "game")):
        state = "LIVE"
        basis.append("client artifact ships crypto code and API calls"
                     if client_live else "a downloadable release resolves")
    elif gated:
        state = "AUTH_ONLY"
        basis.append("every api/auth probe is gated (401/403/login redirect)")
    elif kind == "onchain" and chain_searched and not signals["addresses_found"]:
        state = "NOT_DEPLOYED"
        basis.append("%d asset(s) and %d chain probe(s) scanned, zero addresses found"
                     % (signals["assets_scanned"], len(chains)))
    elif page_ok:
        state = "MARKETING_ONLY"
        basis.append("page responds but no API data, chain artifact or client release was observed")
        warnings.append("page-only-surface")
    else:
        state = "UNKNOWN"
        basis.append("no successful page, API or chain observation")
        warnings.append("inconclusive-probes")

    if signals["addresses_found"] > signals["addresses_verified"]:
        warnings.append("addresses-without-bytecode")
    if kind == "api-backend" and not apis:
        warnings.append("api-claim-unprobed")
    if kind == "onchain" and not chain_searched:
        warnings.append("chain-claim-unsearched")
    if kind == "client-app" and not signals["assets_scanned"] and not any(
            p["kind"] == "bundle" for p in probes):
        warnings.append("client-bundles-unprobed")
    if inert_page:
        warnings.append("inert-download-controls")
    if (kind == "client-app" and signals["assets_scanned"]
            and not signals["client_crypto_libs"] and not signals["client_api_calls"]):
        warnings.append("no-client-crypto-or-api")
    return {"id": component["id"], "kind": kind, "status": state,
            "basis": basis, "next_action": NEXT[state],
            "signals": signals,
            "probe_counts": {k: sum(1 for p in probes if p["kind"] == k)
                             for k in sorted({p["kind"] for p in probes})}}, warnings


def evaluate(doc):
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise ValueError("probe file must use schema_version=1")
    rows = doc.get("components")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 200:
        raise ValueError("components must be an array of 1..200")
    seen, result, warnings = set(), [], []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("component must be an object")
        ident = row.get("id")
        if not isinstance(ident, str) or not 1 <= len(ident) <= 120 or ident in seen:
            raise ValueError("component id invalid or duplicate")
        seen.add(ident)
        if row.get("kind") not in KINDS:
            raise ValueError("%s has an invalid kind" % ident)
        claims = row.get("claims", [])
        if not isinstance(claims, list) or len(claims) > 50 or not all(
                isinstance(x, str) and 1 <= len(x) <= 200 for x in claims):
            raise ValueError("%s claims must be a short string list" % ident)
        if len(row.get("probes", [])) > 500:
            raise ValueError("%s has too many probes" % ident)
        item, found = classify(row)
        result.append(item)
        warnings.extend("%s:%s" % (ident, w) for w in found)
    counts = {state: sum(1 for x in result if x["status"] == state)
              for state in sorted(STATES)}
    return {"schema_version": 1, "execution": "offline-classification-of-supplied-probes",
            "component_count": len(result), "status_counts": counts,
            "live_components": [x["id"] for x in result if x["status"] == "LIVE"],
            "blocked_components": [{"id": x["id"], "status": x["status"],
                                    "next_action": x["next_action"]}
                                   for x in result
                                   if x["status"] in ("AUTH_ONLY", "BACKEND_BROKEN")],
            "dead_claims": [x["id"] for x in result
                            if x["status"] in ("NOT_DEPLOYED", "MARKETING_ONLY")],
            "unverified_components": [x["id"] for x in result if x["status"] == "UNKNOWN"],
            "warnings": warnings, "components": result,
            "notice": ("This sorts the supplied observations; it does not prove a surface "
                       "absent, a backend permanently down or a component out of scope. "
                       "No probe was sent and no target code was executed.")}


def _pairs(items):
    out = {}
    for key, value in items:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key] = value
    return out


def read(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 2_000_000:
        raise ValueError("input must be a local regular JSON <=2MB")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_pairs)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--probes", required=True, help="saved probe/observation JSON")
    p.add_argument("--out", help="optional new JSON file")
    a = p.parse_args(argv)
    try:
        data = evaluate(read(a.probes))
        encoded = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if a.out:
            dest = Path(a.out).expanduser()
            if dest.exists() or dest.is_symlink():
                raise ValueError("output already exists")
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("x", encoding="utf-8") as f:
                f.write(encoded)
            print(json.dumps({"out": a.out, "component_count": data["component_count"]}))
        else:
            print(encoded, end="")
    except (ValueError, KeyError, TypeError, OSError) as exc:
        p.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
