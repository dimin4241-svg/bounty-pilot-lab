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
SIGNAL_KEYS = {"assets_scanned", "address_search_complete", "client_search_complete",
               "addresses_found", "addresses_verified", "client_api_calls",
               "client_crypto_libs", "download_links", "source_repository"}
INIT_FAILURE = ("prismaclientinitializationerror", "enotfound", "econnrefused",
                "connection refused", "could not connect", "database is down",
                "tenant/user", "no such host")
AUTH_MARKERS = ("unauthorized", "forbidden", "not authenticated", "not authorized",
                "authentication required", "sign in", "login required", "access denied")
API_FAILURE_TEXT = ("not found", "does not exist", "method not allowed",
                    "internal server error", "temporarily unavailable",
                    "service unavailable", "bad gateway", "gateway timeout",
                    "upstream error", "upstream timed out", "something went wrong",
                    "failed to fetch", "traceback")
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
    out = {"assets_scanned": 0, "address_search_complete": False,
           "client_search_complete": False,
           "addresses_found": 0, "addresses_verified": 0,
           "client_api_calls": 0, "client_crypto_libs": [],
           "download_links": {"total": 0, "resolving": 0},
           "source_repository": False}
    raw = component.get("signals", {})
    if not isinstance(raw, dict):
        raise ValueError("signals must be an object")
    for key, value in raw.items():
        if key not in SIGNAL_KEYS:
            raise ValueError("unknown signal %r" % key)
    complete = raw.get("address_search_complete", False)
    if not isinstance(complete, bool):
        raise ValueError("signal address_search_complete must be boolean")
    out["address_search_complete"] = complete
    client_complete = raw.get("client_search_complete", False)
    if not isinstance(client_complete, bool):
        raise ValueError("signal client_search_complete must be boolean")
    out["client_search_complete"] = client_complete
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
        redirect_to = raw.get("redirect_to", "")
        if not isinstance(redirect_to, str) or len(redirect_to) > 500:
            raise ValueError("probe %d redirect_to must be a string <=500" % pos)
        out.append({"index": pos, "kind": kind, "status": status,
                    "excerpt": excerpt, "target": target,
                    "redirect_to": redirect_to})
    return out


def _api_payload_is_data(excerpt):
    """Return whether a saved 2xx response looks like a successful API payload.

    This is intentionally conservative. An error envelope, auth challenge, HTML app
    fallback, empty payload or truncated JSON excerpt must not make a backend look LIVE.
    Unstructured plain text is deliberately inconclusive because it can be a health
    message, proxy fallback or generic error page.
    """
    text = excerpt.strip()
    if not text or text.lower() in ("{}", "[]", "null", "false"):
        return False
    lower = text.lower()
    if lower.startswith(("<!doctype html", "<html", "<head", "<body", "<div", "<main")):
        return False
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        # Plain text and clipped JSON cannot establish a useful API surface.
        return False
    return _api_json_has_data(payload)


def _api_json_has_data(value, depth=0):
    """Reject common error/health envelopes while accepting structured payloads."""
    if depth > 20:
        return False
    if isinstance(value, dict):
        if value.get("success") is False or value.get("ok") is False:
            return False
        status = value.get("status")
        if isinstance(status, int) and not isinstance(status, bool) and status >= 400:
            return False
        if value.get("error") not in (None, "", False, [], {}):
            return False
        errors = value.get("errors")
        if errors and value.get("data") is None:
            return False
        for key in ("message", "title", "detail", "type"):
            text = value.get(key)
            if isinstance(text, str):
                lower = text.lower()
                if any(marker in lower for marker in AUTH_MARKERS + API_FAILURE_TEXT):
                    return False
        # Health/error metadata alone is not useful application data. A populated
        # `data` envelope is checked recursively; ordinary domain keys count as data.
        metadata = {"error", "errors", "status", "success", "ok", "message",
                    "title", "detail", "type", "code", "health", "healthy",
                    "uptime", "service", "version", "timestamp", "environment",
                    "build", "dependencies", "checks"}
        data_keys = set(value) - metadata
        if not data_keys:
            return False
        if data_keys == {"data"}:
            return _api_json_has_data(value["data"], depth + 1)
        return True
    if isinstance(value, list):
        return any(_api_json_has_data(item, depth + 1) for item in value)
    if isinstance(value, str):
        text = value.strip()
        lower = text.lower()
        return bool(text) and not lower.startswith(
            ("<!doctype html", "<html", "<head", "<body", "<div", "<main")) \
            and not any(marker in lower for marker in AUTH_MARKERS + API_FAILURE_TEXT)
    if isinstance(value, bool):
        return value
    return isinstance(value, (int, float))


def classify(component):
    signals = _merge_signals(component)
    probes = _probe(component)
    kind = component["kind"]
    client_kinds = ("client-app", "marketplace", "game")
    pages = [p for p in probes if p["kind"] == "page"]
    apis = [p for p in probes if p["kind"] in ("api", "auth")]
    chains = [p for p in probes if p["kind"] == "chain"]
    page_ok = any(p["status"] == 200 for p in pages)
    api_data = [p for p in apis
                if kind != "onchain" and p["status"] is not None
                and 200 <= p["status"] < 300
                and _api_payload_is_data(p["excerpt"])]
    backend_error = kind != "onchain" and any(
        (p["status"] or 0) >= 500
        or any(token in p["excerpt"].lower() for token in INIT_FAILURE)
        for p in apis)
    gated = [p for p in apis if kind != "onchain" and (
        p["status"] in (401, 403)
        or (p["status"] in (301, 302, 303, 307, 308)
            and any(marker in p["redirect_to"].lower()
                    for marker in ("login", "signin", "sign-in", "/authorize", "/sso/"))))]
    auth_only = bool(apis) and len(gated) == len(apis)
    chain_live = (kind == "onchain" and bool(signals["addresses_verified"])
                  and any(p["status"] is not None and 200 <= p["status"] < 300
                          for p in chains))
    client_live = (kind in client_kinds and bool(signals["client_crypto_libs"])
                   and signals["client_api_calls"] > 0)
    release_live = signals["download_links"]["resolving"] > 0
    bundle_searched = (bool(signals["client_crypto_libs"])
                       or signals["client_api_calls"] > 0
                       or any(p["kind"] in ("bundle", "asset") for p in probes))
    inert_page = page_ok and signals["download_links"]["total"] > 0 and not release_live
    basis = []
    warnings = []

    if not probes and not signals["address_search_complete"] and not any(signals[k] for k in
                              ("assets_scanned", "addresses_found", "client_api_calls")) \
            and not signals["download_links"]["resolving"] and not signals["client_crypto_libs"]:
        state = "UNKNOWN"
        basis.append("no probes or scan signals supplied")
        warnings.append("unprobed-component")
    elif api_data or chain_live or client_live or (release_live and kind in client_kinds):
        state = "LIVE"
        if api_data:
            basis.append("API probe returned a non-error payload: %s"
                         % ", ".join(p["target"] for p in api_data[:3]))
        if chain_live:
            basis.append("successful chain probe with %d verified deployed address(es)"
                         % signals["addresses_verified"])
        if client_live:
            basis.append("client bundle signals include crypto code and API calls")
        if release_live and kind in client_kinds:
            basis.append("a downloadable release resolves")
        if backend_error:
            basis.append("another API/auth probe failed; this is a partial backend failure")
            warnings.append("partial-backend-failure")
    elif backend_error:
        state = "BACKEND_BROKEN"
        basis.append("an api/auth probe failed inside the backend (5xx or init failure)")
    elif auth_only:
        state = "AUTH_ONLY"
        basis.append("every api/auth probe is gated (401/403/login redirect)")
    elif (kind == "onchain" and signals["address_search_complete"]
          and not signals["addresses_found"]):
        state = "NOT_DEPLOYED"
        basis.append("complete search of the supplied on-chain claim assets found zero addresses")
    elif kind == "onchain":
        state = "UNKNOWN"
        basis.append("on-chain address search is not marked complete")
    elif kind == "api-backend" and not apis:
        state = "UNKNOWN"
        basis.append("the API claim has no API/auth probes")
    elif kind == "api-backend":
        state = "UNKNOWN"
        basis.append("API/auth probes did not establish data, a full auth gate or a backend failure")
    elif kind in client_kinds and not signals["client_search_complete"]:
        state = "UNKNOWN"
        basis.append("the relevant client asset search is not marked complete")
    elif kind in client_kinds and (signals["client_crypto_libs"]
                                   or signals["client_api_calls"] > 0):
        state = "UNKNOWN"
        basis.append("the client search found runtime cues but no live client surface was probed")
    elif page_ok and kind in client_kinds:
        state = "MARKETING_ONLY"
        basis.append("page responds but no API data, chain artifact or client release was observed")
        warnings.append("page-only-surface")
    elif page_ok:
        state = "UNKNOWN"
        basis.append("a page responds, but the component's functional surface is not established")
        warnings.append("page-only-surface")
    else:
        state = "UNKNOWN"
        basis.append("no successful page, API or chain observation")
        warnings.append("inconclusive-probes")

    if signals["addresses_found"] > signals["addresses_verified"]:
        warnings.append("addresses-without-bytecode")
    if kind == "api-backend" and not apis:
        warnings.append("api-claim-unprobed")
    if kind == "onchain" and not signals["address_search_complete"]:
        warnings.append("chain-claim-unsearched")
    if kind in client_kinds and not bundle_searched \
            and not signals["client_search_complete"]:
        warnings.append("client-bundles-unprobed")
    if kind in client_kinds \
            and not signals["client_search_complete"]:
        warnings.append("client-search-incomplete")
    if inert_page:
        warnings.append("inert-download-controls")
    if (kind in client_kinds
            and signals["client_search_complete"]
            and not signals["client_crypto_libs"] and not signals["client_api_calls"]):
        warnings.append("no-client-crypto-or-api")
    if kind == "api-backend" and apis and not (api_data or backend_error or auth_only):
        warnings.append("api-claim-inconclusive")
    if kind == "onchain" and chains and signals["addresses_verified"] and not chain_live:
        warnings.append("chain-probe-inconclusive")
    if (kind in client_kinds and signals["client_search_complete"]
            and not (signals["client_crypto_libs"] and signals["client_api_calls"])
            and (signals["client_crypto_libs"] or signals["client_api_calls"])):
        warnings.append("client-runtime-unverified")
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
