#!/usr/bin/env python3
"""Join web-route-ast's route graph with business-schema-bind's lexical rule
leads, by handler function, into route-anchored web-business-lab rule leads.

Neither input tool is replaced or duplicated. web_route_ast.py already extracts
Python decorator routes, apparent guard-name cues and every call name inside
each handler, from real AST. business_schema_bind.py already finds where a
web_business_lab rule's concept terms appear lexically, line by line, across
the whole checkout. Read separately they answer "where is this route" and
"where does this word appear"; together they answer the question neither
answers alone: which rule is a GIVEN route's own handler a plausible anchor
for, and what guard does that same route already appear to carry.

A route lead here is still a lexical/structural artifact: a body-range match
only means the term's line number falls between the handler's def and its
last statement, not that the term is reachable, assigned, or read; a
called-function-name match only means a call expression ends in a name a
researcher associated with the rule, never that the callee does what its
name suggests. Read-only, tracked checkout for the business-rule side,
whole-filesystem walk for the route side (matching each tool's own existing
scope); never executes target code.
"""
import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path


def _load_sibling(name):
    path = Path(__file__).resolve().with_name(name + ".py")
    spec = importlib.util.spec_from_file_location("bp_business_route_bind_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


route_ast = _load_sibling("web_route_ast")
schema_bind = _load_sibling("business_schema_bind")

MAX_ROUTES = 4000


def _call_name_matches(call_names, terms):
    matches = set()
    for call in call_names:
        short = call.rsplit(".", 1)[-1].lower()
        if short in terms:
            matches.add(call)
    return sorted(matches)


def bind_routes(repository, rules=None, scope=None):
    route_report = route_ast.inspect_repo(repository)
    schema_report = schema_bind.bind(repository, rules, scope)
    if len(route_report["routes"]) > MAX_ROUTES:
        raise ValueError("route inventory exceeds safety cap; narrow the checkout")
    hits_by_rule = {row["rule"]: row["hits"] for row in schema_report["rules"]}
    terms_by_rule = {row["rule"]: {t.lower() for t in row["searched_terms"]}
                     for row in schema_report["rules"]}
    routes = []
    for route in route_report["routes"]:
        rule_leads = []
        for rule, hits in hits_by_rule.items():
            body_hits = [h for h in hits if h["path"] == route["file"]
                        and route["line"] <= h["line"] <= route["end_line"]]
            call_matches = _call_name_matches(route["call_names"], terms_by_rule[rule])
            if not body_hits and not call_matches:
                continue
            rule_leads.append({
                "rule": rule,
                "body_lexical_hits": body_hits,
                "called_function_name_matches": call_matches,
            })
        if not rule_leads:
            continue
        routes.append({
            "method": route["method"], "path": route["path"], "handler": route["handler"],
            "guard_name_cues": route["guard_name_cues"],
            "route_provenance": route["provenance"],
            "rule_leads": sorted(rule_leads, key=lambda x: x["rule"]),
        })
    return {
        "schema_version": 1, "classification": "ROUTE_ANCHORED_BUSINESS_RULE_LEADS",
        "source_revision": schema_report["source_revision"],
        "routes_scanned": len(route_report["routes"]),
        "code_files_scanned_for_terms": schema_report["code_files_scanned"],
        "route_parse_errors": route_report["parse_errors"],
        "routes_with_leads": len(routes),
        "routes": routes,
        "confirmed_vulnerabilities": 0,
        "notice": ("A route appearing here is a place to read, not a confirmed "
                   "source_anchor: web_business_lab.bridge() still requires a human "
                   "to pick the exact function/line and refuses an unreviewed guess. "
                   "A route absent from this list may still be the real anchor for a "
                   "rule under different names, through server-side includes, or via "
                   "routing registered outside a decorator this scan can see. Only "
                   "Python decorator routes are covered; JS/TS routes are not.")
    }


def main(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--repo", required=True)
    cli.add_argument("--rule", action="append", dest="rules",
                     help="repeatable; default is every web-business-lab rule")
    cli.add_argument("--scope", action="append",
                     help="bounded relative directory/file prefix for the business-rule term scan")
    cli.add_argument("--out")
    args = cli.parse_args(argv)
    try:
        result = bind_routes(args.repo, args.rules, args.scope)
        text = json.dumps(result, indent=2, ensure_ascii=False)
        if args.out:
            target = Path(args.out)
            if target.exists() or target.is_symlink():
                raise ValueError("refusing to overwrite an existing output file")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(target, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(text)
        else:
            print(text)
        return 0
    except (ValueError, OSError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
