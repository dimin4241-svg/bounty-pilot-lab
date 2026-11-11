#!/usr/bin/env python3
"""40 paired synthetic Web-invariant regression cases (80 snapshots).

Uses the *real Phase-3 deterministic analyzers* for actors, business effects,
browser trust and local URL parser normalization. Ten variants per family,
each with positive and negative-control snapshots. These variants are NOT
independent historical vulnerabilities, hidden model tests or proof of
new bug discovery. No AI/model, wallet, deployed target or remote HTTP runs.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

FAMILIES = ("actor", "effect", "browser", "parser")
VARIANTS = 10
COUNT = len(FAMILIES) * VARIANTS


def _mod(filename):
    base = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("bp_regression_" + filename,
                                                  base / (filename + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sha(i, j):
    return hashlib.sha256(("synthetic-owned-" + str(i) + "-" + str(j))
                          .encode("ascii")).hexdigest()


def _actor_doc(i, positive):
    r = "doc" + str(i)
    o, g = "owner" + str(i), "guest" + str(i)
    docs = {
        "schema_version": 1, "environment": "researcher_owned_lab",
        "actors": [{"id": o, "tenant": "tenant-a"},
                   {"id": g, "tenant": "tenant-b"}],
        "resources": [{"id": r, "owner": o, "tenant": "tenant-a",
                       "visibility": "private"}],
        "initial_grants": [],
        "events": [{
            "id": "e" + str(i), "seq": 1, "type": "action",
            "actor": g, "resource": r, "action": "read", "subject": None,
            "new_owner": None, "observed_effect": positive,
            "evidence_sha256": _sha(i, 1)
        }]
    }
    return docs


def _effect_doc(i, positive):
    def obs(before, after, n):
        return {"before": {"quantity": before},
                "after": {"quantity": after},
                "evidence_sha256": _sha(i, n),
                "effect_observed_at_step": 2}
    return {"schema_version": 1, "environment": "researcher_owned_lab",
            "cases": [{
                "id": "effect" + str(i), "resource_kind": "subscription",
                "business_effect": "owned_plan_effect",
                "predicate": {"field": "quantity",
                              "relation": "increased", "value": None},
                "candidate_repetitions": [
                    obs(10 + i, 11 + i if positive else 10 + i, 1),
                    obs(10 + i, 11 + i if positive else 10 + i, 2)],
                "negative_control": [
                    obs(10 + i, 10 + i, 3),
                    obs(10 + i, 10 + i, 4)]
            }]}


def _browser_doc(i, positive):
    nodes = [
        {"id": "source" + str(i), "kind": "user-content",
         "trust": "untrusted", "sensitive": False, "user_controlled": True},
        {"id": "validator" + str(i), "kind": "origin-validator",
         "trust": "trusted", "sensitive": False, "user_controlled": False},
        {"id": "sink" + str(i), "kind": "sensitive-operation",
         "trust": "trusted", "sensitive": True, "user_controlled": False}]
    edges = [
        {"from": nodes[0]["id"], "to": nodes[1]["id"],
         "kind": "validates-url", "observed_in_source": True,
         "evidence_sha256": _sha(i, 5)},
        {"from": nodes[1]["id"], "to": nodes[2]["id"],
         "kind": "sends-auth" if positive else "reads-data",
         "observed_in_source": True, "evidence_sha256": _sha(i, 6)}
    ]
    return {"schema_version": 1,
            "environment": "offline_owned_source_or_fixture",
            "nodes": nodes, "edges": edges}


def _parser_doc(positive):
    pairs = []
    for i in range(VARIANTS):
        base = "https://fixture.invalid/path-" + str(i)
        pairs.append({"id": "case" + str(i),
                      "candidate_url": (base.replace("fixture.invalid",
                                   "fixture.invalid:443") if positive else
                                   base + "?variant=" + str(i)),
                      "negative_control_url": base})
    return {"schema_version": 1, "environment": "synthetic_offline_fixtures",
            "pairs": pairs}


def run():
    actor = _mod("web_actor_state_graph")
    effect = _mod("web_effect_oracle")
    browser = _mod("web_browser_trust_graph")
    parser = _mod("web_parser_lab")
    pairs = []
    for family in FAMILIES:
        for i in range(VARIANTS):
            name = family + "-" + str(i).zfill(2)
            if family == "actor":
                actual = [len(actor.analyze(_actor_doc(i, positive))["leads"]) > 0
                          for positive in (True, False)]
            elif family == "effect":
                actual = [
                    effect.analyze(_effect_doc(i, positive))["controlled_effect_leads"] > 0
                    for positive in (True, False)]
            elif family == "browser":
                actual = [
                    len(browser.analyze(_browser_doc(i, positive))["review_paths"]) > 0
                    for positive in (True, False)]
            else:
                # Batch both actual local parser invocations once per
                # family, not twenty subprocesses for identical structure.
                if i == 0:
                    parse_pos = parser.analyze(_parser_doc(True))
                    parse_neg = parser.analyze(_parser_doc(False))
                actual = [
                    parse_pos["pairs"][i]["status"] ==
                    "CONTROLLED_LOCAL_URL_PARSER_DIFFERENCE",
                    parse_neg["pairs"][i]["status"] ==
                    "CONTROLLED_LOCAL_URL_PARSER_DIFFERENCE"]
            pairs.append({"id": name, "family": family,
                          "positive_detected": actual[0],
                          "negative_control_detected": actual[1],
                          "passed": actual == [True, False]})
    return {"schema_version": 1, "mode": "synthetic-web-invariant-regression",
            "status": "LOCAL_SYNTHETIC_REGRESSION_NOT_HISTORICAL_BENCHMARK",
            "case_pairs": COUNT, "snapshots": COUNT * 2,
            "families": list(FAMILIES),
            "passed_pairs": sum(x["passed"] for x in pairs),
            "missed_fixture_leads": sum(not x["positive_detected"] for x in pairs),
            "control_false_positives": sum(x["negative_control_detected"] for x in pairs),
            "all_passed": all(x["passed"] for x in pairs),
            "results": pairs, "real_model_runs": 0,
            "historical_rediscoveries": None, "payment_outcomes_verified": 0,
            "public_uplift_claim_allowed": False,
            "limitations": ("Ten parameter variants each of four synthetic mechanisms "
                            "are not 40 independent vulnerabilities or genuine hidden "
                            "model evaluations. The deterministic checks use no LLM, "
                            "therefore cost per model-confirmed issue is undefined. "
                            "Use independent publicly source-pinned/reviewer-scored "
                            "historical cases and an unseen holdout for external claims.")}


def _save(path, report):
    p = Path(path)
    if p.exists() or p.is_symlink():
        raise ValueError("output path must be unused")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    try:
        report = run()
        _save(a.out, report)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        p.error(str(exc))
    print(json.dumps({"status": report["status"], "case_pairs": report["case_pairs"],
                      "passed": report["passed_pairs"], "all_passed": report["all_passed"],
                      "historical_rediscoveries": None}))
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
