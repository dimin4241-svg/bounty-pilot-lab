#!/usr/bin/env python3
"""Offline paired vulnerable/fixed regression evaluator with declared provenance.

This scorer is separated from the scanner, but cannot prove a run was blind or
that supplied labels/commits/licenses represent real historical CVEs.
"""
import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

IDENT = re.compile(r"[A-Za-z0-9_.:-]{1,100}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
MAX_CASES = 1000


def _ids(obj, name):
    if not isinstance(obj, list) or not 2 <= len(obj) <= MAX_CASES:
        raise ValueError(name + " must be a bounded list")
    result = {}
    for row in obj:
        if not isinstance(row, dict) or not isinstance(row.get("case_id"), str):
            raise ValueError("case entry invalid")
        key = row["case_id"]
        if not IDENT.fullmatch(key) or key in result:
            raise ValueError("duplicate or invalid case id")
        result[key] = row
    return result


def evaluate(answers, predictions):
    if (not isinstance(answers, dict) or answers.get("schema_version") != 1
            or not isinstance(predictions, dict)
            or predictions.get("schema_version") != 1):
        raise ValueError("schema_version 1 answers and predictions required")
    truth = _ids(answers.get("cases"), "answers")
    observed = _ids(predictions.get("cases"), "predictions")
    if truth.keys() != observed.keys():
        raise ValueError("predictions and truth require identical case ids")
    groups = defaultdict(dict)
    for key, case in truth.items():
        pair = case.get("pair_id")
        variant = case.get("variant")
        revision = case.get("source_commit")
        license_name = case.get("license")
        if (not isinstance(pair, str) or not IDENT.fullmatch(pair)
                or variant not in ("vulnerable", "fixed")
                or not isinstance(revision, str) or not COMMIT.fullmatch(revision)
                or not isinstance(license_name, str) or not license_name.strip()):
            raise ValueError("pair, variant, source_commit and license required")
        if variant in groups[pair]:
            raise ValueError("duplicate variant within pair")
        groups[pair][variant] = key
    for pair, variants in groups.items():
        if set(variants) != {"vulnerable", "fixed"}:
            raise ValueError("each pair needs vulnerable and fixed variants")
        if truth[variants["vulnerable"]]["source_commit"] == (
                truth[variants["fixed"]]["source_commit"]):
            raise ValueError("paired variants must name different commits")
    tp = fp = tn = fn = 0
    for key, row in observed.items():
        if type(row.get("detected")) is not bool:
            raise ValueError("each prediction must contain boolean detected")
        label = truth[key]["variant"] == "vulnerable"
        found = row["detected"]
        if label and found:
            tp += 1
        elif label:
            fn += 1
        elif found:
            fp += 1
        else:
            tn += 1
    fully_correct = sum(
        observed[v["vulnerable"]]["detected"]
        and not observed[v["fixed"]]["detected"]
        for v in groups.values()
    )
    return {
        "schema_version": 1, "engine": "historical-paired-eval",
        "pairs": len(groups), "cases": len(truth),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "fully_correct_pairs": fully_correct,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "recall": round(tp / (tp + fn), 4) if tp + fn else None,
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None,
        "source_revision_and_license": "OPERATOR_DECLARED_NOT_VERIFIED",
        "blinding_verified": False,
        "vulnerabilities_proven_by_this_scorer": 0,
        "limitations": ["blindness and historical source provenance unverified",
                        "small sample and corpus selection bias unadjusted",
                        "detected label does not mean executable PoC or real impact"],
    }


def _load(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("bounded regular JSON required")
    return json.loads(p.read_text("utf-8"))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--answers", required=True)
    ap.add_argument("--predictions", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    try:
        report = evaluate(_load(args.answers), _load(args.predictions))
        path = Path(args.out)
        if path.exists() or path.is_symlink() or not path.parent.is_dir():
            raise ValueError("output must be new")
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write("\n")
        print(json.dumps({"fully_correct_pairs": report["fully_correct_pairs"],
                          "blinding_verified": False}))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
