#!/usr/bin/env python3
"""Campaign scorecard: blind, paired, already-scored backtests and lens ablations.

Uses existing bounty.py backtest seal/score and bench_compare. Never reads answer
catalogs during a hunt, never computes precision without adjudicated negatives,
and never claims a benchmark ran just because a manifest exists.
"""
import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path


def _bench():
    path = Path(__file__).resolve().parent / "bench_compare.py"
    spec = importlib.util.spec_from_file_location("bp_campaign_bench", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BENCH = _bench()


def _read(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 5_000_000:
        raise ValueError("input must be regular non-symlink JSON <=5MB: " + str(p))
    return json.loads(p.read_text(encoding="utf-8"))


def score(manifest, base_dir=None):
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("manifest schema_version=1 required")
    root = Path(base_dir or ".").resolve()
    arms = manifest.get("arms")
    if not isinstance(arms, dict) or not 2 <= len(arms) <= 40:
        raise ValueError("arms requires 2..40 named arms")
    baseline = manifest.get("baseline")
    if not isinstance(baseline, str) or baseline not in arms:
        raise ValueError("baseline must name a supplied arm")
    def load_arm(label):
        item = arms[label]
        if not isinstance(item, dict) or not isinstance(item.get("scored"), str):
            raise ValueError(label + " must name a scored JSON array")
        scored_path = (root / item["scored"]).resolve()
        if root != scored_path and root not in scored_path.parents:
            raise ValueError("arm paths must remain inside manifest directory")
        cases = _read(scored_path)
        metadata = None
        if item.get("metadata") is not None:
            meta_path = (root / item["metadata"]).resolve()
            if root != meta_path and root not in meta_path.parents:
                raise ValueError("metadata path must remain inside manifest directory")
            metadata = _read(meta_path)
        if not isinstance(cases, list):
            raise ValueError(label + " scored must be an array")
        return cases, metadata
    base_cases, base_meta = load_arm(baseline)
    # Require every arm to be a full, matching cohort: never drop a miss or
    # cherry-pick a subset for an appealing ablation.
    comparisons = {}
    for name in sorted(arms):
        if name == baseline:
            continue
        cases, meta = load_arm(name)
        c = BENCH.compare(base_cases, cases, base_meta, meta)
        c["disabled_lenses"] = arms[name].get("disabled_lenses", [])
        if not isinstance(c["disabled_lenses"], list) or any(
                not isinstance(k, str) or not k for k in c["disabled_lenses"]):
            raise ValueError("disabled_lenses must be a list of nonempty names")
        comparisons[name] = c
    # Ground truth is *only* existing scored cases, never read from unpublished
    # findings or supplied here after testing.
    baseline_count = sum(len({r["id"] for r in case.get("rediscovered", [])
                              if r.get("severity") in BENCH.SEV}) for case in base_cases)
    valid = all(c["cases"] >= 5 and
                c["strategy_recommendation"] != "inconclusive-collect-more-controlled-data"
                for c in comparisons.values())
    return {
        "schema_version": 1, "baseline": baseline,
        "cases": len(base_cases), "high_critical_baseline_rediscoveries": baseline_count,
        "comparisons": comparisons,
        "matched_controls": valid,
        "holdout_attested_by_operator": manifest.get("holdout_attested") is True,
        "reportable_advantage": bool(valid and manifest.get("holdout_attested") is True and
                                     all(c["delta"] > 0 for c in comparisons.values())),
        "precision_measured": False, "payout_prediction": False,
        "notice": ("No benchmark case is generated or executed here. Every scored arm must come "
                   "from a separate sealed run. Identical source revisions, ground truth, "
                   "model/budget and provider costs are required for controlled claims. "
                   "No claims about private duplicates, true negatives or future payouts.")
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    m = Path(args.manifest).expanduser().resolve()
    out = Path(args.out).expanduser()
    if out.is_symlink() or out.exists():
        parser.error("output is create-only")
    try:
        result = score(_read(m), m.parent)
    except (KeyError, ValueError, TypeError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(json.dumps({"out": str(out), "cases": result["cases"],
                      "reportable_advantage": result["reportable_advantage"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
