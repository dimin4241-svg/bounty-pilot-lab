#!/usr/bin/env python3
"""Paired historical Web A/B protocol using Bounty Pilot's sealed native scoring.

The module prepares two identical, opaque source task queues, isolated evaluator
directories, and compares only completed sealed predictions + independently
supplied judgments. It never runs agents, verifies reviewer independence or
claims real-world discovery improvements from a public historical corpus.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

import web_historical_bench as historical

SHA40 = re.compile(r"^[0-9a-f]{40}$")
ID = re.compile(r"^[A-Za-z0-9_.:/-]{1,100}$")
MAX_SPEND = 1000.0


def _read(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 3_000_000:
        raise ValueError("input must be JSON from a regular, non-symlink file <=3MB")
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON key")
        obj[key] = value
    return obj


def _write(path, value):
    p = Path(path).expanduser()
    if p.is_symlink() or p.exists():
        raise ValueError("output must be a new path")
    p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(value, f, sort_keys=True, ensure_ascii=False, indent=2)
        f.write("\n")


def _config(config):
    if not isinstance(config, dict) or set(config) != {
            "schema_version", "model_id", "baseline_skill_revision",
            "candidate_skill_revision", "max_usd_per_task", "max_seconds_per_task"}:
        raise ValueError("config fields invalid")
    if type(config.get("schema_version")) is not int or config["schema_version"] != 1:
        raise ValueError("invalid schema version")
    if not isinstance(config["model_id"], str) or not ID.fullmatch(config["model_id"]):
        raise ValueError("bounded model ID required")
    for key in ("baseline_skill_revision", "candidate_skill_revision"):
        if not isinstance(config[key], str) or not SHA40.fullmatch(config[key]):
            raise ValueError("both skill revisions require exact Git SHAs")
    if config["baseline_skill_revision"] == config["candidate_skill_revision"]:
        raise ValueError("distinct skill revisions required")
    cost = config["max_usd_per_task"]
    seconds = config["max_seconds_per_task"]
    if type(cost) not in (int, float) or not 0 < cost <= MAX_SPEND:
        raise ValueError("positive per-task spend limit required")
    if type(seconds) is not int or not 60 <= seconds <= 14400:
        raise ValueError("time cap must be 60..14400 seconds")
    return config


def prepare(config, catalog, base_path):
    config = _config(config)
    historical._catalog(catalog)
    root = Path(base_path).expanduser().resolve()
    if root.exists():
        raise ValueError("study root must be new")
    root.mkdir(mode=0o700, parents=True)
    base_hunter = root / "baseline" / "hunter"
    base_eval = root / "baseline" / "evaluator"
    base_hunter.parent.mkdir(mode=0o700)
    historical.prepare(catalog, base_hunter, base_eval)
    candidate_hunter = root / "candidate" / "hunter"
    candidate_eval = root / "candidate" / "evaluator"
    candidate_hunter.parent.mkdir(mode=0o700)
    candidate_hunter.mkdir(mode=0o700)
    candidate_eval.mkdir(mode=0o700)
    queue = _read(base_hunter / "blind-queue.json")
    key = _read(base_eval / "answer-map.json")
    historical._write(candidate_hunter / "blind-queue.json", queue)
    historical._write(candidate_eval / "answer-map.json", key)
    study = {
        "schema_version": 1, "state": "PREPARED_NOT_EXECUTED",
        "config": config,
        "hunter_queue_sha256": historical._sha(queue),
        "answer_map_sha256": historical._sha(key),
        "task_count": len(queue["tasks"]), "case_count": len(catalog["cases"]),
        "repository_count": len({x["repository_url"] for x in catalog["cases"]}),
        "catalog_sha256": historical._sha(catalog),
        "notice": ("The same opaque task IDs and source snapshots are used in each arm. "
                   "Keep evaluator directories inaccessible to agents. The tool has NOT "
                   "executed or blinded a model and public disclosures may be memorized.")
    }
    _write(root / "study.json", study)
    return {"state": study["state"], "root": str(root),
            "task_count": study["task_count"], "case_count": study["case_count"],
            "baseline_hunter": str(base_hunter),
            "candidate_hunter": str(candidate_hunter),
            "evaluator_directories_must_remain_private": True}


def _spent(rows, queue, config):
    if not isinstance(rows, dict) or set(rows) != {"schema_version", "model_id", "tasks"} or (
            type(rows.get("schema_version")) is not int or rows["schema_version"] != 1):
        raise ValueError("spend log format invalid")
    if rows["model_id"] != config["model_id"]:
        raise ValueError("model changed between arms")
    items = rows["tasks"]
    expected = {item["task_id"] for item in queue["tasks"]}
    if not isinstance(items, list) or len(items) != len(expected):
        raise ValueError("every task must have a cost/time entry, even failed tasks")
    seen = set()
    totals = {"usd": 0.0, "seconds": 0, "input_tokens": 0, "output_tokens": 0}
    for item in items:
        if not isinstance(item, dict) or set(item) != {
                "task_id", "spent_usd", "elapsed_seconds", "input_tokens", "output_tokens"}:
            raise ValueError("invalid spend task entry")
        ident = item["task_id"]
        if ident not in expected or ident in seen:
            raise ValueError("duplicate/foreign task in spend log")
        seen.add(ident)
        spent, elapsed = item["spent_usd"], item["elapsed_seconds"]
        if (type(spent) not in (float, int) or
                not 0 <= spent <= config["max_usd_per_task"] or
                type(elapsed) is not int or
                not 0 <= elapsed <= config["max_seconds_per_task"]):
            raise ValueError("overspent/over-time task or invalid metrics")
        for k in ("input_tokens", "output_tokens"):
            if type(item[k]) is not int or not 0 <= item[k] <= 100_000_000:
                raise ValueError("token counts must be bounded nonnegative integers")
            totals[k] += item[k]
        totals["usd"] += spent
        totals["seconds"] += elapsed
    totals["usd"] = round(totals["usd"], 6)
    return totals


def evaluate(study_root, baseline_judgments, candidate_judgments,
             baseline_spend, candidate_spend):
    root = Path(study_root).expanduser()
    study = _read(root / "study.json")
    config = _config(study.get("config"))
    if study.get("state") != "PREPARED_NOT_EXECUTED":
        raise ValueError("unsupported study state")
    arms = {}
    queues = {}
    for arm, judgments, spend in (
        ("baseline", baseline_judgments, baseline_spend),
        ("candidate", candidate_judgments, candidate_spend),
    ):
        evaluator = root / arm / "evaluator"
        queue = _read(root / arm / "hunter" / "blind-queue.json")
        key = _read(evaluator / "answer-map.json")
        if historical._sha(queue) != study["hunter_queue_sha256"] or (
                historical._sha(key) != study["answer_map_sha256"]):
            raise ValueError("paired task queue/answer map was modified")
        queues[arm] = queue
        review = historical.score(evaluator, judgments)
        totals = _spent(spend, queue, config)
        arms[arm] = {"scores": review, "recorded_usage": totals}
    n = study["case_count"]
    m = study["repository_count"]
    b, c = arms["baseline"], arms["candidate"]
    candidate_tp = c["scores"]["true_positives"]
    base_tp = b["scores"]["true_positives"]
    return {
        "schema_version": 1, "mode": "paired-web-benchmark",
        "state": "REVIEWER_SUPPLIED_RESULTS_NOT_BLIND_ATTESTED",
        "task_count_per_arm": study["task_count"], "case_count": n,
        "repository_count": m,
        "baseline": b, "candidate": c,
        "delta_true_positives": candidate_tp - base_tp,
        "delta_false_positive_claims": (
            c["scores"]["false_positive_claims"] - b["scores"]["false_positive_claims"]),
        "baseline_usd_per_true_positive": (
            round(b["recorded_usage"]["usd"] / base_tp, 6) if base_tp else None),
        "candidate_usd_per_true_positive": (
            round(c["recorded_usage"]["usd"] / candidate_tp, 6) if candidate_tp else None),
        "minimum_case_diversity_for_exploratory_analysis": n >= 20 and m >= 5,
        "public_uplift_claim_allowed": False,
        "model_runs_executed_by_this_tool": 0,
        "limitations": ("Does not independently verify model/provider spend, actor isolation, "
                        "reviewer independence, source checkout or native PoC. "
                        "Pretrained models may know historical public findings. "
                        "Use private unseen holdout and original evidence before making "
                        "any performance, payment or vulnerability-discovery claims.")
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("prepare")
    a.add_argument("--config", required=True)
    a.add_argument("--catalog", required=True)
    a.add_argument("--out-dir", required=True)
    b = sub.add_parser("compare")
    b.add_argument("--study", required=True)
    b.add_argument("--baseline-judgments", required=True)
    b.add_argument("--candidate-judgments", required=True)
    b.add_argument("--baseline-spend", required=True)
    b.add_argument("--candidate-spend", required=True)
    b.add_argument("--out", required=True)
    arg = p.parse_args(argv)
    try:
        if arg.command == "prepare":
            result = prepare(_read(arg.config), _read(arg.catalog), arg.out_dir)
        else:
            result = evaluate(arg.study, _read(arg.baseline_judgments),
                              _read(arg.candidate_judgments),
                              _read(arg.baseline_spend), _read(arg.candidate_spend))
            _write(arg.out, result)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps(result if arg.command == "prepare" else {
        "out": arg.out, "state": result["state"],
        "delta_true_positives": result["delta_true_positives"],
        "public_uplift_claim_allowed": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
