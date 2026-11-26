#!/usr/bin/env python3
"""Private offline research bookkeeping. No model, target, or network execution."""
import argparse
import hashlib
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path

IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}\Z")
REV = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
MAX_AMOUNT = 10**12  # integer micro-USD
OUTCOMES = ("accepted", "duplicate", "excluded", "insufficient", "rejected", "pending")


def ident(value):
    if not isinstance(value, str) or not IDENT.fullmatch(value):
        raise ValueError("invalid identifier")
    return value


def amount(value):
    if type(value) is not int or not 0 <= value <= MAX_AMOUNT:
        raise ValueError("amount must be bounded integer micro-USD")
    return value


def digest(path):
    p = Path(path)
    if not p.is_file() or p.is_symlink() or p.stat().st_size > 20 * 1024 * 1024:
        raise ValueError("bounded regular evidence file required")
    return hashlib.sha256(p.read_bytes()).hexdigest()


SCHEMA = """
CREATE TABLE session (id INTEGER PRIMARY KEY CHECK(id=1), revision TEXT NOT NULL,
  scope_sha TEXT NOT NULL, budget INTEGER NOT NULL);
CREATE TABLE reservations (id TEXT PRIMARY KEY, model TEXT NOT NULL,
  ceiling INTEGER NOT NULL, actual INTEGER);
CREATE TABLE reviews (id TEXT PRIMARY KEY, author TEXT NOT NULL, reviewer TEXT NOT NULL,
  candidate_sha TEXT NOT NULL, control_sha TEXT NOT NULL, verdict TEXT NOT NULL);
CREATE TABLE feedback (seq INTEGER PRIMARY KEY, id TEXT NOT NULL, outcome TEXT NOT NULL,
  receipt_sha TEXT NOT NULL, UNIQUE(id, outcome, receipt_sha));
"""


def initialize(db, revision, scope, budget, confirmed=False):
    if confirmed is not True or not isinstance(revision, str) or not REV.fullmatch(revision):
        raise ValueError("reviewed scope and pinned revision required")
    scope_sha = digest(scope)
    amount(budget)
    p = Path(db)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    try:
        with sqlite3.connect(p) as con:
            con.executescript(SCHEMA)
            con.execute("INSERT INTO session VALUES (1,?,?,?)", (revision, scope_sha, budget))
    except Exception:
        p.unlink()
        raise


@contextmanager
def opened(db, scope, revision):
    p = Path(db)
    if not p.is_file() or p.is_symlink() or p.stat().st_mode & 0o077:
        raise ValueError("private existing ledger required")
    con = sqlite3.connect(p, timeout=10, isolation_level=None)
    try:
        con.execute("BEGIN IMMEDIATE")
        row = con.execute("SELECT revision,scope_sha,budget FROM session WHERE id=1").fetchone()
        if row is None or row[:2] != (revision, digest(scope)):
            raise ValueError("scope or revision changed; create a new session")
        yield con, row[2]
        con.execute("COMMIT")
    except Exception:
        if con.in_transaction:
            con.execute("ROLLBACK")
        raise
    finally:
        con.close()


def totals(con, budget):
    paid, held = con.execute("""
        SELECT coalesce(sum(actual),0),
               coalesce(sum(CASE WHEN actual IS NULL THEN ceiling ELSE 0 END),0)
        FROM reservations""").fetchone()
    return {"budget_micro_usd": budget, "settled_micro_usd": paid,
            "reserved_micro_usd": held, "available_micro_usd": max(0, budget-paid-held),
            "over_budget": paid+held > budget}


def reserve(con, budget, job, model, ceiling):
    ident(job)
    ident(model)
    amount(ceiling)
    status = totals(con, budget)
    if ceiling == 0 or status["over_budget"] or ceiling > status["available_micro_usd"]:
        raise ValueError("budget reservation denied")
    con.execute("INSERT INTO reservations VALUES (?,?,?,NULL)", (job, model, ceiling))


def settle(con, job, actual):
    ident(job)
    amount(actual)
    # Preserve actual spend even if a provider charged more than reserved.
    changed = con.execute("UPDATE reservations SET actual=? WHERE id=? AND actual IS NULL",
                          (actual, job)).rowcount
    if changed != 1:
        raise ValueError("unknown or already settled reservation")


def review(con, case, author, reviewer, candidate, control, verdict):
    for value in (case, author, reviewer):
        ident(value)
    if author == reviewer or verdict not in ("supports", "refutes", "inconclusive"):
        raise ValueError("distinct reviewer and valid verdict required")
    c, n = digest(candidate), digest(control)
    if c == n:
        raise ValueError("candidate and control must differ")
    con.execute("INSERT INTO reviews VALUES (?,?,?,?,?,?)",
                (case, author, reviewer, c, n, verdict))


def feedback(con, case, outcome, receipt):
    ident(case)
    if outcome not in OUTCOMES:
        raise ValueError("unknown outcome")
    con.execute("INSERT INTO feedback (id,outcome,receipt_sha) VALUES (?,?,?)", (case, outcome, digest(receipt)))


def status(con, budget):
    result = totals(con, budget)
    result["reviews"] = dict(con.execute("SELECT verdict,count(*) FROM reviews GROUP BY verdict"))
    result["feedback"] = dict(con.execute("""
        SELECT outcome,count(*) FROM feedback WHERE seq IN
        (SELECT max(seq) FROM feedback GROUP BY id) GROUP BY outcome"""))
    result["feedback_events"] = con.execute("SELECT count(*) FROM feedback").fetchone()[0]
    result["pending_reservations"] = [
        {"id": job, "model": model, "ceiling_micro_usd": ceiling}
        for job, model, ceiling in con.execute(
            "SELECT id,model,ceiling FROM reservations WHERE actual IS NULL ORDER BY id")]
    result["by_model"] = [
        {"model": model, "settled_micro_usd": paid, "reserved_micro_usd": held}
        for model, paid, held in con.execute("""
        SELECT model,coalesce(sum(actual),0),
               coalesce(sum(CASE WHEN actual IS NULL THEN ceiling ELSE 0 END),0)
        FROM reservations GROUP BY model ORDER BY model""")]
    result["independently_verified_by_ledger"] = 0
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--revision", required=True)
    sub = parser.add_subparsers(dest="action", required=True)
    init = sub.add_parser("init")
    init.add_argument("--budget", type=int, required=True)
    init.add_argument("--confirm-reviewed-scope", action="store_true")
    r = sub.add_parser("reserve")
    r.add_argument("job")
    r.add_argument("model")
    r.add_argument("ceiling", type=int)
    s = sub.add_parser("settle")
    s.add_argument("job")
    s.add_argument("actual", type=int)
    v = sub.add_parser("review")
    for field in ("case", "author", "reviewer", "candidate", "control"):
        v.add_argument(field)
    v.add_argument("verdict", choices=("supports", "refutes", "inconclusive"))
    f = sub.add_parser("feedback")
    f.add_argument("case")
    f.add_argument("outcome", choices=OUTCOMES)
    f.add_argument("receipt")
    sub.add_parser("status")
    a = parser.parse_args(argv)
    try:
        if a.action == "init":
            initialize(a.db, a.revision, a.scope, a.budget, a.confirm_reviewed_scope)
        with opened(a.db, a.scope, a.revision) as (con, budget):
            if a.action == "reserve":
                reserve(con, budget, a.job, a.model, a.ceiling)
            elif a.action == "settle":
                settle(con, a.job, a.actual)
            elif a.action == "review":
                review(con, a.case, a.author, a.reviewer, a.candidate, a.control, a.verdict)
            elif a.action == "feedback":
                feedback(con, a.case, a.outcome, a.receipt)
            print(json.dumps(status(con, budget), sort_keys=True))
    except (ValueError, OSError, sqlite3.Error) as exc:
        parser.exit(2, "research-ledger: " + str(exc) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
