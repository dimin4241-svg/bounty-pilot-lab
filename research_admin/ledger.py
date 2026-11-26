"""Local administrative ledger. No scanning, model calls or command execution."""
import argparse
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
 id TEXT PRIMARY KEY, limit_micro INTEGER NOT NULL CHECK(limit_micro >= 0),
 note TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'review'
);
CREATE TABLE IF NOT EXISTS charges (
 id TEXT PRIMARY KEY, project TEXT NOT NULL REFERENCES projects(id),
 model TEXT NOT NULL, reserved INTEGER NOT NULL CHECK(reserved >= 0),
 actual INTEGER CHECK(actual >= 0 AND actual <= reserved)
);
CREATE TABLE IF NOT EXISTS artifacts (
 project TEXT NOT NULL REFERENCES projects(id), path TEXT NOT NULL,
 digest TEXT NOT NULL, size INTEGER NOT NULL, PRIMARY KEY(project,path)
);
CREATE TABLE IF NOT EXISTS reviews (
 id INTEGER PRIMARY KEY, project TEXT NOT NULL REFERENCES projects(id),
 outcome TEXT NOT NULL, note TEXT NOT NULL, created TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS evaluations (
 suite TEXT NOT NULL, version TEXT NOT NULL, case_id TEXT NOT NULL,
 model TEXT NOT NULL, expected INTEGER NOT NULL CHECK(expected IN (0,1)),
 observed INTEGER NOT NULL CHECK(observed IN (0,1)),
 cost_micro INTEGER NOT NULL CHECK(cost_micro >= 0),
 PRIMARY KEY(suite,version,case_id,model)
);
"""
OUTCOMES = {"pending","accepted","rejected","duplicate","downgraded","needs_review"}
class Ledger:
    def __init__(self, path):
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def project(self, name, limit_micro, note=""):
        with self.transaction():
            self.db.execute("INSERT INTO projects(id,limit_micro,note) VALUES(?,?,?)",
                            (name,limit_micro,note))

    def reserve(self, name, charge_id, model, maximum):
        if not isinstance(maximum,int) or maximum < 0:
            raise ValueError("Nonnegative integer microdollars required")
        with self.transaction():
            row = self.db.execute("SELECT limit_micro FROM projects WHERE id=?", (name,)).fetchone()
            if row is None:
                raise ValueError("Unknown project")
            used = self.db.execute(
                "SELECT COALESCE(SUM(COALESCE(actual,reserved)),0) FROM charges WHERE project=?",
                (name,)).fetchone()[0]
            if used + maximum > row[0]:
                raise ValueError("Project budget exceeded")
            self.db.execute("INSERT INTO charges VALUES(?,?,?,?,NULL)",
                            (charge_id,name,model,maximum))

    def settle(self, charge_id, actual):
        if not isinstance(actual,int) or actual < 0:
            raise ValueError("Nonnegative integer microdollars required")
        with self.transaction():
            cur = self.db.execute(
                "UPDATE charges SET actual=? WHERE id=? AND actual IS NULL AND reserved>=?",
                (actual,charge_id,actual))
            if cur.rowcount != 1:
                raise ValueError("Unknown, already settled or exceeds reservation")

    @staticmethod
    def fingerprint(root, relative):
        root = Path(root).resolve(strict=True)
        file = (root / relative).resolve(strict=True)
        if not file.is_relative_to(root) or not file.is_file():
            raise ValueError("Artifact must be a regular file inside root")
        h = hashlib.sha256()
        size = 0
        with file.open("rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                h.update(chunk)
                size += len(chunk)
        return h.hexdigest(), size

    def register(self, name, root, relative):
        digest, size = self.fingerprint(root,relative)
        with self.transaction():
            self.db.execute("INSERT INTO artifacts VALUES(?,?,?,?)",
                            (name,relative,digest,size))
        return digest

    def verify(self, name, root, relative):
        row = self.db.execute("SELECT digest,size FROM artifacts WHERE project=? AND path=?",
                              (name,relative)).fetchone()
        if not row:
            raise ValueError("Unknown artifact")
        return self.fingerprint(root,relative) == row

    def review(self, name, outcome, note):
        if outcome not in OUTCOMES or not note.strip():
            raise ValueError("Valid manual review outcome and note required")
        self.db.execute("INSERT INTO reviews(project,outcome,note) VALUES(?,?,?)",
                        (name,outcome,note))

    def evaluate(self, suite, version, case_id, model, expected, observed, cost):
        self.db.execute("INSERT INTO evaluations VALUES(?,?,?,?,?,?,?)",
                        (suite,version,case_id,model,expected,observed,cost))

    def metrics(self):
        rows = self.db.execute("""
        SELECT suite,version,model,COUNT(*),SUM(expected=observed),
        SUM(expected=0 AND observed=1),SUM(expected=1 AND observed=0),SUM(cost_micro)
        FROM evaluations GROUP BY suite,version,model ORDER BY suite,version,model
        """)
        keys = ("suite","version","model","cases","correct","false_positive","false_negative","cost_micro")
        return [dict(zip(keys,row)) for row in rows]

    def summary(self):
        rows = self.db.execute("""
        SELECT p.id,p.limit_micro,
        COALESCE((SELECT SUM(actual) FROM charges WHERE project=p.id),0),
        COALESCE((SELECT SUM(reserved) FROM charges WHERE project=p.id AND actual IS NULL),0),
        (SELECT COUNT(*) FROM artifacts WHERE project=p.id),
        (SELECT COUNT(*) FROM reviews WHERE project=p.id)
        FROM projects p ORDER BY p.id
        """)
        keys = ("project","limit_micro","spent_micro","reserved_micro","artifacts","reviews")
        return {"projects":[dict(zip(keys,row)) for row in rows],"metrics":self.metrics()}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    sub = parser.add_subparsers(dest="action", required=True)
    for action, fields in {
        "project":[("name",str),("limit_micro",int),("note",str)],
        "reserve":[("name",str),("charge_id",str),("model",str),("maximum",int)],
        "settle":[("charge_id",str),("actual",int)],
        "register":[("name",str),("root",str),("relative",str)],
        "verify":[("name",str),("root",str),("relative",str)],
        "review":[("name",str),("outcome",str),("note",str)],
        "evaluate":[("suite",str),("version",str),("case_id",str),("model",str),
                    ("expected",int),("observed",int),("cost",int)],
        "summary":[],
    }.items():
        command = sub.add_parser(action)
        for field, kind in fields:
            command.add_argument(field,type=kind)
    args = vars(parser.parse_args())
    ledger = Ledger(args.pop("db"))
    action = args.pop("action")
    try:
        result = getattr(ledger,action)(**args)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return 1 if action == "verify" and result is False else 0
    finally:
        ledger.close()

if __name__ == "__main__":
    raise SystemExit(main())
