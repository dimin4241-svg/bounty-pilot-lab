"""Manual, offline review journal. No agent execution or network access."""
import argparse
import json
import sqlite3

from ledger import Ledger

SCHEMA = """
CREATE TABLE IF NOT EXISTS admin_journal (
 project TEXT NOT NULL REFERENCES projects(id),
 entry_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('observation','assumption','question','control','limitation')),
 description TEXT NOT NULL,
 source TEXT NOT NULL,
 PRIMARY KEY(project,entry_id)
);
CREATE TABLE IF NOT EXISTS admin_journal_review (
 id INTEGER PRIMARY KEY,
 project TEXT NOT NULL,
 entry_id TEXT NOT NULL,
 decision TEXT NOT NULL CHECK(decision IN ('open','supported','refuted','deferred')),
 reviewer TEXT NOT NULL,
 reason TEXT NOT NULL,
 created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(project,entry_id) REFERENCES admin_journal(project,entry_id)
);
"""
KINDS = ("observation","assumption","question","control","limitation")
DECISIONS = ("open","supported","refuted","deferred")

class Journal(Ledger):
    def __init__(self,path):
        super().__init__(path)
        self.db.executescript(SCHEMA)

    def add(self,project,entry_id,kind,description,source):
        if kind not in KINDS or not all(x.strip() for x in
                (project,entry_id,description,source)):
            raise ValueError("Kind, identifier, description and source required")
        self.db.execute("INSERT INTO admin_journal VALUES(?,?,?,?,?)",
                        (project,entry_id,kind,description,source))

    def decide(self,project,entry_id,decision,reviewer,reason):
        if decision not in DECISIONS or not reviewer.strip() or not reason.strip():
            raise ValueError("Decision, reviewer and reason required")
        self.db.execute("""
            INSERT INTO admin_journal_review(project,entry_id,decision,reviewer,reason)
            VALUES(?,?,?,?,?)
        """,(project,entry_id,decision,reviewer,reason))

    def handoff(self,project):
        with self.transaction():
            if not self.db.execute("SELECT 1 FROM projects WHERE id=?",(project,)).fetchone():
                raise ValueError("Unknown project")
            keys = ("entry_id","kind","description","source","decision","reviewer","reason")
            rows = self.db.execute("""
                SELECT j.entry_id,j.kind,j.description,j.source,
                       COALESCE(r.decision,'open'),r.reviewer,r.reason
                FROM admin_journal j
                LEFT JOIN admin_journal_review r ON r.id=(
                  SELECT MAX(id) FROM admin_journal_review
                  WHERE project=j.project AND entry_id=j.entry_id)
                WHERE j.project=? ORDER BY j.entry_id
            """,(project,))
            entries = [dict(zip(keys,row)) for row in rows]
            history = [dict(zip(("entry_id","decision","reviewer","reason","created"),row))
                       for row in self.db.execute("""
                SELECT entry_id,decision,reviewer,reason,created
                FROM admin_journal_review WHERE project=? ORDER BY id
            """,(project,))]
        counts = {d:sum(e["decision"]==d for e in entries) for d in DECISIONS}
        return {"project":project,"entries":entries,"history":history,"counts":counts,
                "review_complete":bool(entries) and counts["open"]==0 and counts["deferred"]==0,
                "notice":"Manual attestations only; not proof of technical findings."}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db",required=True)
    sub=parser.add_subparsers(dest="action",required=True)
    for action,fields in {
        "add":("project","entry_id","kind","description","source"),
        "decide":("project","entry_id","decision","reviewer","reason"),
        "handoff":("project",),
    }.items():
        p=sub.add_parser(action)
        for field in fields:
            p.add_argument(field)
    args=vars(parser.parse_args())
    action=args.pop("action")
    db=Journal(args.pop("db"))
    try:
        print(json.dumps(getattr(db,action)(**args),ensure_ascii=False,indent=2))
    except (ValueError,sqlite3.Error,OSError) as exc:
        parser.exit(1,f"Error: {exc}\n")
    finally:
        db.close()

if __name__=="__main__":
    main()
