"""Manual project administration and a static, local status report."""
import argparse
import html
import json
import os
from pathlib import Path

from ledger import Ledger

SCHEMA = """
CREATE TABLE IF NOT EXISTS admin_checkpoints (
 project TEXT NOT NULL REFERENCES projects(id),
 name TEXT NOT NULL,
 decision TEXT NOT NULL CHECK(decision IN ('approved','blocked')),
 reviewer TEXT NOT NULL,
 note TEXT NOT NULL,
 changed TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(project,name)
);
CREATE TABLE IF NOT EXISTS admin_events (
 id INTEGER PRIMARY KEY,
 project TEXT NOT NULL REFERENCES projects(id),
 event TEXT NOT NULL,
 actor TEXT NOT NULL,
 note TEXT NOT NULL,
 created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""
REQUIRED = ("authorization", "data_handling", "review")
TRANSITIONS = {
    "review": {"active", "archived"},
    "active": {"paused", "review"},
    "paused": {"active", "review", "archived"},
    "archived": set(),
}

class Workflow(Ledger):
    def __init__(self, path):
        super().__init__(path)
        self.db.executescript(SCHEMA)

    def _status(self, project):
        row = self.db.execute("SELECT status FROM projects WHERE id=?", (project,)).fetchone()
        if row is None:
            raise ValueError("Unknown project")
        return row[0]

    @staticmethod
    def _validate(actor, note):
        if not actor.strip() or not note.strip():
            raise ValueError("Reviewer and justification required")

    def _event(self, project, event, actor, note):
        self.db.execute("INSERT INTO admin_events(project,event,actor,note) VALUES(?,?,?,?)",
                        (project,event,actor,note))

    def checkpoint(self, project, name, decision, reviewer, note):
        self._validate(reviewer,note)
        if name not in REQUIRED or decision not in ("approved","blocked"):
            raise ValueError("Unknown checkpoint or decision")
        with self.transaction():
            state = self._status(project)
            if state == "archived":
                raise ValueError("Project is archived")
            self.db.execute("""
                INSERT INTO admin_checkpoints(project,name,decision,reviewer,note)
                VALUES(?,?,?,?,?) ON CONFLICT(project,name) DO UPDATE SET
                decision=excluded.decision, reviewer=excluded.reviewer,
                note=excluded.note, changed=CURRENT_TIMESTAMP
            """,(project,name,decision,reviewer,note))
            self._event(project,"checkpoint:"+name+":"+decision,reviewer,note)
            if decision == "blocked" and state == "active":
                self.db.execute("UPDATE projects SET status='paused' WHERE id=?", (project,))
                self._event(project,"active->paused",reviewer,"Checkpoint blocked: "+name)

    def transition(self, project, target, actor, note):
        self._validate(actor,note)
        with self.transaction():
            old = self._status(project)
            if target not in TRANSITIONS.get(old,set()):
                raise ValueError("Invalid state transition")
            if target == "active":
                approved = {r[0] for r in self.db.execute(
                    "SELECT name FROM admin_checkpoints WHERE project=? AND decision='approved'",
                    (project,))}
                if not set(REQUIRED).issubset(approved):
                    raise ValueError("Required manual approvals missing")
            if target == "archived":
                pending = self.db.execute(
                    "SELECT COUNT(*) FROM charges WHERE project=? AND actual IS NULL",
                    (project,)).fetchone()[0]
                if pending:
                    raise ValueError("Settle outstanding reservations before archiving")
            self.db.execute("UPDATE projects SET status=? WHERE id=?", (target,project))
            self._event(project,old+"->"+target,actor,note)

    def snapshot(self):
        with self.transaction():
            data = self.summary()
            for item in data["projects"]:
                name = item["project"]
                item["status"] = self._status(name)
                rows = dict(self.db.execute(
                    "SELECT name,decision FROM admin_checkpoints WHERE project=?", (name,)))
                item["checkpoints"] = {key:rows.get(key,"pending") for key in REQUIRED}
                item["remaining_micro"] = item["limit_micro"]-item["spent_micro"]-item["reserved_micro"]
            return data

    def history(self, project):
        self._status(project)
        keys = ("id","event","actor","note","created")
        return [dict(zip(keys,row)) for row in self.db.execute(
            "SELECT id,event,actor,note,created FROM admin_events WHERE project=? ORDER BY id",
            (project,))]

def render(data):
    def esc(value):
        return html.escape(str(value),quote=True)
    def money(value):
        sign = "-" if value < 0 else ""
        whole, fraction = divmod(abs(value),1000000)
        return f"{sign}${whole:,}.{fraction:06d}"
    def table(headers, rows):
        return "<table><thead><tr>"+"".join("<th>"+esc(h)+"</th>" for h in headers)+"</tr></thead><tbody>"+ "".join("<tr>"+"".join("<td>"+esc(v)+"</td>" for v in row)+"</tr>" for row in rows)+"</tbody></table>"
    projects = [(p["project"],p["status"],money(p["limit_micro"]),
                 money(p["spent_micro"]),money(p["reserved_micro"]),money(p["remaining_micro"]),
                 ", ".join(k+": "+v for k,v in p["checkpoints"].items()))
                for p in data["projects"]]
    metrics = [(m["suite"],m["version"],m["model"],m["cases"],m["correct"],
                m["false_positive"],m["false_negative"],money(m["cost_micro"]))
               for m in data["metrics"]]
    return """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Local research administration</title>
<style>body{font:15px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;color:#172033;background:#f8fafc}h1{font-size:30px}table{border-collapse:collapse;width:100%;background:white}th,td{padding:12px;text-align:left;border-bottom:1px solid #dce2ea}th{background:#e6edf5}section{overflow:auto;margin:24px 0}small{color:#526174}</style>
<h1>Local research administration</h1><p>Read-only snapshot of manually entered records. Not a security assessment.</p><section><h2>Projects and budget</h2>"""+table(
        ("Project","Status","Limit","Spent","Reserved","Remaining","Checkpoints"),projects)+"""
</section><section><h2>Offline evaluation counts</h2>"""+table(
        ("Suite","Version","Model","Cases","Correct","FP","FN","Cost"),metrics)+"""
</section><small>Compare only equivalent case sets. No network or live updates.</small></html>"""

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db",required=True)
    sub = parser.add_subparsers(dest="action",required=True)
    for action, fields in {
        "checkpoint":("project","name","decision","reviewer","note"),
        "transition":("project","target","actor","note"),
        "history":("project",),
        "snapshot":(),
        "dashboard":("output",),
    }.items():
        p = sub.add_parser(action)
        for field in fields:
            p.add_argument(field)
    args = vars(parser.parse_args())
    db = Workflow(args.pop("db"))
    action = args.pop("action")
    try:
        if action == "dashboard":
            path = Path(args["output"])
            if path.suffix.lower() != ".html":
                raise ValueError("Output must be an HTML file")
            with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w", encoding="utf-8") as f:
                f.write(render(db.snapshot()))
            print(str(path))
        else:
            print(json.dumps(getattr(db,action)(**args),ensure_ascii=False,indent=2))
    finally:
        db.close()

if __name__ == "__main__":
    main()
