"""Manual knowledge catalog and matched, offline quality comparisons."""
import argparse
import json
from ledger import Ledger

SCHEMA = """
CREATE TABLE IF NOT EXISTS admin_knowledge (
 id TEXT PRIMARY KEY,
 category TEXT NOT NULL CHECK(category IN ('process','documentation','quality','cost','review')),
 title TEXT NOT NULL,
 note TEXT NOT NULL,
 source TEXT NOT NULL,
 created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""
CATEGORIES = ("process","documentation","quality","cost","review")

class Quality(Ledger):
    def __init__(self,path):
        super().__init__(path)
        self.db.executescript(SCHEMA)

    def record(self, entry_id, category, title, note, source):
        if category not in CATEGORIES or not all(x.strip() for x in (entry_id,title,note,source)):
            raise ValueError("Category, identifier, title, note and source are required")
        self.db.execute("INSERT INTO admin_knowledge(id,category,title,note,source) VALUES(?,?,?,?,?)",
                        (entry_id,category,title,note,source))

    def catalog(self, category="all"):
        if category != "all" and category not in CATEGORIES:
            raise ValueError("Unknown category")
        sql = "SELECT id,category,title,note,source,created FROM admin_knowledge"
        args = ()
        if category != "all":
            sql += " WHERE category=?"
            args = (category,)
        keys = ("id","category","title","note","source","created")
        return [dict(zip(keys,r)) for r in self.db.execute(sql+" ORDER BY id",args)]

    def compare(self, suite, version_a, model_a, version_b, model_b):
        def rows(version, model):
            return {r[0]:r[1:] for r in self.db.execute(
                "SELECT case_id,expected,observed,cost_micro FROM evaluations WHERE suite=? AND version=? AND model=?",
                (suite,version,model))}
        with self.transaction():
            a,b = rows(version_a,model_a),rows(version_b,model_b)
        if not a or set(a) != set(b):
            raise ValueError("Both runs must have identical nonempty case sets")
        if any(a[k][0] != b[k][0] for k in a):
            raise ValueError("Reference labels differ")
        def stats(run):
            count = len(run)
            tp = sum(e==1 and o==1 for e,o,c in run.values())
            tn = sum(e==0 and o==0 for e,o,c in run.values())
            fp = sum(e==0 and o==1 for e,o,c in run.values())
            fn = sum(e==1 and o==0 for e,o,c in run.values())
            cost = sum(c for e,o,c in run.values())
            return dict(cases=count,correct=tp+tn,accuracy=(tp+tn)/count,
                        precision=tp/(tp+fp) if tp+fp else None,
                        recall=tp/(tp+fn) if tp+fn else None,
                        false_positive=fp,false_negative=fn,cost_micro=cost)
        x,y = stats(a),stats(b)
        return {"suite":suite,"baseline":{"version":version_a,"model":model_a,**x},
                "candidate":{"version":version_b,"model":model_b,**y},
                "delta":{"accuracy":y["accuracy"]-x["accuracy"],
                         "cost_micro":y["cost_micro"]-x["cost_micro"]},
                "improved_cases":sum(a[k][0]!=a[k][1] and b[k][0]==b[k][1] for k in a),
                "regressed_cases":sum(a[k][0]==a[k][1] and b[k][0]!=b[k][1] for k in a)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db",required=True)
    sub = parser.add_subparsers(dest="action",required=True)
    for action,fields in {
        "record":("entry_id","category","title","note","source"),
        "catalog":("category",),
        "compare":("suite","version_a","model_a","version_b","model_b"),
    }.items():
        p = sub.add_parser(action)
        for field in fields:
            p.add_argument(field)
    args = vars(parser.parse_args())
    db = Quality(args.pop("db"))
    action = args.pop("action")
    try:
        print(json.dumps(getattr(db,action)(**args),ensure_ascii=False,indent=2))
    finally:
        db.close()

if __name__ == "__main__":
    main()
