#!/usr/bin/env python3
"""Offline mechanism-level duplicate risk analysis with explicit uncertainty.

Matches root causes within one target/program, not title similarity or time.
Known records must be supplied with provenance; absent matches NEVER imply novelty.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

FIELDS=("component", "operation", "state_resource", "failure_mode", "invariant")
WEIGHTS={"component":1,"operation":2,"state_resource":3,"failure_mode":4,"invariant":3}
MAX_KNOWN=2000
ID=re.compile(r"^[A-Za-z0-9._:/-]{1,150}$")
REV=re.compile(r"^[0-9a-f]{40}$")
STOP={"the","a","an","of","to","is","are","in","on","for","with","and","or", "_", "."}


def _tokens(value):
    if not isinstance(value,str) or not 1<=len(value)<=240:
        raise ValueError("mechanism field must be a 1..240 character string")
    text=re.sub(r"([a-z0-9])([A-Z])",r"\1 \2",value)
    return tuple(sorted(set(x for x in re.findall(r"[a-z0-9]+",text.lower()) if x not in STOP)))


def _read(path):
    p=Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size>750_000:
        raise ValueError("unavailable/symlinked/oversized input")
    return json.loads(p.read_text(encoding="utf-8"))


def _validate(row):
    if not isinstance(row,dict):
        raise ValueError("report must be object")
    if not isinstance(row.get("id"),str) or not ID.fullmatch(row["id"]):
        raise ValueError("report id invalid")
    if not isinstance(row.get("project"),str) or not ID.fullmatch(row["project"]):
        raise ValueError("project (stable scope identifier) missing")
    revision=row.get("source_revision")
    if revision is not None and (not isinstance(revision,str) or not REV.fullmatch(revision)):
        raise ValueError("invalid optional pinned source revision")
    rc=row.get("root_cause")
    if not isinstance(rc,dict) or set(rc)!=set(FIELDS):
        raise ValueError("root_cause must have exactly component,operation,state_resource,failure_mode,invariant")
    for key in FIELDS:
        _tokens(rc[key])
    if row.get("status") is not None and row.get("status") not in (
        "Confirmed","Duplicate","Accepted","Paid","Rejected","Informational","Open","Other"):
        raise ValueError("unrecognized outcome status")
    for name in ("impact","source_url"):
        if row.get(name) is not None and (not isinstance(row[name],str) or len(row[name])>500):
            raise ValueError("invalid "+name)
    return row


def _similar(a,b):
    s1,s2=set(_tokens(a)),set(_tokens(b))
    if not s1 or not s2:
        return 0.0
    return len(s1&s2)/len(s1|s2)


def _compare(candidate,known):
    if candidate["project"]!=known["project"]:
        return None
    a,b=candidate["root_cause"],known["root_cause"]
    sim={x:round(_similar(a[x],b[x]),3) for x in FIELDS}
    strength=sum(WEIGHTS[x]*sim[x] for x in FIELDS)/sum(WEIGHTS.values())
    exact=(all(sim[x]==1.0 for x in FIELDS))
    core=(sim["failure_mode"]>=0.8 and sim["state_resource"]>=0.65 and
          (sim["operation"]>=0.5 or sim["invariant"]>=0.75))
    weak=(sim["failure_mode"]>=0.6 and (sim["state_resource"]>=0.55 or sim["operation"]>=0.7))
    if exact:
        tier="EXACT_STRUCTURED_ROOT_CAUSE"
    elif core:
        tier="PROBABLE_SAME_MECHANISM_REVIEW"
    elif weak:
        tier="RELATED_MECHANISM_REVIEW"
    else:
        return None
    return {"known_id":known["id"],"tier":tier,"similarity_by_field":sim,
            "weighted_similarity":round(strength,3),"historical_status":known.get("status","Unknown"),
            "known_source":known.get("source_url"),
            "impact_differs":_tokens(candidate.get("impact") or "unspecified") != _tokens(known.get("impact") or "unspecified"),
            "same_source_revision":bool(candidate.get("source_revision") and
                                         candidate.get("source_revision")==known.get("source_revision"))}


def analyze(doc):
    if not isinstance(doc,dict) or doc.get("schema_version")!=1:
        raise ValueError("schema_version=1 required")
    candidate=_validate(doc.get("candidate"))
    known=doc.get("known")
    if not isinstance(known,list) or len(known)>MAX_KNOWN:
        raise ValueError("known must be an array of <=2000 records")
    reviewed=[]; seen=set()
    for row in known:
        item=_validate(row)
        if (item["project"],item["id"]) in seen:
            raise ValueError("duplicate known record")
        seen.add((item["project"],item["id"]))
        if item["id"]==candidate["id"] and item["project"]==candidate["project"]:
            continue
        match=_compare(candidate,item)
        if match:
            reviewed.append(match)
    ordered={"EXACT_STRUCTURED_ROOT_CAUSE":0,"PROBABLE_SAME_MECHANISM_REVIEW":1,
             "RELATED_MECHANISM_REVIEW":2}
    reviewed.sort(key=lambda x:(ordered[x["tier"]],-x["weighted_similarity"],x["known_id"]))
    risk=("REVIEW_LIKELY_DUPLICATE" if any(x["tier"]=="EXACT_STRUCTURED_ROOT_CAUSE" for x in reviewed)
          else "REVIEW_POSSIBLE_DUPLICATE" if reviewed else "NO_LOCAL_MATCH_REMOTE_UNCHECKED")
    fingerprint=json.dumps({"project":candidate["project"],
        "root_cause":{k:list(_tokens(candidate["root_cause"][k])) for k in FIELDS}},sort_keys=True)
    return {"schema_version":1,"candidate_id":candidate["id"],"project":candidate["project"],
       "mechanism_sha256":hashlib.sha256(fingerprint.encode()).hexdigest(),
       "known_considered":len(known),"same_project_known":sum(x["project"]==candidate["project"] for x in known),
       "duplicate_risk":risk,"matches":reviewed[:30],"match_count":len(reviewed),
       "next_action": ("Compare source anchors and actual causes; a different consequence may share a root bug."
                        if reviewed else "Search current contests, known issues, PRs and historic audits externally before claiming novelty."),
       "notice": "Structural/token heuristics may miss duplicates or overmatch; records are unverified user inputs, not Cantina rulings."}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input",required=True,help="candidate + local known-history JSON")
    p.add_argument("--out",help="new private report")
    a=p.parse_args(argv)
    try:
        result=analyze(_read(a.input));payload=json.dumps(result,indent=2,ensure_ascii=False)+"\n"
        if a.out:
            dest=Path(a.out)
            dest.parent.mkdir(parents=True,exist_ok=True)
            with os.fdopen(os.open(str(dest),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"w",encoding="utf-8") as f:
                f.write(payload)
        else:print(payload,end="")
        return 0
    except (OSError,ValueError,TypeError,KeyError) as e:
        print("Error: "+str(e),file=sys.stderr)
        return 2

if __name__=="__main__":
    sys.exit(main())