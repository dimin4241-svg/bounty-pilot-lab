"""Offline completeness checks for manually authored technical review documents."""
import argparse
import json
import os
from pathlib import Path

SECTIONS = {
    "root_cause": "Underlying cause, distinguished from symptom",
    "code_location": "Version and location in reviewed material",
    "expected_behavior": "Expected behavior and its documented basis",
    "actual_behavior": "Observed behavior",
    "preconditions": "Context and assumptions",
    "evidence": "References to manually reviewed material",
    "negative_control": "Control result or reason unavailable",
    "reproducibility": "Independent reproduction status",
    "impact": "Observed consequences, not speculation",
    "scope": "Applicable authorization and limitations",
    "novelty": "Prior documentation review",
    "severity": "Manual assessment and rationale",
    "remediation": "Proposed corrective action",
    "limitations": "Unresolved questions and limitations",
    "independent_review": "Manual reviewer decision",
}
STATUSES = {"unresolved", "documented", "not_applicable"}
# Missing or inapplicable core observations cannot constitute a complete review.
CORE = {"root_cause", "expected_behavior", "actual_behavior", "evidence",
        "independent_review", "scope"}

def template():
    return {"schema_version":1,"review_id":"","reviewer":"",
            "sections":{k:{"status":"unresolved","note":"","sources":[]} for k in SECTIONS}}

def evaluate(document):
    if not isinstance(document,dict) or set(document)!={"schema_version","review_id","reviewer","sections"}:
        raise ValueError("Unexpected document structure")
    if type(document["schema_version"]) is not int or document["schema_version"]!=1:
        raise ValueError("Unsupported schema version")
    if not all(isinstance(document[k],str) for k in ("review_id","reviewer")):
        raise ValueError("Review identifiers must be text")
    sections=document["sections"]
    if not isinstance(sections,dict) or set(sections)!=set(SECTIONS):
        raise ValueError("Exactly the documented section keys are required")
    missing=[]
    unresolved=[]
    for key,record in sections.items():
        if not isinstance(record,dict) or set(record)!={"status","note","sources"}:
            raise ValueError("Invalid section: "+key)
        state,note,sources=(record[k] for k in ("status","note","sources"))
        if not isinstance(state,str) or state not in STATUSES or not isinstance(note,str):
            raise ValueError("Invalid status or note: "+key)
        if not isinstance(sources,list) or not all(isinstance(s,str) and s.strip() for s in sources):
            raise ValueError("Sources must be nonempty reference strings: "+key)
        if len(sources)!=len(set(sources)):
            raise ValueError("Duplicate references: "+key)
        if not note.strip() or (state=="documented" and not sources):
            missing.append(key)
        if state=="unresolved" or (state=="not_applicable" and key in CORE):
            unresolved.append(key)
    missing_identity=[k for k in ("review_id","reviewer") if not document[k].strip()]
    return {
        "review_id":document["review_id"],
        "sections":len(SECTIONS),
        "missing_fields":sorted(missing),
        "missing_identity":missing_identity,
        "unresolved_sections":sorted(unresolved),
        "documentation_complete":not (missing or unresolved or missing_identity),
        "technical_validity":"not_assessed",
        "notice":"Completeness only. References, claims and reviewer identity are not verified."
    }

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest="action",required=True)
    sub.add_parser("template").add_argument("output")
    sub.add_parser("check").add_argument("input")
    args=parser.parse_args()
    try:
        if args.action=="template":
            with os.fdopen(os.open(Path(args.output),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),"w",encoding="utf-8") as f:
                json.dump(template(),f,ensure_ascii=False,indent=2)
                f.write("\n")
            print(args.output)
            return 0
        with Path(args.input).open(encoding="utf-8") as f:
            result=evaluate(json.load(f))
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return 0 if result["documentation_complete"] else 1
    except (ValueError,OSError) as exc:
        parser.exit(2,f"Error: {exc}\n")

if __name__=="__main__":
    raise SystemExit(main())
