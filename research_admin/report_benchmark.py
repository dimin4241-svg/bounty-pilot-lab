"""Offline benchmark of generic documentation completeness, not vulnerability discovery."""
import argparse
import json
from pathlib import Path

LABELS = {"supported", "refuted", "unresolved"}

def load(path, allow_empty=False):
    with Path(path).open(encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data,list) or (not data and not allow_empty):
        raise ValueError("Expected a nonempty JSON list")
    return data

def index(rows, fields):
    result = {}
    for row in rows:
        if not isinstance(row,dict) or set(row)!=set(fields):
            raise ValueError("Unexpected record fields")
        if not isinstance(row["id"],str) or not row["id"].strip() or row["id"] in result:
            raise ValueError("Unique nonempty case IDs required")
        result[row["id"]]=row
    return result

def score(tasks, references, answers):
    tasks=index(tasks,("id","question","documents"))
    refs=index(references,("id","label","source_ids"))
    answers=index(answers,("id","label","source_ids","reason"))
    if set(tasks)!=set(refs) or not set(answers)<=set(tasks):
        raise ValueError("Case sets mismatch")
    results=[]
    for key,task in sorted(tasks.items()):
        if not isinstance(task["question"],str) or not task["question"].strip():
            raise ValueError("Question required")
        docs=task["documents"]
        if not isinstance(docs,dict) or not docs or not all(
                isinstance(k,str) and k.strip() and isinstance(v,str) and v.strip()
                for k,v in docs.items()):
            raise ValueError("Named documents required")
        ref=refs[key]
        answer=answers.get(key)
        def sources(record):
            raw=record["source_ids"]
            if not isinstance(raw,list) or not all(isinstance(x,str) for x in raw):
                raise ValueError("source_ids must be a list of strings")
            if len(set(raw))!=len(raw):
                raise ValueError("Repeated source IDs")
            return set(raw)
        required=sources(ref)
        if ref["label"] not in LABELS or not required<=set(docs):
            raise ValueError("Invalid reference")
        correct=complete=False
        if answer is not None:
            cited=sources(answer)
            if answer["label"] not in LABELS:
                raise ValueError("Invalid answer label")
            if not isinstance(answer["reason"],str):
                raise ValueError("Reason must be text")
            correct=answer["label"]==ref["label"]
            complete=bool(answer["reason"].strip()) and required<=cited and cited<=set(docs)
        results.append({"id":key,"answered":answer is not None,"label_correct":correct,
                        "documentation_complete":complete,"passed":correct and complete})
    n=len(results)
    return {"cases":n,"answered":sum(x["answered"] for x in results),
            "passed":sum(x["passed"] for x in results),
            "accuracy":sum(x["passed"] for x in results)/n,"results":results}

def compare(tasks,refs,baseline,candidate):
    a,b=score(tasks,refs,baseline),score(tasks,refs,candidate)
    paired=list(zip(a["results"],b["results"]))
    return {"baseline":a,"candidate":b,"delta":b["accuracy"]-a["accuracy"],
            "improved":sum(not x["passed"] and y["passed"] for x,y in paired),
            "regressed":sum(x["passed"] and not y["passed"] for x,y in paired),
            "no_regression":all(not x["passed"] or y["passed"] for x,y in paired)}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tasks")
    parser.add_argument("references")
    parser.add_argument("answers")
    parser.add_argument("--baseline")
    args=parser.parse_args()
    try:
        tasks,refs=map(load,(args.tasks,args.references))
        answers=load(args.answers, allow_empty=True)
        result=compare(tasks,refs,load(args.baseline, allow_empty=True),answers) if args.baseline else score(tasks,refs,answers)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return 1 if args.baseline and not result["no_regression"] else 0
    except (OSError,ValueError,TypeError) as exc:
        parser.exit(2,f"Error: {exc}\n")

if __name__=="__main__":
    raise SystemExit(main())
