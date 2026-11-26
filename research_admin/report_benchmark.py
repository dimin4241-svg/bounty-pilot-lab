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

def adjudicate(tasks, references, answers, reviews):
    """Combine structural scores with independent, manually entered prose reviews."""
    result = score(tasks, references, answers)
    decisions = index(reviews, ("id", "decision", "reviewer", "note"))
    answered = {row["id"] for row in result["results"] if row["answered"]}
    if not set(decisions) <= answered:
        raise ValueError("Review must refer to a submitted answer")
    for record in decisions.values():
        if record["decision"] not in ("accepted", "rejected", "uncertain"):
            raise ValueError("Unknown review decision")
        if not all(isinstance(record[k], str) and record[k].strip()
                   for k in ("reviewer", "note")):
            raise ValueError("Reviewer and explanation required")
    for row in result["results"]:
        review = decisions.get(row["id"])
        decision = review["decision"] if review else "pending"
        row["manual_decision"] = decision
        row["reviewed_pass"] = row["passed"] and decision == "accepted"
    result["reviewed_count"] = len(decisions)
    result["review_complete"] = set(decisions) == answered and all(
        d["decision"] != "uncertain" for d in decisions.values())
    result["reviewed_passed"] = sum(row["reviewed_pass"] for row in result["results"])
    result["reviewed_accuracy"] = result["reviewed_passed"] / result["cases"]
    result["notice"] = ("Review decisions are human attestations, not automatically "
                        "verified facts or measurements of vulnerability discovery.")
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tasks")
    parser.add_argument("references")
    parser.add_argument("answers")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--baseline")
    mode.add_argument("--reviews", help="Independent manual review decisions (JSON list)")
    args=parser.parse_args()
    try:
        tasks,refs=map(load,(args.tasks,args.references))
        answers=load(args.answers, allow_empty=True)
        if args.reviews:
            result = adjudicate(tasks, refs, answers, load(args.reviews, allow_empty=True))
        else:
            result = compare(tasks,refs,load(args.baseline, allow_empty=True),answers) if args.baseline else score(tasks,refs,answers)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        if args.reviews and not result["review_complete"]:
            return 1
        return 1 if args.baseline and not result["no_regression"] else 0
    except (OSError,ValueError,TypeError) as exc:
        parser.exit(2,f"Error: {exc}\n")

if __name__=="__main__":
    raise SystemExit(main())
