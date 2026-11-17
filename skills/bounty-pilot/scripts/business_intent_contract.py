#!/usr/bin/env python3
"""Extract and anchor reviewed business invariants in local protocol documents.

Normative language produces only candidate requirements. A reviewer must cite
exact source/document spans before any discrepancy is called a hypothesis.
No network, model, target execution or hidden inferred business guarantees.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

PIN = re.compile(r"[0-9a-f]{40}\Z")
ID = re.compile(r"[A-Z][A-Z0-9_-]{2,60}\Z")
STRONG = re.compile(r"\b(?:must|shall|never|always|only|prohibited|required|ensures?|guarantees?)\b|"
                    r"(?:должен|должна|должны|обязан|обязана|только|всегда|никогда|нельзя|запрещен|гарантир)",re.I)
WEAK = re.compile(r"\b(?:should|may|might|can|expected|intended|supports?|designed|when|after)\b|"
                  r"(?:может|рекоменд|ожидает|предполагает|после|при|позволяет|поддержива)",re.I)
KINDS = {"authorization", "fund_isolation", "trigger_liveness", "mode_semantics",
         "accrual", "asset_identity", "lifecycle_rights", "recovery", "other"}
MAX_BYTES = 200000


def _file(root, rel):
    if not isinstance(rel,str) or len(rel)>240 or "\\" in rel:
        raise ValueError("bad relative file path")
    p=Path(rel)
    if p.is_absolute() or not p.parts or any(part in (".", "..") for part in p.parts):
        raise ValueError("absolute/traversal file path forbidden")
    base=Path(root).resolve()
    full=base/p
    if full.is_symlink() or not full.is_file() or full.stat().st_size > MAX_BYTES:
        raise ValueError("unavailable/symlinked/oversized file: "+rel)
    if not full.resolve().is_relative_to(base):
        raise ValueError("path escapes repository")
    data=full.read_bytes()
    return data.decode("utf-8"),hashlib.sha256(data).hexdigest()


def _git_sha(repo):
    # Disable project-supplied fsmonitor/hooks for even a read-only command.
    env={"PATH":os.environ.get("PATH","/usr/bin:/bin"),"HOME":"/nonexistent",
         "GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null", "GIT_OPTIONAL_LOCKS":"0"}
    done=subprocess.run(["git","-C",str(Path(repo).resolve()),"--no-optional-locks",
        "-c","core.fsmonitor=false","-c","core.hooksPath=/dev/null", "rev-parse","HEAD"],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10,env=env,check=False)
    if done.returncode:
        raise ValueError("cannot verify repository revision")
    sha=done.stdout.strip()
    if not PIN.fullmatch(sha):
        raise ValueError("invalid git revision")
    return sha


def extract(repo,docs,max_items=100):
    if not 1<=len(docs)<=20 or not 1<=max_items<=250:
        raise ValueError("need 1..20 docs, 1..250 max items")
    sha=_git_sha(repo)
    out=[]
    for path in docs:
        if not path.endswith((".md",".txt",".rst")):
            raise ValueError("documentation must be markdown/txt/rst")
        text,digest=_file(repo,path)
        for index,line in enumerate(text.splitlines(),1):
            line=line.strip()
            if not 20<=len(line)<=750 or line.startswith(("#", "```", "|", "<!--")):
                continue
            strength="strong" if STRONG.search(line) else "weak" if WEAK.search(line) else None
            if strength:
                out.append({"basis":{"file":path,"line":index,"quote":line,"sha256":digest},
                    "cue_strength":strength,"status":"DOCUMENTATION_CANDIDATE_REVIEW_REQUIRED"})
    return {"schema_version":1,"source_revision":sha,"requirements":out[:max_items],
        "truncated":len(out)>max_items,"description": (
          "Textual candidates are NOT interpreted security promises; docs may be marketing, stale, or untrusted.")}


def _anchor(repo,row,doc=False):
    if not isinstance(row,dict) or set(row) != ({"file","line","quote","sha256"} if doc else {"file","line","needle","sha256"}):
        raise ValueError("anchor missing fields")
    path=row["file"]
    text,digest=_file(repo,path)
    if digest!=row["sha256"]:
        raise ValueError("anchor file SHA mismatch: "+path)
    line=row["line"]
    lines=text.splitlines()
    if type(line) is not int or line<1 or line>len(lines):
        raise ValueError("invalid anchor line number")
    key="quote" if doc else "needle"
    value=row[key]
    if not isinstance(value,str) or len(value)<3 or len(value)>1500:
        raise ValueError("anchor quote/needle invalid")
    if (lines[line-1].strip()!=value.strip()) if doc else (value not in lines[line-1]):
        raise ValueError("anchor text does not match pinned source at line")


def verify(repo,manifest):
    if not isinstance(manifest,dict) or manifest.get("schema_version")!=1:
        raise ValueError("schema_version=1 required")
    revision=manifest.get("source_revision")
    if not isinstance(revision,str) or not PIN.fullmatch(revision):
        raise ValueError("40-character source_revision required")
    if revision!=_git_sha(repo):
        raise ValueError("manifest revision does not match local checkout")
    reqs=manifest.get("requirements")
    if not isinstance(reqs,list) or not 1<=len(reqs)<=100:
        raise ValueError("1..100 reviewed requirements required")
    seen=set(); out=[]
    for req in reqs:
        if not isinstance(req,dict):
            raise ValueError("requirement object expected")
        name=req.get("id")
        if not isinstance(name,str) or not ID.fullmatch(name) or name in seen:
            raise ValueError("missing/duplicate requirement id")
        seen.add(name)
        if req.get("kind") not in KINDS:
            raise ValueError("unsupported requirement kind")
        _anchor(repo,req.get("basis"),doc=True)
        refs=req.get("source_anchors")
        if not isinstance(refs,list) or not 1<=len(refs)<=8:
            raise ValueError("requirement must cite at least one source implementation anchor")
        for ref in refs:
            _anchor(repo,ref)
        if not isinstance(req.get("expected_behavior"),str) or len(req["expected_behavior"].strip())<15:
            raise ValueError("explain expected behavior")
        if not isinstance(req.get("negative_control"),str) or len(req["negative_control"].strip())<15:
            raise ValueError("explain safe negative control")
        reviewed=req.get("operator_reviewed") is True
        out.append({"id":name,"kind":req["kind"],"documentation":req["basis"]["file"],
            "code_anchors":len(refs),"status":(
                 "SOURCE_ANCHORED_REVIEWED_INTENT_NOT_VERIFIED" if reviewed else "INTENT_NEEDS_OPERATOR_REVIEW"),
            "scenario":req.get("scenario", "requires native reproduction"),
            "expected_behavior":req["expected_behavior"],
            "negative_control":req["negative_control"]})
    return {"schema_version":1,"source_revision":revision,"requirements":out,
       "notice":"Anchor checks prove bytes and revision, never semantic correctness, deployed reachability or a security impact."}


def compare(review_result,observations):
    if not isinstance(observations,dict) or observations.get("source_revision")!=review_result["source_revision"]:
        raise ValueError("observations must match pinned revision")
    allowed={r["id"]:r for r in review_result["requirements"]}
    if not isinstance(observations.get("results"),list) or len(observations["results"])>100:
        raise ValueError("results must be a bounded list")
    output=[]; seen=set()
    for item in observations["results"]:
        if not isinstance(item,dict):
            raise ValueError("observation must be object")
        ident=item.get("requirement_id")
        if ident not in allowed or ident in seen:
            raise ValueError("unknown/duplicate requirement id")
        seen.add(ident)
        cand=item.get("candidate"); ctrl=item.get("negative_control")
        if not isinstance(cand,dict) or not isinstance(ctrl,dict):
            raise ValueError("both candidate and negative_control required")
        if type(cand.get("satisfies")) is not bool or type(ctrl.get("satisfies")) is not bool:
            raise ValueError("explicit observed satisfaction booleans required")
        status="INCONCLUSIVE"
        if allowed[ident]["status"]=="SOURCE_ANCHORED_REVIEWED_INTENT_NOT_VERIFIED":
            if not cand["satisfies"] and ctrl["satisfies"]:
                status="REPORTED_INTENT_CONFLICT_REQUIRES_NATIVE_PAIR"
            elif cand["satisfies"] and ctrl["satisfies"]:
                status="NO_CONFLICT_IN_SUPPLIED_OBSERVATIONS"
        output.append({"requirement_id":ident,"status":status,"candidate_satisfies":cand["satisfies"],
                       "negative_control_satisfies":ctrl["satisfies"],
                       "missing_evidence": ["actual executable candidate/control source", "repeatable receipt",
                                            "authorized deployed applicability", "independent economic impact"]})
    return {"schema_version":1,"source_revision":review_result["source_revision"],"comparisons":output,
            "notice":"Observations are self-reported and not independently authenticated."}


def _read_json(path):
    p=Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size>MAX_BYTES:
        raise ValueError("bad JSON input")
    return json.loads(p.read_text(encoding="utf-8"))


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest="mode",required=True)
    x=sub.add_parser("extract",help="source-pinned local normative language candidates")
    x.add_argument("--repo",required=True); x.add_argument("--document",action="append",required=True)
    x.add_argument("--limit",type=int,default=100)
    x.add_argument("--out",help="create-only output")
    x=sub.add_parser("verify",help="verify reviewed source+documentation anchors")
    x.add_argument("--repo",required=True); x.add_argument("--manifest",required=True)
    x.add_argument("--observations")
    x.add_argument("--out",help="create-only output")
    a=p.parse_args(argv)
    try:
        if a.mode=="extract":
            result=extract(a.repo,a.document,a.limit)
        else:
            result=verify(a.repo,_read_json(a.manifest))
            if a.observations:
                result["paired_review"]=compare(result,_read_json(a.observations))
        payload=json.dumps(result,ensure_ascii=False,indent=2)+"\n"
        if a.out:
            dest=Path(a.out)
            dest.parent.mkdir(parents=True,exist_ok=True)
            with os.fdopen(os.open(str(dest),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"w",encoding="utf-8") as f:
                f.write(payload)
        else:
            print(payload,end="")
        return 0
    except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as e:
        print("Error: "+str(e),file=sys.stderr)
        return 2

if __name__=="__main__":
    sys.exit(main())