#!/usr/bin/env python3
"""Generate and validate paired, source-pinned Foundry replay tests from reviewed actions.

Never probes a network or executes a target. The generated tests call *only*
researcher-supplied fixture bindings in an explicitly disposable local checkout.
Passing generated tests can be evidence only after independent validation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

IDENT = re.compile(r"^[A-Za-z_][A-Za-z_0-9]{0,63}$")
CASE_ID = re.compile(r"^[a-zA-Z][a-zA-Z_0-9-]{0,63}$")
REV = re.compile(r"^[0-9a-f]{40}$")
FUNC = re.compile(r"^[A-Za-z_][a-zA-Z_0-9]*\(((?:[a-z0-9,]*)?)\)$")
INT = re.compile(r"^(u?int)(8|16|32|64|128|160|192|224|256)?$")
COMPARISONS = {"eq": "assertEq", "ne": "assertNotEq", "gt": "assertGt",
               "lt": "assertLt", "ge": "assertGe", "le": "assertLe"}
MAX_ACTIONS = 32
MAX_LENGTH = 200_000


def _identifier(value, context):
    if not isinstance(value, str) or not IDENT.fullmatch(value):
        raise ValueError("invalid %s identifier" % context)
    return value


def _relative(value):
    if not isinstance(value, str) or not value.endswith(".sol") or len(value) > 220:
        raise ValueError("fixture_import must be a repository-relative .sol file")
    p = Path(value)
    if p.is_absolute() or any(x in (".", "..") for x in p.parts) or "\\" in value or '"' in value:
        raise ValueError("unsafe fixture_import")
    return value


def _string(value):
    return json.dumps(value, ensure_ascii=True)


def _signature(value, arity=None):
    if not isinstance(value, str) or len(value) > 170:
        raise ValueError("function signature invalid")
    match = FUNC.fullmatch(value)
    if not match:
        raise ValueError("signature must be canonical method(type1,type2)")
    types = match.group(1).split(",") if match.group(1) else []
    if arity is not None and len(types) != arity:
        raise ValueError("ABI argument arity mismatch")
    for typ in types:
        if typ not in {"address", "bool", "bytes32"} and not INT.fullmatch(typ):
            raise ValueError("unsupported ABI type; review and adapt manually: " + typ)
    return types


def _arg(typ, arg):
    if not isinstance(arg, dict) or set(arg) not in ({"literal"}, {"fixture_ref"}):
        raise ValueError("argument must have exactly literal or fixture_ref")
    if "fixture_ref" in arg:
        binding = _identifier(arg["fixture_ref"], "fixture_ref")
        if typ == "address":
            return "address(%s)" % binding
        return "%s(%s)" % (typ or "uint256", binding)
    v = arg["literal"]
    if typ == "address":
        if not isinstance(v, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", v):
            raise ValueError("address literal must be 20-byte hex")
        return "address(%s)" % v
    if typ == "bool":
        if type(v) is not bool:
            raise ValueError("boolean literal expected")
        return "true" if v else "false"
    if typ == "bytes32":
        if not isinstance(v, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", v):
            raise ValueError("bytes32 literal expected")
        return "bytes32(%s)" % v
    if type(v) not in (str, int) or not re.fullmatch(r"-?[0-9]{1,78}", str(v)):
        raise ValueError("integer literal must be decimal")
    value = int(v)
    width = 256 if typ in ("int", "uint") else int(INT.fullmatch(typ).group(2) or 256)
    if typ.startswith("uint") and not 0 <= value < (1 << width):
        raise ValueError("unsigned integer overflow")
    if typ.startswith("int") and not -(1 << (width-1)) <= value < (1 << (width-1)):
        raise ValueError("signed integer overflow")
    return "%s(%s)" % (typ, value)


def _call_expr(step):
    signature = step.get("signature")
    args = step.get("args", [])
    if not isinstance(args, list) or len(args) > 12:
        raise ValueError("invalid args")
    types = _signature(signature, len(args))
    values = [_arg(t, a) for t, a in zip(types, args)]
    return "abi.encodeWithSignature(%s%s)" % (_string(signature),
         ", " + ", ".join(values) if values else "")


def _action(step, i):
    if not isinstance(step, dict) or set(step) - {"target", "signature", "args", "actor", "expect_revert", "role"}:
        raise ValueError("unrecognized action fields")
    target = _identifier(step.get("target"), "target")
    actor = step.get("actor")
    if actor is not None:
        _identifier(actor, "actor")
    if type(step.get("expect_revert", False)) is not bool:
        raise ValueError("expect_revert must be boolean")
    if step.get("role", "action") not in ("action", "enabler", "setup"):
        raise ValueError("unsupported action role")
    expression = _call_expr(step)
    lines = []
    if actor:
        lines.append("vm.prank(address(%s));" % actor)
    lines += ["(bool ok%d,) = address(%s).call(%s);" % (i, target, expression),
              "%s(ok%d, %s);" % ("assertFalse" if step.get("expect_revert") else "assertTrue", i,
                                _string("native action %d outcome" % i))]
    return "\n        ".join(lines)


def _method_name(name):
    _identifier(name, "observation")
    return "_observe_" + name


def _observer(obs):
    if not isinstance(obs, dict) or set(obs) != {"name", "target", "signature", "args"}:
        raise ValueError("observation needs name,target,signature,args")
    name = _identifier(obs["name"], "observation")
    target = _identifier(obs["target"], "target")
    expression = _call_expr(obs)
    return ("function %s() internal view returns (uint256 value) {\n"
        "        (bool ok, bytes memory data) = address(%s).staticcall(%s);\n"
        "        require(ok && data.length == 32, \"observation unavailable\");\n"
        "        value = abi.decode(data, (uint256));\n"
        "    }") % (_method_name(name), target, expression)


def _check(check, names, role):
    if not isinstance(check, dict) or set(check) != {"observation", "relation"}:
        raise ValueError("candidate/control check needs observation/relation")
    name = _identifier(check["observation"], "check observation")
    if name not in names:
        raise ValueError("unknown observation in " + role)
    relation = check["relation"]
    if relation not in COMPARISONS:
        raise ValueError("unsupported numeric relation")
    return "%s(after_%s, before_%s, %s);" % (COMPARISONS[relation], name, name,
                                                   _string(role + " invariant comparison"))


def render(doc):
    """Build concrete tests, but never infer the user's business semantics."""
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise ValueError("schema_version=1 required")
    source_revision = doc.get("source_revision")
    if not isinstance(source_revision, str) or not REV.fullmatch(source_revision):
        raise ValueError("pinned source_revision required")
    ident = doc.get("id")
    if not isinstance(ident, str) or not CASE_ID.fullmatch(ident):
        raise ValueError("id must be a stable short identifier")
    fixture = doc.get("fixture")
    if not isinstance(fixture, dict) or set(fixture) != {"import", "contract"}:
        raise ValueError("fixture needs repository-relative import and contract")
    rel = _relative(fixture["import"])
    contract = _identifier(fixture["contract"], "fixture contract")
    actions = doc.get("actions")
    if not isinstance(actions, list) or not 1 <= len(actions) <= MAX_ACTIONS:
        raise ValueError("actions require 1..32 steps")
    explicit_controls = doc.get("negative_control")
    if explicit_controls is not None and (not isinstance(explicit_controls, list) or len(explicit_controls) > MAX_ACTIONS):
        raise ValueError("negative_control must be <=32 actions")
    if explicit_controls is None and not any(s.get("role") == "enabler" for s in actions if isinstance(s,dict)):
        raise ValueError("missing negative_control and no tagged enabler to omit")
    controls = explicit_controls if explicit_controls is not None else [x for x in actions if x.get("role") != "enabler"]
    if not controls:
        raise ValueError("negative control must exercise at least one operation")
    observations = doc.get("observations", [])
    if not isinstance(observations, list) or not 1 <= len(observations) <= 12:
        raise ValueError("1..12 observations required")
    names = [x.get("name") if isinstance(x,dict) else None for x in observations]
    if len(set(names)) != len(names):
        raise ValueError("duplicate observation")
    observers = [_observer(x) for x in observations]
    checks = doc.get("checks")
    if not isinstance(checks, dict) or set(checks) != {"candidate", "negative_control"}:
        raise ValueError("two explicit independently reviewed checks required")
    for role in checks:
        if not isinstance(checks[role], list) or not checks[role] or len(checks[role]) > 20:
            raise ValueError("each path must have a nonempty check array")
    if doc.get("operator_reviewed_intent") is not True:
        raise ValueError("operator_reviewed_intent=true required for executable assertions")
    test_id = ident.replace("-", "_")
    if not IDENT.fullmatch(test_id):
        raise ValueError("invalid test identifier")
    def method(role, items):
        head = "test_candidate_" if role == "candidate" else "test_negative_control_"
        before = ["uint256 before_%s = %s();" % (name, _method_name(name)) for name in names]
        after = ["uint256 after_%s = %s();" % (name, _method_name(name)) for name in names]
        action_lines = [_action(item, i) for i, item in enumerate(items)]
        comparison = [_check(c, names, role) for c in checks[role]]
        body = before + action_lines + after + comparison
        return "function %s%s() public {\n        %s\n    }" % (head, test_id, "\n        ".join(body))
    header = "// SPDX-License-Identifier: UNLICENSED\npragma solidity ^0.8.20;\n" + (
        "// Generated by Bounty Pilot; unmodified target must be deployed in local fixture.\n"
        "// Source revision claim: %s; execution is not performed by this generator.\n" % source_revision)
    source = header + 'import {%s} from "%s";\n\n' % (contract, rel)
    source += "contract BPSequence_%s is %s {\n    " % (test_id, contract)
    source += "\n\n    ".join(observers + [method("candidate", actions), method("negative_control", controls)]) + "\n}\n"
    tests = ["test_candidate_"+test_id,"test_negative_control_"+test_id]
    return {"source_revision":source_revision,"test_file":"test/bp_generated/BPSequence_%s.t.sol" % test_id,
            "test_names":tests,"solidity":source,"sha256":hashlib.sha256(source.encode()).hexdigest(),
            "controls_derived_by_omitting_enabler":explicit_controls is None,
            "classification":"GENERATED_TESTS_UNEXECUTED", "warning": (
                 "Tests are mechanically generated against a researcher-owned fixture. A green test does not independently "
                 "authenticate its input intent, test fixture, exploit scope or deployment.")}


def execution_plan(bundle):
    """Yield a plan directly understood by existing scenario_runner.py."""
    path = bundle["test_file"]
    names = bundle["test_names"]
    return {"schema_version":1,"source_revision":bundle["source_revision"],"cases":[
        {"id":"candidate", "pair_id":"bp-sequence-pair", "role":"candidate",
         "argv":["forge","test","--match-path",path,"--match-test",names[0],"-vv"],"timeout_sec":300},
        {"id":"negative-control", "pair_id":"bp-sequence-pair", "role":"negative-control",
         "argv":["forge","test","--match-path",path,"--match-test",names[1],"-vv"],"timeout_sec":300}],
        "notice":"Dry-run until scenario_runner --allow-exec in reviewed disposable isolated checkout."}


def _write_create_only(path, content):
    target = Path(path)
    if target.exists() or target.is_symlink():
        raise ValueError("output already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(str(target), os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600), "w",encoding="utf-8") as fh:
        fh.write(content)


def emit(doc, dest):
    """Emit private bundle only; copying into a target checkout is an explicit review step."""
    result = render(doc)
    target = Path(dest)
    if target.exists() or target.is_symlink():
        raise ValueError("output must be a new directory")
    target.mkdir(parents=True, mode=0o700)
    try:
        _write_create_only(target / "BPSequence.t.sol", result["solidity"])
        _write_create_only(target / "runner-plan.json", json.dumps(execution_plan(result), indent=2)+"\n")
        review = {k:v for k,v in result.items() if k != "solidity"}
        _write_create_only(target / "manifest.json", json.dumps(review, indent=2)+"\n")
        return review
    except BaseException:
        # Preserve partial files for inspection, never silently overwrite.
        raise



def install_disposable(bundle, repo):
    """Install generated tests only into an operator-marked, source-pinned disposable clone.

    This does not run forge. The marker is a deliberate local authorization gate.
    Git invocation disables repository-supplied hooks/fsmonitor and global config.
    """
    import subprocess
    root = Path(repo).resolve()
    marker = root / ".bounty-pilot-disposable-proof"
    if marker.is_symlink() or not marker.is_file() or marker.read_text(encoding="utf-8").strip() != "I_CONTROL_THIS_DISPOSABLE_CHECKOUT":
        raise ValueError("repo must have explicit .bounty-pilot-disposable-proof marker")
    env = {"PATH":os.environ.get("PATH","/usr/bin:/bin"),"HOME":"/nonexistent",
           "GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null","GIT_OPTIONAL_LOCKS":"0"}
    command = ["git","-C",str(root),"--no-optional-locks", "-c","core.fsmonitor=false",
               "-c","core.hooksPath=/dev/null"]
    result = subprocess.run(command + ["rev-parse","HEAD"],capture_output=True,text=True,
                            env=env,timeout=10,check=False)
    if result.returncode or result.stdout.strip() != bundle["source_revision"]:
        raise ValueError("disposable checkout does not match requested pinned source revision")
    status = subprocess.run(command + ["status","--porcelain","--untracked-files=no"],
                            capture_output=True,text=True,env=env,timeout=10,check=False)
    if status.returncode or status.stdout.strip():
        raise ValueError("disposable repo has modified tracked files; do not overwrite")
    dest = root / bundle["test_file"]
    if dest.is_symlink() or dest.exists() or not dest.parent.resolve().is_relative_to(root):
        raise ValueError("generated test path already exists or escapes disposable checkout")
    _write_create_only(dest,bundle["solidity"])
    return {"installed_test":bundle["test_file"],"source_revision":bundle["source_revision"],
            "classification":"SOURCE_INSTALLED_NOT_COMPILED_OR_EXECUTED",
            "next_step":"Use scenario_runner --plan runner-plan.json --repo DISPOSABLE --allow-exec only inside externally isolated disposable sandbox."}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scenario",required=True,help="reviewed schema-v1 JSON")
    p.add_argument("--out-dir",required=True,help="new private bundle outside target repo")
    p.add_argument("--install-disposable",help="optional operator-marked disposable target checkout")
    args=p.parse_args(argv)
    try:
        src=Path(args.scenario)
        if src.is_symlink() or not src.is_file() or src.stat().st_size > MAX_LENGTH:
            raise ValueError("missing, symlinked or oversized scenario")
        data=json.loads(src.read_text(encoding="utf-8"))
        if args.install_disposable and Path(args.out_dir).resolve().is_relative_to(Path(args.install_disposable).resolve()):
            raise ValueError("output bundle must be outside the disposable checkout")
        result=emit(data,args.out_dir)
        if args.install_disposable:
            result["installation"]=install_disposable(render(data),args.install_disposable)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as e:
        print("Error: " + str(e),file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())