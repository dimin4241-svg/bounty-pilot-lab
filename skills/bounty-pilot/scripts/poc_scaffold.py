#!/usr/bin/env python3
"""Create deliberately failing native-test skeletons; never fabricate passing PoCs."""
import argparse
import json
import re
from pathlib import Path

KINDS = {"solidity": ".t.sol", "rust": ".rs", "python": ".py", "go": "_test.go"}
def safe_id(label):
    ident = re.sub(r"[^a-zA-Z0-9_]", "_", label.strip()).strip("_").lower()[:55]
    if not ident:
        raise ValueError("finding id must contain letters or digits")
    if ident[0].isdigit():
        ident = "case_" + ident
    return ident

def scaffold(finding, stack):
    if stack not in KINDS:
        raise ValueError("supported: solidity, rust, python, go")
    required = ("id", "invariant", "entry_point", "attacker_capabilities", "steps")
    if any(not finding.get(x) for x in required):
        raise ValueError("finding needs id, invariant, entry_point, attacker_capabilities and steps")
    if not isinstance(finding["steps"], list) or not all(isinstance(x, str) for x in finding["steps"]):
        raise ValueError("steps must be a nonempty array of strings")
    ident = safe_id(str(finding["id"]))
    if stack == "solidity":
        data = '''// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";

// CONVENTION (see templates/README.md): both tests are expected to exit 0 (pass).
//   - The CANDIDATE passes IFF the vulnerability is demonstrated: assert the attacker's
//     gain, the broken invariant, or the wrong resulting state.
//   - The NEGATIVE CONTROL passes IFF the protection holds on the control path.
// Until filled in, both deliberately FAIL so an empty skeleton is never mistaken for evidence.
// TODO: replace with the actual deployed/unmodified target and pinned dependencies.
contract BountyPilotScenario is Test {
    function test_candidate_''' + ident + '''() public {
        // TODO: reach the state, run the attacker's ordered actions, then assert the
        //       attacker gained / the invariant broke (this PASSES only when the bug is real).
        revert("fill in: candidate must assert the demonstrated vulnerability");
    }

    function test_negative_control_''' + ident + '''() public {
        // TODO: same path with the attacker capability removed (or patched code);
        //       assert the protection holds (this PASSES only when the control is safe).
        revert("fill in: negative control must assert the protection holds");
    }
}
'''
    elif stack == "rust":
        data = '''// CONVENTION (see templates/README.md): both tests are expected to exit 0 (pass).
//   - The CANDIDATE passes IFF the vulnerability is demonstrated (assert the attacker's
//     gain / broken invariant / wrong state).
//   - The NEGATIVE CONTROL passes IFF the protection holds on the control path.
// Until filled in, both deliberately panic so an empty skeleton is never mistaken for evidence.
// TODO: import the original target crate and build realistic actors/state.
#[test]
fn candidate_''' + ident + '''() {
    // TODO: execute attack sequence; assert the demonstrated impact so this PASSES only when real.
    panic!("fill in: candidate must assert the demonstrated vulnerability");
}

#[test]
fn negative_control_''' + ident + '''() {
    // TODO: execute the comparable protected scenario; assert the protection holds.
    panic!("fill in: negative control must assert the protection holds");
}
'''
    elif stack == "python":
        data = '''"""CONVENTION (see templates/README.md): both tests are expected to exit 0 (pass).
- The CANDIDATE passes IFF the vulnerability is demonstrated (assert the attacker's gain /
  broken invariant / wrong state).
- The NEGATIVE CONTROL passes IFF the protection holds on the control path.
Until filled in, both deliberately fail so an empty skeleton is never mistaken for evidence.
TODO: import the original service, fixtures and real dependencies."""
def test_candidate_''' + ident + '''():
    # TODO: reachable setup, ordered actions; assert the measurable victim effect (PASS == bug real).
    raise AssertionError("fill in: candidate must assert the demonstrated vulnerability")

def test_negative_control_''' + ident + '''():
    # TODO: protected counterpart; assert the protection holds.
    raise AssertionError("fill in: negative control must assert the protection holds")
'''
    else:
        camel = "".join(p[:1].upper() + p[1:] for p in ident.split("_"))
        data = '''package scenario_test

import "testing"

// CONVENTION (see templates/README.md): both tests are expected to exit 0 (pass).
//   - The CANDIDATE passes IFF the vulnerability is demonstrated (assert the attacker's
//     gain / broken invariant / wrong state).
//   - The NEGATIVE CONTROL passes IFF the protection holds on the control path.
// Until filled in, both deliberately fail so an empty skeleton is never mistaken for evidence.
// TODO: use the target package's native test setup and actual process semantics.
func TestCandidate''' + camel + '''(t *testing.T) {
    t.Fatal("fill in: candidate must assert the demonstrated vulnerability")
}

func TestNegativeControl''' + camel + '''(t *testing.T) {
    t.Fatal("fill in: negative control must assert the protection holds")
}
'''
    notes = {"finding_id": finding["id"], "stack": stack,
             "entry_point": finding["entry_point"], "invariant": finding["invariant"],
             "attacker_capabilities": finding["attacker_capabilities"],
             "steps": finding["steps"], "status": "incomplete-test-skeleton",
             "source_integrity": "target must remain unmodified",
             "verification": "not-run-not-proven"}
    return ident, data, notes

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--finding", required=True, help="JSON hypothesis with reachable steps")
    p.add_argument("--stack", required=True, choices=sorted(KINDS))
    p.add_argument("--out-dir", required=True, help="private output outside target checkout")
    args = p.parse_args(argv)
    try:
        finding = json.loads(Path(args.finding).read_text(encoding="utf-8"))
        ident, code, notes = scaffold(finding, args.stack)
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        # Prefix with test_ so pytest collects the Python skeletons by default
        # (its default collection only picks up test_*.py / *_test.py).
        basename = "test_bp_" + ident
        path = out / (basename + KINDS[args.stack])
        meta = out / (basename + ".json")
        # Exclusive creation means we never silently erase test work.
        if path.exists() or meta.exists():
            raise ValueError("output already exists; choose a new output directory")
        with path.open("x", encoding="utf-8") as w:
            w.write(code)
        with meta.open("x", encoding="utf-8") as w:
            json.dump(notes, w, indent=2, ensure_ascii=False)
            w.write("\n")
        print(json.dumps({"template": str(path), "metadata": str(meta),
                          "status": "incomplete-test-skeleton"}))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
