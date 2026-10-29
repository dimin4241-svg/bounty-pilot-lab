#!/usr/bin/env python3
"""A display rule that skips a field on a sentinel, where the sentinel carries meaning.

A rendering loop drops a field when its value is `None`, zero or empty, and justifies it with a
*type-level* claim - the schema says this field is optional, so absence cannot matter. Sometimes
absence is the action. `None` can mean *remove the authority*; zero can mean *unset the lockup*.
The user then confirms a transaction whose most consequential field was the one that looked empty.

The calibration case, and the whole bug in one line:

    if property_template.optional and value is None:
        continue

Trezor's own commit says why it is wrong - "optional params ... were never displayed when their
value is None, even though None may encode an action rather than the absence of one" - and the fix
makes the skip opt in **per field** (`default_value_to_hide: "none"` in the program definition)
while rendering the string "None" otherwise (`0fea14829`).

So the question is never "does it skip on a sentinel" - every UI does - but **what licenses the
skip**:

- a **per-field** policy read from the definition (`ui_property.default_value_to_hide`, a
  `hide_when`, a `display_rule`) is a decision somebody made about that field: clean, and it goes
  to `notes` so the policy values can still be reviewed;
- a **type-level** property (`optional`, `nullable`, `required`) is a claim about a whole class of
  fields standing in for that decision: a lead, rank 0;
- **no qualifier at all** - a blanket `if value is None: continue` - is a lead at rank 1.

Every row is a lead. The verdict needs the field's domain: read the definition and ask what the
sentinel means there. `blind-spots.md` has the triage steps.
"""
import argparse
import ast
import json
import re
from pathlib import Path

# What counts as drawing a screen; the default is Trezor-shaped. A pattern that misses a
# project's real renderers makes this report a confident zero, so it is an option.
RENDERER_DEFAULT = r"^_?(confirm|require_confirm|show|display|ask)_|_confirm$|^confirm$"
RENDERER = re.compile(RENDERER_DEFAULT)
# A decision recorded per field, by whoever wrote the field down.
PER_FIELD = re.compile(r"default_value|hide|suppress|display_rule|policy|skip_when|show_when",
                       re.I)
# A claim about a whole class of fields, standing in for that decision.
TYPE_LEVEL = re.compile(r"\b(optional|is_optional|nullable|required|has_default|omitempty)\b",
                        re.I)
SENTINELS = (None, 0, "", b"", False)


def _name_of(call):
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    return func.id if isinstance(func, ast.Name) else None


def _root(node):
    while isinstance(node, (ast.Subscript, ast.Attribute)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _text(node):
    try:
        return ast.unparse(node)
    except AttributeError:  # pragma: no cover - Python < 3.9
        return _root(node) or "?"


def _renders(block, renderer=RENDERER):
    return any(isinstance(n, ast.Call) and renderer.search(_name_of(n) or "")
               for statement in block for n in ast.walk(statement))


def _rendering_loops(fn, renderer=RENDERER):
    return [node for node in ast.walk(fn)
            if isinstance(node, (ast.For, ast.AsyncFor)) and _renders(node.body, renderer)]


def _parents(root):
    links = {}
    for node in ast.walk(root):
        for child in ast.iter_child_nodes(node):
            links[child] = node
    return links


def _enclosing_tests(node, links, stop):
    tests = []
    while node in links and node is not stop:
        parent = links[node]
        if isinstance(parent, ast.If) and any(
                node is st or node in ast.walk(st) for st in parent.body + parent.orelse):
            tests.append(parent.test)
        node = parent
    return tests


def _sentinel_comparisons(test):
    """`(expression, sentinel)` for every comparison of a value against an empty-ish constant."""
    found = []
    for node in ast.walk(test):
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
            if not isinstance(node.ops[0], (ast.Is, ast.Eq, ast.IsNot, ast.NotEq)):
                continue
            left, right = node.left, node.comparators[0]
            for value, other in ((left, right), (right, left)):
                if isinstance(value, ast.Constant) and any(
                        value.value is sentinel or
                        (type(value.value) is type(sentinel) and value.value == sentinel)
                        for sentinel in SENTINELS):
                    found.append((_text(other), repr(value.value)))
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not) \
                and isinstance(node.operand, (ast.Name, ast.Attribute, ast.Subscript)):
            found.append((_text(node.operand), "falsy"))
    return found


def _is_a_value_rule(expression, loop):
    """Is this sentinel comparison a rule about a field's *value*?

    Two kinds of `is None` in the same loop are not display rules and would otherwise be most of
    the output:

    - a dispatch on the loop item's own shape - `if ui_property.parameter is not None: ... elif
      ui_property.account is not None:` - which selects what kind of property this is;
    - a test for whether a per-field policy exists at all, `default_value_to_hide is not None`.
    """
    root = expression.split(".")[0].split("[")[0]
    if isinstance(loop.target, ast.Name) and root == loop.target.id:
        return False
    return not PER_FIELD.search(expression)


def _qualifiers(tests, sentinel_expressions):
    """Everything else the skip is conditioned on, besides the sentinel comparison itself."""
    out = set()
    for test in tests:
        for node in ast.walk(test):
            if isinstance(node, (ast.Name, ast.Attribute)):
                text = _text(node)
                if text not in sentinel_expressions:
                    out.add(text)
    return out


def analyse(source, renderer_pattern=RENDERER_DEFAULT):
    renderer = re.compile(renderer_pattern)
    tree = ast.parse(source)
    leads, notes = [], []
    for fn in [n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        for loop in _rendering_loops(fn, renderer):
            links = _parents(loop)
            for jump in [n for n in ast.walk(loop)
                         if isinstance(n, (ast.Continue, ast.Return))]:
                tests = _enclosing_tests(jump, links, loop)
                if not tests:
                    continue
                comparisons = [pair for test in tests for pair in _sentinel_comparisons(test)
                               if _is_a_value_rule(pair[0], loop)]
                if not comparisons:
                    continue
                sentinel_expressions = {expression for expression, _ in comparisons}
                qualifiers = _qualifiers(tests, sentinel_expressions)
                per_field = sorted(q for q in qualifiers if PER_FIELD.search(q))
                type_level = sorted(q for q in qualifiers if TYPE_LEVEL.search(q))
                row = {
                    "function": fn.name, "loop_over": _text(loop.iter),
                    "skips_on": sorted({f"{expression} {sentinel}"
                                        for expression, sentinel in comparisons}),
                    "qualifiers": sorted(qualifiers),
                    "type_level_qualifiers": type_level,
                    "per_field_qualifiers": per_field,
                }
                if per_field:
                    notes.append(dict(row, note="the skip is licensed by a per-field policy, "
                                                "which is a decision somebody made about this "
                                                "field; review the policy values, not the code"))
                    continue
                leads.append(dict(
                    row,
                    why=("a type-level claim (" + ", ".join(f"`{q}`" for q in type_level)
                         + ") licenses dropping the field whenever it is "
                         + ", ".join(row["skips_on"])
                         + ": that is a statement about a class of fields, not a decision about "
                           "this one, and for some of them the sentinel is the action"
                         if type_level else
                         "the field is dropped whenever it is " + ", ".join(row["skips_on"])
                         + " with nothing licensing it: no per-field policy, no type-level claim"),
                    rank=0 if type_level else 1))
    leads.sort(key=lambda row: (row["rank"], row["function"]))
    return {"leads": leads, "notes": notes,
            "counts": {"sentinel-skip": len(leads),
                       "licensed-by-a-type-level-claim": sum(1 for r in leads
                                                             if r["rank"] == 0)},
            "notice": "Leads, not findings. For each row read the field's own definition and ask "
                      "what the sentinel means there - an absent value, or an action. The "
                      "calibration case had both meanings in one instruction set."}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", required=True, action="append", help="module to read; repeatable")
    p.add_argument("--renderer", default=RENDERER_DEFAULT,
                   help="regex matching the calls that draw a screen in THIS project; the "
                        "default is Trezor-shaped and a pattern that misses the real ones makes "
                        "this report a confident zero")
    p.add_argument("--out")
    a = p.parse_args(argv)
    report = {"leads": [], "notes": [],
              "counts": {"sentinel-skip": 0, "licensed-by-a-type-level-claim": 0}, "notice": "", "skipped": []}
    for path in a.source:
        try:
            one = analyse(Path(path).read_text(encoding="utf-8"), a.renderer)
        except (SyntaxError, UnicodeDecodeError) as exc:
            # A file this interpreter cannot parse is skipped and SAID, never fatal: six of
            # Coldcard's 94 shared modules are generated data blobs, and killing the sweep on
            # the first one returned no result at all for the other 88.
            report["skipped"].append({"source": path, "reason": f"{type(exc).__name__}: {exc}"})
            continue
        except OSError as exc:
            p.error(str(exc))
        report["leads"] += [dict(row, source=path) for row in one["leads"]]
        report["notes"] += [dict(row, source=path) for row in one["notes"]]
        report["notice"] = one["notice"]
    report["counts"]["sentinel-skip"] = len(report["leads"])
    report["counts"]["licensed-by-a-type-level-claim"] = sum(
        1 for row in report["leads"] if row["rank"] == 0)
    report["leads"].sort(key=lambda row: (row["rank"], row["source"], row["function"]))
    if report["skipped"]:
        report["notice"] += (f' {len(report["skipped"])} source file(s) could not be parsed and '
                             'were skipped; see "skipped". A sweep that reports nothing because '
                             'it read nothing is not a clean result.')
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if a.out:
        Path(a.out).write_text(payload, encoding="utf-8")
        print(json.dumps({"out": a.out, "counts": report["counts"]}))
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
