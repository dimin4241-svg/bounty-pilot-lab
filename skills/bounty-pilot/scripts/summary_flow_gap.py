#!/usr/bin/env python3
"""A summary flow that accepts a case it cannot render.

A device that recognises a known transaction shape shows a curated screen instead of the generic
field-by-field one. Two sets then have to match: what the recogniser *accepts* and what the
curated screen *shows*. When the accept-set is wider, the host can vary a field the user is never
shown, and the curated screen is the one that looks trustworthy.

Both calibration cases were fixed by making the recogniser narrower - "fall back to the generic
UI" - rather than by showing more, which is the tell that the accept-set was the defect.

Two checks, over the AST of the summary module and the declared fields of the instruction classes
it accepts:

- `unconstrained-unrendered`: a declared field of an accepted class that the flow never mentions,
  on an object the flow does not hand whole to the screen. Nothing reads it, nothing shows it, and
  the host chooses it.
- `reference-used-by-value`: an address-typed field read as `x.field[0]` - the resolved value -
  with no guard call naming `x.field` on that path. Where an address may be a table reference,
  the first element is the table's own address, not the account.

Every row is a lead to read. A field can be legitimately absent from a screen, and a sysvar is a
fixed address; the ranking puts plain values first and `*_sysvar` last for that reason.
"""
import argparse
import ast
import json
import re
from pathlib import Path

DEFAULT_GUARD = r"is_address_reference|is_reference|is_unresolved|is_lookup"
RENDERER = re.compile(r"^(confirm|show|require_confirm|display)_|_confirm$|^confirm$")
ADDRESS_ANNOTATIONS = ("Account",)


def _name_of(node):
    """The function name of a call, with any attribute path dropped."""
    func = node.func if isinstance(node, ast.Call) else node
    if isinstance(func, ast.Attribute):
        return func.attr
    return func.id if isinstance(func, ast.Name) else None


def _root(node):
    """The root Name of an expression like `a[0].b[1]`, or None."""
    while isinstance(node, (ast.Subscript, ast.Attribute)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _annotation_text(node):
    try:
        return ast.unparse(node)
    except AttributeError:  # pragma: no cover - Python < 3.9
        return ""


def instruction_fields(source, base="Instruction"):
    """`{class name: {field: annotation}}` for every class derived from the instruction base."""
    found = {}
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ClassDef):
            continue
        if base not in [_annotation_text(b) for b in node.bases]:
            continue
        fields = {}
        for statement in node.body:
            if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                fields[statement.target.id] = _annotation_text(statement.annotation)
        if fields:
            found[node.name] = fields
    return found


def _type_aliases(tree, classes):
    """`X = A | B` unions of instruction classes, including inside `if TYPE_CHECKING`."""
    aliases = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        if not isinstance(node.targets[0], ast.Name):
            continue
        members = [n.id for n in ast.walk(node.value)
                   if isinstance(n, ast.Name) and n.id in classes]
        if members:
            aliases[node.targets[0].id] = sorted(set(members))
    return aliases


def _list_returning(tree, classes, aliases):
    """Functions annotated `-> list[<instruction class or alias>]`."""
    out = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not node.returns:
            continue
        text = _annotation_text(node.returns)
        if not text.startswith("list["):
            continue
        inner = text[len("list["):-1]
        if inner in classes:
            out[node.name] = [inner]
        elif inner in aliases:
            out[node.name] = aliases[inner]
    return out


def _bindings(fn, classes, list_returning, aliases):
    """Local names bound to instruction classes, and the ones that could not be resolved."""
    bound, pending, unresolved = {}, None, []
    for node in ast.walk(fn):
        # a call whose arguments are all instruction classes, in the order they are expected
        if isinstance(node, ast.Call) and node.args and all(
                isinstance(a, ast.Name) and a.id in classes for a in node.args):
            pending = [a.id for a in node.args]
            continue
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
            # `a, b, c = instructions` right after such a call
            if isinstance(target, ast.Tuple) and pending:
                names = [e.id for e in target.elts if isinstance(e, ast.Name)]
                if len(names) == len(pending):
                    for name, cls in zip(names, pending):
                        bound.setdefault(name, []).append(cls)
                    pending = None
                    continue
            # `xs = get_...()` whose annotation says what the list holds
            if isinstance(target, ast.Name) and isinstance(value, ast.Call):
                produced = list_returning.get(_name_of(value))
                if produced:
                    bound.setdefault(target.id, []).extend(produced)
        if isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)) \
                and isinstance(node.target, ast.Name):
            source_name = _root(node.iter)
            if source_name in bound:
                bound.setdefault(node.target.id, []).extend(bound[source_name])
            elif source_name:
                unresolved.append(node.target.id)
    return {name: sorted(set(v)) for name, v in bound.items()}, sorted(set(unresolved))


def _attributes(fn):
    """`{root name: {attribute}}` for every attribute access in the function."""
    seen = {}
    for node in ast.walk(fn):
        if isinstance(node, ast.Attribute):
            root = _root(node.value)
            if root:
                seen.setdefault(root, set()).add(node.attr)
    return seen


def _passed_whole(fn):
    """Names handed to a renderer as a whole object, so the screen decides what it shows."""
    names = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        called = _name_of(node)
        if not called or not RENDERER.search(called):
            continue
        for argument in list(node.args) + [kw.value for kw in node.keywords]:
            if isinstance(argument, ast.Name):
                names.add(argument.id)
    return names


def _guarded(fn, guard):
    """`{(root, attribute)}` naming every attribute that reaches a guard call."""
    pairs = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        called = _name_of(node)
        inside = guard.search(called or "")
        # `map(is_address_reference, (a.x, a.y))` hands the guard its arguments indirectly
        passes_guard = any(isinstance(a, ast.Name) and guard.search(a.id) for a in node.args)
        if not inside and not passes_guard:
            continue
        for attribute in [n for n in ast.walk(node) if isinstance(n, ast.Attribute)]:
            root = _root(attribute.value)
            if root:
                pairs.add((root, attribute.attr))
    return pairs


def _read_by_value(fn):
    """`x.attribute[0]` reads, split by what happens to the resolved value.

    A read that only feeds a comparison is self-limiting: if the address was a table reference the
    comparison fails and the flow falls back instead of showing the wrong account. A read that
    becomes a binding the flow then works from - `mint = x.token_mint[0]` - is the value the rest
    of the flow, and the screen it draws, treats as the account. A binding used *only* inside
    comparisons counts as the first kind.
    """
    bindings, compared = {}, set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            for inner in ast.walk(node.value):
                pair = _zero_read(inner)
                if pair:
                    bindings.setdefault(node.targets[0].id, set()).add(pair)
    used_outside_compare = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Compare):
            continue
        for inner in ast.iter_child_nodes(node):
            if isinstance(inner, ast.Name):
                used_outside_compare.add(inner.id)
            elif isinstance(inner, (ast.Attribute, ast.Subscript)):
                root = _root(inner)
                if root:
                    used_outside_compare.add(root)
    carried = set()
    for target, pairs in bindings.items():
        if target in used_outside_compare:
            carried |= pairs
        else:
            compared |= pairs
    for node in ast.walk(fn):
        for inner in ast.walk(node):
            pair = _zero_read(inner)
            if pair and pair not in carried:
                compared.add(pair)
    return carried, compared


def _zero_read(node):
    """`(root, attribute)` when the node is exactly `x.attribute[0]`."""
    if not isinstance(node, ast.Subscript) or not isinstance(node.value, ast.Attribute):
        return None
    index = node.slice.value if isinstance(node.slice, ast.Index) else node.slice
    if not (isinstance(index, ast.Constant) and index.value == 0):
        return None
    root = _root(node.value.value)
    return (root, node.value.attr) if root else None


def _rank(kind, annotation, field):
    """Plain values first: a sysvar is a fixed address and a screen may fairly omit it."""
    if kind == "reference-used-by-value":
        return 0
    if field.endswith("_sysvar") or field.endswith("_program"):
        return 3
    return 1 if annotation not in ADDRESS_ANNOTATIONS else 2


def _calls_renderer(fn):
    return any(RENDERER.search(_name_of(n) or "") for n in ast.walk(fn)
               if isinstance(n, ast.Call))


def _called_in_module(fn, defined):
    return {name for name in (_name_of(n) for n in ast.walk(fn) if isinstance(n, ast.Call))
            if name in defined}


def analyse(summary_source, instructions_source, guard_pattern=DEFAULT_GUARD):
    """Leads for one summary module, read against the fields of the classes it accepts.

    Everything is keyed on the *instruction class and field*, never on the local variable: the
    same instruction is reached as a list, as `xs[0]` and as a loop variable, and a guard written
    against one of those spellings protects all of them. A field-level guard found in a predicate
    this flow calls counts for the flow too - one level, because that is how the two calibration
    fixes are written: the recogniser guards, the renderer trusts it.
    """
    guard = re.compile(guard_pattern)
    fields = instruction_fields(instructions_source)
    tree = ast.parse(summary_source)
    aliases = _type_aliases(tree, fields)
    list_returning = _list_returning(tree, fields, aliases)
    functions = [n for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    defined = {fn.name: fn for fn in functions}
    own_guards = {fn.name: {field for _, field in _guarded(fn, guard)} for fn in functions}
    own_mentions = {fn.name: {field for fields_seen in _attributes(fn).values()
                              for field in fields_seen} for fn in functions}

    leads, notes = [], []
    for fn in functions:
        bound, unresolved = _bindings(fn, fields, list_returning, aliases)
        if not bound:
            continue
        mentioned = _attributes(fn)
        whole = _passed_whole(fn)
        carried, compared_only = _read_by_value(fn)
        renders = bool(whole) or _calls_renderer(fn)
        guarded = set(own_guards[fn.name])
        inherited_mentions = set()
        for callee in sorted(_called_in_module(fn, defined)):
            guarded |= own_guards.get(callee, set())
            inherited_mentions |= own_mentions.get(callee, set())

        # one entry per accepted class, merging every local bound to it
        per_class = {}
        for name, class_names in bound.items():
            for class_name in class_names:
                entry = per_class.setdefault(class_name, {"locals": set(), "mentioned": set(),
                                                          "carried": set(), "whole": False})
                entry["locals"].add(name)
                entry["mentioned"] |= mentioned.get(name, set()) | inherited_mentions
                entry["carried"] |= {field for root, field in carried if root == name}
                entry["whole"] = entry["whole"] or name in whole

        for name in unresolved:
            notes.append({"function": fn.name, "name": name,
                          "note": "iterates something this parser could not type; its fields "
                                  "were not checked"})
        if not renders:
            notes.append({"function": fn.name,
                          "note": "a recogniser that renders nothing: which of its accepted "
                                  "fields are invisible is decided at its call site, so the "
                                  "unrendered-field check is not applied here"})

        for class_name, entry in sorted(per_class.items()):
            local = sorted(entry["locals"])[0]
            address_fields = {field for field, annotation in fields[class_name].items()
                              if annotation in ADDRESS_ANNOTATIONS}
            for field in sorted(entry["carried"] - guarded):
                if field not in address_fields:
                    continue
                leads.append({"kind": "reference-used-by-value", "function": fn.name,
                              "instruction": class_name, "local": local, "field": field,
                              "annotation": "Account",
                              "why": f"`{local}.{field}[0]` becomes a value this flow works "
                                     f"from, and no guard in `{fn.name}` or in a predicate it "
                                     f"calls names `{field}`: a table-referenced address "
                                     f"resolves to the table, not the account",
                              "rank": 0})
            if entry["whole"] or not renders:
                if entry["whole"]:
                    notes.append({"function": fn.name, "instruction": class_name,
                                  "note": "handed whole to a renderer, so the screen decides "
                                          "what it shows; read that screen instead"})
                continue
            for field, annotation in sorted(fields[class_name].items()):
                if field in entry["mentioned"]:
                    continue
                leads.append({"kind": "unconstrained-unrendered", "function": fn.name,
                              "instruction": class_name, "local": local, "field": field,
                              "annotation": annotation,
                              "why": f"`{class_name}.{field}` is accepted by `{fn.name}`, never "
                                     f"mentioned there, and `{local}` is not handed to the "
                                     f"screen: the host picks it and nobody shows it",
                              "rank": _rank("unconstrained-unrendered", annotation, field)})
        for root, field in sorted(compared_only):
            if field in guarded or root not in bound:
                continue
            notes.append({"function": fn.name, "name": root, "field": field,
                          "note": "`[0]` read only inside a comparison: a table reference makes "
                                  "the comparison fail, which falls back rather than misleading "
                                  "- read it only if the other side is host-chosen too"})

    merged, unique = {}, []
    for row in leads:
        key = (row["kind"], row["function"], row["local"], row["field"])
        if key in merged:
            previous = merged[key]
            if row["instruction"] not in previous["instruction"].split(", "):
                previous["instruction"] += ", " + row["instruction"]
            continue
        merged[key] = row
        unique.append(row)
    unique.sort(key=lambda row: (row["rank"], row["function"], row["field"]))
    return {"leads": unique, "notes": notes,
            "counts": {kind: sum(1 for row in unique if row["kind"] == kind)
                       for kind in ("reference-used-by-value", "unconstrained-unrendered")},
            "instruction_classes": len(fields),
            "notice": "Leads, not findings. For each row, read the curated screen this flow "
                      "draws and ask what the host can vary that the screen never names. Both "
                      "calibration cases were fixed by narrowing the recogniser, not by showing "
                      "more, which is the tell that the accept-set was the defect."}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--summary", required=True,
                   help="module with the recogniser and the curated flow")
    p.add_argument("--instructions", required=True,
                   help="module declaring the accepted instruction classes and their fields")
    p.add_argument("--guard", default=DEFAULT_GUARD,
                   help=f"regex for the call that marks a value unresolvable (default: "
                        f"{DEFAULT_GUARD})")
    p.add_argument("--out")
    a = p.parse_args(argv)
    try:
        report = analyse(Path(a.summary).read_text(encoding="utf-8"),
                         Path(a.instructions).read_text(encoding="utf-8"), a.guard)
    except (OSError, SyntaxError, ValueError) as exc:
        p.error(str(exc))
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if a.out:
        Path(a.out).write_text(payload, encoding="utf-8")
        print(json.dumps({"out": a.out, "leads": len(report["leads"]),
                          "counts": report["counts"]}))
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
