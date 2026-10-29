#!/usr/bin/env python3
"""A confirmation suppressed on a proxy for having shown it, instead of on a witness.

A flow shows a field in one place and, later, decides whether to show it again - or at all - by
asking something else: a host-supplied index, a count, a flag from the request. The question it
means to ask is "did the user already see this?", and the only thing that can answer it is a
value written where the showing happened. An input cannot: the display path has `continue`s,
early returns and branches the input knows nothing about.

The calibration case, Trezor's Monero flow. The output loop showed the payment id only for
outputs named by the host's `integrated_indices`, and skipped change and dummy outputs entirely.
The standalone payment-id screen was then suppressed by `not tsx_data.integrated_indices`: name
an index the loop skips and the payment id reached no screen at all while it was still folded
into the signed transaction. The fix tracks `payment_id_shown` where the output is confirmed and
gates on that - a witness instead of a proxy.

What makes an operand a proxy rather than a legitimate "only show it if it is set":

- it is neither the value being displayed by the call it guards, nor
- a local written in a branch or loop body that itself confirms something.

So `if unlock_time is not None: await confirm_unlock_time(unlock_time)` is clean - the gate tests
the field it shows - while a gate naming a *different* host field is a question the input cannot
answer. Negation sharpens it: `not x` reads as "skip, because x says it was handled".

A negated operand is what makes the gate read as "skip, because this says it was handled", so a
gate that is not a negation goes to `notes` as a precondition rather than a suppression. Rank 0 is
the calibration shape - the display it stands in for sits in a loop a `continue` can skip; rank 1
is the same gate over a display that is merely conditional.

Every row is a lead. Read the display path the proxy stands in for and ask which of its branches
leave the field on no screen.

This does not cover a gate whose witness is itself derived from the rendered text rather than
from the fact of rendering - that shape is `cosmetic_regression.py`, and the two are
complementary.
"""
import argparse
import ast
import json
import re
from pathlib import Path

# What counts as drawing a screen. The default is Trezor-shaped; every project names these
# differently, and a pattern that misses the real ones makes every check below report a confident
# zero - Coldcard's firmware draws with `ux_show_story`, which this default does not match.
RENDERER_DEFAULT = r"^_?(confirm|require_confirm|show|display|ask)_|_confirm$|^confirm$"
RENDERER = re.compile(RENDERER_DEFAULT)
JUMPS = (ast.Continue, ast.Break, ast.Return)


def _name_of(call):
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    return func.id if isinstance(func, ast.Name) else None


def _root(node):
    while isinstance(node, (ast.Subscript, ast.Attribute)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _is_renderer(call, renderer=RENDERER):
    name = _name_of(call)
    return bool(name and renderer.search(name))


def _renderer_calls(node, renderer=RENDERER):
    return [n for n in ast.walk(node)
            if isinstance(n, ast.Call) and _is_renderer(n, renderer)]


def _parents(fn):
    links = {}
    for node in ast.walk(fn):
        for child in ast.iter_child_nodes(node):
            links[child] = node
    return links


def _enclosing_tests(call, links):
    """The `if` tests that control whether this call runs, innermost first."""
    tests, node = [], call
    while node in links:
        parent = links[node]
        if isinstance(parent, ast.If):
            # only the body and orelse are controlled by the test, not the test itself
            if any(node is statement or node in ast.walk(statement)
                   for statement in parent.body + parent.orelse):
                tests.append((parent.test, node in [s for s in parent.orelse]
                              or any(node in ast.walk(s) for s in parent.orelse)))
        node = parent
    return tests


def _operands(test):
    """Every host-reachable name in a condition, with whether it appears negated."""
    found = {}

    def walk(node, negated):
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            walk(node.operand, not negated)
            return
        if isinstance(node, ast.BoolOp):
            for value in node.values:
                walk(value, negated)
            return
        if isinstance(node, ast.Compare):
            walk(node.left, negated)
            for comparator in node.comparators:
                walk(comparator, negated)
            return
        if isinstance(node, ast.Call):
            for argument in list(node.args) + [kw.value for kw in node.keywords]:
                walk(argument, negated)
            return
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.Name)):
            root = _root(node)
            if root:
                try:
                    text = ast.unparse(node)
                except AttributeError:  # pragma: no cover - Python < 3.9
                    text = root
                previous = found.get(text)
                found[text] = {"root": root, "negated": negated or bool(previous
                                                                       and previous["negated"])}
            return
        for child in ast.iter_child_nodes(node):
            walk(child, negated)

    walk(test, False)
    return found


def _aliases(fn):
    """`local -> "param.attr"` for `payment_id = tsx_data.payment_id`.

    Without this, a gate on the field a call displays reads as a proxy whenever the call was
    handed the local copy instead of the attribute chain.
    """
    out = {}
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) \
                and isinstance(node.value, (ast.Attribute, ast.Subscript)):
            try:
                out[node.targets[0].id] = ast.unparse(node.value)
            except AttributeError:  # pragma: no cover - Python < 3.9
                continue
    return out


def _confirming_blocks(fn, renderer=RENDERER):
    """Statement lists whose own code confirms something, where a witness can be written."""
    blocks = []
    for node in ast.walk(fn):
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            candidates = [node.body]
        elif isinstance(node, ast.If):
            candidates = [node.body, node.orelse]
        else:
            continue
        for block in candidates:
            if any(_renderer_calls(statement, renderer) for statement in block):
                blocks.append(block)
    return blocks


def _host_locals(fn, parameters, witnesses, renderer=RENDERER):
    """`local -> source text` for a local computed from a parameter outside any confirming block.

    A flag like `shown = bool(msg.items)` is a proxy wearing a local name: it is derived from the
    request, not from the display having happened, so it answers the same wrong question.
    """
    inside = {id(statement) for block in _confirming_blocks(fn, renderer)
              for statement in block
              for statement in ast.walk(statement)}
    out = {}
    for node in ast.walk(fn):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        if not isinstance(node.targets[0], ast.Name) or id(node) in inside:
            continue
        name = node.targets[0].id
        if name in witnesses:
            continue
        roots = {_root(inner) for inner in ast.walk(node.value)
                 if isinstance(inner, (ast.Name, ast.Attribute, ast.Subscript))}
        if roots & parameters:
            try:
                out[name] = ast.unparse(node.value)
            except AttributeError:  # pragma: no cover - Python < 3.9
                out[name] = name
    return out


def _inner_chains(node):
    """Every name and attribute chain appearing inside an expression."""
    texts = set()
    for inner in ast.walk(node):
        if isinstance(inner, (ast.Name, ast.Attribute, ast.Subscript)):
            try:
                texts.add(ast.unparse(inner))
            except AttributeError:  # pragma: no cover - Python < 3.9
                root = _root(inner)
                if root:
                    texts.add(root)
    return texts


def _resolves_through(text, shown, aliases, host_locals):
    """Is this operand computed from something the call displays?

    `is_payment = SCHEMA_PAYMENT.match(witness_path)` and
    `accounts_match = msg.source_account == address` are questions *about* the displayed value, so
    they are preconditions on it and not proxies for having shown it.
    """
    source_text = host_locals.get(text, aliases.get(text, text))
    candidates = {source_text}
    try:
        candidates |= _inner_chains(ast.parse(source_text, mode="eval").body)
    except SyntaxError:
        pass
    return bool(candidates & shown)


def _sibling_branch_renders(call, links, renderer=RENDERER):
    """True when an alternative branch of the same `if` chain also confirms something.

    `if verified_payment_request: confirm_payment_request(...)` / `else: confirm_recipient(...)`
    is a choice of presentation, not a suppression: both branches show the value.
    """
    node = call
    while node in links:
        parent = links[node]
        if isinstance(parent, ast.If):
            in_body = any(node is st or node in ast.walk(st) for st in parent.body)
            others = parent.orelse if in_body else parent.body
            if any(_renderer_calls(statement, renderer) for statement in others):
                return True
        node = parent
    return False


def _self_attributes_written(tree):
    """`{class: {"self.x", ...}}` for attributes a class writes outside `__init__`.

    State the device accumulates while it walks a transaction - `self.external_in += txi.amount`
    in an input handler - is a witness in every sense that matters; it just does not live in a
    local.
    """
    out = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        written = set()
        for method in node.body:
            if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if method.name == "__init__":
                continue
            for inner in ast.walk(method):
                targets = []
                if isinstance(inner, ast.Assign):
                    targets = inner.targets
                elif isinstance(inner, (ast.AugAssign, ast.AnnAssign)):
                    targets = [inner.target]
                for target in targets:
                    if isinstance(target, ast.Attribute) and _root(target.value) == "self":
                        written.add(f"self.{target.attr}")
        if written:
            out[node.name] = written
    return out


def _methods_of(tree):
    """`{id(function node): class}` so a method can see its class's accumulated state."""
    owner = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for method in node.body:
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    owner[id(method)] = node.name
    return owner


def _witnesses(fn, renderer=RENDERER):
    """Locals written in a branch or loop body that confirms something.

    That is the only kind of value that can answer "was it shown": it is written where the
    showing is decided, so every `continue` and early return above it already applies.
    """
    names = set()
    for block in _confirming_blocks(fn, renderer):
        if True:
            for statement in block:
                for inner in ast.walk(statement):
                    if isinstance(inner, ast.Assign):
                        for target in inner.targets:
                            if isinstance(target, ast.Name):
                                names.add(target.id)
                    elif isinstance(inner, (ast.AnnAssign, ast.AugAssign)) \
                            and isinstance(inner.target, ast.Name):
                        names.add(inner.target.id)
    return names


def _conditional_renderers(fn, links, renderer=RENDERER):
    """Renderer calls whose reachability depends on a branch, a loop or a jump above them."""
    out = []
    for call in _renderer_calls(fn, renderer):
        node, conditional = call, False
        while node in links:
            parent = links[node]
            if isinstance(parent, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try)):
                conditional = True
                break
            node = parent
        if conditional:
            out.append(call)
    return out


def _has_jumping_display(fn, links, renderer=RENDERER):
    """A display path that some branch skips: the thing a proxy gate cannot know about."""
    for call in _conditional_renderers(fn, links, renderer):
        node = call
        while node in links:
            parent = links[node]
            if isinstance(parent, (ast.For, ast.AsyncFor, ast.While)) and any(
                    isinstance(n, JUMPS) for statement in parent.body
                    for n in ast.walk(statement)):
                return True
            node = parent
    return False


def analyse(source, renderer_pattern=RENDERER_DEFAULT):
    renderer = re.compile(renderer_pattern)
    tree = ast.parse(source)
    self_state = _self_attributes_written(tree)
    owners = _methods_of(tree)
    leads, notes = [], []
    for fn in [n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        calls = _renderer_calls(fn, renderer)
        if not calls:
            continue
        links = _parents(fn)
        positional = list(fn.args.posonlyargs) + list(fn.args.args)
        # A parameter with a default is supplied by the caller - recursion state, a flag the
        # device computed - not by the request. `self` is never the request either.
        defaulted = {argument.arg for argument in
                     (positional[len(positional) - len(fn.args.defaults):]
                      if fn.args.defaults else [])}
        defaulted |= {argument.arg for argument, default
                      in zip(fn.args.kwonlyargs, fn.args.kw_defaults) if default is not None}
        parameters = {argument.arg for argument in positional + list(fn.args.kwonlyargs)
                      } - defaulted - {"self"}
        witnesses = _witnesses(fn, renderer)
        witnesses |= self_state.get(owners.get(id(fn)), set())
        aliases = _aliases(fn)
        host_locals = _host_locals(fn, parameters, witnesses, renderer)
        conditional = _conditional_renderers(fn, links, renderer)
        skippable = _has_jumping_display(fn, links, renderer)
        for call in calls:
            shown, host_shown = set(), False
            for argument in list(call.args) + [kw.value for kw in call.keywords]:
                for text in _operands(argument):
                    shown.add(text)
                    shown.add(aliases.get(text, text))
            for text in sorted(shown):
                root = text.split(".")[0].split("[")[0]
                if root in parameters or root in host_locals:
                    host_shown = True
            proxies, witness_in_gate = [], False
            for test, _ in _enclosing_tests(call, links):
                for text, operand in _operands(test).items():
                    if operand["root"] in witnesses or text in witnesses:
                        witness_in_gate = True
                    elif text in shown or aliases.get(text, text) in shown:
                        continue
                    elif _resolves_through(text, shown, aliases, host_locals):
                        continue
                    elif operand["root"] in parameters:
                        proxies.append({"operand": text, "negated": operand["negated"]})
                    elif operand["root"] in host_locals:
                        proxies.append({
                            "operand": f'{text} (= {host_locals[operand["root"]]})',
                            "negated": operand["negated"]})
            if not proxies or witness_in_gate:
                continue
            if not host_shown:
                notes.append({"function": fn.name, "call": _name_of(call),
                              "note": "gated on a host field, but this call displays nothing "
                                      "host-supplied - it is a static label, and whether it "
                                      "applies is a policy question, not a suppression"})
                continue
            if _sibling_branch_renders(call, links, renderer):
                notes.append({"function": fn.name, "call": _name_of(call),
                              "note": "an alternative branch of the same `if` chain also "
                                      "confirms something, so this is a choice of presentation "
                                      "rather than a suppression"})
                continue
            negated = any(p["negated"] for p in proxies)
            others = [other for other in conditional if other is not call]
            if not negated or not others:
                notes.append({
                    "function": fn.name, "call": _name_of(call),
                    "proxy_operands": sorted({p["operand"] for p in proxies}),
                    "note": "gated on a host field it does not display, but "
                            + ("the gate is not a negation, so it reads as a precondition "
                               "rather than as 'already handled'" if not negated else
                               "no other confirmation here is conditional, so there is no "
                               "display path for the proxy to stand in for")})
                continue
            leads.append({
                "function": fn.name, "suppressed_call": _name_of(call),
                "proxy_operands": sorted({p["operand"] for p in proxies}),
                "negated": any(p["negated"] for p in proxies),
                "witness_candidates": sorted(witnesses),
                "display_path_can_skip": skippable,
                "why": f"`{_name_of(call)}` is gated on "
                       + ", ".join(f"`{p['operand']}`" for p in proxies)
                       + ", which the host supplies and which this call does not display, while "
                         "another confirmation in the same function sits behind a branch that "
                         "can skip it: the gate is a proxy for having shown the value, not a "
                         "witness that it was shown"
                       + (", and that branch is a loop a `continue` can skip" if skippable
                          else ""),
                "rank": 0 if skippable else 1})
    leads.sort(key=lambda row: (row["rank"], row["function"], row["suppressed_call"]))
    return {"leads": leads, "notes": notes,
            "counts": {"suppressed-on-a-proxy": len(leads),
                       "with-a-skippable-display-path": sum(1 for row in leads
                                                            if row["rank"] == 0)},
            "notice": "Leads, not findings. Read the display path the proxy stands in for and "
                      "ask which of its branches leave the value on no screen. A gate on the "
                      "field it shows is legitimate and is not reported; a gate carrying a "
                      "local written where the showing happens is a witness and is not either."}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", required=True, action="append",
                   help="module to read; repeatable")
    p.add_argument("--renderer", default=RENDERER_DEFAULT,
                   help="regex matching the calls that draw a screen in THIS project. The "
                        "default is Trezor-shaped; a pattern that misses the real ones makes "
                        "every check report a confident zero. Coldcard needs "
                        "'^ux_|^_?confirm|_confirm$'")
    p.add_argument("--out")
    a = p.parse_args(argv)
    report = {"leads": [], "notes": [],
              "counts": {"suppressed-on-a-proxy": 0, "with-a-skippable-display-path": 0},
              "notice": "", "skipped": []}
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
        for row in one["leads"]:
            report["leads"].append(dict(row, source=path))
        for row in one["notes"]:
            report["notes"].append(dict(row, source=path))
        report["notice"] = one["notice"]
    report["counts"]["suppressed-on-a-proxy"] = len(report["leads"])
    report["counts"]["with-a-skippable-display-path"] = sum(
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
