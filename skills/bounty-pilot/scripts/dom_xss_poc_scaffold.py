#!/usr/bin/env python3
"""Local, static candidate/control HTML pair for a DOM-sink execution claim.

This has NOT been executed in a real browser by this tool - there is no browser
available to this script, only a text generator. The detection technique for each
sink (onerror firing from a failed image load inserted via innerHTML; document.write
executing an embedded script, which `<script>` inserted through innerHTML does not;
eval/Function running a string directly) is standard, long-documented DOM/HTML
parsing behavior, not something this tool verified by running it. Open both files
yourself, in a disposable browser profile with network access disabled, before
treating either result as evidence. This never contacts the real target, never
reaches a live site, and is not itself proof that a specific application's sink
is reachable with attacker-controlled data - only that the demonstrated mechanism
reliably executes script when it receives unsanitized HTML or code.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

SINKS = ("innerHTML", "dangerouslySetInnerHTML", "document.write", "eval")
SAFE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")

README = """# DOM-sink execution scaffold: {sink}

Generated for the lead at {anchor}. This demonstrates a MECHANISM, not your
finding: it illustrates how `{sink}` may execute unsanitized input in a
local browser context that permits inline scripts/event handlers, not that
your application's specific code path actually reaches it with
attacker-controlled data. You still have to show that separately.

## Run it

1. Open `candidate.html` in a disposable browser profile with network access
   disabled (airplane mode, or a sandboxed VM). Read it first; it does nothing
   except what is printed below.
2. Check the page title or `document.title` in DevTools after it loads.
   `BP_POC_RESULT:FIRED` means the marker executed; `NOT_FIRED` means it did not.
3. Open `control.html` the same way. It carries the identical marker payload
   through the safe equivalent (`textContent`, an escaped write, or inert data
   instead of `eval`) and must show `NOT_FIRED`.
4. If candidate fires and control does not, you have demonstrated the sink
   mechanism. Report reachability and real attacker control separately,
   exactly as `references/hunt-agents/web-frontend-agent.md` requires - and
   only within whatever impact class the program's rubric actually pays for.

## What this is not

Not an execution of your target. Not a claim this specific application is
vulnerable. Not verified against a real browser by the tool that generated it -
only standard DOM/HTML parsing behavior. Browser policies such as CSP
may block inline execution; this local scaffold does not model target CSP.
"""


def _write(path, text):
    if path.exists() or path.is_symlink():
        raise ValueError("refusing to overwrite an existing output path: " + str(path))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)


def _pair(sink):
    marker = ("document.title = 'BP_POC_RESULT:' + "
             "(window.__bp_poc_marker ? 'FIRED' : 'NOT_FIRED');")
    if sink in ("innerHTML", "dangerouslySetInnerHTML"):
        # A <script> tag assigned through innerHTML never executes, by design, in any modern
        # browser; an <img> whose src fails to load and whose onerror handler runs is the
        # standard way to show innerHTML executes attacker-supplied markup regardless.
        candidate = """<!doctype html><html><body><div id="t"></div><script>
var payload = '<img src="x" onerror="window.__bp_poc_marker=1">';
document.getElementById('t').innerHTML = payload;
setTimeout(function(){{ {marker} }}, 80);
</script></body></html>
""".format(marker=marker)
        control = """<!doctype html><html><body><div id="t"></div><script>
var payload = '<img src="x" onerror="window.__bp_poc_marker=1">';
document.getElementById('t').textContent = payload;
setTimeout(function(){{ {marker} }}, 80);
</script></body></html>
""".format(marker=marker)
    elif sink == "document.write":
        candidate = """<!doctype html><html><body><script>
var payload = '<scr' + 'ipt>window.__bp_poc_marker=1</scr' + 'ipt>';
document.write(payload);
setTimeout(function(){{ {marker} }}, 80);
</script></body></html>
""".format(marker=marker)
        control = """<!doctype html><html><body><div id="t"></div><script>
function escapeHtml(s) {{
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}}
var payload = '<scr' + 'ipt>window.__bp_poc_marker=1</scr' + 'ipt>';
document.getElementById('t').textContent = escapeHtml(payload);
setTimeout(function(){{ {marker} }}, 80);
</script></body></html>
""".format(marker=marker)
    else:
        assert sink == "eval"
        candidate = """<!doctype html><html><body><script>
var payload = 'window.__bp_poc_marker=1';
eval(payload);
setTimeout(function(){{ {marker} }}, 80);
</script></body></html>
""".format(marker=marker)
        control = """<!doctype html><html><body><div id="t"></div><script>
var payload = 'window.__bp_poc_marker=1';
document.getElementById('t').textContent = payload; // treated as inert data, never evaluated
setTimeout(function(){{ {marker} }}, 80);
</script></body></html>
""".format(marker=marker)
    return candidate, control


def scaffold(sink, anchor, out_dir):
    if sink not in SINKS:
        raise ValueError("sink must be one of: " + ", ".join(SINKS))
    if not isinstance(anchor, str) or not SAFE_ID.fullmatch(anchor):
        raise ValueError("anchor must be a short bounded identifier, e.g. file.tsx:Component:12")
    out = Path(out_dir)
    if out.exists():
        raise ValueError("refusing to write into an existing directory")
    out.mkdir(mode=0o700, parents=True)
    candidate, control = _pair(sink)
    _write(out / "candidate.html", candidate)
    _write(out / "control.html", control)
    _write(out / "README.md", README.format(sink=sink, anchor=anchor))
    return {"schema_version": 1, "classification": "LOCAL_STATIC_POC_SCAFFOLD",
            "sink": sink, "anchor": anchor, "out_dir": str(out),
            "files": ["candidate.html", "control.html", "README.md"],
            "network_requests": 0, "confirmed_vulnerabilities": 0,
            "executed_in_a_browser_by_this_tool": False,
            "notice": ("Standard, long-documented DOM/HTML parsing behavior, not verified "
                      "against a real browser by this generator. Open both files yourself "
                      "before treating either result as evidence, and remember a fired "
                      "candidate proves the sink mechanism, not that your application's "
                      "own code reaches it with real attacker-controlled data.")}


def main(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--sink", required=True, choices=SINKS)
    cli.add_argument("--anchor", required=True,
                     help="short identifier for the lead this scaffold is for, e.g. file.tsx:Comp:12")
    cli.add_argument("--out-dir", required=True)
    args = cli.parse_args(argv)
    try:
        result = scaffold(args.sink, args.anchor, args.out_dir)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (ValueError, OSError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
