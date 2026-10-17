# Web frontend agent — the dApp page that builds the transaction

Most Web3 programs put a website in scope next to the contracts, and `hack-patterns.md` says why that
matters: the web surface has real payouts and far fewer competent competitors, because almost everyone
who can read Solidity goes straight to the contracts. A five-pass run on one program spent its whole
budget on the contracts, found nothing submittable, and the closest thing to a finding came from the
first hour ever spent on the frontend.

The impact that pays is narrow and specific. For a dApp the rubric is usually some version of *"XSS
reports are limited to those prompting a user to sign a transaction or redirect"*, and the exclusion
list kills everything a scanner would report: missing headers, self-XSS, content spoofing, CSRF with no
impact, server banners, user enumeration, bare open redirects, no-TLS. So aim at exactly one thing:
**can an attacker change what the user is asked to sign, or execute script on the real origin where a
wallet is injected.**

## Procedure

1. **Pin the scope literally.** These briefs name one origin and exclude subdomains. Note every other
   host the page talks to: they are out of scope as targets, but the in-scope page *trusting* them
   without validation is an in-scope defect. Say that distinction in the record, because triage asks.
2. **Static first, and that is also the safety boundary.** The program forbids automated testing that
   generates traffic. So load the page once, collect the script URLs, and pull the whole static closure
   to a fixpoint — then work offline. One run downloaded 775 chunks / 69 MB and did everything else
   with `grep`. No scanner, no fuzzer, no endpoint spraying.
3. **Inventory the sinks, not the symptoms.** `innerHTML`, `dangerouslySetInnerHTML`, `document.write`,
   `eval`, `new Function`, string `setTimeout`, `location`/`href` assignment, `window.open`,
   `postMessage` handlers with no origin check, and any markdown or HTML renderer (check whether its
   sanitizer is overridden — a library default in the bundle is not an override; read the call sites).
4. **Then the wallet sinks, which are the ones that pay.** `sendTransaction`, `writeContract`,
   `signTypedData`, `eth_sendTransaction`, `approve`, `permit`. The question that settles most dApp
   hunts in one grep: **does any URL query parameter, hash fragment or stored value set a transaction
   recipient, spender, router, token address or calldata?** If no, say so — it closes the biggest class
   in one line.
5. **Prove the sink and the source separately, and file neither alone.** This is the discipline that
   keeps a web record honest. A guard that checks a URL badly is a *sink* result; it is not filable
   until an attacker-controlled *source* reaches it. Enumerate every **non-literal** argument to each
   sink and classify its origin: literal, route param, query, hash, `localStorage`, `postMessage`, or
   remote JSON — and for remote JSON, which origin and whether anything validates a scheme between
   fetch and render. The table is the deliverable even when the verdict is refuted.
6. **Test URL guards against the parser, not by eye.** A hostname comparison that ignores the scheme is
   the classic dApp link-guard bug, and `new URL()` is where you settle it. `javascript://host/%0a…`
   parses with `protocol = "javascript:"` and `hostname = "host"`, so a check on hostname alone passes
   it; a bare `javascript:alert(1)` has an empty hostname and is blocked. A guard comparing only the
   last two labels also trusts every subdomain. Build the little table of inputs versus verdicts — it
   costs one local script and it is evidence.
7. **Treat remote config as an untrusted input and then check who owns it.** dApps pull token lists,
   banner and ads config, partner links, hook or market registries. Trace each to a sink. But be strict
   about the attacker model: if every such origin is the project's own infrastructure, there is no
   attacker-controlled source, and the honest verdict is a defence-in-depth gap, not a finding.

## Safety, and it is not negotiable

Read-only. **Never connect a wallet, never sign anything, never enter credentials, never create an
account, never submit a form, never iframe or `postMessage` the live site, and never navigate a crafted
payload at it.** If a candidate needs a payload to demonstrate, reproduce the sink in a local harness
and describe the demonstration; do not fire it at production. Keep total traffic to a handful of
read-only requests and say in the record exactly how many you made.

## What to record

The script inventory and the remote-origin table; the sink inventory with bundle-offset anchors; the
non-literal-argument classification; and for each record, the data flow step by step from source to
sink, which eligible impact class it reaches, and how plausible the required user action is. A clean
"no eligible finding, here is the sink inventory and why each is unreachable" is a result — it is the
first coverage that surface has had, and it tells the next pass where not to look.
