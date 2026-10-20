# Intake and scope

Resolve a bare GitHub repository URL without repeatedly asking for preferences. For tree and blob
links preserve the requested revision and subpath; do not assume a branch name contains no slash. If
revision resolution is ambiguous, fetch refs or ask one precise question. Reject arbitrary command
strings as repository URLs. Prefer authenticated repository tools for private code, and keep
credentials out of logs and remotes.

A URL-only request authorizes useful local review. Continue without a bounty page by marking
eligibility unknown. Read-only inspection is distinct from active testing; follow the program's
limits for any network interaction. A public repository alone does not authorize testing a running
service.

## First, probe what this run can actually prove

Before the lenses are chosen and before any pass reads code for bugs, record what this environment
can do:

```sh
python3 <skill-dir>/scripts/bounty.py capability-probe --repo <checkout> --run <run> \
    [--rpc <read-only-url>] [--deep]
```

It writes `capabilities.json`: which toolchains are present and at which versions, which build and
test files the checkout actually has — including whether a root manifest exists and what workspaces
it declares — and, with `--rpc`, the chain id, the head block and the **measured archive depth**,
how far back the endpoint still answers historical queries. `--deep` additionally runs the build
and test command and records their exit codes. The RPC URL itself is never written into the run and
never printed.

Run it here, not after a candidate has been parked. The archive-depth measurement is the specific
fact hunts keep rediscovering by hand, always too late — "needs an archive mainnet RPC", "public
RPCs give no archive or log history", "blocked without a paid key", each one found with a candidate
already in hand that was then parked unproven. Measured at Stage 1 the same fact is a boundary the
hunt is aimed inside: it tells you which experiments are decidable here before you choose what to
look for, and whether this target needs access you do not have. It also contradicts a wrong blocker
in one command — a root manifest a record claims does not exist appears in `capabilities.json` with
its workspace list (`blind-spots.md` §8).

## Record in `scope.md`

- Canonical repository, full commit, clean or dirty status, and local changes relevant to the audit.
- Program URL, the date the rules were read, eligible repositories and contracts, explicitly
  excluded impacts, and the trust assumptions the program states.
- Chain id, contract address, proxy implementation and block number, each grounded in an
  authoritative source. Otherwise `unknown` — never a plausible-looking guess.
- Previous audits and contests with their **exact** reviewed revisions. If no baseline is evidenced,
  do a full review; never call an arbitrary recent range the post-audit delta.
- The commands needed to compile and test, whether they were inspected, and whether they were run.
  `capabilities.json` answers all three, and `--deep` is what makes the last one a recorded exit
  code rather than a claim.

### Before claiming a rule, an audit or a program does not exist

A negative claim about a *document* needs the same evidence standard as a negative claim about code,
and it is the cheapest claim to get wrong. Two live runs were steered badly by one each: a Solana
target recorded as having "no audit in the repository at all" because `SECURITY.md` only pointed at
the bounty program — the `## Audits` table was in `README.md`, eight days old, and its one
**Acknowledged** finding was verbatim the lane two agents were already on; and a second target
recorded as having no bounty program at all, from a security page that did not mention one plus an
empty platform listing, when the program was at `/security/bug-bounty`, the **sibling of the page
already fetched**.

Before writing "there is none", exhaust and then *name* what was checked:

- the site's `sitemap.xml` and `llms.txt`, grepped for `bounty|secur|audit`;
- the **Markdown twin**, where appending `.md` to a docs URL returns source that renders collapsed
  `<details>` blocks. A rendered page hid an entire smart-contract known-issues list that the `.md`
  twin printed in full — and that list contained the exact mechanism then under investigation;
- sibling paths of any security page found: `/security/bug-bounty`, `/bug-bounty`, `/security`,
  `/responsible-disclosure`, `/.well-known/security.txt`;
- in the repository: `README.md`, `SECURITY.md`, `.github/SECURITY.md`, an `audits/` directory, and
  the vendor's separate `<project>-audits` repository.

A platform page that is empty or delisted means *that* listing is gone, not that no program exists;
the team may have moved it in-house.

**The scope page is usually not the rewards page.** One program's bounty page named reward tiers and
no contracts at all; the authoritative in-scope list — 21 addresses — lived on
`/security/contracts-and-ownership`, and it held two in-scope contracts that appear in no audit, in
no repository and not even in the project's own contracts API. Find the scope page separately and
record its URL and retrieval date beside the rules.

## Write these three files before any pass reads code for bugs

1. **`program.json`** — the published program facts, in the shape `targets.md` defines. It drives
   `score-target` and gate 5, and every field records where it came from.
2. **`dup-map.json`** — the surfaces and bug classes already burned by the program's known-issues
   list, its audits, its contests and its closed issues. `dup-map.md` has the procedure. Building
   this after the hunt wastes passes on ground the team has already published. Start with
   `dup-harvest`, which retrieves the closed issues and PRs the team already judged; triage every
   candidate it returns, because the submission gate blocks while any is untriaged.
3. **The delta baseline** — the exact commit of the last audit, written into `run.json` as
   `audited_revision`, so `bounty.py delta` can rank what nobody has reviewed.

### Fetch every published report before the first pass, not after it

`audit-inventory` sees only what the repository ships. The reports that actually decide a finding
are usually published elsewhere — a firm's site, a CDN, a contest platform — and they are the
cheapest duplicate evidence that exists. Pull them in Stage 1 and keep the text beside the run:

```sh
mkdir -p <run>/dup-sources/<name> && cd <run>/dup-sources/<name>
curl -sSL -A "Mozilla/5.0" -o report.pdf "<url>" && pdftotext -layout report.pdf report.txt
grep -n -i -E "<your candidate's mechanism>|<its primitive>" report.txt
```

**A Download button that does nothing when you read the page is not a paywall.** On one program the
competition report looked login-gated: the button carried no `href` and the obvious findings
endpoint answered `401`. The page's own API held the answer — `/api/v0/reports/<id>` returned a
field `reportPdfLink` pointing at a plain public CDN URL that needed no cookie at all. That file
contained the load-bearing primitive of a finding already verified on a mainnet fork, stated in one
sentence in an acknowledged Low-risk entry, which ended its eligibility outright. A full week of
work rested on a file that was one `curl` away on day one.

So before recording any published report as unreadable, from inside the page: `fetch` a few endpoint
shapes and print the status with the first few hundred bytes, and look for a `*PdfLink`, `*Url` or
`downloadUrl` field in whatever object the page already loaded. If a direct URL comes back, fetch it
with the shell. Record `unavailable` only with the list of endpoints tried — the same standard an
absence claim about code has to meet.

### Account for every audit the repository ships

The densest list of issues a team already knows is usually sitting in the checkout. Royco, Squads
and marginfi all ship their review reports inside the repository — ten of them in the Squads case —
and nothing here ever listed them, let alone read them; all three lost findings to ground the team
had already covered in its own repository — a shipped audit in two of them, a discussion on the
team's own PR #623 in marginfi's.

```sh
python3 <skill-dir>/scripts/bounty.py audit-inventory --repo <checkout> --run <run> [--gate]
```

It enumerates the published review artifacts the repository ships — an `audit/`, `audits/`,
`security/` or `reviews/` directory, files named like a review wherever they sit, and `SECURITY.md`
when it names one — attributes a firm where the name is recognised, and writes
`audit-inventory.json` with every artifact `unreviewed` until you say otherwise.

**It cannot read a PDF and does not pretend to.** The inventory is an accounting of known-issue
sources, not a summary of them. Each artifact has to end as `read`, as `not-applicable` with a
reason (wrong component, a revision the scope predates), or as `unavailable` when the repository
names a report it does not actually contain. What a report you read burned then goes into
`dup-map.json` as a `past-audit` entry at the exact revision it covered; `dup-map.md` has the
format.

`--gate`, and the submission gate, refuse a run that still holds an `unreviewed` artifact. A target
that ships none is never blocked.

Then establish what is deployed:

```sh
python3 <skill-dir>/scripts/bounty.py verify-deployment --rpc <read-only-url> \
    --address <in-scope address> --artifact <out/Name.sol/Name.json> --run <run>
```

`--run` writes `<run>/deployments/<address>.json`; a finding claiming `deployment_status: exact`
names that file in `deployment_evidence`, and the submission gate checks it. The RPC URL is never
written to disk. Immutables and library links are masked when the artifact lists their offsets
(`immutableReferences`, `linkReferences`), so an implementation with immutables can still match
`exact`. A `partial` result is informative and must not be rounded up: same-length bytecode that
differs without listed offsets is consistent with immutables or a different compiler build, and
it is not proof the logic matches. Recognised proxies: EIP-1967 (and beacons), EIP-1822, EIP-1167,
the legacy zeppelinos slot, Safe, Compound's Unitroller; an EIP-2535 diamond lists its facets and
stays `partial` until each facet is compared. A small runtime that delegates but matches none of
these is `partial` too: treat it as an unrecognised proxy. A `mismatch` means the repository is not what runs, and that is
the single most common reason a bounty report is rejected — find the revision that is deployed
before reading further.

### Before calling a size difference a divergence, sweep the compiler

A `mismatch` whose only evidence is a length difference is not yet a result. Build the same source
across the optimizer settings the project itself uses elsewhere — sibling packages in a monorepo
routinely differ (`runs` of 200, 999, 2_000, 1_000_000 and "no optimizer block at all" are all
common in one repository), and the spread in runtime size across that range can exceed 50%.
Note the direction is not fixed: a high `runs` inlines aggressively and can make the runtime
*larger* than an unoptimized build, so "deployed is bigger, therefore it is different code" is not
sound on its own. Only after no setting reproduces the deployed length is divergence established.
One free cross-check costs nothing: a factory or deployer must embed the **creation** code of what
it deploys, so it can never be smaller than that contract's deployed runtime. If you measure a
deployed instance larger than the deployer that supposedly produced it, more than one deployer
generation has been used — which is a finding about the deployment, not an arithmetic error.

### Enumerate what is deployed but absent from the repository

Verifying the addresses the program hands you is necessary and not sufficient. Audits cover what is
in the repository, so anything deployed-and-not-in-the-repository is reviewed by nobody and is
invisible to every other hunter reading HEAD. Two checks, both cheap:

1. **Diff the project's own deployment records against HEAD.** Collect every address from its
   `deployments/*.json`, `script/config/*.json`, deploy scripts and docs, then ask of each: does a
   contract by that name still exist in the in-scope source? In a live run a "fix" commit deleted a
   helper contract *and* its mainnet address from three config files in the same change — the
   contract is still live, still holds the flaw the commit was avoiding, and no longer appears at
   HEAD for anyone to read. Also check the reverse: an address the repository records may no longer
   be the one in use, so read the pointer from the contract that consumes it rather than the file.
2. **Sample every live instance, not one.** Where a factory or deployer mints instances over time,
   several generations can be live simultaneously. Enumerate the instances through the registry that
   owns them and group them by `eth_getCode` length. In a live run 51 active farms resolved to two
   distinct implementation sizes, and **neither** matched the in-scope source at any optimizer
   setting — so a fuzz campaign built from that source was testing code that runs nowhere. Record
   that as a limitation on every conclusion drawn from the source, not as a detail.

If the deployed implementation is not in any in-scope repository, say so in `scope.md`: a defect
there is probably not an in-scope asset, and the defensible framing is the in-scope seam — the
audited contract that grants authority to the unpublished one.

**Getting the deployed source, and comparing it without a false positive.** Where an explorer API is
blocked, Sourcify answers keyless and per chain:
`GET https://sourcify.dev/server/v2/contract/<chainId>/<address>?fields=sources,compilation` returns
every verified source file plus the compiler settings; a contest or audit snapshot of the same file
is usually fetchable from the auditor's own repository. **Normalise line endings before diffing** —
`tr -d '\r' < a.sol > /tmp/a.sol` on both sides — or `diff` reports one whole-file hunk and the
real delta is invisible. In a live run that one step turned an unreadable 2,341-line diff into
**5 hunks, +63/−14**, small enough to read in full; the same comparison on a second contract gave
21 hunks, +392/−155 of unaudited code on the contract holding the entire protocol TVL.

### Never infer configuration from bytecode

Storage variables do not appear in runtime bytecode. An address absent from a contract's code may
still be its live configuration, because it was set by a setter after deployment rather than fixed
as an immutable. In a live run this produced a wrong conclusion in the project's favour — a module
was recorded as "not wired" because its factory address was missing from the deployed bytecode, when
in fact `stableSwapFactory` was a plain storage variable holding exactly the expected value. Read
the getter, or the slot. Constants and immutables are the only configuration bytecode can answer for.

## Environment

Choose a private output directory, outside the target checkout and outside the skill package. Do not
commit run artifacts. Read manifests and relevant build scripts before running any target code. Use
an isolated, secret-free environment. Do not load wallets or private keys and do not broadcast
transactions; read-only RPC and local forks are acceptable where the environment and the program
permit. Avoid shell interpolation of URLs, branch names and target content.

For large repositories, map all relevant components, prioritise reachable value-bearing paths and
recent changes, and mark unreviewed modules explicitly. There is no universal LOC cutoff. Review the
dependency boundary and off-chain workers where they influence on-chain safety; technical relevance
and scope eligibility are different questions and are answered separately.
