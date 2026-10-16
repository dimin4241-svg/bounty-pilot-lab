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

## Record in `scope.md`

- Canonical repository, full commit, clean or dirty status, and local changes relevant to the audit.
- Program URL, the date the rules were read, eligible repositories and contracts, explicitly
  excluded impacts, and the trust assumptions the program states.
- Chain id, contract address, proxy implementation and block number, each grounded in an
  authoritative source. Otherwise `unknown` — never a plausible-looking guess.
- Previous audits and contests with their **exact** reviewed revisions. If no baseline is evidenced,
  do a full review; never call an arbitrary recent range the post-audit delta.
- The commands needed to compile and test, whether they were inspected, and whether they were run.

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
