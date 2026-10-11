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
   this after the hunt wastes passes on ground the team has already published.
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
