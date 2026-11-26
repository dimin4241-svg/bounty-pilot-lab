# Release readiness — 2026-11-26

This is a maintenance assessment, not a security-research effectiveness claim. Baseline: main at 5eb4f26b639505d2ac6b6846488f55ac3ba7c426, version 0.60.1.

## Verified baseline
- [Main CI](https://github.com/dimin4241-svg/bounty-pilot-lab/actions/runs/45041612165): full synthetic suite failed; native smoke passed.
- [Portable CI](https://github.com/dimin4241-svg/bounty-pilot-lab/actions/runs/45041612190): both Python runs reported 2240 tests, 1 failure and 90 skipped. The failure was the documented entrypoint size limit (236 lines, maximum 200). Lint reported one unused import.
- [Administrative CI](https://github.com/dimin4241-svg/bounty-pilot-lab/actions/runs/45841616336): Python 3.11 and 3.12 passed for the administrative module at 70ea0481a3b6fdc7ab0894af7e9bc8b180cded86.
- The local installed skill copies examined during this assessment reported 0.26.2. This observation is not a statement about all installations.

## Maintenance changes
- Remove the unused import without changing runtime behavior.
- Restrict the self-hosted Mac regression workflow to manual dispatch on main. A workflow-level restriction does not protect against malicious changes by repository writers. Prefer disposable isolated runners; avoid running public-repository workflows on a personal computer containing sensitive files or credentials.
- Keep the administrative module independent and keep private databases and reports outside the public repository. See [administration documentation](../research_admin/README.md).

## Release gates
- [ ] Full synthetic CI and lint succeed on the exact proposed release commit.
- [ ] Resolve the entrypoint size failure without relaxing the assertion or deleting required safeguards.
- [ ] Review public-repository runner exposure and permissions. No untrusted pull request code on personal self-hosted runners.
- [ ] Review installation manifests and version metadata; do not equate a repository commit with a deployed copy.
- [ ] Verify private data and credentials are excluded from release artifacts.
- [ ] Publish release notes that distinguish tested functionality from untested claims.

Do not mark the whole project production-ready based on administrative unit tests. They do not establish discovery effectiveness, verify technical findings, or imply integration with external models. No deployment or local skill update was performed in this maintenance change.
