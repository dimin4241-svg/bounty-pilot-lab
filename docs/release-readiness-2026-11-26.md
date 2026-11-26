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

## Additional maintenance verification

- [Administrative CI](https://github.com/dimin4241-svg/bounty-pilot-lab/actions/runs/45842983986) passed on Python 3.11 and 3.12 for the database consistency changes.
- The read-only `research_admin/release_check.py` preflight compares VERSION and plugin metadata, checks the marketplace entry and screens tracked filenames for common private artifacts. It reports counts, not filenames or contents. It does not inspect file contents or Git history and cannot establish absence of secrets.
- Run the preflight from the repository root with `python3 research_admin/release_check.py`. The administrative CI now includes it. A passing preflight is not a release approval.

## Maintenance checkpoint

At commit `9ddf0aa17a06a0fa882064d586aecb97f9b1e01e`, [administrative CI](https://github.com/dimin4241-svg/bounty-pilot-lab/actions/runs/45843394668) completed successfully. The release preflight and administrative tests are separate from the full skill suite.

| Area | Verified status |
| --- | --- |
| Administrative Python 3.11 and 3.12 CI | Passed at the commit above |
| Release preflight on repository changes | Enabled in maintenance branch |
| Main synthetic suite and lint | Historical failures; no new full-suite result |
| Skill entrypoint size | Unresolved, 236 lines vs. 200 limit |
| Local skill installations | Not updated |
| Main release and deployment | Not performed |
| Discovery performance or model comparison | Not evaluated |

This checkpoint is not a release tag. Do not treat the maintenance branch as a tested replacement for main. The unresolved gates below remain open.

## Observed Shannon export interoperability

Read-only smoke test of `sarif_summary.py` and `summary_workspace.py` from Pilot Lab commit `950d6e9317163576db150b0f208a85f2fd8a355c` against the public [Shannon Photoview benchmark exports](https://github.com/KeygraphHQ/shannon/tree/main/benchmark), downloaded on 2026-11-26. Only aggregate metadata was read; no scanning engine or target was executed.

| Export | Bytes | Reported records | SHA-256 |
| --- | ---: | ---: | --- |
| DeepSeek v4 Flash | 95060 | 18 | `5bff8b89b7fdc965a80a1e99c2598d69232eaf1b6abdbfd0ef7a6f4a80184c7b` |
| Grok 4.6 | 47095 | 10 | `42a6c72b017e56f78656d5d128585bca47d5c779cbb43ec7ba8f05b70e6adffb` |
| Claude Opus 5 | 101826 | 24 | `08796510f0484504b1f210914385e148cd09fda55704541a4b211f8d37328b54` |

All three inputs passed summary creation and verification. Repeated imports reused the existing summary; final inventory contained three valid summaries and zero structurally invalid ones. Temporary test data was removed. These counts describe report records, not independently validated findings. This is compatibility evidence, not a comparative assessment of research performance. Shannon remains a separate tool.

## Post-merge verification

The administrative maintenance changes were merged into main in PR [#88](https://github.com/dimin4241-svg/bounty-pilot-lab/pull/88). At commit `5d378d2b6c45703ba566f7501a863e6e5fcb00dc`, [administrative CI](https://github.com/dimin4241-svg/bounty-pilot-lab/actions/runs/45849599142) passed. All 73 administrative tests also passed on a synchronized local checkout.

The [full suite](https://github.com/dimin4241-svg/bounty-pilot-lab/actions/runs/45848998353) at the merge commit ran 2240 tests per Python version (3.9 and 3.12), with 2149 passing, 90 skipped, and one failing. The known entrypoint length assertion (236 versus 200 lines) remains unresolved. Lint also reported an unused exception variable in existing code. The subsequent [portable CI](https://github.com/dimin4241-svg/bounty-pilot-lab/actions/runs/45849599128) remained unsuccessful.

A read-only comparison found differences between installed copies and the checkout. A package version alone does not prove identical content. The standalone administrative directory is not an installed agent skill. Preserve local changes until their provenance and suitability are understood; do not overwrite or publish unknown local files. No updated agent deployment, stable release, or model-performance claim is implied.

## Release gates
- [ ] Full synthetic CI and lint succeed on the exact proposed release commit.
- [ ] Resolve the entrypoint size failure without relaxing the assertion or deleting required safeguards.
- [ ] Review public-repository runner exposure and permissions. No untrusted pull request code on personal self-hosted runners.
- [ ] Review installation manifests and version metadata; do not equate a repository commit with a deployed copy.
- [ ] Verify private data and credentials are excluded from release artifacts.
- [ ] Publish release notes that distinguish tested functionality from untested claims.

Do not mark the whole project production-ready based on administrative unit tests. They do not establish discovery effectiveness, verify technical findings, or imply integration with external models. No deployment or local skill update was performed in this maintenance change.
