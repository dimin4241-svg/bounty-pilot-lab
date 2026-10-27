# Ecosystem attack-chain review

Copy this file into the private run directory. Pin the target commit and scope file. Keep target
artifacts, account data, logs, and any sensitive evidence outside this skill and outside the target
checkout.

- Target repository:
- Target commit:
- Scope file and decision:
- Reviewer:
- Review date:

For each row, use `UNASSESSED`, `SIGNAL`, `CHECKED_NO_SIGNAL`, `UNAVAILABLE`, or `DISCONFIRMED`.
`CHECKED_NO_SIGNAL` names the exact checked artifacts. `UNAVAILABLE` records the missing evidence
and attempted read. A signal is a research lead, not a finding.

| ID | Direction | Priority | Status | Evidence paths and anchors | Disconfirming evidence / unavailable input |
|---|---|---|---|---|---|
| EAC-01 | Forgotten control-plane agents | Very high | UNASSESSED | | |
| EAC-02 | Data survives deletion | Very high | UNASSESSED | | |
| EAC-03 | Incomplete permission migration | Very high | UNASSESSED | | |
| EAC-04 | Stale update mechanism | Very high | UNASSESSED | | |
| EAC-05 | Legacy CI/CD workflows | High | UNASSESSED | | |
| EAC-06 | Revoked authorization returns after restore | High | UNASSESSED | | |
| EAC-07 | Orphaned OAuth integrations | High | UNASSESSED | | |
| EAC-08 | Machine identity copied during cloning | High | UNASSESSED | | |
| EAC-09 | Support console as a second access path | High | UNASSESSED | | |
| EAC-10 | Stale dependency domains | High | UNASSESSED | | |
| EAC-11 | Controller/worker authorization mismatch | Very high | UNASSESSED | | |
| EAC-12 | Security policy differs across versions | Very high | UNASSESSED | | |

## Candidate chain (only when evidence connects the steps)

- Attacker-controlled input and low-privilege starting point:
- Source and authorization boundary:
- Identity/command/data handoff:
- Worker or service action:
- Affected tenant, asset, or security property:
- Exact source/configuration anchors and revision:
- Assumptions still unverified:
- Strongest disconfirming evidence:

## Local candidate/control plan

- Isolated local fixture, mock, or fork:
- Candidate case:
- Negative control:
- Expected invariant and observable state/balance delta:
- Exact command and result (leave `NOT_RUN` until executed):
- Logs and artifact digests:

No live tenant data, production control plane, real credential, or public exploit transaction belongs
in this review.
