# Offline cross-domain impact and OAuth lifecycle workflows

These tools review locally supplied observations, not third-party applications.
They never execute target code or call remote endpoints.

## Business impact gate

Example:

    python3 skills/bounty-pilot/scripts/bounty.py business-impact-oracle \
      --case /private/cases/impact-case.json \
      --receipts /private/cases/witnesses \
      --out /private/reviews/impact-review.json

The case is JSON with schema_version 1, domain (web/api/android/ios/electron/web3),
scenario_id, scope (operator_confirmed boolean and policy_reference string),
expected_policy (candidate_effect_permitted boolean) and two objects named
candidate and control. Each contains actor_id, before_sha256, after_sha256,
receipt_file, receipt_sha256. State comparisons are exact digests; initial
candidate and control digests must match for a clean differential. Witness
files must be regular, 2 MiB or smaller, under the supplied private root,
and their SHA-256 content hashes are verified.

The strongest possible status is
DIFFERENTIAL_UNAUTHORIZED_BY_STATED_POLICY_REVIEW_REQUIRED. This is still
an operator-supplied lead, NOT actual exploit impact verified. SHA-256
attests integrity of the receipt file, not its authenticity or accuracy.

## OAuth and role lifecycle

Example:

    python3 skills/bounty-pilot/scripts/bounty.py oauth-lifecycle-lab \
      --trace /private/cases/oauth-trace.json \
      --out /private/reviews/oauth-review.json

The input JSON has schema_version 1, policy and ordered events. Policy must
explicitly state invalidate_unredeemed_codes, invalidate_refresh_on_revoke
(boolean), and role_actions (role -> list of allowed actions).

Each event has id, seq, type and relevant opaque identifiers:
grant(grant, actor); issue_code(grant, code);
exchange_code(grant, code, accepted);
issue_refresh(grant, refresh_id); refresh(grant, refresh_id, accepted);
revoke_grant(grant); set_role(actor, role); action(actor, action, accepted).
Only exchange_code, refresh and action supply observed accepted booleans.

The engine compares operator-reported acceptance with the explicit policy
and reports POLICY_DIVERGENCE_REVIEW on mismatches. No OAuth standard
automatically requires the same revocation policy for every service;
token validity and grant consent must be distinguished. Neither successful
HTTP replies nor operator statements establish protected state effects.
Never include raw secrets or tokens: use opaque local labels.

These modules complement existing web_business_lab, web_effect_oracle,
web_actor_state_graph and evidence_verifier. Independent scope checking,
real caller attribution, paired reproducibility and impact are still needed.
