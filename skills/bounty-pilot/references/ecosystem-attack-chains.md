# Ecosystem attack-chain research

Use this playbook when an in-scope project spans a control plane, worker, cloud/storage service,
identity provider, CI/CD, support console, updater, or multiple deployed versions. It complements
the source hunt with lifecycle and trust-boundary questions. It does not establish that any of the
listed mechanisms exist in a target.

The priority labels below preserve the requested investigation order. They express research
priority only; they do not estimate vulnerability likelihood, severity, bounty eligibility, or
payout. Read [`ecosystem-intelligence.md`](ecosystem-intelligence.md) for the passive collector's
scope and data limits. Copy [`../templates/attack-chain-review.md`](../templates/attack-chain-review.md)
to the private run directory and record every applicable pattern.

## Review method

For each pattern, follow one evidenced path:

`unprivileged input → control/validation boundary → command or state transition → affected asset`

Record exact paths and line anchors, the pinned commit, what artifact classes were inspected,
attacker-controlled fields, the invariant, disconfirming evidence, and a local candidate/control
test plan. Separate code evidence from deployment assumptions. Do not use administrator compromise,
host compromise, or compromise of an unrelated provider as the attacker starting point. If that is
the only route, mark the vector unavailable or reject it unless a separate in-scope low-privilege
path is evidenced.

Use these ledger states:

- `UNASSESSED`: no review has been done yet.
- `SIGNAL`: one or more source-anchored clues warrant tracing; this is not a finding.
- `CHECKED_NO_SIGNAL`: named in-scope artifacts were inspected and yielded no relevant clue. This
  says nothing about omitted, generated, remote, or live configuration.
- `UNAVAILABLE`: a required source, deployment inventory, provider setting, or authorized test
  environment could not be inspected. Name the missing artifact and attempted read.
- `DISCONFIRMED`: observed evidence rules out this mechanism on the reviewed revision and scope;
  cite that evidence. A missing keyword is not disconfirmation.

The playbook is passive. Never validate credentials, use discovered secrets, register abandoned
domains, impersonate users, access another tenant's storage, invoke support recovery on real
accounts, install a remote package, alter CI settings, or send commands to production agents. Use
synthetic data and investigator-owned local mocks. Any target-side effect needs separate explicit
authorization and is outside the playbook.

## Twelve patterns

### EAC-01 — Forgotten control-plane agents

**Research priority: Very high.** An old privileged daemon or guest agent remains reachable after
the project moved its control plane, and still accepts commands from a stale controller or weakly
bound sender.

- **Inspect:** deployment and image manifests, systemd/launchd/service definitions, agent versions,
  old endpoint references, task queues, enrollment code, command signatures, mTLS identity checks,
  expiry/revocation, and controller-to-agent authorization.
- **Invariant:** every command binds an authenticated issuer, unique agent identity, target, allowed
  operation, freshness/nonce, and authorization epoch; retired issuers cannot issue accepted work.
- **Disconfirm:** prove the old agent is absent from supported images/inventory, or show its command
  path enforces the same current authorization and rejects revoked identities.
- **Safe test:** use a local fake agent and synthetic signed commands; compare valid current issuer
  with a stale issuer, wrong agent, changed operation, and replay.

### EAC-02 — Data survives deletion

**Research priority: Very high.** A delete/release path removes the visible VM or tenant record but
leaves data reachable through a storage pool, snapshot, image, cache, backup, or later allocation.

- **Inspect:** API deletion handlers, asynchronous cleanup jobs, block/object storage lifecycle,
  snapshot and image retention, cache invalidation, tenant ownership labels, encryption-key
  destruction, and re-provisioning paths.
- **Invariant:** after the documented deletion boundary, no other tenant or subsequent allocation
  can read the deleted tenant's data; retention and crypto-erasure match the product contract.
- **Disconfirm:** trace the complete cleanup/retention lifecycle and demonstrate tenant isolation or
  key destruction for every retained copy.
- **Safe test:** use synthetic tenants and local storage mocks; assert deletion, snapshot expiry,
  reuse, and a second tenant's reads. Never inspect another user's or a real customer's storage.

### EAC-03 — Incomplete permission migration

**Research priority: Very high.** V2 becomes the documented authority, while a V1 route, role,
signer, allowance, worker, or deployment path retains permission to change state or assets.

- **Inspect:** V1/V2 handlers, API gateways, role and signer manifests, migrations, revocation code,
  proxy/upgrade paths, job consumers, deployment scripts, and local history around the migration.
- **Invariant:** only the current authority can mutate protected state; migration revokes or safely
  constrains every old route and identity before V2 is treated as complete.
- **Disconfirm:** establish that the old route is unreachable/removed and its identities are revoked,
  or that it delegates to the same current authorization decision.
- **Safe test:** create a local V1/V2 mock with synthetic roles; migrate and revoke, then compare
  old-route and new-route operations under a low-privilege caller.

### EAC-04 — Stale update mechanism

**Research priority: Very high.** The primary service is updated, but an installer, agent, recovery
module, or package updater still trusts another source, unsigned artifacts, stale versions, or
unsafe rollback behavior.

- **Inspect:** installer and updater scripts, package/release sources, manifest pinning, signature
  and checksum verification, version constraints, key rotation, downgrade handling, and update
  configuration for agents and recovery tools.
- **Invariant:** only an authenticated artifact from an authorized source, at an allowed version and
  rollback state, can replace executable code.
- **Disconfirm:** trace verification from downloaded bytes to execution, including key rotation and
  downgrade policy; a URL or checksum string alone does not prove verification.
- **Safe test:** feed a local updater fixture valid, unsigned, corrupted, stale, and downgraded
  artifacts. Do not fetch or execute a real third-party package.

### EAC-05 — Legacy CI/CD workflows

**Research priority: High.** A secondary release, test, recovery, or manual workflow retains a
privileged token or handles untrusted artifacts/code with write permissions.

- **Inspect:** every tracked CI configuration and workflow, including release and recovery jobs;
  triggers, `permissions`, environment protection, reusable workflows, artifact provenance, secret
  references, branch filters, and execution of fork-controlled code.
- **Invariant:** untrusted input cannot reach a job with unnecessary write/deploy authority; each
  privileged workflow has explicit trigger, approval, least privilege, and artifact binding.
- **Disconfirm:** review all workflow files and reusable dependencies and show that dangerous input
  cannot reach a privileged job under the configured permission model.
- **Safe test:** parse repository-local fixtures or run a local policy check. Use fake tokens only;
  never print, validate, or exercise real CI credentials.

### EAC-06 — Revoked authorization returns after restore

**Research priority: High.** Backup recovery restores an old role, token, signer, trust setting, or
authorization cache that was revoked after the backup was created.

- **Inspect:** backup schemas, restore/import procedures, revocation ledgers, permission epochs,
  caches, key rotation, and post-restore reconciliation jobs.
- **Invariant:** restore cannot make a revoked identity valid again; revocation state newer than the
  backup is preserved or re-applied before the service resumes.
- **Disconfirm:** show a monotonic revocation source or mandatory reconciliation that runs before
  restored services accept commands.
- **Safe test:** restore a synthetic backup from before revocation into a local fixture and verify
  the old identity remains rejected while a newly authorized identity works.

### EAC-07 — Orphaned OAuth integrations

**Research priority: High.** A removed application, domain, or callback remains trusted by an
identity provider or an old callback path still accepts authorization responses.

- **Inspect:** OAuth/OIDC client references, callback and redirect URI construction, state/nonce
  validation, app registration manifests, environment-specific configuration, old domains, and
  migration docs. Provider-console state may be unavailable from source.
- **Invariant:** each authorization response is bound to the intended client, exact registered
  redirect, user session, state, and one-time transaction; retired callbacks cannot complete login.
- **Disconfirm:** obtain authorized read-only configuration evidence that the obsolete client and
  callback are removed and confirm the current flow binds state and redirect correctly.
- **Safe test:** use a local mock identity provider and synthetic users to test mismatched and stale
  callbacks. Never initiate login or redeem a code against a real provider.

### EAC-08 — Machine identity copied during cloning

**Research priority: High.** A cloned VM or container image inherits the source machine's agent
registration, identity, credentials, keys, or permissions.

- **Inspect:** image build and cloud-init/user-data scripts, machine/instance ID generation,
  enrollment and rotation, guest-agent state, cached credentials, and clone/reprovision lifecycle.
- **Invariant:** every clone receives a fresh identity and credentials; the source identity is not
  shared, and copied enrollment material is revoked or unusable.
- **Disconfirm:** trace first boot to unique enrollment and verify image build strips identity state
  and secrets before publication.
- **Safe test:** instantiate two local mock machines from one synthetic image and assert distinct
  identities; test that the source credential fails on the clone.

### EAC-09 — Support console as a second access path

**Research priority: High.** A support, recovery, remote-console, impersonation, or break-glass
service bypasses protections enforced by the primary API.

- **Inspect:** support/admin routes, account recovery and reset workflows, remote console services,
  impersonation approvals, break-glass roles, MFA/session checks, audit trail, and links to cloud or
  signing operations.
- **Invariant:** the alternate path enforces equivalent tenant/asset authorization, explicit
  approval and traceability, with bounded and revocable support authority.
- **Disconfirm:** show authorization is shared or stronger, tenant/object IDs are rechecked, and
  support actions are constrained and audited.
- **Safe test:** use an investigator-owned local account and mock support service; test cross-tenant
  IDs and expired approvals without performing a real reset or opening a support ticket.

### EAC-10 — Stale dependency domains

**Research priority: High.** A retired hostname remains trusted by a webhook, OAuth callback, SDK,
installer, DNS record, or configuration, allowing misdelivery if ownership or routing changes.

- **Inspect:** current and historical domain references in tracked code/config/docs, local Git
  history, callback and webhook allowlists, package/update sources, and any authorized public
  archive snapshot. Classify each hostname against explicit scope.
- **Invariant:** every trusted hostname has an evidenced current owner and intended purpose; retired
  destinations are removed or rejected. A URL mention alone does not show a live trust relationship.
- **Disconfirm:** show the reference is unused or the destination is currently owned and
  authenticated with strict endpoint binding. Mark unavailable when DNS/provider state is outside
  permitted evidence.
- **Safe test:** use local URL/config fixtures to check allowlist behavior. Do not register, probe,
  or attempt to claim a domain; do not contact an out-of-scope endpoint.

### EAC-11 — Controller/worker authorization mismatch

**Research priority: Very high.** A controller authorizes a request, then a privileged worker
executes a queued or delayed command using stale, incomplete, or differently scoped data.

- **Inspect:** API authorization and serialization, queue producer/consumer schemas, worker identity,
  tenant and target binding, operation allowlists, request IDs/nonces, cancellation/revocation,
  retries, and reauthorization at execution time.
- **Invariant:** the worker authenticates the job and rechecks principal, tenant, target, operation,
  freshness, and current authorization at the point of execution; queued data cannot widen the
  controller's decision.
- **Disconfirm:** trace one request ID end to end and show integrity, scope binding, and current
  authorization are preserved through retries and delayed execution.
- **Safe test:** use a local mock queue and fake identities; alter tenant, operation, target,
  authorization epoch, or request ID between enqueue and execution and compare against a valid
  control job.

### EAC-12 — Security policy differs across versions

**Research priority: Very high.** During rolling deployment or across nodes, relayers, validators,
workers, clients, or bridge components, some versions enforce weaker authorization or message rules.

- **Inspect:** version manifests and lockfiles, compatibility negotiation, protocol/message schema,
  rolling deployment and downgrade policy, feature flags, node/worker matrices, and security fixes
  across local tags and history.
- **Invariant:** all accepted participants enforce compatible security semantics; mismatched or
  downgraded peers fail closed, and signatures/messages bind the applicable policy/version.
- **Disconfirm:** compare all deployed/released version paths and show mismatches are rejected or
  retain equivalent checks. A version string is not proof of deployed behavior.
- **Safe test:** use a local compatibility matrix with old/new synthetic nodes and candidate/control
  messages; record the pinned revisions and reject downgrade or weaker-policy negotiation.

## Interpretation

Do not combine two patterns into one attack chain unless source or configuration evidence connects
the exact components and identities. Do not turn a pattern match, keyword, stale reference, or
missing artifact into a vulnerability. No pattern has been benchmarked for recall, false positives,
or bounty acceptance. The ordinary source, deployment, scope, duplicate, reproduction, impact, and
independent-review gates still decide whether a lead can become a report.
