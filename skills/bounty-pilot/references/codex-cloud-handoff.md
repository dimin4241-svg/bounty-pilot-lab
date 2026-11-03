# Codex Cloud handoff for Bounty Pilot Lab

This guide connects the existing evidence-first research workflow to the official Codex Cloud task UI. It does not submit reports, start GitHub Actions, call an LLM API, or run target code on a Mac.

## Roles and order

ChatGPT performs reconnaissance, scope review, source analysis, reachability, impact and known-issue triage. Keep an idea at HYPOTHESIS until source anchors, authorized scope, attacker capability, impact path and a decisive candidate/control test are written down. Set READY_FOR_POC only after that review. Codex Cloud is an executor for that pinned test plan; it is not the researcher or the independent reviewer.

Use the task states HYPOTHESIS, READY_FOR_POC, TESTING, CONFIRMED, REFUTED, INCONCLUSIVE and OUT_OF_SCOPE. A Cloud response that reproduces a test is still TESTING until ChatGPT independently checks the source, test assertions, negative control, commit and impact. CONFIRMED requires a reproducible candidate/control pair and an independent review that supports the finding. A green process exit by itself never confirms a vulnerability.

## Private task files and schemas

Keep live target tasks, results, PoCs, logs and report drafts under a private run directory. The root research/tasks, research/results, research/pocs and research/reports folders are convenient locations when this checkout is private. The repository ignores their contents by default. Commit only generic schemas, documentation and synthetic fixtures; never commit a live hypothesis, source excerpt, PoC, log or report to this public repository.

The JSON Schemas are in skills/bounty-pilot/schemas. The standard-library validator supports the keywords used there and checks the cross-field evidence gates:

    python3 skills/bounty-pilot/scripts/research_handoff.py validate-task /private/run/research/tasks/BP-001.json
    python3 skills/bounty-pilot/scripts/research_handoff.py validate-task /private/run/research/tasks/BP-001.json --for-cloud
    python3 skills/bounty-pilot/scripts/research_handoff.py validate-result /private/run/research/results/BP-001.json --task /private/run/research/tasks/BP-001.json

Only submit a security_hypothesis task whose status is READY_FOR_POC. The cloud-readiness check also requires an in-scope target, an evidenced attacker path, source anchors pinned to the repository commit, a candidate and negative control, and a reviewed known-issue check. A workflow_smoke_test may use a synthetic target and must never be reported as a bounty finding.

Every task pins repository URL, ref and full commit SHA. Every source anchor must name a tracked path, line range and excerpt. Results bind back to the task ID and the same commit. A result marked CONFIRMED must include a zero-exit test run, at least one test, an explicit demonstrated behavior, a PoC artifact, a test-log artifact whose SHA-256 matches the execution record, and an independent review that supports the finding. REFUTED also requires executed evidence and an independent review. INCONCLUSIVE needs a concrete blocker with the attempted command and output.

## Start the task in Codex Cloud

1. Open Codex in ChatGPT or the desktop app, choose Work in > Cloud, and select the published Bounty Pilot Lab environment.
2. Select the pinned repository ref/commit shown in the task JSON. Do not use a floating main branch when the task specifies a commit.
3. Open the model picker and verify the selected model reads GPT-6 Luna before sending. If Luna is unavailable or the account blocks the task at its included Plus limit, stop. Do not choose another model, enable paid credits or use an API.
4. Paste the validated task JSON and ask Codex to run only its bounded candidate/control plan in the Cloud workspace. Require it to return a result JSON matching the result schema, test commands and exit codes, test counts, relevant log excerpts, artifact paths and SHA-256 digests. Keep tests on local simulation or an authorized local fork; prohibit mainnet, live transactions and production writes.
5. Review the Codex Cloud conversation and actual saved log/PoC before changing the task status. Store a copy of the result in the private run directory and validate it against both schemas.

Do not use agent_dispatch.py --provider codex for a Cloud PoC: that provider invokes local codex exec on the current host. It may remain useful for its existing source-only workflow, but it does not satisfy this Cloud-only execution requirement.

## What is and is not automatic

ChatGPT Work can open Codex Cloud and a published environment directly, so no GitHub commit is needed as a task trigger. This handoff still requires a person to choose the environment, verify GPT-6 Luna and submit the specific hypothesis. No event-driven trigger is installed. GitHub Actions are not used.

The documented experimental codex cloud command submits a task with an environment and prompt, but its documented cloud-specific flags do not include a model override. Use the UI model picker when the model must be verifiably GPT-6 Luna. Codex Cloud keeps the executor conversation and outputs in the same ChatGPT account; the researcher must inspect that task and copy its result into the private run. It does not silently promote or publish reports.
