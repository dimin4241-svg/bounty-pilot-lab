# Research handoff artifacts

This directory defines the private file layout for Bounty Pilot Lab handoffs. The checked-in content is generic documentation and ignore rules; live target data belongs in a private run directory and must never be pushed to this public repository.

- tasks: source-grounded hypotheses and READY_FOR_POC task JSON
- results: Codex Cloud execution results and independent review status
- pocs: bounded local-simulation or authorized local-fork PoCs
- reports: private drafts for human review

The JSON Schemas and validator are shipped under skills/bounty-pilot. Start with the workflow in skills/bounty-pilot/references/codex-cloud-handoff.md. Do not put secrets, unpublished findings, target-specific source excerpts, logs or report drafts in GitHub.

The direct Work to Cloud UI path is supported. Task creation from a newly committed file is not automatic. Choose the published environment, verify GPT-6 Luna in the model picker, and submit only a validated READY_FOR_POC task. No GitHub Actions, OpenAI API key, paid LLM API or Mac test runner is involved.
