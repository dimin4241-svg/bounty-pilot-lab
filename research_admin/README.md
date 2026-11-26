# Research administration (standalone)

Local, manually operated ledger for cost accounting, artifact integrity, review history and generic offline quality metrics. Python 3.9+ language compatibility; standard library only. Current administrative CI tests Python 3.11 and 3.12. No network, provider calls, target access, subprocess execution or automatic security testing.

Keep the SQLite database outside the repository and restrict its permissions. Do not store credentials or sensitive report contents in notes. Amounts are integer microdollars (1 USD = 1,000,000). Reserve a conservative maximum before any separately authorized expenditure; settlement releases unused funds. A reservation remains open after interruption. This is a ledger, not enforcement at the provider; costs incurred outside it are not tracked. No model/API integration is included.

```sh
umask 077
DB="$HOME/research-admin.sqlite3"
python3 research_admin/ledger.py --db "$DB" project demo 1000000 'Local review'
python3 research_admin/ledger.py --db "$DB" reserve demo sample mock 100000
python3 research_admin/ledger.py --db "$DB" settle sample 50000
python3 research_admin/ledger.py --db "$DB" review demo pending 'Manual review required'
python3 research_admin/ledger.py --db "$DB" summary
python3 -m unittest discover -s research_admin -p 'test_*.py'
```

Artifact registration hashes a manually chosen regular file inside a supplied local directory; verification checks byte integrity, not the correctness, impact or validity of a finding. Review outcomes are manually entered, not inferred. The evaluate command stores manually supplied binary reference and observed labels for generic synthetic cases; metrics are descriptive counts, not a benchmark of vulnerability discovery. Compare only identical case sets, and maintain reference labels separately from participants. No 550-case corpus is included.

The summary command emits JSON suitable for manual reporting. The separate workflow module described below adds a static dashboard; neither module includes remote workers or an autonomous discovery pipeline.

## Manual workflow and static dashboard

The workflow module adds administrative states (review, active, paused, archived), three manually attested checkpoints (authorization, data_handling, review), and an event history. It upgrades a previous ledger by adding two tables without rewriting existing records. A blocked checkpoint changes the administrative state from active to paused. Archiving requires settled reservations. These are bookkeeping states, not process controls: they do not start, stop, schedule or authorize any external action or enforce the ledger across other programs. Reviewer identity and approval validity are manually entered, not authenticated.

```sh
python3 research_admin/workflow.py --db "$DB" checkpoint demo authorization approved operator 'Document checked'
python3 research_admin/workflow.py --db "$DB" checkpoint demo data_handling approved operator 'Handling plan reviewed'
python3 research_admin/workflow.py --db "$DB" checkpoint demo review approved operator 'Manual review completed'
python3 research_admin/workflow.py --db "$DB" transition demo active operator 'Administrative status'
python3 research_admin/workflow.py --db "$DB" history demo
python3 research_admin/workflow.py --db "$DB" snapshot
python3 research_admin/workflow.py --db "$DB" dashboard "$HOME/research-status.html"
```

The HTML is a static local snapshot with no JavaScript, external requests, server, or editing controls. The output must not already exist. Keep the report private because it includes project identifiers and financial data. The dashboard is a static report, separate from the original ledger.

## Manual knowledge and matched quality comparison

The quality module catalogs non-sensitive, manually entered process notes and review decisions, with a required source reference. It does not ingest private reports, discover targets, call models, or infer technical findings. Keep the database private and use non-secret reference identifiers.

```sh
python3 research_admin/quality.py --db "$DB" record lesson-1 process 'Review notes' 'Require manual sign-off' 'Internal review'
python3 research_admin/quality.py --db "$DB" catalog all
python3 research_admin/quality.py --db "$DB" compare generic v1 mock-a v2 mock-b
```

The comparison requires identical nonempty case IDs and reference labels on both sides, then computes accuracy, precision, recall, false-positive/negative counts, paired improvement/regression counts and cost deltas. Undefined ratios are null. The command consumes existing manually recorded evaluation rows; it does not generate or run benchmarks. No real-world model ranking can be inferred from the synthetic unit tests.

## Operational checklist

Use a private directory outside the repository. New database files, backups and static dashboard files are created with mode 0600; existing database permissions are not changed. Keep the parent directory private as well. Do not put actual reports, keys or provider credentials in this public repository.

```sh
umask 077
mkdir -p "$HOME/.local/share/research-admin"
chmod 700 "$HOME/.local/share/research-admin"
DB="$HOME/.local/share/research-admin/ledger.db"
python3 research_admin/maintenance.py --db "$DB" doctor
python3 research_admin/maintenance.py --db "$DB" backup "$DB.backup"
python3 -m unittest discover -s research_admin -p 'test_*.py' -v
```

The doctor is read-only and validates SQLite integrity, foreign keys, base ledger tables, required columns and the aggregate of settled and reserved costs against each project's limit. It does not repair the database or verify provider invoices; a failed check blocks the backup command. The backup uses SQLite's backup API and refuses to overwrite an existing file. Before restoring, close all writers, retain the original separately and verify the backup with doctor; the test suite verifies that a backup opens with matching administrative state. A new reservation for an archived project is rejected. The dedicated GitHub Actions workflow runs only the offline administrative unit tests under Python 3.11 and 3.12. This module is independent of the original research pipeline; CI coverage of this module is not evidence of security research effectiveness or full-project readiness.

## Manual review journal

The journal records observations, assumptions, questions, controls and limitations as manually entered documentation with a required source reference. Decisions are append-only review records with a named reviewer and a reason. Open and deferred entries remain visible in a read-only handoff snapshot. Reopening an entry preserves previous decisions. A complete review means no unresolved journal entries, not that a technical finding is valid or that an entire project has been examined.

```sh
python3 research_admin/journal.py --db "$DB" add demo note-1 question 'Documentation incomplete' 'Internal notes'
python3 research_admin/journal.py --db "$DB" decide demo note-1 deferred reviewer 'Awaiting documentation'
python3 research_admin/journal.py --db "$DB" handoff demo
```

No agent prompting, automated action selection, exploit-chain construction, network requests or test execution is performed. Do not publish private journal contents. References for the general documentation and manual-review approach: OWASP WSTG Introduction and Reporting Structure; NIST developer verification guidance.

## Offline documentation benchmark

`report_benchmark.py` evaluates manually submitted answers to generic document-review questions, without invoking agents or running security tests. Task JSON records contain id, question and a mapping of source document IDs to text. Separate reference JSON records contain id, label (supported/refuted/unresolved) and required source_ids. Answer records contain id, label, source_ids and reason. Keep reference files outside participant access; separation is procedural, not an access-control sandbox. Missing answers count as failures, duplicate and unknown IDs are rejected, and a comparison flags individual regressions even if aggregate accuracy is unchanged. The evaluator verifies labels, source IDs and presence of a reason; it cannot establish the semantic validity of prose.

```sh
python3 research_admin/report_benchmark.py tasks.json references.json answers.json --baseline old-answers.json
```

Exit 1 indicates a paired regression and exit 2 invalid input. The unit tests use synthetic order/receipt documents. This is a documentation-quality benchmark, not a benchmark of security vulnerability detection or proof of improved AI performance.

## Manual technical review form

`review_form.py` creates a blank JSON form with 15 named sections for a human reviewer, including cause, observed and expected behavior, documentation references, limitations and manual review. It is a completeness checker, not an analysis or proof engine. A documented section requires a note and reference strings; unresolved sections and missing reviewer details prevent a complete status. Core sections cannot be bypassed by marking them not applicable. Optional not-applicable sections require a justification. The tool never verifies the referenced material or determines the actual cause, impact, validity or severity. A complete document is not evidence of a verified finding.

```sh
python3 research_admin/review_form.py template "$HOME/private-review.json"
# Edit the form manually using locally reviewed information.
python3 research_admin/review_form.py check "$HOME/private-review.json"
```

Exit 0 means structurally complete, 1 incomplete, 2 malformed input or filesystem error. Do not publish populated forms or sensitive review materials to the public repository.

### Public documentation exercises

The `fixtures/documentation_tasks.json` file contains 12 fictional documentation review questions across backup operations, version records, accounting and routine document review. The separate `fixtures/documentation_references.json` file contains four supported, four refuted and four unresolved reference labels. These are open examples, not a blind benchmark: the answer key is public. The unit tests use answers derived from that key solely to check the evaluator's behavior; they do not measure a model.

For a manual classroom exercise, provide only the tasks to participants and collect answers using the documented format. Run the evaluator against those answers locally:

```sh
python3 research_admin/report_benchmark.py research_admin/fixtures/documentation_tasks.json research_admin/fixtures/documentation_references.json "$HOME/private/answers.json"
```

Do not publish private participant responses. For an independent evaluation use a new privately held dataset. No external model calls, automated target analysis or security tests are included.

## Local SARIF inventory

`sarif_summary.py` reads a manually supplied local SARIF 2.1.0 file from a completed authorized exercise or defensive review. It produces a JSON inventory with a SHA-256 fingerprint, file size, run count, reported result levels and a pending manual review status.

```sh
python3 research_admin/sarif_summary.py "$HOME/private/report.sarif"
```

The reader caps input at 16 MiB, refuses final-component symlinks and nonregular files, and does not follow SARIF locations, external references or URLs. Report messages, target paths and evidence are not included in the summary. Counts describe the source's reported levels, not verified findings, unique issues or assessed severity. The fingerprint identifies bytes, not an authenticated author. This is a limited SARIF inventory, not a full schema validator. Tests use synthetic documents. Compatibility with a real Shannon export has not been established. No Shannon code, model integration, automatic execution or target testing is included.

To persist the inventory privately and compare it later with the original file:

```sh
umask 077
python3 research_admin/sarif_summary.py "$HOME/private/report.sarif" --save "$HOME/private/report-summary.json"
python3 research_admin/sarif_summary.py "$HOME/private/report.sarif" --verify "$HOME/private/report-summary.json"
```

Use an existing private directory controlled by the operator. Export creates a new mode-0600 file and refuses overwrites. Verification compares the entire saved inventory with a newly calculated one; exit 0 means match, 1 means mismatch, 2 means invalid or unreadable input/output. Neither a match nor a report hash establishes authenticity or the technical truth of the report. This does not import report content into the ledger or connect to Shannon.

## Private summary workspace

For locally reviewed report inventories, use an owner-controlled directory outside the Git repository:

```sh
python3 research_admin/summary_workspace.py --workspace "$HOME/pilot-summaries" init
python3 research_admin/summary_workspace.py --workspace "$HOME/pilot-summaries" store "$HOME/private/report.sarif"
python3 research_admin/summary_workspace.py --workspace "$HOME/pilot-summaries" inventory
```

The directory must be private (no group or other permissions). Identical report bytes map to the same SHA-256-based summary filename. Existing summaries are checked rather than overwritten. The inventory checks the complete administrative summary field set, allowed status values, byte bounds and arithmetic consistency of reported counts. It does not authenticate report authors, verify original reports, validate findings or validate the full SARIF schema. Use a trusted local directory, not a shared or adversarial filesystem. No report text, target paths, agents or test execution are imported.
