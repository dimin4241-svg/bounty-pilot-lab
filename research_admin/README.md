# Research administration (standalone)

Local, manually operated ledger for cost accounting, artifact integrity, review history and generic offline quality metrics. Python 3.9+; standard library only. No network, provider calls, target access, subprocess execution or automatic security testing.

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

The summary command emits JSON suitable for later manual reporting. No dashboard, remote workers or autonomous discovery pipeline is included.

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

The HTML is a static local snapshot with no JavaScript, external requests, server, or editing controls. The output must not already exist. Keep the report private because it includes project identifiers and financial data. The previous statement that no dashboard was included applies to the original ledger alone; this second stage adds a static report.
