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
