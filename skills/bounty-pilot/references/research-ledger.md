# Research ledger P0

An optional offline session ledger, complementing research-run, research-loop,
bounty-outcome-feedback and historical-paired-eval rather than replacing them.
No model/API calls, automatic experiment dispatch, network traffic or target execution.

Keep the DB and all inputs in a private local directory outside the repository.
Use a dedicated directory with mode 0700; never commit the DB, report receipts
or scope documents to the repository. The DB is initialized with mode 0600.

Set a local shell helper (example for a reviewed synthetic project):

    bp() {
      python3 skills/bounty-pilot/scripts/bounty.py research-ledger \
        --db "$LEDGER" --scope "$POLICY" --revision "$REVISION" "$@"
    }

Set LEDGER to a new private SQLite path, POLICY to the current reviewed scope
file, and REVISION to the pinned source commit (40 or 64 lowercase hex digits).

    bp init --budget 5000000 --confirm-reviewed-scope
    bp reserve review-001 model-a 250000
    bp status
    bp settle review-001 200000
    bp review case-001 analyst reviewer candidate.json control.json inconclusive
    bp feedback case-001 pending triage-receipt.json
    bp status

Amounts are integer micro-USD: 1000000 = 1 USD. Reserve a ceiling BEFORE
starting a separately approved task. Settle after obtaining the actual provider
charge. A failed or interrupted task remains reserved until its charge is known.
Do not settle to zero unless confirmed. SQLite serializes reservations, persists
pending entries and rejects duplicate job IDs or repeated settlements. If actual
spend exceeds the total budget, subsequent reservations are denied. The true
charge is preserved even if higher than the reserved amount.

This is accounting, not a provider-enforced hard cap: callers must use the
ledger consistently and independently configure provider spending limits.
The ledger does not make model calls or cancel in-flight calls.
Scope/revision strings are operator assertions, not verification of legal
permission or actual checkout identity. A changed scope file or revision
requires a new session. IDs must not contain secrets or personal identifiers.

Review records bind distinct candidate/control hashes and distinct declared
author/reviewer IDs. A hash does not authenticate a receipt, prove independence,
prove target behavior or establish impact. No record is marked verified by this
tool. Use existing evidence gates and independently reproduce in an authorized
isolated fixture. Feedback history accepts additional distinct events and
reports the latest recorded outcome per case. Feedback is operator-supplied,
not automatically imported or validated. There is no automated report submission.

Run the synthetic tests:

    python3 -m unittest discover -s tests -p test_research_ledger.py -v

The ledger does not encrypt data at rest or defend against someone who can
modify the private DB. Store only non-secret IDs and evidence digests; keep
raw evidence private. Use the existing paired benchmark tools for measured
performance rather than treating review counts as discovery success.
