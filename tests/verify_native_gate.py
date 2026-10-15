#!/usr/bin/env python3
"""CI-only: bind real native runner output to a synthetic private finding."""
import json
import sys
from pathlib import Path

run = Path(sys.argv[1]).resolve()
head = json.loads((run / "run.json").read_text())["commit"]
(run / "findings.json").write_text(json.dumps([{
    "id": "BP-001",
    "status": "needs-evidence",
    "severity": "high",
    "revision": head
}]), encoding="utf-8")
(run / "experiments.json").write_text(json.dumps({
    "version": 1,
    "experiments": [{
        "finding_id": "BP-001",
        "status": "executed",
        "revision": head,
        "result_path": "native-results.json",
        "observation": "Observed Foundry and Cargo candidate/control assertions in native CI."
    }]
}), encoding="utf-8")
