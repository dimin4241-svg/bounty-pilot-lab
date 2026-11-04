#!/usr/bin/env python3
"""Non-dropping AVRE hypothesis selection after full heuristic scoring.

This module does not claim security impact, novelty, or runtime reachability.
Candidates not selected are returned for an immutable private deferral artifact.
"""
from collections import Counter


def select(rows, budget):
    if type(budget) is not int or not 1 <= budget <= 5000:
        raise ValueError("budget must be 1..5000")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("rows must be a list of already scored hypotheses")
    if len(rows) != len({row.get("id") for row in rows}):
        raise ValueError("hypotheses need unique ids")
    if len(rows) <= budget:
        return list(rows), [], {
            "evaluated": len(rows), "selected": len(rows), "deferred": 0,
            "policy": "full-score-then-diverse-selection",
            "selected_by_module": dict(Counter(row.get("module", "unknown") for row in rows))}
    ordered = sorted(rows, key=lambda row: (-float(row.get("scores", {}).get("priority", 0)),
                                            str(row.get("id", ""))))
    # Reserve one representative per generating module when there is room.
    heads = {}
    for row in ordered:
        heads.setdefault(row.get("module", "unknown"), row)
    chosen = []
    included = set()
    # When modules outnumber the budget, take the best heads rather than
    # silently giving priority to earlier module registration order.
    for head in sorted(heads.values(), key=lambda r: (-float(r.get("scores", {}).get("priority", 0)),
                                                      str(r.get("id", ""))))[:budget]:
        chosen.append(head)
        included.add(head["id"])
    classes = Counter(row.get("bug_class") for row in chosen)
    surfaces = Counter(tuple(row.get("affected_paths", [])[:2]) for row in chosen)
    while len(chosen) < budget:
        remaining = [row for row in ordered if row["id"] not in included]
        # Prefer a new mechanism and new surface on otherwise close scores.
        # Bonuses are deliberately bounded to avoid burying strong candidates.
        def quality(row):
            base = float(row.get("scores", {}).get("priority", 0))
            novel_class = 0.035 if not classes[row.get("bug_class")] else 0
            novel_surface = 0.02 if not surfaces[tuple(row.get("affected_paths", [])[:2])] else 0
            return base + novel_class + novel_surface
        next_row = sorted(remaining, key=lambda r: (-quality(r), str(r["id"])))[0]
        chosen.append(next_row)
        included.add(next_row["id"])
        classes[next_row.get("bug_class")] += 1
        surfaces[tuple(next_row.get("affected_paths", [])[:2])] += 1
    selected = [{**row, "selection_rank": n} for n, row in enumerate(chosen, 1)]
    deferred = [{**row, "deferred_reason": "bounded-research-budget-not-refuted"}
                for row in ordered if row["id"] not in included]
    return selected, deferred, {
        "evaluated": len(rows), "selected": len(selected), "deferred": len(deferred),
        "policy": "full-score-then-diverse-selection",
        "selected_by_module": dict(Counter(row.get("module", "unknown") for row in selected)),
        "deferred_by_module": dict(Counter(row.get("module", "unknown") for row in deferred)),
    }
