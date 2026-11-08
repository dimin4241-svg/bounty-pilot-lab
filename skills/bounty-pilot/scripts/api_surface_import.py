#!/usr/bin/env python3
"""Turn saved mitmproxy2swagger/OpenAPI 3 output into a review queue of GET paths.

Never fetches $ref, visits the API or produces replayable authorization
requests. Object IDs, token env vars, unique owner markers and test permission
must be separately supplied by the operator to web_auth_lab.py.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

ID_HINT = re.compile(r"(?i)(?:^|[/_{}-])(user|owner|account|order|invoice|payment|"
                     r"position|wallet|team|project|tenant|merchant|organization|org|id)")
METHODS = {"get"}


def load(path):
    p = Path(path).expanduser()
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 5_000_000:
        raise ValueError("spec must be regular non-symlink JSON/YAML <=5MB")
    raw = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:
            raise ValueError("PyYAML needed for YAML; alternatively export OpenAPI JSON") from exc
        obj = yaml.safe_load(raw)
    elif p.suffix.lower() == ".json":
        obj = json.loads(raw)
    else:
        raise ValueError("spec must be JSON or YAML")
    return obj


def build(spec):
    if not isinstance(spec, dict) or not str(spec.get("openapi", "")).startswith("3."):
        raise ValueError("OpenAPI version 3.x required")
    paths = spec.get("paths")
    if not isinstance(paths, dict) or len(paths) > 10000:
        raise ValueError("paths must be bounded OpenAPI map")
    leads = []
    for path, operations in sorted(paths.items()):
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or len(path) > 600:
            continue
        if not isinstance(operations, dict):
            continue
        for method in METHODS:
            op = operations.get(method)
            if not isinstance(op, dict):
                continue
            if len(leads) >= 5000:
                raise ValueError("too many GET leads")
            params = re.findall(r"\{([A-Za-z][A-Za-z0-9_]*)\}", path)
            tag = "object-identifier-review" if params or ID_HINT.search(path) else "general-get"
            sec = op.get("security", spec.get("security", []))
            if not isinstance(sec, list):
                sec = []
            tags = op.get("tags") or []
            if not isinstance(tags, list):
                tags = []
            leads.append({"method": "GET", "path_template": path,
                          "parameter_names": sorted(set(params)),
                          "operation_id": str(op.get("operationId") or "")[:120],
                          "review_category": tag,
                          "advertised_security": bool(sec),
                          "tags": [x[:50] for x in tags[:10] if isinstance(x, str)],
                          "review": ("Materialize only OWNED test-object IDs, and prepare "
                                     "two-account baseline/control in web_auth_lab.py. "
                                     "A schema path is not proof of an IDOR.")})
    return {"schema_version": 1, "leads": leads, "count": len(leads),
            "execution": "offline-openapi-inventory",
            "notice": ("OpenAPI is untrusted documentation, not an authorization grant. "
                       "No requests were sent and no resource IDs guessed. "
                       "All traffic requires verified program policy and owned accounts.")}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--spec", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    out = Path(a.out).expanduser()
    if out.exists() or out.is_symlink():
        p.error("output must not exist")
    try:
        result = build(load(a.spec))
        out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(out), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except (ValueError, OSError, TypeError, KeyError, json.JSONDecodeError) as exc:
        p.error(str(exc))
    print(json.dumps({"out": str(out), "leads": result["count"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
