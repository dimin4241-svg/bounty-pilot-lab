#!/usr/bin/env python3
"""Lexical source-anchor leads for web_business_lab rules; NOT a verified anchor.

web_business_lab.plan() requires a human-found `source_anchor` for every job, and
web_business_lab.bridge() explicitly "never accepts automatically guessed code
anchors". This tool does not change that: it only shortens the search by listing,
per selected rule, where its concept-specific terms appear lexically in the target's
own tracked checkout. A hit is a place to go read, never a confirmed anchor; a rule
with no hit may still be enforced under a different name, a vendored dependency or a
generated file this scan excludes. Read-only, tracked checkout, bounded exact-term
matching. Never executes target code.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

GIT_OPTS = ("--no-optional-locks", "-c", "core.fsmonitor=false",
            "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat")
CODE_SUFFIX = {".sol", ".vy", ".rs", ".go", ".py", ".ts", ".tsx", ".js", ".jsx",
              ".move", ".cairo", ".java", ".rb", ".php"}
EXCLUDED = {"node_modules", "vendor", "dist", "build", "target", ".git", "test", "tests"}
MAX_FILE = 200_000
MAX_HITS_PER_TERM = 8
MAX_HITS_PER_RULE = 25

def _load_sibling(name):
    """Load a script from this same directory regardless of the caller's cwd or
    sys.path. A bare `from X import Y` here silently falls back on any import
    error, including the common case of this file being loaded by path (as
    bounty.py's dispatcher and the test suite both do) from a different cwd."""
    import importlib.util
    path = Path(__file__).resolve().with_name(name + ".py")
    spec = importlib.util.spec_from_file_location("bp_business_schema_bind_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Fail closed if the sibling analyzer is unavailable or broken; silently
# substituting family=None masks an actual integration failure.
RULES = _load_sibling("web_business_lab").RULES

# One researcher-curated term list per rule; every term is lexical only, never a
# claim that matching code exists, enforces the rule or compiles.
RULE_KEYWORDS = {
    "account-owner": ("credential_version", "change_password", "update_credentials",
                      "actor_authorized", "update_account"),
    "mfa-gate": ("mfa", "totp", "two_factor", "twofactor", "mfa_required", "mfa_verified"),
    "session-revocation": ("session_active", "revoke_session", "invalidate_session",
                           "logout_all", "session_revoked"),
    "reset-one-use": ("reset_token", "password_reset", "token_used", "reset_token_used"),
    "oauth-binding": ("oauth", "issuer", "audience", "nonce", "id_token", "oidc"),
    "email-verification": ("email_verified", "verify_email", "pending_email",
                           "email_verification"),
    "unpaid-credit": ("psp_confirmed", "available_cents", "credit_balance",
                      "balance_credit", "non_payment_credit"),
    "event-replay": ("payment_event", "idempotency_key", "processed_events",
                     "event_already_processed", "payment_event_ref"),
    "webhook-binding": ("webhook", "signature_valid", "verify_signature", "hmac",
                        "webhook_signature"),
    "refund-replay": ("refund", "refund_event", "refund_event_ref", "refund_idempotency"),
    "subscription-entitlement": ("subscription", "entitlement_active", "activate_subscription",
                                 "grant_entitlement"),
    "cancellation-stale": ("cancel_subscription", "grace_period", "cancellation",
                           "entitlement_active"),
    "cross-tenant-credit": ("tenant_id", "organization_id", "org_id", "cross_tenant"),
    "cross-actor-disclosure": ("owner_id", "user_id", "actor_authorized",
                               "get_profile", "resource_owner"),
}
TERM = re.compile(r"^[a-z][a-z0-9_]{2,40}$")


def _rules():
    for rule in RULES:
        if rule not in RULE_KEYWORDS:
            raise ValueError("rule has no curated keyword list: " + rule)
    return RULES


def _path_prefix(value):
    if not isinstance(value, str) or not value or len(value) > 240:
        raise ValueError("scope must be a short relative checkout path")
    p = Path(value)
    if p.is_absolute() or ".." in p.parts or "\\" in value or "\x00" in value or p.as_posix() == ".":
        raise ValueError("path traversal or unsupported relative scope")
    if any(x in EXCLUDED or "secret" in x.lower() for x in p.parts):
        raise ValueError("excluded or sensitive scope")
    return p.as_posix().rstrip("/")


def _revision(root):
    commit = subprocess.run(["git", *GIT_OPTS, "-C", str(root), "rev-parse", "--verify",
                             "HEAD^{commit}"], text=True, capture_output=True,
                            check=True, timeout=20).stdout.strip()
    changed = subprocess.run(["git", *GIT_OPTS, "-C", str(root), "status",
                              "--porcelain", "--untracked-files=no"],
                             text=True, capture_output=True, check=True, timeout=20)
    if changed.stdout:
        raise ValueError("tracked checkout is modified; use a clean pinned source checkout")
    return commit


def _write_private(path, text):
    target = Path(path)
    if target.exists() or target.is_symlink():
        raise ValueError("refusing to overwrite an existing output file")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(target, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)


def _files(root):
    cp = subprocess.run(["git", *GIT_OPTS, "-C", str(root), "ls-files", "-z"],
                        capture_output=True, check=True, timeout=20)
    names = cp.stdout.decode("utf-8", "replace").split("\x00")
    if len(names) > 30000:
        raise ValueError("tracked file inventory exceeds safety cap")
    return {n for n in names if n}


def _read(root, name, tracked):
    if name not in tracked:
        return None
    p = root / name
    if p.is_symlink() or not p.is_file() or not p.resolve().is_relative_to(root):
        return None
    if p.stat().st_size > MAX_FILE:
        return None
    try:
        return p.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, UnicodeError):
        return None


def bind(repository, rules=None, scope=None):
    root = Path(repository).resolve()
    if not (root / ".git").exists():
        raise ValueError("a local git checkout is required")
    revision = _revision(root)
    all_rules = _rules()
    selected = list(all_rules) if rules is None else list(rules)
    if not selected or len(set(selected)) != len(selected) or any(
            r not in all_rules for r in selected):
        raise ValueError("invalid/duplicate rule selection")
    prefixes = [_path_prefix(x) for x in scope] if scope else None
    tracked = _files(root)
    names = sorted(n for n in tracked
                   if Path(n).suffix.lower() in CODE_SUFFIX
                   and not EXCLUDED.intersection(Path(n).parts)
                   and (prefixes is None or any(n == p or n.startswith(p + "/") for p in prefixes)))
    if len(names) > 8000:
        raise ValueError("scope exceeds 8000 trackable code files; narrow --scope")
    cache = {}

    def lines_for(name):
        if name not in cache:
            cache[name] = _read(root, name, tracked)
        return cache[name]

    report = []
    for rule in selected:
        terms = [t for t in RULE_KEYWORDS[rule] if TERM.fullmatch(t)]
        hits = []
        term_counts = {term: 0 for term in terms}
        for name in names:
            if len(hits) >= MAX_HITS_PER_RULE:
                break
            body = lines_for(name)
            if body is None:
                continue
            for n, line in enumerate(body, 1):
                for term in terms:
                    if term_counts[term] >= MAX_HITS_PER_TERM:
                        continue
                    if re.search(r"(?<![A-Za-z0-9_])" + re.escape(term) + r"(?![A-Za-z0-9_])",
                                line, re.IGNORECASE):
                        hits.append({"path": name, "line": n, "term": term,
                                    "line_sha256": hashlib.sha256(
                                        line.encode("utf-8")).hexdigest()})
                        term_counts[term] += 1
                        break
                if len(hits) >= MAX_HITS_PER_RULE:
                    break
        report.append({
            "rule": rule, "family": (all_rules[rule][0] if all_rules[rule] else None),
            "searched_terms": terms,
            "classification": "LEXICAL_RULE_ANCHOR_LEAD" if hits else "NO_LEXICAL_ANCHOR_FOUND",
            "hits": hits,
            "hit_cap_reached": len(hits) >= MAX_HITS_PER_RULE,
        })
    return {
        "schema_version": 1, "classification": "LEXICAL_ANCHOR_LEADS",
        "source_revision": revision,
        "code_files_scanned": len(names), "rules": report,
        "notice": ("A lexical hit is a place to read, never a confirmed source_anchor "
                   "or code_anchor. web_business_lab.bridge() still requires a human to "
                   "pick the exact function/line and will refuse an unreviewed guess. "
                   "NO_LEXICAL_ANCHOR_FOUND is not evidence the rule is unenforced: the "
                   "concept may use different names, live in an excluded or vendored "
                   "path, or be enforced in a layer this scan does not read (a proxy, a "
                   "framework default, a database constraint).")
    }


def main(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--repo", required=True)
    cli.add_argument("--rule", action="append", dest="rules",
                     help="repeatable; default is every web-business-lab rule")
    cli.add_argument("--scope", action="append",
                     help="bounded relative directory/file prefix; repeatable")
    cli.add_argument("--out")
    args = cli.parse_args(argv)
    try:
        result = bind(args.repo, args.rules, args.scope)
        text = json.dumps(result, indent=2, ensure_ascii=False)
        if args.out:
            out = Path(args.out)
            _write_private(out, text)
        else:
            print(text)
        return 0
    except (ValueError, OSError, subprocess.SubprocessError, UnicodeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
