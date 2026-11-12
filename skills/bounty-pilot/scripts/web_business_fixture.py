#!/usr/bin/env python3
"""Disposable SQLite bug/fix fixtures for web_business_lab.

Synthetic sample apps only. No HTTP, wallet, gateway, real user or real funds.
A deliberately defective mode and corrected mode use the same initial DB.
"""
import hashlib
import hmac
import json
import sqlite3

try:
    from web_business_lab import RULES
except ImportError:
    # Standalone fixture invocation from the Bounty Pilot dynamic CLI loader.
    RULES = {
        x: None for x in (
            "account-owner", "mfa-gate", "session-revocation", "reset-one-use",
            "oauth-binding", "email-verification", "unpaid-credit", "event-replay",
            "webhook-binding", "refund-replay", "subscription-entitlement",
            "cancellation-stale", "cross-tenant-credit")
    }

SOURCE_REVISION = hashlib.sha1(b"owned-synthetic-sqlite-v1-not-a-target-commit").hexdigest()


def _digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class FakePSP:
    """Researcher-owned fake provider, with separate authoritative status and HMAC."""
    KEY = b"owned-fixture-test-key-not-for-real-payments"

    def __init__(self):
        self.events = {}

    @staticmethod
    def _body(ref, amount, currency, merchant):
        return json.dumps({"event": ref, "amount_cents": amount, "currency": currency,
                           "merchant": merchant}, sort_keys=True,
                          separators=(",", ":")).encode()

    def create(self, ref, *, paid):
        if ref not in self.events:
            self.events[ref] = {"paid": bool(paid), "amount_cents": 500,
                                "currency": "USD", "merchant": "owned-store"}

    def callback(self, ref, *, tampered):
        status = self.events[ref]
        amount = 999 if tampered else status["amount_cents"]
        expected = hmac.new(self.KEY, self._body(ref, status["amount_cents"],
                           status["currency"], status["merchant"]),
                            hashlib.sha256).hexdigest()
        supplied = expected  # Provider signature over the real payment.
        signed_data = self._body(ref, amount, status["currency"], status["merchant"])
        signature_valid = hmac.compare_digest(
            supplied, hmac.new(self.KEY, signed_data, hashlib.sha256).hexdigest())
        return {"paid": status["paid"], "signature_valid": signature_valid,
                "order_bound": not tampered, "amount_bound": not tampered,
                "currency_bound": True, "merchant_bound": True}


class LocalApp:
    def __init__(self, defective):
        self.defective = defective
        self.psp = FakePSP()
        self.db = sqlite3.connect(":memory:")
        self.db.execute(
            "CREATE TABLE account (id TEXT PRIMARY KEY, credential_version INTEGER, "
            "email_version INTEGER, session_count INTEGER, session_active INTEGER, "
            "available_cents INTEGER, refunded_cents INTEGER, entitlement_active INTEGER)")
        self.db.executemany(
            "INSERT INTO account VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [("alice", 1, 1, 1, 1, 10000, 0, 0),
             ("bob", 1, 1, 1, 1, 10000, 0, 0)])
        self.db.execute("CREATE TABLE balance_ledger (seq INTEGER PRIMARY KEY, "
                        "account TEXT, event_ref TEXT, amount_cents INTEGER)")
        self.db.execute("CREATE TABLE payment_events (id TEXT PRIMARY KEY)")
        self.db.execute("CREATE TABLE refund_events (id TEXT PRIMARY KEY)")
        self.db.execute("CREATE TABLE reset_tokens (id TEXT PRIMARY KEY, used INTEGER)")
        self.db.executemany("INSERT INTO reset_tokens VALUES (?, ?)",
                            [("used-token", 1), ("fresh-token", 0)])
        self.db.commit()

    def close(self):
        self.db.close()

    def snapshot(self):
        row = self.db.execute(
            "SELECT credential_version,email_version,session_count,session_active,"
            "available_cents,refunded_cents,entitlement_active FROM account "
            "WHERE id='alice'").fetchone()
        keys = ("credential_version", "email_version", "session_count",
                "session_active", "available_cents", "refunded_cents",
                "entitlement_active")
        state = dict(zip(keys, row))
        state["entitlement_active"] = bool(state["entitlement_active"])
        state["ledger_credited_cents"] = self.db.execute(
            "SELECT COALESCE(SUM(amount_cents),0) FROM balance_ledger "
            "WHERE account='alice'").fetchone()[0]
        return state

    def _bump(self, field, amount=1):
        if field not in {"credential_version", "email_version", "session_count",
                         "available_cents", "refunded_cents"}:
            raise ValueError("unsupported synthetic update")
        self.db.execute("UPDATE account SET " + field + "=" + field +
                        "+? WHERE id='alice'", (amount,))
        self.db.commit()

    def _entitlement(self, value):
        self.db.execute("UPDATE account SET entitlement_active=? WHERE id='alice'",
                        (int(value),))
        self.db.commit()

    def _seen(self, table, ref):
        if table not in ("payment_events", "refund_events"):
            raise ValueError("invalid test table")
        found = self.db.execute("SELECT 1 FROM " + table + " WHERE id=?", (ref,)).fetchone()
        if not found:
            self.db.execute("INSERT INTO " + table + " VALUES (?)", (ref,))
            self.db.commit()
        return bool(found)

    def update_account(self, *, actor, authorized=True, mfa_verified=True,
                       session_active=True):
        permitted = authorized and mfa_verified and session_active
        if permitted or self.defective:
            self._bump("credential_version")
        return {"actor_authorized": authorized, "mfa_required": True,
                "mfa_verified": mfa_verified, "session_active": session_active}

    def reset_password(self, token):
        used = bool(self.db.execute(
            "SELECT used FROM reset_tokens WHERE id=?", (token,)).fetchone()[0])
        if not used or self.defective:
            self._bump("credential_version")
            self.db.execute("UPDATE reset_tokens SET used=1 WHERE id=?", (token,))
            self.db.commit()
        return {"reset_token_previously_used": used}

    def oauth_login(self, *, valid):
        if valid or self.defective:
            self._bump("session_count")
        return {"issuer_valid": valid, "audience_valid": valid,
                "nonce_valid": valid, "subject_matches": valid}

    def change_email(self, *, verified):
        if verified or self.defective:
            self._bump("email_version")
            self._bump("credential_version")
        return {"verification_required": True, "email_verified": verified}

    def credit(self, ref, *, confirmed=True, bound=True, authorized=True,
               cross_tenant=False):
        self.psp.create(ref, paid=confirmed)
        receipt = self.psp.callback(ref, tampered=not bound)
        duplicate = self._seen("payment_events", ref)
        accepted = (receipt["paid"] and receipt["signature_valid"] and
                    receipt["order_bound"] and receipt["amount_bound"] and
                    receipt["currency_bound"] and receipt["merchant_bound"] and
                    authorized and not duplicate)
        if accepted or self.defective:
            self._bump("available_cents", 500)
            self.db.execute("INSERT INTO balance_ledger (account,event_ref,amount_cents)"
                            " VALUES ('alice',?,500)", (ref,))
            self.db.commit()
        return {"psp_confirmed": receipt["paid"],
                "non_payment_credit_allowed": False,
                "signature_valid": receipt["signature_valid"],
                "order_bound": receipt["order_bound"],
                "amount_bound": receipt["amount_bound"],
                "currency_bound": receipt["currency_bound"],
                "merchant_bound": receipt["merchant_bound"],
                "actor_authorized": authorized,
                "cross_tenant": cross_tenant}

    def refund(self, ref):
        duplicate = self._seen("refund_events", ref)
        if not duplicate or self.defective:
            self._bump("refunded_cents", 100)
        return {}

    def activate(self, *, confirmed):
        if confirmed or self.defective:
            self._entitlement(True)
        return {"psp_confirmed": confirmed, "non_payment_grant_allowed": False}

    def cancel(self, *, grace):
        if not grace and not self.defective:
            self._entitlement(False)
        return {"cancelled_now": True, "grace_period_allowed": grace}


def _record(app, kind, action, *, actor="alice", subject="alice",
            payment_event_ref=None, refund_event_ref=None):
    before = app.snapshot()
    facts = action()
    after = app.snapshot()
    event = {"kind": kind, "actor": actor, "subject": subject,
             "facts": facts, "before": before, "after": after}
    if payment_event_ref is not None:
        event["payment_event_ref"] = payment_event_ref
    if refund_event_ref is not None:
        event["refund_event_ref"] = refund_event_ref
    return event


def _run(rule, *, defective, candidate, repetition):
    app = LocalApp(defective)
    try:
        if rule == "cancellation-stale":
            app._entitlement(True)
        initial = app.snapshot()
        events = []
        if rule == "session-revocation" and candidate:
            def revoke():
                app.db.execute("UPDATE account SET session_active=0 WHERE id='alice'")
                app.db.commit()
                return {"revoked": True}
            events.append(_record(app, "session_revoked", revoke))
        if rule == "account-owner":
            actor = "bob" if candidate else "alice"
            events.append(_record(app, "sensitive_account_update",
                lambda: app.update_account(actor=actor, authorized=not candidate),
                actor=actor))
        elif rule == "mfa-gate":
            events.append(_record(app, "sensitive_account_update",
                lambda: app.update_account(actor="alice", mfa_verified=not candidate)))
        elif rule == "session-revocation":
            events.append(_record(app, "sensitive_account_update",
                lambda: app.update_account(actor="alice", session_active=not candidate)))
        elif rule == "reset-one-use":
            events.append(_record(app, "password_reset",
                lambda: app.reset_password("used-token" if candidate else "fresh-token")))
        elif rule == "oauth-binding":
            events.append(_record(app, "oauth_login",
                lambda: app.oauth_login(valid=not candidate)))
        elif rule == "email-verification":
            events.append(_record(app, "email_change",
                lambda: app.change_email(verified=not candidate)))
        elif rule == "unpaid-credit":
            events.append(_record(app, "credit",
                lambda: app.credit("payment-1", confirmed=not candidate),
                payment_event_ref="payment-1"))
        elif rule == "event-replay":
            events.append(_record(app, "credit",
                lambda: app.credit("payment-1"), payment_event_ref="payment-1"))
            second = "payment-1" if candidate else "payment-2"
            events.append(_record(app, "credit",
                lambda: app.credit(second), payment_event_ref=second))
        elif rule == "webhook-binding":
            events.append(_record(app, "credit",
                lambda: app.credit("payment-1", bound=not candidate),
                payment_event_ref="payment-1"))
        elif rule == "refund-replay":
            events.append(_record(app, "refund",
                lambda: app.refund("refund-1"), refund_event_ref="refund-1"))
            second = "refund-1" if candidate else "refund-2"
            events.append(_record(app, "refund",
                lambda: app.refund(second), refund_event_ref=second))
        elif rule == "subscription-entitlement":
            events.append(_record(app, "subscription_activated",
                lambda: app.activate(confirmed=not candidate)))
        elif rule == "cancellation-stale":
            events.append(_record(app, "subscription_cancelled",
                lambda: app.cancel(grace=not candidate)))
        elif rule == "cross-tenant-credit":
            actor = "bob" if candidate else "alice"
            events.append(_record(app, "credit",
                lambda: app.credit("payment-1", authorized=not candidate,
                                   cross_tenant=candidate), actor=actor,
                payment_event_ref="payment-1"))
        else:
            raise ValueError("unsupported synthetic scenario")
        receipt = {"fixture": "sqlite", "defective": defective,
                   "candidate": candidate, "repetition": repetition,
                   "initial": initial, "events": events, "final": app.snapshot()}
        return {"initial_state_digest": _digest(initial),
                "evidence_sha256": _digest(receipt), "events": events}
    finally:
        app.close()


def generate(*, defective=True, rules=None):
    selected = list(RULES) if rules is None else list(rules)
    if not selected or len(set(selected)) != len(selected) or any(r not in RULES for r in selected):
        raise ValueError("invalid synthetic scenario selection")
    cases = []
    for rule in selected:
        cases.append({
            "id": "sqlite-" + rule, "rule": rule,
            "invariant_basis": "documented",
            "candidate_runs": [_run(rule, defective=defective, candidate=True,
                                    repetition=i) for i in (1, 2)],
            "control_runs": [_run(rule, defective=defective, candidate=False,
                                  repetition=i) for i in (1, 2)],
        })
    return {"schema_version": 1, "environment": "researcher_owned_lab",
            "source_revision": SOURCE_REVISION, "cases": cases}


if __name__ == "__main__":
    print(json.dumps({"scenario_count": len(generate()["cases"]),
                      "notice": "synthetic SQLite only; no external requests"}))
