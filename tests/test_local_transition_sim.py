"""Real offline replay of toy state-machine traces, not live execution."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / "skills/bounty-pilot/scripts/local_transition_sim.py"
spec = importlib.util.spec_from_file_location("bp_local_transition_sim", PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def run(domain, initial, actions):
    return mod.simulate({"schema_version": 1, "domain": domain,
                         "initial": initial, "actions": actions})


class LocalTransitionSimTests(unittest.TestCase):
    def test_cex_deposit_finality_repeat_settlement_transfer_and_address_binding(self):
        st = {"accounts": {"alice": {"available": 100, "held": 0},
                           "bob": {"available": 0, "held": 0}},
              "custody": 100}
        rows = [
            {"op": "deposit", "id": "unfinalized", "account": "alice",
             "amount": 10, "finalized": False},
            {"op": "deposit", "id": "final", "account": "alice",
             "amount": 10, "finalized": True},
            {"op": "withdraw_request", "id": "wrong-dest", "account": "alice",
             "amount": 10, "reviewed_destination": "alice-wallet",
             "authorized_destination": "attacker-wallet"},
            {"op": "withdraw_request", "id": "safe-1", "account": "alice",
             "amount": 30, "reviewed_destination": "alice-wallet",
             "authorized_destination": "alice-wallet"},
            {"op": "withdraw_settle", "id": "safe-1"},
            {"op": "withdraw_settle", "id": "safe-1"},
            {"op": "transfer", "id": "tx1", "source": "alice",
             "destination": "bob", "amount": 20},
            {"op": "transfer", "id": "tx1", "source": "alice",
             "destination": "bob", "amount": 20},
        ]
        r = run("cex-custody", st, rows)
        self.assertEqual(r["accepted"], 4)
        self.assertEqual(r["rejected"], 4)
        self.assertEqual(r["final_state"]["custody"], 80)
        self.assertEqual(r["final_state"]["accounts"]["alice"]["available"], 60)
        self.assertEqual(r["final_state"]["accounts"]["bob"]["available"], 20)
        self.assertEqual(r["final_state"]["accounts"]["alice"]["held"], 0)

    def test_rollup_never_executes_before_finality_or_twice(self):
        st = {"messages": {}}
        post = {"op": "post", "id": "msg1", "origin": "L1",
                "destination": "L2", "payload_digest": "digest-1",
                "source_finalized": True}
        execute = {"op": "execute", "id": "msg1", "origin": "L1",
                   "destination": "L2", "payload_digest": "digest-1"}
        r = run("rollup-l2", st, [
            post, execute,
            {"op": "prove", "id": "msg1", "proof_verified": True},
            execute,
            {"op": "close_challenge", "id": "msg1", "challenge_window_closed": True},
            {**execute, "origin": "forged-L1"},
            execute, execute])
        self.assertEqual(r["accepted"], 4)
        self.assertEqual(r["rejected"], 4)
        self.assertEqual(r["final_state"]["messages"]["msg1"]["executed"], True)

    def test_restaking_pending_share_exits_absorb_slash(self):
        st = {"assets": 100, "total_shares": 100,
              "available_shares": {"alice": 50, "bob": 50}, "exits": {}}
        r = run("restaking-lst", st, [
            {"op": "queue_exit", "id": "alice-exit", "account": "alice",
             "shares": 50},
            {"op": "slash", "amount": 10},
            {"op": "settle_exit", "id": "alice-exit"},
            {"op": "settle_exit", "id": "alice-exit"},
        ])
        self.assertEqual([q["status"] for q in r["receipts"]],
                         ["accepted", "accepted", "accepted",
                          "rejected-by-reference-model"])
        self.assertEqual(r["receipts"][2]["observations"]["payout"], 45)
        self.assertEqual(r["final_state"]["assets"], 45)
        self.assertEqual(r["final_state"]["total_shares"], 50)

    def test_perps_funding_conserved_and_health_based_on_mark(self):
        st = {"margins": {"alice": 100, "bob": 100},
              "positions": {"alice": {"size": 2, "entry_price": 100},
                            "bob": {"size": -2, "entry_price": 100}},
              "maintenance_bps": 1000}
        r = run("perps", st, [
            {"op": "funding", "payer": "alice", "receiver": "bob",
             "amount": 20},
            {"op": "liquidation_check", "account": "alice",
             "mark_price": 100},
            {"op": "liquidation_check", "account": "bob",
             "mark_price": 200},
            {"op": "funding", "payer": "alice", "receiver": "bob",
             "amount": 10000},
        ])
        self.assertEqual(r["accepted"], 3)
        self.assertFalse(r["receipts"][1]["observations"]["eligible"])
        self.assertTrue(r["receipts"][2]["observations"]["eligible"])
        self.assertEqual(r["final_state"]["margins"], {"alice": 80, "bob": 120})

    def test_fail_closed_invalid_initial_state_and_domain(self):
        with self.assertRaises(ValueError):
            run("cex-custody", {"accounts": {"a": {"available": 5, "held": 0}},
                                "custody": 100}, [{"op": "deposit"}])
        with self.assertRaises(ValueError):
            run("not-a-domain", {}, [{"op": "post"}])
        with self.assertRaises(ValueError):
            run("rollup-l2", {"messages": {"x": 1}}, [{"op": "execute"}])

    def test_cli_is_offline_and_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            src, dst = root / "trace.json", root / "output.json"
            src.write_text(json.dumps({"schema_version": 1,
                                       "domain": "rollup-l2",
                                       "initial": {"messages": {}},
                                       "actions": [{"op": "post", "id": "1",
                                                    "origin": "A", "destination": "B",
                                                    "payload_digest": "0x0",
                                                    "source_finalized": True}]}))
            cmd = [sys.executable, str(PATH), "--input", str(src), "--out", str(dst)]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(dst.read_text())["accepted"], 1)
            again = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            self.assertNotEqual(again.returncode, 0)


if __name__ == "__main__":
    unittest.main()
