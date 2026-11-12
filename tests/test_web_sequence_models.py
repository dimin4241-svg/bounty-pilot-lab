"""Paired scenario_fuzz web ATO/payment sequence models actually find their bug.

A single request never looks wrong in either worked example; only the two-step
order does. This locks the templates/stateful/web-*.json pairs to scenario_fuzz's
actual behaviour so a future change to the engine or the fixtures is caught here,
not only by a human re-running the CLI by hand.
"""
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'skills' / 'bounty-pilot' / 'templates' / 'stateful'


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fuzz = load('bp_scenario_fuzz_seq_test', 'skills/bounty-pilot/scripts/scenario_fuzz.py')


def read(name):
    return json.loads((FIXTURES / name).read_text(encoding='utf-8'))


class WebSequenceModelTests(unittest.TestCase):
    def test_every_fixture_is_valid_json(self):
        for path in FIXTURES.glob('web-*.json'):
            json.loads(path.read_text(encoding='utf-8'))

    def test_ato_session_fixation_pair(self):
        candidate = read('web-ato-session-fixation.candidate.json')
        control = read('web-ato-session-fixation.control.json')
        bad = fuzz.explore(candidate, depth=3)
        good = fuzz.explore(control, depth=3)
        self.assertEqual(bad['status'], 'model-counterexample')
        trace = [s['action'] for s in bad['counterexamples'][0]['trace']]
        self.assertEqual(trace, ['owner_change_email', 'attacker_use_old_session'])
        self.assertEqual(good['status'], 'no-model-counterexample-within-bounds')

    def test_ato_fixture_single_step_is_not_enough(self):
        # The attacker's own still-valid session acting before any email change is
        # ordinary, legitimate use, not a violation; depth=1 must find nothing.
        candidate = read('web-ato-session-fixation.candidate.json')
        self.assertEqual(fuzz.explore(candidate, depth=1)['status'],
                         'no-model-counterexample-within-bounds')

    def test_payment_stale_webhook_pair(self):
        candidate = read('web-payment-stale-webhook.candidate.json')
        control = read('web-payment-stale-webhook.control.json')
        bad = fuzz.explore(candidate, depth=3)
        good = fuzz.explore(control, depth=3)
        self.assertEqual(bad['status'], 'model-counterexample')
        trace = [s['action'] for s in bad['counterexamples'][0]['trace']]
        self.assertEqual(trace, ['cancel_subscription', 'late_webhook_reactivates'])
        self.assertEqual(good['status'], 'no-model-counterexample-within-bounds')

    def test_payment_fixture_single_step_is_not_enough(self):
        # A webhook arriving before any cancellation is an ordinary first activation,
        # not a violation; depth=1 must find nothing in either model.
        candidate = read('web-payment-stale-webhook.candidate.json')
        control = read('web-payment-stale-webhook.control.json')
        self.assertEqual(fuzz.explore(candidate, depth=1)['status'],
                         'no-model-counterexample-within-bounds')
        self.assertEqual(fuzz.explore(control, depth=1)['status'],
                         'no-model-counterexample-within-bounds')


if __name__ == '__main__':
    unittest.main()
