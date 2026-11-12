"""Paired scenario_fuzz economic-conservation sequence model actually finds its bug.

Combines two mechanisms that already existed separately but had never been
exercised together: invariant_check.py's "conservation" rule kind, and
scenario_fuzz.py's bounded BFS sequence search. Neither action looks wrong in
isolation; only the retry-after-settlement order breaks the sum.
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


fuzz = load('bp_scenario_fuzz_econ_test', 'skills/bounty-pilot/scripts/scenario_fuzz.py')


def read(name):
    return json.loads((FIXTURES / name).read_text(encoding='utf-8'))


class EconomicSequenceModelTests(unittest.TestCase):
    def test_every_fixture_is_valid_json(self):
        for path in FIXTURES.glob('economic-*.json'):
            json.loads(path.read_text(encoding='utf-8'))

    def test_subaccount_retry_credit_pair(self):
        candidate = read('economic-subaccount-retry-credit.candidate.json')
        control = read('economic-subaccount-retry-credit.control.json')
        bad = fuzz.explore(candidate, depth=4)
        good = fuzz.explore(control, depth=4)
        self.assertEqual(bad['status'], 'model-counterexample')
        trace = [s['action'] for s in bad['counterexamples'][0]['trace']]
        self.assertEqual(trace, ['apply_transfer', 'retry_apply_transfer'])
        self.assertEqual(bad['counterexamples'][0]['state']['trading'], '70')
        self.assertEqual(bad['counterexamples'][0]['state']['savings'], '60')
        self.assertEqual(good['status'], 'no-model-counterexample-within-bounds')

    def test_single_action_alone_is_never_a_violation(self):
        # apply_transfer alone must hold (sum stays 100); retry_apply_transfer alone
        # cannot even fire before a transfer has been applied once.
        candidate = read('economic-subaccount-retry-credit.candidate.json')
        self.assertEqual(fuzz.explore(candidate, depth=1)['status'],
                         'no-model-counterexample-within-bounds')


if __name__ == '__main__':
    unittest.main()
