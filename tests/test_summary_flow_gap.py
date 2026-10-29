"""The summary-flow generator, calibrated on two bugs Trezor fixed in firmware 2.12.5.

Both were paid disclosures and both have the same shape: a flow that recognises a known
transaction and draws a curated screen accepted a case the screen does not show. Trezor fixed
both by narrowing the recogniser - "fall back to the generic UI" - not by showing more, which is
what says the accept-set was the defect.

`tests/fixtures/summary-flow-gap/` holds the real module at five revisions, including
`s2-partial.py`: the first fix closed one of three identical holes. A generator that goes quiet on
a partial fix would have been useless here, so that revision is asserted on its own.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/summary-flow-gap'


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gap = load('bp_test_summary_gap', 'skills/bounty-pilot/scripts/summary_flow_gap.py')
INSTRUCTIONS = (FIXTURES / 'instructions.py').read_text(encoding='utf-8')


def run(revision):
    return gap.analyse((FIXTURES / f'{revision}.py').read_text(encoding='utf-8'), INSTRUCTIONS)


def fields(report, kind, function):
    return sorted({row['field'] for row in report['leads']
                   if row['kind'] == kind and row['function'] == function})


class InstructionFieldTests(unittest.TestCase):
    def test_the_field_list_comes_from_the_real_definitions(self):
        declared = gap.instruction_fields(INSTRUCTIONS)
        self.assertEqual(
            declared['StakeProgramInitializeInstruction'],
            {'staker': 'Account', 'withdrawer': 'Account', 'unix_timestamp': 'int',
             'epoch': 'int', 'custodian': 'Account',
             'uninitialized_stake_account': 'Account', 'rent_sysvar': 'Account'})

    def test_it_reads_the_whole_generated_module(self):
        self.assertGreater(len(gap.instruction_fields(INSTRUCTIONS)), 40)


class AltReferenceTests(unittest.TestCase):
    """S2: an address that may be a lookup-table reference, read as its resolved value."""

    FLOW = 'is_predefined_token_transfer'

    def test_before_the_fix_all_three_accounts_are_reported(self):
        self.assertEqual(fields(run('s2-pre'), 'reference-used-by-value', self.FLOW),
                         ['destination_account', 'owner', 'token_mint'])

    def test_the_partial_fix_is_still_reported(self):
        """`537b34f84` guarded the destination only; the other two holes were identical."""
        self.assertEqual(fields(run('s2-partial'), 'reference-used-by-value', self.FLOW),
                         ['owner', 'token_mint'])

    def test_the_complete_fix_is_silent(self):
        self.assertEqual(fields(run('s2-fixed'), 'reference-used-by-value', self.FLOW), [])

    def test_a_guard_written_through_map_is_credited(self):
        """The complete fix spells it `any(map(is_address_reference, (a, b, c)))`."""
        source = (FIXTURES / 's2-fixed.py').read_text(encoding='utf-8')
        self.assertIn('map(', source)
        self.assertEqual(fields(run('s2-fixed'), 'reference-used-by-value', self.FLOW), [])


class UnshownFieldTests(unittest.TestCase):
    """S1: a field the staking flow accepts, never reads, and never hands to the screen."""

    FLOW = 'try_confirm_staking_transaction'

    def test_before_the_fix_the_lockup_fields_are_reported(self):
        reported = fields(run('s1-pre'), 'unconstrained-unrendered', self.FLOW)
        self.assertIn('epoch', reported)
        self.assertIn('unix_timestamp', reported)

    def test_after_the_fix_they_are_gone(self):
        reported = fields(run('s1-fixed'), 'unconstrained-unrendered', self.FLOW)
        self.assertNotIn('epoch', reported)
        self.assertNotIn('unix_timestamp', reported)

    def test_the_value_fields_outrank_the_sysvar(self):
        rows = [row for row in run('s1-pre')['leads']
                if row['kind'] == 'unconstrained-unrendered' and row['function'] == self.FLOW]
        self.assertEqual([row['field'] for row in rows][:2], ['epoch', 'unix_timestamp'])
        self.assertEqual(rows[-1]['field'], 'rent_sysvar')


class NoiseFloorTests(unittest.TestCase):
    """What a fully fixed module still reports, pinned so new noise fails the suite."""

    def test_the_residue_on_the_fixed_revisions_is_small_and_named(self):
        for revision, expected in (('s2-fixed', 3), ('s1-fixed', 6)):
            with self.subTest(revision=revision):
                self.assertEqual(len(run(revision)['leads']), expected)

    def test_a_field_mentioned_only_in_a_comprehension_counts_as_mentioned(self):
        """`sum(i.amount for i in xs)` is a read; before this, `amount` was reported."""
        for revision in ('s2-pre', 's2-fixed'):
            self.assertNotIn('amount', [row['field'] for row in run(revision)['leads']])

    def test_a_recogniser_that_renders_nothing_is_noted_not_judged(self):
        report = run('s2-pre')
        self.assertEqual(fields(report, 'unconstrained-unrendered',
                                'is_predefined_token_transfer'), [])
        self.assertTrue(any(note.get('function') == 'is_predefined_token_transfer'
                            and 'renders nothing' in note['note']
                            for note in report['notes']))

    def test_every_lead_carries_an_anchor_and_a_reason(self):
        for row in run('s2-pre')['leads']:
            self.assertTrue(row['instruction'])
            self.assertIn(row['field'], row['why'])
            self.assertIn(row['kind'], ('reference-used-by-value', 'unconstrained-unrendered'))


class CliTests(unittest.TestCase):
    def test_it_writes_a_report_and_exits_zero(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / 'report.json'
            code = gap.main(['--summary', str(FIXTURES / 's2-pre.py'),
                             '--instructions', str(FIXTURES / 'instructions.py'),
                             '--out', str(out)])
            self.assertEqual(code, 0)
            written = json.loads(out.read_text(encoding='utf-8'))
            self.assertEqual(written['counts']['reference-used-by-value'], 6)

    def test_a_custom_guard_name_is_honoured(self):
        """The guard call is a project's own spelling, so it is an argument, not a constant."""
        report = gap.analyse((FIXTURES / 's2-fixed.py').read_text(encoding='utf-8'),
                             INSTRUCTIONS, guard_pattern='never_matches_anything')
        self.assertEqual(fields(report, 'reference-used-by-value',
                                'is_predefined_token_transfer'),
                         ['destination_account', 'owner', 'token_mint'])


if __name__ == '__main__':
    unittest.main()
