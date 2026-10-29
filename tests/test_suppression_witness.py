"""The suppression-witness generator, calibrated on Trezor's Monero payment-id bug.

`tests/fixtures/suppression-witness/` holds `core/src/apps/monero/layout.py` either side of
`9558d1cbf`, whose own message states the mechanism: "integrated_indices is host-supplied and
never validated, so an index naming an output the confirmation loop skips left the payment id on
no screen while it was still folded into the signed transaction." The fix replaces the gate on
that input with a `payment_id_shown` flag written where the output is confirmed - a witness
instead of a proxy.

The synthetic modules below pin the three rules that keep this from flooding: a gate on the field
it displays is a precondition, not a suppression; a gate that is not a negation is a
precondition too; and a local only counts as a witness when it is written in a branch that
confirms something.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/suppression-witness'


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


witness = load('bp_test_suppression', 'skills/bounty-pilot/scripts/suppression_witness.py')


def run(revision):
    return witness.analyse((FIXTURES / f'{revision}.py').read_text(encoding='utf-8'))


PROXY = '''
async def flow(msg):
    for item in msg.items:
        if item.skip:
            continue
        await confirm_item(item)
    if msg.payload and not msg.indices:
        await confirm_payload(msg.payload)
'''

WITNESS = '''
async def flow(msg):
    shown = False
    for item in msg.items:
        if item.skip:
            continue
        shown = True
        await confirm_item(item)
    if msg.payload and not shown:
        await confirm_payload(msg.payload)
'''

WITNESS_OUTSIDE_A_CONFIRMING_BRANCH = '''
async def flow(msg):
    shown = False
    for item in msg.items:
        if item.skip:
            continue
        await confirm_item(item)
    shown = bool(msg.items)
    if msg.payload and not shown:
        await confirm_payload(msg.payload)
'''

GATE_ON_THE_FIELD_IT_SHOWS = '''
async def flow(msg):
    for item in msg.items:
        if item.skip:
            continue
        await confirm_item(item)
    if msg.unlock_time is not None and msg.unlock_time != 0:
        await confirm_unlock_time(msg.unlock_time)
'''

NOT_NEGATED = '''
async def flow(msg):
    for item in msg.items:
        if item.skip:
            continue
        await confirm_item(item)
    if msg.indices:
        await confirm_payload(msg.payload)
'''


class CalibrationTests(unittest.TestCase):
    def test_the_real_bug_is_one_lead_at_the_sharpest_rank(self):
        report = run('monero-layout-pre')
        self.assertEqual(report['counts'],
                         {'suppressed-on-a-proxy': 1, 'with-a-skippable-display-path': 1})
        row = report['leads'][0]
        self.assertEqual(row['function'], 'require_confirm_transaction')
        self.assertEqual(row['suppressed_call'], '_require_confirm_payment_id')
        self.assertEqual(row['proxy_operands'], ['tsx_data.integrated_indices'])
        self.assertTrue(row['negated'])
        self.assertTrue(row['display_path_can_skip'])
        self.assertEqual(row['rank'], 0)

    def test_the_fix_is_silent(self):
        self.assertEqual(run('monero-layout-fixed')['leads'], [])

    def test_the_fix_is_silent_because_the_witness_is_credited(self):
        """Not because the check stopped firing: the witness name is what changed."""
        fixed = (FIXTURES / 'monero-layout-fixed.py').read_text(encoding='utf-8')
        self.assertIn('payment_id_shown', fixed)
        without_the_witness = fixed.replace('not payment_id_shown',
                                            'not tsx_data.integrated_indices')
        back = witness.analyse(without_the_witness)
        self.assertEqual(len(back['leads']), 1)
        self.assertEqual(back['leads'][0]['suppressed_call'], '_require_confirm_payment_id')

    def test_the_gate_on_the_displayed_field_is_not_reported(self):
        """`_require_confirm_unlock_time` is gated on the value it shows, in the same function."""
        for revision in ('monero-layout-pre', 'monero-layout-fixed'):
            calls = [row['suppressed_call'] for row in run(revision)['leads']]
            self.assertNotIn('_require_confirm_unlock_time', calls)


class RuleTests(unittest.TestCase):
    def test_a_proxy_gate_over_a_skippable_loop_is_a_lead(self):
        report = witness.analyse(PROXY)
        self.assertEqual(report['counts']['suppressed-on-a-proxy'], 1)
        self.assertEqual(report['leads'][0]['proxy_operands'], ['msg.indices'])

    def test_a_witness_written_where_the_showing_happens_clears_it(self):
        self.assertEqual(witness.analyse(WITNESS)['leads'], [])

    def test_a_flag_written_outside_a_confirming_branch_is_not_a_witness(self):
        """`shown = bool(msg.items)` is another proxy wearing a local name."""
        report = witness.analyse(WITNESS_OUTSIDE_A_CONFIRMING_BRANCH)
        self.assertEqual(report['counts']['suppressed-on-a-proxy'], 1)

    def test_a_gate_on_the_field_it_displays_is_a_precondition(self):
        self.assertEqual(witness.analyse(GATE_ON_THE_FIELD_IT_SHOWS)['leads'], [])

    def test_a_gate_that_is_not_a_negation_goes_to_notes(self):
        report = witness.analyse(NOT_NEGATED)
        self.assertEqual(report['leads'], [])
        self.assertTrue(any('not a negation' in note['note'] for note in report['notes']))

    def test_a_module_with_no_confirmation_is_silent(self):
        self.assertEqual(witness.analyse('def f(msg):\n    return msg.x\n')['leads'], [])


PRECONDITION_FROM_DISPLAYED = """
async def flow(msg, witness_path):
    for item in msg.items:
        if item.skip:
            continue
        await confirm_item(item)
    is_payment = SCHEMA_PAYMENT.match(witness_path)
    if not is_payment:
        await confirm_witness_request(witness_path)
"""

COMPARISON_AGAINST_OUR_OWN = """
async def flow(msg, address):
    for item in msg.items:
        if item.skip:
            continue
        await confirm_item(item)
    accounts_match = msg.source_account == address
    if not accounts_match:
        await confirm_tx_source(msg.source_account)
"""

ALTERNATIVE_BRANCH = """
async def flow(msg, verified_payment_request):
    for item in msg.items:
        if item.skip:
            continue
        await confirm_item(item)
    if verified_payment_request:
        await confirm_payment_request(msg.recipient)
    else:
        await confirm_recipient(msg.recipient)
"""

DEFAULTED_PARAMETER = """
async def flow(msg, is_root=False):
    for item in msg.items:
        if item.skip:
            continue
        await confirm_item(item)
    if not is_root:
        await confirm_invoke_contract(msg.function)
"""

ACCUMULATED_ON_SELF = """
class Approver:
    def __init__(self):
        self.external_in = 0

    def add_external_input(self, txi):
        self.external_in += txi.amount

    async def approve_tx(self, msg):
        for item in msg.items:
            if item.skip:
                continue
            await confirm_item(item)
        if not self.external_in:
            await confirm_total(msg.total)
"""

STATIC_LABEL = """
async def flow(msg, multisig):
    if not multisig:
        await confirm_text(TR.nem__convert_account_to_multisig)
    for item in msg.items:
        if item.skip:
            continue
        await confirm_item(item)
"""


class DiscriminatorTests(unittest.TestCase):
    """The five rules that took the live false-positive rate from eleven to zero.

    Every shape here is one a real site in current firmware has, named in each test. All eleven
    rank-1 leads this generator produced over 59 confirmation modules were of these five shapes,
    and all eleven were benign on inspection.
    """

    def test_an_operand_computed_from_the_displayed_value_is_a_precondition(self):
        """cardano `_show_witness_request`: `is_payment = SCHEMA_PAYMENT.match(witness_path)`."""
        self.assertEqual(witness.analyse(PRECONDITION_FROM_DISPLAYED)['leads'], [])

    def test_a_comparison_against_our_own_value_is_a_precondition(self):
        """stellar `sign_tx`: `accounts_match = msg.source_account == address`."""
        self.assertEqual(witness.analyse(COMPARISON_AGAINST_OUR_OWN)['leads'], [])

    def test_an_alternative_branch_that_also_confirms_is_presentation(self):
        """solana `confirm_system_transfer`: payment-request screen or recipient screen."""
        report = witness.analyse(ALTERNATIVE_BRANCH)
        self.assertEqual(report['leads'], [])
        self.assertTrue(any('presentation' in note['note'] for note in report['notes']))

    def test_a_parameter_with_a_default_is_not_the_request(self):
        """stellar `confirm_invocation(..., is_root: bool = False)` is recursion state."""
        self.assertEqual(witness.analyse(DEFAULTED_PARAMETER)['leads'], [])

    def test_state_the_class_accumulates_is_a_witness(self):
        """bitcoin approvers: `self.external_in += txi.amount` in `add_external_input`."""
        self.assertEqual(witness.analyse(ACCUMULATED_ON_SELF)['leads'], [])

    def test_a_call_that_displays_nothing_host_supplied_is_a_policy_question(self):
        """nem `ask_aggregate_modification`: the suppressed screen is a fixed label."""
        report = witness.analyse(STATIC_LABEL)
        self.assertEqual(report['leads'], [])
        self.assertTrue(any('static label' in note['note'] for note in report['notes']))

    def test_the_calibration_still_fires_through_all_five(self):
        """The rules must not have been bought by silencing the known positive."""
        report = run('monero-layout-pre')
        self.assertEqual(report['counts']['suppressed-on-a-proxy'], 1)
        self.assertEqual(report['leads'][0]['rank'], 0)


COLDCARD_SHAPED = """
async def flow(msg):
    for item in msg.items:
        if item.skip:
            continue
        await ux_show_story(item.text)
    if msg.payload and not msg.indices:
        await ux_show_story(msg.payload)
"""

COLDCARD_RENDERER = r'^ux_(show|confirm|msg|render|sign|enter|input)|^_?confirm|_confirm$'


class RendererOptionTests(unittest.TestCase):
    """The pattern that decides what counts as drawing a screen has to be an argument.

    Coldcard's firmware draws with `ux_show_story` - 326 call sites in its `shared/` modules
    against 75 for `ux_confirm` - and the Trezor-shaped default matches none of them. Run with
    the default there and every check reports a confident zero while reading almost nothing.
    """

    def test_the_default_is_blind_to_a_coldcard_shaped_renderer(self):
        self.assertEqual(witness.analyse(COLDCARD_SHAPED)['leads'], [])

    def test_the_option_makes_the_same_code_fire(self):
        report = witness.analyse(COLDCARD_SHAPED, COLDCARD_RENDERER)
        self.assertEqual(report['counts']['suppressed-on-a-proxy'], 1)
        self.assertEqual(report['leads'][0]['suppressed_call'], 'ux_show_story')
        self.assertEqual(report['leads'][0]['proxy_operands'], ['msg.indices'])

    def test_the_calibration_still_fires_on_the_default(self):
        """Changing the default would silently rewrite every earlier result."""
        self.assertEqual(run('monero-layout-pre')['counts']['suppressed-on-a-proxy'], 1)


class UnparseableSourceTests(unittest.TestCase):
    """One file this interpreter cannot parse must not end the sweep.

    Six of Coldcard's 94 shared modules are generated data blobs. Before this, the first of them
    aborted the run with `invalid syntax (<unknown>, line 1)` - no file named, no result for the
    other 88, and an exit that reads like nothing was found.
    """

    def test_a_broken_source_is_skipped_named_and_not_fatal(self):
        with tempfile.TemporaryDirectory() as folder:
            good = Path(folder) / 'good.py'
            good.write_text(COLDCARD_SHAPED, encoding='utf-8')
            bad = Path(folder) / 'generated_blob.py'
            bad.write_text('\\x00 this is not python\n', encoding='utf-8')
            out = Path(folder) / 'report.json'
            code = witness.main(['--source', str(bad), '--source', str(good),
                                 '--renderer', COLDCARD_RENDERER, '--out', str(out)])
            self.assertEqual(code, 0)
            report = json.loads(out.read_text(encoding='utf-8'))
            self.assertEqual(len(report['skipped']), 1)
            self.assertTrue(report['skipped'][0]['source'].endswith('generated_blob.py'))
            self.assertIn('SyntaxError', report['skipped'][0]['reason'])
            self.assertEqual(report['counts']['suppressed-on-a-proxy'], 1)
            self.assertIn('could not be parsed', report['notice'])


class CliTests(unittest.TestCase):
    def test_several_sources_are_merged_and_tagged(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / 'report.json'
            code = witness.main(['--source', str(FIXTURES / 'monero-layout-pre.py'),
                                 '--source', str(FIXTURES / 'monero-layout-fixed.py'),
                                 '--out', str(out)])
            self.assertEqual(code, 0)
            report = json.loads(out.read_text(encoding='utf-8'))
            self.assertEqual(report['counts']['suppressed-on-a-proxy'], 1)
            self.assertTrue(report['leads'][0]['source'].endswith('monero-layout-pre.py'))


if __name__ == '__main__':
    unittest.main()
