"""The sentinel-skip generator, calibrated on Trezor's Solana optional-parameter bug.

`tests/fixtures/sentinel-skip/` holds `core/src/apps/solana/layout.py` either side of
`0fea14829`, shipped in 2.13.0. The whole bug is one line:

    if property_template.optional and value is None:
        continue

and Trezor's commit says why it is wrong - "optional params ... were never displayed when their
value is None, even though None may encode an action rather than the absence of one". In the Token
programs' SetAuthority, None means *remove the authority*.

What the generator keys on is not the skip, which every UI has, but what licenses it: a per-field
policy is a decision about that field, a type-level claim like `optional` is a statement about a
whole class of fields standing in for that decision.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/sentinel-skip'


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sentinel = load('bp_test_sentinel', 'skills/bounty-pilot/scripts/sentinel_skip.py')

DISPATCH_ON_THE_LOOP_ITEM = """
async def flow(instruction):
    for ui_property in instruction.ui_properties:
        if ui_property.parameter is None:
            continue
        await confirm_properties(ui_property.display_name, ui_property.value)
"""

PER_FIELD_POLICY = """
async def flow(instruction):
    for ui_property in instruction.ui_properties:
        value = instruction.data[ui_property.name]
        if ui_property.default_value_to_hide == "none" and value is None:
            continue
        await confirm_properties(ui_property.display_name, value)
"""

TYPE_LEVEL_CLAIM = """
async def flow(instruction):
    for ui_property in instruction.ui_properties:
        value = instruction.data[ui_property.name]
        template = instruction.template(ui_property.name)
        if template.optional and value is None:
            continue
        await confirm_properties(ui_property.display_name, value)
"""

NOTHING_LICENSES_IT = """
async def flow(instruction):
    for ui_property in instruction.ui_properties:
        value = instruction.data[ui_property.name]
        if value is None:
            continue
        await confirm_properties(ui_property.display_name, value)
"""

FALSY_TEST = """
async def flow(instruction):
    for ui_property in instruction.ui_properties:
        amount = instruction.data[ui_property.name]
        if not amount:
            continue
        await confirm_properties(ui_property.display_name, amount)
"""

NO_RENDERER_IN_THE_LOOP = """
def collect(instruction):
    out = []
    for ui_property in instruction.ui_properties:
        value = instruction.data[ui_property.name]
        if value is None:
            continue
        out.append(value)
    return out
"""


class CalibrationTests(unittest.TestCase):
    def run_fixture(self, revision):
        return sentinel.analyse((FIXTURES / f'{revision}.py').read_text(encoding='utf-8'))

    def test_the_real_bug_is_one_lead_at_rank_zero(self):
        report = self.run_fixture('solana-layout-pre')
        self.assertEqual(report['counts'],
                         {'sentinel-skip': 1, 'licensed-by-a-type-level-claim': 1})
        row = report['leads'][0]
        self.assertEqual(row['function'], 'confirm_instruction')
        self.assertEqual(row['skips_on'], ['value None'])
        self.assertEqual(row['type_level_qualifiers'], ['property_template.optional'])
        self.assertEqual(row['rank'], 0)

    def test_the_fix_leaves_no_lead_and_notes_the_policy(self):
        report = self.run_fixture('solana-layout-fixed')
        self.assertEqual(report['leads'], [])
        self.assertEqual(len(report['notes']), 1)
        self.assertIn('default_value_to_hide', report['notes'][0]['per_field_qualifiers'][0])

    def test_restoring_the_line_brings_the_lead_back(self):
        """The silence on the fixed revision is the line being gone, not the check being blind."""
        fixed = (FIXTURES / 'solana-layout-fixed.py').read_text(encoding='utf-8')
        anchor = '            default_value_to_hide = ui_property.default_value_to_hide\n'
        self.assertIn(anchor, fixed)
        restored = fixed.replace(
            anchor,
            '            if property_template.optional and value is None:\n'
            '                continue\n\n' + anchor, 1)
        report = sentinel.analyse(restored)
        self.assertEqual(report['counts']['licensed-by-a-type-level-claim'], 1)
        self.assertEqual(report['leads'][0]['type_level_qualifiers'],
                         ['property_template.optional'])


class RuleTests(unittest.TestCase):
    def test_a_dispatch_on_the_loop_item_is_not_a_display_rule(self):
        self.assertEqual(sentinel.analyse(DISPATCH_ON_THE_LOOP_ITEM)['leads'], [])

    def test_a_per_field_policy_is_noted_not_flagged(self):
        report = sentinel.analyse(PER_FIELD_POLICY)
        self.assertEqual(report['leads'], [])
        self.assertEqual(len(report['notes']), 1)

    def test_a_type_level_claim_is_rank_zero(self):
        report = sentinel.analyse(TYPE_LEVEL_CLAIM)
        self.assertEqual(report['counts']['licensed-by-a-type-level-claim'], 1)
        self.assertEqual(report['leads'][0]['type_level_qualifiers'], ['template.optional'])

    def test_an_unlicensed_skip_is_rank_one(self):
        report = sentinel.analyse(NOTHING_LICENSES_IT)
        self.assertEqual(len(report['leads']), 1)
        self.assertEqual(report['leads'][0]['rank'], 1)
        self.assertEqual(report['leads'][0]['qualifiers'], [])

    def test_a_falsy_test_counts_as_a_sentinel(self):
        report = sentinel.analyse(FALSY_TEST)
        self.assertEqual(len(report['leads']), 1)
        self.assertEqual(report['leads'][0]['skips_on'], ['amount falsy'])

    def test_a_loop_that_renders_nothing_is_silent(self):
        self.assertEqual(sentinel.analyse(NO_RENDERER_IN_THE_LOOP)['leads'], [])


class CliTests(unittest.TestCase):
    def test_it_writes_a_report_and_tags_the_source(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / 'report.json'
            code = sentinel.main(['--source', str(FIXTURES / 'solana-layout-pre.py'),
                                  '--source', str(FIXTURES / 'solana-layout-fixed.py'),
                                  '--out', str(out)])
            self.assertEqual(code, 0)
            report = json.loads(out.read_text(encoding='utf-8'))
            self.assertEqual(report['counts']['sentinel-skip'], 1)
            self.assertTrue(report['leads'][0]['source'].endswith('solana-layout-pre.py'))


if __name__ == '__main__':
    unittest.main()
