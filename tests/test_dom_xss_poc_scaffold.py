"""Static candidate/control HTML scaffold generation; never executes a browser."""
import importlib.util
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = 'skills/bounty-pilot/scripts/dom_xss_poc_scaffold.py'


def load():
    spec = importlib.util.spec_from_file_location('dom_xss_poc_scaffold', ROOT / SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scaffold_mod = load()


class _LenientParser(HTMLParser):
    """Just confirms the generator never emits something HTMLParser chokes on."""


class DomXssPocScaffoldTests(unittest.TestCase):
    def test_every_sink_generates_a_well_formed_candidate_and_control(self):
        for sink in scaffold_mod.SINKS:
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / 'scaffold'
                result = scaffold_mod.scaffold(sink, 'file.tsx:Comp:12', str(out))
                self.assertEqual(result['sink'], sink)
                self.assertFalse(result['executed_in_a_browser_by_this_tool'])
                for name in ('candidate.html', 'control.html', 'README.md'):
                    self.assertTrue((out / name).is_file())
                candidate = (out / 'candidate.html').read_text(encoding='utf-8')
                control = (out / 'control.html').read_text(encoding='utf-8')
                _LenientParser().feed(candidate)
                _LenientParser().feed(control)
                self.assertIn('__bp_poc_marker', candidate)
                self.assertIn('BP_POC_RESULT', candidate)
                self.assertIn('__bp_poc_marker', control)
                self.assertNotIn('http://', candidate)
                self.assertNotIn('https://', candidate)

    def test_candidate_and_control_differ_only_in_the_safe_mechanism(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'scaffold'
            scaffold_mod.scaffold('innerHTML', 'a.tsx:X:1', str(out))
            candidate = (out / 'candidate.html').read_text(encoding='utf-8')
            control = (out / 'control.html').read_text(encoding='utf-8')
            self.assertIn('.innerHTML =', candidate)
            self.assertIn('.textContent =', control)
            self.assertNotIn('.innerHTML =', control)

    def test_unknown_sink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                scaffold_mod.scaffold('onclick', 'a.tsx:X:1', str(Path(tmp) / 'out'))

    def test_refuses_to_write_into_an_existing_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'scaffold'
            scaffold_mod.scaffold('eval', 'a.tsx:X:1', str(out))
            with self.assertRaisesRegex(ValueError, 'existing directory'):
                scaffold_mod.scaffold('eval', 'a.tsx:X:1', str(out))

    def test_anchor_must_be_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                scaffold_mod.scaffold('eval', 'a' * 200, str(Path(tmp) / 'out'))
            with self.assertRaises(ValueError):
                scaffold_mod.scaffold('eval', 'has spaces here', str(Path(tmp) / 'out2'))

    def test_cli_rejects_unknown_sink_choice(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit) as ctx:
                scaffold_mod.main(['--sink', 'onclick', '--anchor', 'a:b:1',
                                   '--out-dir', str(Path(tmp) / 'out')])
            self.assertEqual(ctx.exception.code, 2)

    def test_cli_reports_application_error_without_raising(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'out'
            out.mkdir()
            code = scaffold_mod.main(['--sink', 'eval', '--anchor', 'a:b:1',
                                      '--out-dir', str(out)])
            self.assertEqual(code, 2)


if __name__ == '__main__':
    unittest.main()
