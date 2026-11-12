"""javascript:// hostname-check bypass shape, parsed with real urllib and WHATWG URL."""
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = 'skills/bounty-pilot/scripts/url_scheme_guard_check.py'


def load():
    spec = importlib.util.spec_from_file_location('url_scheme_guard_check', ROOT / SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = load()


@unittest.skipUnless(shutil.which('node'), 'Node.js WHATWG URL implementation unavailable')
class UrlSchemeGuardCheckTests(unittest.TestCase):
    def test_javascript_scheme_with_a_hostname_is_the_bypass_shape(self):
        result = guard.check(['javascript://trusted.example/%0aalert(1)'])
        row = result['rows'][0]
        self.assertTrue(row['dangerous_protocol'])
        self.assertEqual(row['whatwg_url']['hostname'], 'trusted.example')
        self.assertTrue(row['hostname_check_bypass_shape'])
        self.assertEqual(result['hostname_check_bypass_shapes'], 1)

    def test_bare_javascript_scheme_has_no_hostname_and_is_not_the_bypass_shape(self):
        result = guard.check(['javascript:alert(1)'])
        row = result['rows'][0]
        self.assertTrue(row['dangerous_protocol'])
        self.assertFalse(row['whatwg_url']['hostname'])
        self.assertFalse(row['hostname_check_bypass_shape'])

    def test_ordinary_https_url_is_never_flagged(self):
        result = guard.check(['https://trusted.example/path?x=1'])
        row = result['rows'][0]
        self.assertFalse(row['dangerous_protocol'])
        self.assertFalse(row['hostname_check_bypass_shape'])

    def test_protocol_relative_url_resolves_against_an_inert_local_base(self):
        result = guard.check(['//evil.example/x'])
        row = result['rows'][0]
        self.assertTrue(row['whatwg_url']['resolved_against_relative_base'])
        self.assertEqual(row['whatwg_url']['hostname'], 'evil.example')
        self.assertFalse(row['dangerous_protocol'])

    def test_data_scheme_with_hostname_is_also_a_bypass_shape(self):
        result = guard.check(['data://trusted.example/%0a<script>'])
        self.assertTrue(result['rows'][0]['hostname_check_bypass_shape'])

    def test_duplicate_candidates_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            guard.check(['https://a.example/', 'https://a.example/'])

    def test_too_many_candidates_are_rejected(self):
        with self.assertRaises(ValueError):
            guard.check(['https://a.example/'] * 61)

    def test_non_printable_candidate_is_rejected(self):
        with self.assertRaises(ValueError):
            guard.check(['javascript:alert(1)\x00'])

    def test_cli_refuses_to_overwrite_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'urls.json'
            src.write_text(json.dumps(['https://a.example/']), encoding='utf-8')
            out = Path(tmp) / 'out.json'
            out.write_text('{}', encoding='utf-8')
            code = guard.main(['--input', str(src), '--out', str(out)])
            self.assertEqual(code, 2)

    def test_cli_writes_private_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'urls.json'
            src.write_text(json.dumps(['javascript://trusted.example/%0aalert(1)']),
                           encoding='utf-8')
            out = Path(tmp) / 'out.json'
            code = guard.main(['--input', str(src), '--out', str(out)])
            self.assertEqual(code, 0)
            payload = json.loads(out.read_text(encoding='utf-8'))
            self.assertEqual(payload['hostname_check_bypass_shapes'], 1)


if __name__ == '__main__':
    unittest.main()
