"""Join web-route-ast routes with business-schema-bind lexical leads, by handler."""
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = 'skills/bounty-pilot/scripts/business_route_bind.py'

ENV = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t', GIT_COMMITTER_NAME='t',
           GIT_COMMITTER_EMAIL='t@t')


def load():
    spec = importlib.util.spec_from_file_location('business_route_bind', ROOT / SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rb = load()


def git(repo, *args):
    subprocess.run(['git', '-C', str(repo), *args], check=True, env=ENV,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write(repo, rel, text):
    path = Path(repo) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


class BusinessRouteBindTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / 'target'
        self.repo.mkdir()
        git(self.repo, 'init', '-q')

    def tearDown(self):
        self.tmp.cleanup()

    def commit(self, msg='c'):
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-qm', msg)

    def test_route_body_hit_is_anchored_to_its_own_handler(self):
        write(self.repo, 'app/views.py', '''
@app.post("/account/session/revoke")
def revoke(session_id: str):
    account.session_active = False
    return {"ok": True}

@app.get("/account/profile/{uid}")
def profile(uid: str):
    return load_profile(uid)
''')
        self.commit()
        report = rb.bind_routes(str(self.repo), rules=['session-revocation'])
        self.assertEqual(report['routes_scanned'], 2)
        self.assertEqual(report['routes_with_leads'], 1)
        route = report['routes'][0]
        self.assertEqual(route['handler'], 'app/views.py:revoke')
        self.assertEqual(route['method'], 'POST')
        lead = route['rule_leads'][0]
        self.assertEqual(lead['rule'], 'session-revocation')
        self.assertEqual(lead['body_lexical_hits'][0]['term'], 'session_active')

    def test_a_hit_outside_any_handlers_line_range_is_not_anchored(self):
        write(self.repo, 'app/views.py', '''
# session_active appears here, outside every handler below.
MODULE_NOTE = "session_active bookkeeping lives in the model layer"

@app.get("/account/profile/{uid}")
def profile(uid: str):
    return load_profile(uid)
''')
        self.commit()
        report = rb.bind_routes(str(self.repo), rules=['session-revocation'])
        self.assertEqual(report['routes_with_leads'], 0)

    def test_called_function_name_match_is_reported_alongside_the_body_hit(self):
        write(self.repo, 'app/views.py', '''
@app.post("/account/session/revoke")
def revoke(session_id: str):
    revoke_session(session_id)
    return {"ok": True}
''')
        self.commit()
        report = rb.bind_routes(str(self.repo), rules=['session-revocation'])
        lead = report['routes'][0]['rule_leads'][0]
        self.assertIn('revoke_session', lead['called_function_name_matches'])
        self.assertTrue(lead['body_lexical_hits'])

    def test_guard_cues_from_route_ast_are_carried_through(self):
        write(self.repo, 'app/views.py', '''
from fastapi import Depends

@app.post("/account/session/revoke", dependencies=[Depends(require_owner)])
def revoke(session_id: str):
    account.session_active = False
    return {"ok": True}
''')
        self.commit()
        report = rb.bind_routes(str(self.repo), rules=['session-revocation'])
        self.assertIn('require_owner', report['routes'][0]['guard_name_cues'])

    def test_rule_selection_is_forwarded_to_the_schema_scan(self):
        write(self.repo, 'app/views.py', '''
@app.post("/account/session/revoke")
def revoke(session_id: str):
    account.session_active = False

@app.post("/pay")
def pay():
    psp_confirmed = True
''')
        self.commit()
        report = rb.bind_routes(str(self.repo), rules=['session-revocation'])
        rules_seen = {lead['rule'] for route in report['routes'] for lead in route['rule_leads']}
        self.assertEqual(rules_seen, {'session-revocation'})

    def test_cli_refuses_to_overwrite_existing_output(self):
        write(self.repo, 'app/a.py', 'x = 1\n')
        self.commit()
        out = Path(self.tmp.name) / 'out.json'
        out.write_text('{}', encoding='utf-8')
        code = rb.main(['--repo', str(self.repo), '--out', str(out)])
        self.assertEqual(code, 2)

    def test_dirty_tree_is_refused_same_as_business_schema_bind(self):
        write(self.repo, 'app/a.py', 'x = 1\n')
        self.commit()
        write(self.repo, 'app/a.py', 'x = 2\n')
        with self.assertRaises(ValueError):
            rb.bind_routes(str(self.repo))


if __name__ == '__main__':
    unittest.main()
