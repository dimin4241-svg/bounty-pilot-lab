"""Lexical source-anchor leads for web_business_lab rules on a real checkout."""
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = 'skills/bounty-pilot/scripts/business_schema_bind.py'

ENV = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t', GIT_COMMITTER_NAME='t',
           GIT_COMMITTER_EMAIL='t@t')


def load():
    spec = importlib.util.spec_from_file_location('business_schema_bind', ROOT / SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bind_mod = load()


def git(repo, *args):
    subprocess.run(['git', '-C', str(repo), *args], check=True, env=ENV,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write(repo, rel, text):
    path = Path(repo) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


class BusinessSchemaBindTests(unittest.TestCase):
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

    def test_every_lab_rule_has_a_curated_keyword_list(self):
        for rule in bind_mod.RULES:
            self.assertIn(rule, bind_mod.RULE_KEYWORDS)
            self.assertTrue(bind_mod.RULE_KEYWORDS[rule])

    def test_hit_and_miss_classification(self):
        write(self.repo, 'app/models.py',
             'def revoke_session(user):\n    user.session_active = False\n')
        self.commit()
        report = bind_mod.bind(str(self.repo),
                              rules=['session-revocation', 'oauth-binding'])
        by_rule = {row['rule']: row for row in report['rules']}
        self.assertEqual(by_rule['session-revocation']['classification'],
                         'LEXICAL_RULE_ANCHOR_LEAD')
        self.assertTrue(by_rule['session-revocation']['hits'])
        self.assertEqual(by_rule['oauth-binding']['classification'],
                         'NO_LEXICAL_ANCHOR_FOUND')
        self.assertEqual(by_rule['oauth-binding']['hits'], [])

    def test_untracked_files_are_invisible(self):
        write(self.repo, 'app/tracked.py', 'def noop():\n    return None\n')
        self.commit()
        (self.repo / 'app' / 'untracked.py').write_text(
            'def revoke_session(user):\n    user.session_active = False\n', encoding='utf-8')
        report = bind_mod.bind(str(self.repo), rules=['session-revocation'])
        self.assertEqual(report['rules'][0]['classification'], 'NO_LEXICAL_ANCHOR_FOUND')

    def test_scope_restricts_files_scanned(self):
        write(self.repo, 'app/in_scope.py',
             'def revoke_session(user):\n    user.session_active = False\n')
        write(self.repo, 'other/out_of_scope.py',
             'def revoke_session(user):\n    user.session_active = False\n')
        self.commit()
        report = bind_mod.bind(str(self.repo), rules=['session-revocation'], scope=['app'])
        self.assertEqual(report['code_files_scanned'], 1)
        for hit in report['rules'][0]['hits']:
            self.assertTrue(hit['path'].startswith('app/'))

    def test_unknown_rule_is_rejected(self):
        write(self.repo, 'app/a.py', 'x = 1\n')
        self.commit()
        with self.assertRaises(ValueError):
            bind_mod.bind(str(self.repo), rules=['not-a-real-rule'])

    def test_repo_without_git_is_rejected(self):
        with tempfile.TemporaryDirectory() as plain:
            with self.assertRaisesRegex(ValueError, 'git checkout'):
                bind_mod.bind(plain)

    def test_path_traversal_scope_is_rejected(self):
        write(self.repo, 'app/a.py', 'x = 1\n')
        self.commit()
        with self.assertRaises(ValueError):
            bind_mod.bind(str(self.repo), scope=['../outside'])

    def test_cli_refuses_to_overwrite_existing_output(self):
        write(self.repo, 'app/a.py', 'x = 1\n')
        self.commit()
        out = Path(self.tmp.name) / 'out.json'
        out.write_text('{}', encoding='utf-8')
        code = bind_mod.main(['--repo', str(self.repo), '--out', str(out)])
        self.assertEqual(code, 2)

    def test_default_rule_selection_covers_every_rule(self):
        write(self.repo, 'app/a.py', 'x = 1\n')
        self.commit()
        report = bind_mod.bind(str(self.repo))
        self.assertEqual({row['rule'] for row in report['rules']}, set(bind_mod.RULES))


if __name__ == '__main__':
    unittest.main()
