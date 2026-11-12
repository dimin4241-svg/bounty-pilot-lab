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

    def test_family_is_loaded_from_the_real_sibling_module_not_a_stale_fallback(self):
        # Regression: a bare `from web_business_lab import RULES` silently falls back
        # to the None-valued dict whenever this file is loaded by path from a cwd
        # other than scripts/ (every real caller: bounty.py's dispatcher and this
        # test suite), which would make every report's "family" field quietly None.
        self.assertEqual(bind_mod.RULES['account-owner'][0], 'identity')
        self.assertEqual(bind_mod.RULES['unpaid-credit'][0], 'payment')
        self.assertEqual(bind_mod.RULES['cross-actor-disclosure'][0], 'disclosure')
        write(self.repo, 'app/a.py', 'x = 1\n')
        self.commit()
        report = bind_mod.bind(str(self.repo), rules=['account-owner'])
        self.assertEqual(report['rules'][0]['family'], 'identity')

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

    def test_per_term_hit_cap_prevents_one_term_from_hiding_other_anchors(self):
        lines = ["session_active = 1" for _ in range(30)]
        lines.append("revoke_session = lambda user: None")
        write(self.repo, 'app/session.py', "\n".join(lines) + "\n")
        self.commit()
        output = bind_mod.bind(str(self.repo), rules=["session-revocation"])
        hits = output["rules"][0]["hits"]
        self.assertLessEqual(sum(h["term"] == "session_active" for h in hits),
                             bind_mod.MAX_HITS_PER_TERM)
        self.assertTrue(any(h["term"] == "revoke_session" for h in hits))
        self.assertLessEqual(len(hits), bind_mod.MAX_HITS_PER_RULE)

    def test_output_uses_private_mode_and_rejects_symlink(self):
        write(self.repo, 'app/a.py', 'def revoke_session(user):\n    return None\n')
        self.commit()
        out = Path(self.tmp.name) / 'private.json'
        self.assertEqual(bind_mod.main(['--repo', str(self.repo), '--out', str(out)]), 0)
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)
        alias = Path(self.tmp.name) / 'alias.json'
        alias.symlink_to(out)
        self.assertEqual(bind_mod.main(['--repo', str(self.repo), '--out', str(alias)]), 2)

    def test_revision_matches_git_and_dirty_tracked_source_refused(self):
        write(self.repo, 'app/a.py', 'def revoke_session(user):\n    return None\n')
        self.commit()
        report = bind_mod.bind(str(self.repo))
        actual = subprocess.run(['git', '-C', str(self.repo), 'rev-parse', 'HEAD'],
                                capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(report["source_revision"], actual)
        write(self.repo, 'app/a.py', 'def revoke_session(user):\n    return True\n')
        with self.assertRaisesRegex(ValueError, "modified"):
            bind_mod.bind(str(self.repo))

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
