"""Tier 1 of the 2026-10-21 design: stop dropping findings, stop trusting my own citations,
price duplicates before the experiment, and read the audit gap first.

Every test here failed on `fd2f48b` (0.23.0). The four changes answer four measured facts:
eleven of the first twelve decided reports came back duplicate; about sixteen candidates died
on public prior art only after the PoC; anchors and coverage rows were never checked against
the code they cite; and on published data most loss in audited protocols came through paths no
audit covered.
"""
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/bounty-pilot/scripts'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bounty = load('t1_bounty', 'bounty.py')


def git(repo, *args):
    subprocess.run(['git', '-C', str(repo), *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def commit(repo, message='fixture'):
    git(repo, 'add', '-A')
    git(repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
        '-c', 'commit.gpgsign=false', 'commit', '-qm', message)


def head(repo):
    return subprocess.run(['git', '-C', str(repo), 'rev-parse', 'HEAD'],
                          capture_output=True, text=True).stdout.strip()


VAULT = '''// SPDX-License-Identifier: MIT
contract Vault {
    mapping(address => uint256) balances;
    uint256 totalDebt;

    function deposit(uint256 amount) external {
        require(msg.sender != address(0));
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        totalDebt -= amount;
    }
}
'''


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        (self.repo / 'src/Vault.sol').write_text(VAULT)
        commit(self.repo)
        self.run = self.base / 'run'
        bounty.initialize(self.repo, self.run)

    def record(self, **fields):
        row = bounty.template()
        row.update(id='BP-001', title='Debt is not decremented', status='hypothesis',
                   severity='unassessed', bug_class='aggregate-not-decremented',
                   revision=head(self.repo), root_cause='withdraw skips the write',
                   affected_paths=['src/Vault.sol:Vault.withdraw'],
                   attacker_capabilities='any caller', preconditions='an open loan',
                   impact='debt drifts',
                   next_experiment={'question': 'q', 'method': 'm', 'expected_evidence': 'e',
                                    'blocker': ''})
        row.update(fields)
        return row

    def known(self, *rows):
        path = self.run / 'known-hypotheses.md'
        path.write_text(path.read_text() + '\n'.join(rows) + '\n')


# ---------------------------------------------------------------------------------------------
# T1.5 — the paths that dropped a finding with nobody reviewing it
# ---------------------------------------------------------------------------------------------

class SuppressionTests(Fixture):
    def test_a_closed_row_without_an_anchor_is_reported(self):
        self.known('| src/Vault.sol | reentrancy | closed-refuted | no external call here |')
        rows = bounty._unanchored_closures(self.run)
        self.assertEqual(len(rows), 1)                             # fd2f48b: nothing checked
        self.assertEqual(rows[0]['bug_class'], 'reentrancy')
        self.assertTrue(any('closes that ground with no anchor' in e
                            for e in bounty.validate(self.run)))

    def test_an_anchored_closure_and_an_open_row_are_left_alone(self):
        self.known('| src/Vault.sol | reentrancy | closed-refuted | '
                   '`require(msg.sender != address(0))` at src/Vault.sol:7 |')
        self.assertEqual(bounty._unanchored_closures(self.run), [])

    def test_the_table_header_is_not_a_hypothesis(self):
        # The shipped template's own header row read as a closed row with status "status".
        self.known('| surface | bug-class | status | why |', '| --- | --- | --- | --- |',
                   '| src/Vault.sol | reentrancy | closed-refuted | `require` at L7 |')
        self.assertEqual(bounty._unanchored_closures(self.run), [])  # fd2f48b: flagged the header
        self.assertEqual([r['surface'] for r in bounty._known_hypothesis_rows(self.run)],
                         ['src/Vault.sol'])

    def test_queue_shows_the_unanchored_closures(self):
        self.known('| src/Vault.sol | reentrancy | closed-refuted | looks fine |')
        self.assertEqual(len(bounty.lead_queue(self.run)['unanchored_closures']), 1)

    def test_the_shared_rules_tell_the_reader_to_emit_not_delete(self):
        text = (ROOT / 'skills/bounty-pilot/references/hunt-agents/_shared.md').read_text()
        self.assertIn('likely-excluded', text)                      # fd2f48b: "Never report ..."
        skill = (ROOT / 'skills/bounty-pilot/SKILL.md').read_text()
        self.assertNotIn('is ground the lenses skip', skill)


class MechanismKeyTests(Fixture):
    """Two different bugs of one class in one function merged into a single saturated group."""

    def reading(self, name, *lines):
        folder = self.base / 'readings'
        folder.mkdir(exist_ok=True)
        (folder / name).write_text('\n'.join(lines) + '\n')
        return folder

    def test_a_named_mechanism_keeps_its_own_group(self):
        self.reading('a.md', 'CANDIDATE | lens: accounting | surface: src/Vault.sol:Vault.withdraw'
                             ' | bug_class: accounting-drift', 'mechanism: totalDebt underflows')
        folder = self.reading('b.md',
                              'CANDIDATE | lens: economics | surface: src/Vault.sol:Vault.withdraw'
                              ' | bug_class: accounting-drift',
                              'mechanism: balances is written before the transfer')
        result = bounty.converge([str(folder)], self.run)
        self.assertEqual(result['saturated_groups'], 0)             # fd2f48b: 1, one bug lost
        self.assertEqual(result['singletons'], 2)

    def test_without_a_mechanism_the_grouping_is_unchanged(self):
        self.reading('a.md', 'CANDIDATE | lens: accounting | surface: src/Vault.sol:Vault.withdraw'
                             ' | bug_class: accounting-drift')
        folder = self.reading('b.md',
                              'CANDIDATE | lens: economics | surface: src/Vault.sol:Vault.withdraw'
                              ' | bug_class: accounting-drift')
        self.assertEqual(bounty.converge([str(folder)], self.run)['saturated_groups'], 1)


# ---------------------------------------------------------------------------------------------
# T3.1 / T3.2 — an anchor has to quote code that is really there
# ---------------------------------------------------------------------------------------------

class AnchorVerificationTests(Fixture):
    def with_objection(self, anchor):
        row = self.record()
        row['objections'] = [{'gate': 'reachability', 'claim': 'a guard stops it',
                              'anchor': anchor, 'outcome': 'sustained'}]
        bounty.dump(self.run / 'findings.json', [row])
        return bounty.verify_anchors(self.run)

    def test_a_quote_that_is_in_the_file_verifies(self):
        report = self.with_objection('code: src/Vault.sol:7 `require(msg.sender != address(0))`')
        self.assertEqual(report['problems'], [])
        self.assertEqual(report['by_state'].get('verified'), 1)

    def test_a_quote_reformatted_by_the_reader_still_verifies(self):
        report = self.with_objection('src/Vault.sol `balances[msg.sender]   += amount;`')
        self.assertEqual(report['problems'], [])

    def test_a_quote_that_is_not_in_the_file_is_reported(self):
        report = self.with_objection('src/Vault.sol `require(amount <= balances[msg.sender])`')
        self.assertEqual([p['state'] for p in report['problems']], ['quote-not-found'])
        self.assertTrue(any('is not in src/Vault.sol' in e       # fd2f48b: nothing checked it
                            for e in bounty.validate(self.run, submission=True)))

    def test_a_path_the_checkout_does_not_have_is_reported(self):
        report = self.with_objection('code: src/Guard.sol:12 `onlyOwner`')
        self.assertEqual([p['state'] for p in report['problems']], ['path-missing'])

    def test_a_line_past_the_end_is_reported_but_does_not_block(self):
        report = self.with_objection('code: src/Vault.sol:900 bounds it')
        self.assertEqual([p['state'] for p in report['problems']], ['line-missing'])
        # A line number drifts with every edit above it; a quote does not.
        self.assertFalse(any('line-missing' in e for e in
                             bounty.validate(self.run, submission=True)))

    def test_an_anchor_naming_no_file_is_reported_as_unchecked_not_clean(self):
        report = self.with_objection('the pause modifier covers it')
        self.assertEqual(report['by_state'].get('no-path'), 1)
        self.assertEqual(report['problems'], [])

    def test_an_examined_function_that_does_not_exist_is_reported(self):
        bounty.dump(self.run / 'findings.json', [self.record()])
        bounty.dump(self.run / bounty.EXAMINED_FILE,
                    {'examined': [{'surface': 'src/Vault.sol:Vault.withdraw'},
                                  {'surface': 'src/Vault.sol:Vault.liquidate'}],
                     'not_reached': []})
        states = {p['state']: p for p in bounty.verify_anchors(self.run)['problems']}
        self.assertIn('symbol-not-found', states)                 # fd2f48b: coverage believed
        self.assertIn('liquidate', states['symbol-not-found']['detail'])

    def test_a_checkout_that_is_gone_reads_as_unverifiable(self):
        bounty.dump(self.run / 'findings.json', [self.record()])
        meta = bounty.read_json(self.run / 'run.json')
        meta['target_root'] = str(self.base / 'not-here')
        bounty.dump(self.run / 'run.json', meta)
        report = bounty.verify_anchors(self.run)
        self.assertEqual(report['state'], 'unverifiable')
        self.assertIn('Unchecked, not clean', report['notice'])


# ---------------------------------------------------------------------------------------------
# T1.3 — duplicate risk priced before the experiment budget
# ---------------------------------------------------------------------------------------------

class Response:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode('utf-8')

    def read(self):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class NoveltyRiskTests(Fixture):
    def setUp(self):
        super().setUp()
        bounty.dump(self.run / 'findings.json', [self.record()])

    def test_offline_records_the_judgements_as_unanswered(self):
        result = bounty.novelty_risk(self.run, offline=True)
        row = result['records'][0]
        self.assertEqual(row['band'],
                         'unknown: nothing was searched (no repository, or --offline)')
        self.assertEqual(len(row['unanswered_judgements']), len(bounty.NOVELTY_JUDGEMENTS))

    def test_a_known_signal_answered_yes_makes_the_risk_high(self):
        bounty.novelty_risk(self.run, offline=True)
        data = bounty.read_json(self.run / bounty.NOVELTY_RISK_FILE)
        for key, _ in bounty.NOVELTY_JUDGEMENTS:
            data['records'][0]['judgements'][key] = 'no'
        data['records'][0]['judgements']['visible_in_their_telemetry'] = 'yes'
        bounty.dump(self.run / bounty.NOVELTY_RISK_FILE, data)
        row = bounty.novelty_risk(self.run, offline=True)['records'][0]
        self.assertTrue(row['band'].startswith('high:'))
        self.assertEqual(row['known_signals'], ['visible_in_their_telemetry'])

    def test_a_review_comment_hit_is_found_and_held_untriaged(self):
        def opener(request, timeout=None):
            if '/security-advisories' in request.full_url:
                return Response([])
            return Response({'total_count': 1, 'incomplete_results': False, 'items': [
                {'number': 210, 'title': 'fix: withdraw does not decrement totalDebt',
                 'state': 'closed', 'pull_request': {},
                 'html_url': 'https://github.com/org/vault/pull/210',
                 'repository_url': 'https://api.github.com/repos/org/vault'}]})
        row = bounty.novelty_risk(self.run, repo='org/vault', token_env=None,
                                  opener=opener)['records'][0]
        self.assertIn('withdraw', row['terms'])
        self.assertEqual(row['hit_count'], 1)                      # fd2f48b: no such search
        self.assertEqual(row['untriaged_hits'], ['#210'])
        self.assertIn('not yet read', row['band'])

    def test_a_triaged_hit_and_answered_judgements_clear_the_band(self):
        def opener(request, timeout=None):
            if '/security-advisories' in request.full_url:
                return Response([])
            return Response({'total_count': 0, 'incomplete_results': False, 'items': []})
        bounty.novelty_risk(self.run, repo='org/vault', token_env=None, opener=opener)
        data = bounty.read_json(self.run / bounty.NOVELTY_RISK_FILE)
        for key, _ in bounty.NOVELTY_JUDGEMENTS:
            data['records'][0]['judgements'][key] = 'no'
        bounty.dump(self.run / bounty.NOVELTY_RISK_FILE, data)
        row = bounty.novelty_risk(self.run, repo='org/vault', token_env=None,
                                  opener=opener)['records'][0]
        self.assertTrue(row['band'].startswith('searched:'))
        self.assertIn('private duplicates remain invisible', row['band'])

    def test_queue_reports_the_band(self):
        bounty.novelty_risk(self.run, offline=True)
        reported = bounty.lead_queue(self.run)['novelty_risk']
        self.assertEqual(reported['records'][0]['id'], 'BP-001')


# ---------------------------------------------------------------------------------------------
# T1.2 — the audit gap is the reading order
# ---------------------------------------------------------------------------------------------

class AuditGapTests(Fixture):
    def setUp(self):
        super().setUp()
        self.audited = head(self.repo)
        (self.repo / 'src/New.sol').write_text('contract New { function f() external {} }\n')
        (self.repo / 'src/Vault.sol').write_text(VAULT + '// touched after the audit\n')
        (self.repo / 'script').mkdir()
        (self.repo / 'script/Deploy.s.sol').write_text('contract Deploy {}\n')
        commit(self.repo, 'after the audit')

    def bands(self, **kwargs):
        result = bounty.audit_gap(self.repo, self.run, **kwargs)
        return result, {row['path']: row['band'] for row in result['ranked']}

    def test_each_file_lands_in_the_band_that_describes_it(self):
        result, bands = self.bands(audited=[self.audited])
        self.assertEqual(bands['src/New.sol'], 'never-audited')
        self.assertEqual(bands['src/Vault.sol'], 'changed-after-audit')
        # Band 1 reads first, and inside it the deployment script comes before the contract.
        self.assertEqual(result['ranked'][0]['path'], 'script/Deploy.s.sol')
        self.assertEqual(result['by_band']['never-audited'], 2)

    def test_an_untouched_file_under_a_recent_audit_is_band_four(self):
        (self.repo / 'src/Quiet.sol').write_text('contract Quiet {}\n')
        commit(self.repo, 'add quiet')
        audited = head(self.repo)
        (self.repo / 'src/Vault.sol').write_text(VAULT + '// later\n')
        commit(self.repo, 'later')
        _, bands = self.bands(audited=[audited])
        self.assertEqual(bands['src/Quiet.sol'], 'audited-recent')

    def test_an_old_audit_makes_an_untouched_file_stale(self):
        (self.repo / 'src/Quiet.sol').write_text('contract Quiet {}\n')
        commit(self.repo, 'add quiet')
        audited = head(self.repo)
        (self.repo / 'src/Vault.sol').write_text(VAULT + '// later still\n')
        commit(self.repo, 'later')
        _, fresh = self.bands(audited=[audited])
        self.assertEqual(fresh['src/Quiet.sol'], 'audited-recent')
        _, stale = self.bands(audited=[audited], stale_days=0)
        self.assertEqual(stale['src/Quiet.sol'], 'audited-stale')

    def test_deployment_and_migration_files_are_called_out(self):
        result, _ = self.bands(audited=[self.audited])
        self.assertIn('script/Deploy.s.sol', result['sequence_surfaces'])
        self.assertEqual(result['sequence_surface_count'], 1)

    def test_no_baseline_is_an_unknown_not_a_pass(self):
        result, bands = self.bands()
        self.assertEqual(set(bands.values()), {'no-baseline'})
        self.assertIn('an unknown, not a', result['notice'])
        self.assertEqual(result['baselines'], [])

    def test_the_audited_revision_is_read_from_program_json(self):
        bounty.dump(self.run / 'program.json', {'audited_revision': self.audited})
        result, bands = self.bands()
        self.assertEqual(bands['src/New.sol'], 'never-audited')
        self.assertEqual(result['baselines'][0]['given'], self.audited)

    def test_a_revision_the_checkout_does_not_have_is_named(self):
        result, _ = self.bands(audited=['deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'])
        self.assertEqual(result['unresolved_baselines'],
                         ['deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'])

    def test_scope_limits_what_is_ranked(self):
        _, bands = self.bands(audited=[self.audited], scope_prefixes=['script/'])
        self.assertEqual(set(bands), {'script/Deploy.s.sol'})

    def test_queue_reports_the_bands(self):
        bounty.audit_gap(self.repo, self.run, audited=[self.audited])
        reported = bounty.lead_queue(self.run)['audit_gap']
        self.assertEqual(reported['by_band']['never-audited'], 2)
        self.assertEqual(reported['baselines'], [self.audited])


if __name__ == '__main__':
    unittest.main()
