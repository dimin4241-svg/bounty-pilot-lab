"""Search plumbing: converge, import-findings, bundle inputs, the lens registry, delta and
score-target. Each test names the way the old behaviour hid or merged something."""
import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bounty = load('bounty', 'skills/bounty-pilot/scripts/bounty.py')
stack_route = load('bp_stack_route_test', 'skills/bounty-pilot/scripts/stack_route.py')
scope_coverage = load('bp_scope_coverage_test', 'skills/bounty-pilot/scripts/scope_coverage.py')


def git(repo, *args):
    subprocess.run(['git', '-C', str(repo), *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def commit(repo, message):
    git(repo, 'add', '-A')
    git(repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
        'commit', '-qm', message)


def head(repo):
    return subprocess.run(['git', '-C', str(repo), 'rev-parse', 'HEAD'], check=True,
                          stdout=subprocess.PIPE).stdout.decode().strip()


VAULT = ('contract Vault {\n  uint256 totalDebt;\n'
         '  function withdraw(uint256 a) external { totalDebt -= a; }\n'
         '  function deposit(uint256 a) external { totalDebt += a; }\n}\n')

# solidity-auditor v4.1 raw agent output, as its shared rules define it.
AUDITOR_RAW = """FINDING | contract: Vault | function: withdraw | bug_class: reentrancy | group_key: Vault | withdraw | reentrancy
path: attacker -> withdraw -> external call before totalDebt write -> drain
proof: withdraw sends ETH at line 3 before totalDebt is decremented
description: An attacker re-enters withdraw and takes funds twice.
fix: Write totalDebt before the call.

LEAD | contract: Router | function: withdraw | bug_class: reentrancy | group_key: Router | withdraw | reentrancy
code_smells: external call before state write
description: The trail ends at an unverified callback.
"""

# A solidity-auditor run file, as dedup-and-assembly.md defines it.
AUDITOR_RUN_FILE = """# Run {k} — solidity-auditor

<!--RUN pass={k} of=2 stamp=20261017-101010 sha=abc1234 agents=12/12-->

Pass {k} of 2 · 2026-10-17 · `abc1234` · 12/12 agents returned.

## Findings

<!--F key=vault|withdraw|reentrancy conf=95 kind={kind} agents=8-->

[95] **Withdraw can be re-entered**

`Vault.withdraw` · Confidence: 95

**Description**
An attacker re-enters withdraw and takes funds twice.

**Fix**

```diff
- (bool ok,) = msg.sender.call{{value: a}}("");
+ totalDebt -= a;
```

<!--/F-->

## Leads

<!--F key=vault|deposit|accounting-drift kind=LEAD agents=2-->

- **Deposit share drift** — `Vault.deposit` · NEW — shares round down — not verified

<!--/F-->
"""

AUDITOR_FULL_REPORT = """# \U0001F510 Security Review — vault

---

## Findings

[95] **1. Withdraw can be re-entered**

`Vault.withdraw` · Confidence: 95 · seen in 2/2 runs

**Description**
An attacker re-enters withdraw and takes funds twice.

---

## Leads

- **Deposit share drift** — `Vault.deposit` · seen in 1/2 runs — shares round down
"""


def walk_json(value):
    """Every (key, value) pair in a parsed JSON document, depth first."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from walk_json(item)
    elif isinstance(value, list):
        for item in value:
            yield None, item
            yield from walk_json(item)


def assert_no_confidence(test, document):
    """Upstream confidence (95) and agent counts (8) must not be carried anywhere.

    Checked on parsed keys and values: a substring test over the file text failed whenever a
    timestamp, digest or temporary path happened to contain `95`.
    """
    pairs = list(walk_json(document))
    test.assertFalse({key for key, _ in pairs if isinstance(key, str)}
                     & {'conf', 'confidence', 'agents'})
    scalars = [value for _, value in pairs if not isinstance(value, (dict, list))]
    test.assertNotIn(95, scalars)
    test.assertNotIn(8, scalars)
    for value in scalars:
        if isinstance(value, str):
            test.assertNotRegex(value, r'(?i)\bconf(?:idence)?\s*[=:]|agents=')
            test.assertNotEqual(value.strip(), '95')


class SearchFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        (self.repo / 'src/Vault.sol').write_text(VAULT)
        (self.repo / 'src/Router.sol').write_text('contract Router {\n'
                                                  '  function withdraw() external {}\n}\n')
        commit(self.repo, 'fixture')
        self.run = self.base / 'run'
        bounty.initialize(self.repo, self.run)
        self.readings = self.base / 'readings'
        self.readings.mkdir()

    def reading(self, name, *lines, directory=None):
        path = (directory or self.readings) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        return path

    def converge(self, *specs, **kwargs):
        return bounty.converge([str(s) for s in specs] or [str(self.readings)], self.run,
                               **kwargs)

    def report(self):
        return bounty.read_json(self.run / 'convergence.json')

    def records(self):
        return bounty.read_json(self.run / 'findings.json')

    def write_records(self, rows):
        bounty.dump(self.run / 'findings.json', rows)

    def record(self, **fields):
        row = bounty.template()
        row.update(title='t', root_cause='r', bug_class='reentrancy', revision='abc',
                   attacker_capabilities='a', preconditions='p', impact='i',
                   next_experiment={'question': 'q', 'method': 'm', 'expected_evidence': 'e',
                                    'blocker': ''})
        row.update(fields)
        return row


class ConvergeKeyTests(SearchFixture):
    """The group key is file + function + bug class, and a record covers a group only on
    the same path, function and class."""

    def test_a_second_function_is_never_closed_by_the_first(self):
        # Keyed on file + class, reentrancy in deposit became saturated "closed ground" the
        # moment withdraw saturated.
        for name in ('a.md', 'b.md'):
            self.reading(name, f'CANDIDATE | lens: {name} | surface: src/Vault.sol:Vault.withdraw '
                               '| bug_class: reentrancy')
        self.reading('c.md', 'LEAD | surface: src/Vault.sol:Vault.deposit | bug_class: reentrancy')
        result = self.converge()
        self.assertEqual(result['saturated_groups'], 1)
        self.assertEqual(result['singletons'], 1)
        singleton = self.report()['singletons'][0]
        self.assertEqual(singleton['function'], 'deposit')
        self.assertNotIn('deposit', (self.run / 'saturated.md').read_text())

    def test_a_record_for_another_version_of_the_file_does_not_cover_the_group(self):
        (self.repo / 'src/v1').mkdir()
        (self.repo / 'src/v2').mkdir()
        for name in ('a.md', 'b.md'):
            self.reading(name, f'CANDIDATE | lens: x{name} | surface: src/v2/Vault.sol:Vault.withdraw '
                               '| bug_class: reentrancy')
        self.write_records([self.record(affected_paths=['src/v1/Vault.sol:Vault.withdraw'])])
        result = self.converge()
        self.assertEqual(len(result['saturated_unrecorded']), 1)
        # A whole-segment suffix is the same file: core/Vault.sol is src/v2/Vault.sol's tail.
        self.write_records([self.record(affected_paths=['v2/Vault.sol:Vault.withdraw'])])
        self.assertEqual(self.converge()['saturated_unrecorded'], [])
        # ...but a record naming another function does not carry this one.
        self.write_records([self.record(affected_paths=['./src/v2/Vault.sol:Vault.deposit'])])
        self.assertEqual(len(self.converge()['saturated_unrecorded']), 1)
        # A record naming only the file carries every function in it.
        self.write_records([self.record(affected_paths=['src/v2/Vault.sol'])])
        self.assertEqual(self.converge()['saturated_unrecorded'], [])

    def test_generic_surfaces_are_reports_and_whole_templates_are_examples(self):
        self.reading('a.md', 'CANDIDATE | lens: seam | surface: src/Pool.move:Pool<T>::swap | '
                             'bug_class: unchecked-coin-type',
                     'CANDIDATE | lens: <lens-name> | surface: <path:Contract.function> | '
                     'bug_class: <kebab-case>',
                     'LEAD | lens: seam | surface: path:program::instruction | bug_class: x-y',
                     'LEAD | surface: <path>:<Contract>.<function> | bug_class: real-class')
        result = self.converge()
        self.assertEqual(result['blocks_parsed'], 1)
        self.assertEqual(result['blocks_skipped'], 3)
        group = self.report()['groups'][0]
        self.assertEqual(group['function'], 'swap')
        self.assertEqual(group['surfaces'], ['src/Pool.move:Pool::swap'])

    def test_numbered_headers_are_parsed_and_near_misses_are_reported(self):
        self.reading('a.md', '1. CANDIDATE | surface: src/Vault.sol:Vault.withdraw | '
                             'bug_class: reentrancy',
                     '2) LEAD | surface: src/Vault.sol:Vault.deposit | bug_class: rounding',
                     '3. **CANDIDATE** | surface: src/Router.sol:Router.withdraw | '
                     'bug_class: reentrancy',
                     '| LEAD | surface: src/Vault.sol | bug_class: in-a-table |')
        result = self.converge()
        self.assertEqual(result['blocks_parsed'], 3)
        skipped = self.report()['skipped_blocks']
        self.assertEqual(len(skipped), 1)
        self.assertIn('not at the start of its line', skipped[0]['reason'])

    def test_block_bodies_do_not_leak_into_the_next_header(self):
        self.reading('a.md',
                     'CANDIDATE | lens: accounting | surface: src/Vault.sol:Vault.withdraw | '
                     'bug_class: reentrancy',
                     'capability: any EOA',
                     'next_experiment:',
                     '  question: can withdraw be re-entered?',
                     '  method: forge test --match-test testReenter',
                     '',
                     'LEAD | surface: src/Vault.sol:Vault.deposit | bug_class: rounding')
        parsed = bounty._parse_reading((self.readings / 'a.md').read_text(), 'a.md')
        self.assertEqual(len(parsed['blocks']), 2)
        fields = parsed['blocks'][0]['fields']
        self.assertEqual(fields['capability'], 'any EOA')
        self.assertEqual(fields['question'], 'can withdraw be re-entered?')
        self.assertEqual(parsed['blocks'][1]['fields'], {})


class ReadingsLedgerTests(SearchFixture):
    """Each converge used to rewrite saturated.md from scratch: pass 2 erased pass 1, and a
    mechanism seen once per pass never saturated."""

    def test_a_mechanism_seen_once_per_pass_saturates_across_calls(self):
        pass1, pass2 = self.base / 'pass1', self.base / 'pass2'
        self.reading('accounting.md', 'CANDIDATE | lens: accounting | surface: '
                     'src/Vault.sol:Vault.withdraw | bug_class: reentrancy', directory=pass1)
        first = self.converge(pass1)
        self.assertEqual((first['readings_parsed'], first['saturated_groups']), (1, 0))
        self.reading('seam.md', 'LEAD | lens: seam | surface: src/Vault.sol:Vault.withdraw | '
                     'bug_class: reentrancy', directory=pass2)
        second = self.converge(pass2)
        self.assertEqual(second['readings_parsed'], 2)
        self.assertEqual(second['this_call']['new'], 1)
        self.assertEqual(second['saturated_groups'], 1)
        self.assertIn('reported by 2 readings', (self.run / 'saturated.md').read_text())
        # Both readings stay visible to the dispatch gate after the second call.
        self.assertEqual(len(self.report()['readings']), 2)
        ledger = bounty.read_json(self.run / bounty.READINGS_LEDGER)
        self.assertEqual(len(ledger['readings']), 2)
        self.assertTrue(all(len(entry['sha256']) == 64 for entry in ledger['readings'].values()))

    def test_a_changed_reading_replaces_its_own_blocks(self):
        path = self.reading('a.md', 'CANDIDATE | surface: src/Vault.sol:Vault.withdraw | '
                                    'bug_class: reentrancy')
        self.reading('b.md', 'CANDIDATE | lens: seam | surface: src/Vault.sol:Vault.withdraw | '
                             'bug_class: reentrancy')
        self.assertEqual(self.converge()['saturated_groups'], 1)
        path.write_text('LEAD | surface: src/Vault.sol:Vault.deposit | bug_class: rounding\n')
        result = self.converge()
        self.assertEqual(result['this_call'], {'new': 0, 'changed': 1, 'unchanged': 1,
                                               'duplicate_content': [], 'derived_reports': []})
        self.assertEqual(result['readings_parsed'], 2)
        self.assertEqual(result['blocks_parsed'], 2)
        self.assertEqual(result['saturated_groups'], 0)

    def test_a_copied_reading_is_one_reading_and_reset_starts_over(self):
        body = 'CANDIDATE | surface: src/Vault.sol:Vault.withdraw | bug_class: reentrancy'
        self.reading('a.md', body)
        self.converge()
        copy = self.base / 'copy'
        self.reading('a.md', body, directory=copy)
        result = self.converge(copy)
        self.assertEqual(result['readings_parsed'], 1)
        self.assertEqual(result['saturated_groups'], 0)
        self.assertEqual(len(result['this_call']['duplicate_content']), 1)
        result = self.converge(copy, reset=True)
        self.assertEqual(result['readings_parsed'], 1)
        self.assertEqual(self.report()['readings'], [str((copy / 'a.md').resolve())])
        self.assertTrue(any('--reset' in note for note in result['notes']))

    def test_a_ledger_from_another_run_is_not_counted(self):
        self.reading('a.md', 'CANDIDATE | surface: src/Vault.sol:Vault.withdraw | '
                             'bug_class: reentrancy')
        self.converge()
        ledger = bounty.read_json(self.run / bounty.READINGS_LEDGER)
        ledger['run_id'] = 'f' * 32
        ledger['readings']['/elsewhere/b.md'] = dict(next(iter(ledger['readings'].values())),
                                                     sha256='0' * 64)
        bounty.dump(self.run / bounty.READINGS_LEDGER, ledger)
        result = self.converge()
        self.assertEqual(result['readings_parsed'], 1)
        self.assertTrue(any('different run' in note for note in result['notes']))

    def test_cli_wires_reset(self):
        self.reading('a.md', 'CANDIDATE | surface: src/Vault.sol | bug_class: x-y')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = bounty.main(['converge', '--readings', str(self.readings), '--run',
                                str(self.run), '--reset'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())['readings_parsed'], 1)


class ExaminedTests(SearchFixture):
    """Readings end with EXAMINED / NOT-REACHED lines; function-coverage and coverage-floor
    credit functions from examined.json, so its name and keys are a contract."""

    def test_coverage_lines_accumulate_into_examined_json(self):
        self.reading('a.md', 'EXAMINED | src/Vault.sol:Vault.withdraw',
                     '- EXAMINED | src/Vault.sol:Vault.deposit',
                     '2. NOT-REACHED | src/Router.sol:Router.withdraw | why: needs a fork',
                     '**EXAMINED** | <path:Contract.function>',
                     'NOT-REACHED | path:Contract.function | why: <reason>')
        self.reading('b.md', '1) EXAMINED | core/Vault.sol:Vault.withdraw',
                     'NOT-REACHED | src/Router.sol:Router.withdraw | why: no RPC')
        result = self.converge()
        self.assertEqual((result['examined_surfaces'], result['not_reached_surfaces']), (3, 1))
        data = bounty.read_json(self.run / bounty.EXAMINED_FILE)
        self.assertEqual(data['version'], 1)
        withdraw = next(row for row in data['examined']
                        if row['surface'] == 'src/Vault.sol:Vault.withdraw')
        # No tracked file ends in `core/Vault.sol`, so that surface stays as reported and the
        # src/ spelling is a different surface, seen by one reading.
        self.assertEqual(len(withdraw['sources']), 1)
        self.assertEqual(set(withdraw), {'surface', 'sources'})
        unreached = data['not_reached'][0]
        self.assertEqual(set(unreached), {'surface', 'why', 'sources'})
        self.assertEqual(unreached['why'], 'needs a fork / no RPC')
        self.assertEqual(len(unreached['sources']), 2)
        skipped = [row['reason'] for row in self.report()['skipped_blocks']]
        self.assertEqual(skipped.count('format example, not a reported surface'), 2)

    def test_a_tracked_suffix_is_put_on_its_full_path(self):
        self.reading('a.md', 'EXAMINED | src/Vault.sol:Vault.withdraw')
        self.reading('b.md', 'EXAMINED | Vault.sol:Vault.withdraw')
        self.converge()
        data = bounty.read_json(self.run / bounty.EXAMINED_FILE)
        self.assertEqual([row['surface'] for row in data['examined']],
                         ['src/Vault.sol:Vault.withdraw'])
        self.assertEqual(len(data['examined'][0]['sources']), 2)

    def test_a_changed_reading_replaces_its_lines_and_reset_clears(self):
        path = self.reading('a.md', 'EXAMINED | src/Vault.sol:Vault.withdraw')
        self.converge()
        path.write_text('EXAMINED | src/Vault.sol:Vault.deposit\n')
        self.converge()
        data = bounty.read_json(self.run / bounty.EXAMINED_FILE)
        self.assertEqual([row['surface'] for row in data['examined']],
                         ['src/Vault.sol:Vault.deposit'])
        other = self.base / 'other'
        self.reading('z.md', 'LEAD | surface: src/Vault.sol | bug_class: x-y', directory=other)
        self.converge(other, reset=True)
        self.assertEqual(bounty.read_json(self.run / bounty.EXAMINED_FILE)['examined'], [])


class SolidityAuditorConvergeTests(SearchFixture):
    """solidity-auditor blocks carry no surface; they used to collapse to `(no surface)`,
    merging different contracts, and its run files parsed to zero blocks silently."""

    def test_raw_blocks_group_by_contract_and_resolve_to_the_declaring_file(self):
        self.reading('auditor.md', AUDITOR_RAW)
        self.reading('bp.md', 'CANDIDATE | lens: external-call | surface: '
                              'src/Vault.sol:Vault.withdraw | bug_class: reentrancy')
        result = self.converge()
        self.assertEqual(result['blocks_parsed'], 3)
        self.assertEqual(result['distinct_groups'], 2)        # Vault and Router stay apart
        self.assertEqual(result['saturated_groups'], 1)       # Vault.withdraw: both tools
        group = self.report()['saturated'][0]
        self.assertEqual(group['surface_path'], 'src/Vault.sol')
        self.assertEqual(sorted(group['tools']), ['bounty-pilot', 'solidity-auditor'])

    def test_run_files_are_parsed_and_their_confidence_is_never_read(self):
        runs = self.base / '.solidity-auditor/runs/20261017-101010'
        self.reading('run-1.md', AUDITOR_RUN_FILE.format(k=1, kind='LEAD'), directory=runs)
        self.reading('run-2.md', AUDITOR_RUN_FILE.format(k=2, kind='FINDING'), directory=runs)
        self.reading('full-report.md', AUDITOR_FULL_REPORT, directory=runs)
        result = self.converge(runs)
        self.assertEqual(result['readings_parsed'], 2)        # the assembled report is derived
        self.assertEqual(len(result['this_call']['derived_reports']), 1)
        self.assertEqual(result['blocks_parsed'], 4)
        self.assertEqual(result['saturated_groups'], 2)
        withdraw = next(g for g in self.report()['groups'] if g['function'] == 'withdraw')
        self.assertEqual((withdraw['claims'], withdraw['leads']), (1, 1))
        self.assertEqual(withdraw['surfaces'], ['src/Vault.sol:Vault.withdraw'])
        assert_no_confidence(self, bounty.read_json(self.run / bounty.READINGS_LEDGER))

    def test_an_unclosed_marker_is_reported(self):
        self.reading('run-1.md', '<!--F key=vault|withdraw|reentrancy kind=FINDING-->',
                     '[90] **Title**')
        result = self.converge()
        self.assertEqual(result['blocks_parsed'], 0)
        self.assertIn('no <!--/F--> close marker', self.report()['skipped_blocks'][0]['reason'])


class QueueSingletonTests(SearchFixture):
    def test_unrecorded_singletons_surface_in_queue(self):
        self.assertFalse(bounty.lead_queue(self.run)['unrecorded_singletons']['converged'])
        self.reading('a.md', 'LEAD | surface: src/Vault.sol:Vault.deposit | bug_class: rounding',
                     'LEAD | surface: src/Router.sol:Router.withdraw | bug_class: reentrancy')
        self.converge()
        report = bounty.lead_queue(self.run)['unrecorded_singletons']
        self.assertEqual(report['count'], 2)
        self.assertEqual({row['bug_class'] for row in report['shown']},
                         {'rounding', 'reentrancy'})
        self.write_records([self.record(bug_class='rounding',
                                        affected_paths=['src/Vault.sol:Vault.deposit'])])
        report = bounty.lead_queue(self.run)['unrecorded_singletons']
        self.assertEqual(report['count'], 1)
        self.assertEqual(report['shown'][0]['surface'], 'src/Router.sol:Router.withdraw')


class ImportFindingsTests(SearchFixture):
    def import_(self, *sources, **kwargs):
        return bounty.import_findings(self.run, [str(s) for s in sources], **kwargs)

    def test_raw_auditor_blocks_become_untriaged_hypotheses(self):
        source = self.reading('auditor.md', AUDITOR_RAW)
        result = self.import_(source, repo=self.repo)
        self.assertEqual((result['imported'], result['skipped_duplicate'], result['unparsed']),
                         (2, 0, 0))
        vault, router = self.records()
        self.assertEqual(vault['id'], 'BP-001')
        self.assertEqual(vault['status'], 'hypothesis')
        self.assertEqual(vault['severity'], 'unassessed')
        self.assertEqual(vault['bug_class'], 'reentrancy')
        self.assertEqual(vault['affected_paths'], ['src/Vault.sol:Vault.withdraw'])
        self.assertEqual(vault['evidence'], {})
        self.assertEqual(vault['origin']['tool'], 'solidity-auditor')
        self.assertEqual(vault['origin']['key'], 'vault|withdraw|reentrancy')
        self.assertEqual(vault['origin']['upstream_kind'], 'FINDING')
        self.assertEqual(vault['origin']['triage'], 'untriaged')
        self.assertEqual(vault['origin']['path_resolution'], 'resolved-from-contract')
        self.assertIn('takes funds twice', vault['root_cause'])
        self.assertIn('reproduce the reported proof', vault['next_experiment']['method'])
        self.assertEqual(vault['preconditions'], bounty.IMPORT_UNSTATED)
        self.assertEqual(router['origin']['upstream_kind'], 'LEAD')
        self.assertEqual(router['affected_paths'], ['src/Router.sol:Router.withdraw'])
        # Structurally valid, so queue still works and lists both as needing triage.
        self.assertEqual(bounty.validate(self.run, ledger=False), [])
        queue = bounty.lead_queue(self.run)
        self.assertEqual(queue['imported_untriaged']['count'], 2)
        self.assertEqual(queue['open_count'], 2)
        vault['origin']['triage'] = 'triaged'
        self.write_records([vault, router])
        self.assertEqual([row['id'] for row in
                          bounty.lead_queue(self.run)['imported_untriaged']['records']],
                         ['BP-002'])

    def test_without_a_checkout_the_path_is_unresolved_and_says_so(self):
        result = self.import_(self.reading('auditor.md', AUDITOR_RAW))
        self.assertEqual(result['path_resolution'], {'unresolved': 2})
        row = self.records()[0]
        self.assertEqual(row['affected_paths'], ['Vault.withdraw'])
        self.assertIn('path unresolved', row['origin']['path_note'])

    def test_import_is_idempotent_and_respects_hand_written_records(self):
        source = self.reading('auditor.md', AUDITOR_RAW)
        self.write_records([self.record(affected_paths=['src/Router.sol:Router.withdraw'])])
        first = self.import_(source, repo=self.repo)
        self.assertEqual((first['imported'], first['skipped_duplicate']), (1, 1))
        self.assertEqual(first['duplicates'][0]['record'], 'BP-001')
        self.assertEqual(self.records()[1]['id'], 'BP-002')
        second = self.import_(source, repo=self.repo)
        self.assertEqual((second['imported'], second['skipped_duplicate']), (0, 2))
        self.assertEqual(len(self.records()), 2)

    def test_run_files_import_the_strongest_kind_and_carry_no_confidence(self):
        runs = self.base / '.solidity-auditor/runs/20261017-101010'
        self.reading('run-1.md', AUDITOR_RUN_FILE.format(k=1, kind='LEAD'), directory=runs)
        self.reading('run-2.md', AUDITOR_RUN_FILE.format(k=2, kind='FINDING'), directory=runs)
        self.reading('full-report.md', AUDITOR_FULL_REPORT, directory=runs)
        result = self.import_(runs, repo=self.repo)
        self.assertEqual((result['imported'], result['unparsed']), (2, 0))
        self.assertEqual(result['report_lines_covered_by_run_files'], 2)
        withdraw = next(r for r in self.records() if r['origin']['key'].endswith('reentrancy'))
        self.assertEqual(withdraw['origin']['upstream_kind'], 'FINDING')
        self.assertEqual(withdraw['title'], 'Withdraw can be re-entered')
        self.assertEqual(withdraw['revision'], 'abc1234')
        self.assertTrue(withdraw['origin']['file'].endswith('run-2.md'))
        self.assertEqual(len(withdraw['origin']['also_in']), 1)
        deposit = next(r for r in self.records() if r['origin']['key'].endswith('drift'))
        self.assertEqual(deposit['title'], 'Deposit share drift')
        self.assertIn('shares round down', deposit['root_cause'])
        assert_no_confidence(self, self.records())

    def test_an_assembled_report_alone_is_unparsed_with_its_reason(self):
        result = self.import_(self.reading('full-report.md', AUDITOR_FULL_REPORT))
        self.assertEqual((result['imported'], result['unparsed']), (0, 2))
        self.assertIn('run-K.md', result['unparsed_blocks'][0]['reason'])
        self.assertEqual(self.records(), [])

    def test_bounty_pilot_blocks_keep_their_lens_and_experiment(self):
        source = self.reading('accounting.md',
                              'CANDIDATE | lens: accounting | surface: src/Vault.sol:Vault.deposit '
                              '| bug_class: aggregate-not-decremented',
                              'capability: any depositor',
                              'breaks: totalDebt no longer equals the sum of positions',
                              'next_experiment:',
                              '  question: does deposit skip the aggregate?',
                              '  method: forge test --match-test testDepositAggregate',
                              '  expected_evidence: totalDebt differs from the sum',
                              'LEAD | lens: liveness | surface: src/Vault.sol:Vault.pause',
                              'smell: pause has no guard')
        result = self.import_(source, source='bounty-pilot')
        self.assertEqual((result['imported'], result['unparsed']), (1, 1))
        self.assertIn('kebab-case label', result['unparsed_blocks'][0]['reason'])
        row = self.records()[0]
        self.assertEqual(row['lens'], 'accounting')
        self.assertEqual(row['attacker_capabilities'], 'any depositor')
        self.assertEqual(row['next_experiment']['method'],
                         'forge test --match-test testDepositAggregate')
        self.assertEqual(row['origin']['upstream_kind'], 'CANDIDATE')
        self.assertEqual(bounty.validate(self.run, ledger=False), [])

    def test_source_filter_and_ambiguous_contracts(self):
        (self.repo / 'src/v2').mkdir()
        (self.repo / 'src/v2/Vault.sol').write_text(VAULT)
        git(self.repo, 'add', '-A')
        source = self.reading('auditor.md', AUDITOR_RAW,
                              'CANDIDATE | surface: src/Router.sol:Router.withdraw | '
                              'bug_class: missing-auth')
        result = self.import_(source, repo=self.repo, source='solidity-auditor')
        self.assertEqual((result['imported'], result['unparsed']), (2, 1))
        vault = self.records()[0]
        self.assertEqual(vault['origin']['path_resolution'], 'ambiguous')
        self.assertEqual(sorted(vault['affected_paths']),
                         ['src/Vault.sol:Vault.withdraw', 'src/v2/Vault.sol:Vault.withdraw'])

    def test_cli_wires_import_findings(self):
        source = self.reading('auditor.md', AUDITOR_RAW)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = bounty.main(['import-findings', '--run', str(self.run), '--from', str(source),
                                '--repo', str(self.repo), '--source', 'solidity-auditor'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())['imported'], 2)
        with self.assertRaisesRegex(ValueError, 'not a file or a directory'):
            bounty.import_findings(self.run, [str(self.base / 'nowhere')])


class BundleInputTests(SearchFixture):
    def setUp(self):
        super().setUp()
        (self.repo / 'app/src').mkdir(parents=True)
        (self.repo / 'app/node_modules/lib').mkdir(parents=True)
        (self.repo / 'app/dist').mkdir()
        (self.repo / 'app/src/App.jsx').write_text('export const App = () => <div/>;\n')
        (self.repo / 'app/src/Swap.tsx').write_text('sendTransaction({ to: query.get("r") });\n')
        (self.repo / 'app/src/Page.vue').write_text('<template><div v-html="x"/></template>\n')
        (self.repo / 'app/index.html').write_text('<script src="main.js"></script>\n')
        (self.repo / 'app/node_modules/lib/index.js').write_text('module.exports = 1;\n')
        (self.repo / 'app/dist/bundle.min.js').write_text('var a=1;\n')
        (self.repo / 'app/src/App.test.jsx').write_text('test("x", () => {});\n')
        commit(self.repo, 'frontend')

    def test_web_frontend_is_a_lens_and_reads_the_web_sources(self):
        result = bounty.bundle(self.repo, self.run, ['web'])
        self.assertEqual([b['lens'] for b in result['bundles']], ['web-frontend'])
        text = (self.run / 'bundles/web-frontend-bundle.md').read_text()
        for name in ('app/src/App.jsx', 'app/src/Swap.tsx', 'app/src/Page.vue', 'app/index.html'):
            self.assertIn('### ' + name, text)
        for name in ('node_modules', 'bundle.min.js', 'App.test.jsx', '### src/Vault.sol'):
            self.assertNotIn(name, text)
        self.assertEqual(result['web_files_bundled_for_web_frontend'], 4)
        self.assertIn('Web frontend agent', text)
        # The contract lenses still get the contract source.
        bounty.bundle(self.repo, self.run, ['accounting'])
        self.assertIn('### src/Vault.sol', (self.run / 'bundles/accounting-bundle.md').read_text())

    def test_analysis_files_go_to_their_lenses_with_a_heuristic_header(self):
        bounty.dump(self.run / 'impact-paths.json', {'ranked': [{'sink': 'Vault.withdraw'}]})
        bounty.dump(self.run / 'odd-one-out.json', {'leads': [{'kind': 'guard-asymmetry'}]})
        bounty.dump(self.run / 'function-coverage.json',
                    {'schema': 1, 'entry_points': [{'id': f'f{n:05d}', 'path': 'src/Vault.sol'}
                                                   for n in range(3000)],
                     'unexamined': [f'src/Vault.sol:Vault.f{n:05d}' for n in range(3000)]})
        (self.run / 'coverage-priority.json').write_text('not json\n' * 12000)
        result = bounty.bundle(self.repo, self.run,
                               ['impact-first', 'classic', 'coverage-gap', 'liveness'])
        read = lambda lens: (self.run / f'bundles/{lens}-bundle.md').read_text()
        impact, classic, gap, liveness = (read(lens) for lens in
                                          ('impact-first', 'classic', 'coverage-gap', 'liveness'))
        self.assertIn('## Precomputed analysis: impact-paths.json', impact)
        self.assertIn('Heuristic, not evidence.', impact)
        self.assertNotIn('## Precomputed analysis: odd-one-out.json', impact)
        self.assertIn('## Precomputed analysis: odd-one-out.json', classic)
        self.assertIn('## Precomputed analysis: function-coverage.json', classic)
        self.assertNotIn('## Precomputed analysis: impact-paths.json', classic)
        self.assertIn('## Precomputed analysis: function-coverage.json', gap)
        self.assertNotIn('Precomputed analysis', liveness)
        self.assertEqual(result['analysis_included']['odd-one-out.json'], ['classic'])
        # The big JSON is cut list by list, and the bundle says exactly how much.
        self.assertRegex(classic, r'`entry_points` keeps the first \d+ of 3000 items')
        self.assertIn('"schema": 1', classic)
        # The big non-JSON file is cut by bytes, and says that too.
        self.assertRegex(impact, r'only the first \d+ of 108000 bytes are included')
        self.assertTrue(any('coverage-priority.json was cut' in n for n in result['notes']))
        manifest = bounty.read_json(self.run / bounty.BUNDLE_MANIFEST)
        entries = {b['lens']: b for b in manifest['dispatches'][-1]['bundles']}
        coverage = next(item for item in entries['classic']['included_analysis']
                        if item['file'] == 'function-coverage.json')
        self.assertEqual(coverage['sha256'],
                         bounty._sha256_file(self.run / 'function-coverage.json'))
        self.assertLess(coverage['included_bytes'], coverage['bytes'])
        self.assertTrue(coverage['cut'])
        self.assertNotIn('included_analysis', entries['liveness'])

    def test_an_explicitly_included_analysis_file_is_not_added_twice(self):
        bounty.dump(self.run / 'impact-paths.json', {'ranked': []})
        result = bounty.bundle(self.repo, self.run, ['impact-first'],
                               includes=[str(self.run / 'impact-paths.json')])
        text = (self.run / 'bundles/impact-first-bundle.md').read_text()
        self.assertEqual(text.count('impact-paths.json'), 1)
        self.assertEqual(result['analysis_included'], {})


class LensRegistryTests(unittest.TestCase):
    def test_classic_and_web_frontend_are_registered(self):
        self.assertIn('classic', bounty.LENSES)
        self.assertIn('web-frontend', bounty.LENSES)
        self.assertEqual(bounty.ATTACK_LENSES[0], 'privileged-path')
        self.assertEqual(bounty.ATTACK_LENSES[-1], 'classic')
        self.assertEqual(bounty.WEB_LENSES, ('web-frontend',))
        for lens in bounty.LENSES:
            self.assertTrue((bounty.SKILL_ROOT / 'references/hunt-agents' / f'{lens}-agent.md')
                            .is_file(), lens)

    def test_the_high_impact_group_holds_the_value_lenses(self):
        for lens in ('accounting', 'external-call', 'integration-auth', 'impact-first'):
            self.assertIn(lens, bounty.HIGH_IMPACT_LENSES)


class RoutingTests(unittest.TestCase):
    def repo_with(self, files):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        repo = Path(temp.name)
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        for name, body in files.items():
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_text(body)
        subprocess.run(['git', '-C', str(repo), 'add', '-A'], check=True)
        return repo

    def test_a_bridge_with_a_rust_relayer_selects_integration_auth(self):
        repo = self.repo_with({'contracts/src/Bridge.sol': 'contract Bridge {}\n',
                               'relayer/Cargo.toml': '[package]\nname = "relayer"\n',
                               'relayer/src/main.rs': 'fn main() {}\n'})
        summary = stack_route.route(repo)
        self.assertTrue(summary['messaging_signals'])
        self.assertIn('integration-auth', summary['prioritization']['selected'])
        self.assertIn('integration-auth', stack_route.prioritize(summary, budget=1)['selected'])

    def test_a_messaging_dependency_is_a_signal_and_a_plain_vault_is_not(self):
        oft = self.repo_with({'contracts/Token.sol': 'contract Token {}\n',
                              'package.json': '{"dependencies":{"@layerzerolabs/oft-evm":"1"}}'})
        self.assertIn('integration-auth', stack_route.route(oft)['prioritization']['selected'])
        plain = self.repo_with({'contracts/Vault.sol': 'contract Vault {}\n',
                                'package.json': '{"devDependencies":{"hardhat":"2"}}'})
        self.assertEqual(stack_route.route(plain)['messaging_signals'], [])


class SourceCoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / 'repo'
        self.repo.mkdir()
        git(self.repo, 'init', '-q')
        self.run = Path(self.temp.name) / 'run'

    def test_every_tracked_stack_suffix_is_a_bundled_source_suffix(self):
        # A stack the bundle can never include is reported missing whatever --scope says.
        self.assertTrue(set(scope_coverage.EXT_STACK) <= bounty.SOURCE_SUFFIXES,
                        set(scope_coverage.EXT_STACK) - bounty.SOURCE_SUFFIXES)
        for suffix in ('.circom', '.nr', '.sw', '.tact', '.fc', '.func', '.jsx', '.mjs'):
            self.assertIn(suffix, bounty.SOURCE_SUFFIXES)
            self.assertIn(suffix, scope_coverage.EXT_STACK)

    def test_circuits_and_a_jsx_frontend_are_bundled_and_the_gate_passes(self):
        for name, body in (('contracts/Vault.sol', 'contract Vault {}\n'),
                           ('circuits/withdraw.circom', 'template Withdraw() {}\n'),
                           ('noir/src/main.nr', 'fn main() {}\n'),
                           ('ton/wallet.tact', 'contract Wallet {}\n'),
                           ('web/App.jsx', 'export default 1;\n'),
                           ('contracts/MockOracle.sol', 'contract MockOracle {}\n')):
            (self.repo / name).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / name).write_text(body)
        commit(self.repo, 'mixed')
        bounty.initialize(self.repo, self.run)
        result = bounty.bundle(self.repo, self.run, ['accounting'])
        source = (self.run / 'bundles/source.md').read_text()
        for name in ('circuits/withdraw.circom', 'noir/src/main.nr', 'ton/wallet.tact',
                     'web/App.jsx'):
            self.assertIn('### ' + name, source)
        audit = result['scope_audit']
        self.assertEqual(audit['missing_stacks'], [])
        self.assertTrue({'circom', 'noir', 'ton', 'js-ts', 'evm'} <= set(audit['stacks_detected']))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = bounty.main(['scope-audit', '--repo', str(self.repo), '--run', str(self.run),
                                '--gate'])
        self.assertEqual(code, 0, out.getvalue())


class DeltaGapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        (self.repo / 'src/A.sol').write_text('contract A { uint256 a; }\n')
        (self.repo / 'foundry.toml').write_text('[profile.default]\n')
        (self.repo / 'remappings.txt').write_text('dep/=lib/dep/src/\n')
        self.dep = self.repo / 'lib/dep'
        (self.dep / 'src').mkdir(parents=True)
        git(self.dep, 'init', '-q')
        (self.dep / 'src/Guard.sol').write_text(
            'contract Guard {\n  function f(address a) external { require(a != address(0)); }\n}\n')
        commit(self.dep, 'v1')
        self.v1 = head(self.dep)
        commit(self.repo, 'audited')
        self.audited = head(self.repo)

    def change(self):
        (self.dep / 'src/Guard.sol').write_text(
            'contract Guard {\n  function f(address a) external { }\n}\n')
        commit(self.dep, 'v2 drops the check')
        self.v2 = head(self.dep)
        (self.repo / 'remappings.txt').write_text('dep/=lib/dep/contracts/\n')
        (self.repo / 'deployments').mkdir()
        (self.repo / 'deployments/mainnet.json').write_text('{"cap": 1000}\n')
        (self.repo / 'pkg').mkdir()
        (self.repo / 'pkg/package.json').write_text('{"name": "nested"}\n')
        (self.repo / 'src/B.sol').write_text('contract B { uint256 b; }\n')
        commit(self.repo, 'post-audit')

    def test_a_submodule_bump_and_config_changes_are_ranked(self):
        self.change()
        report = bounty.delta(self.repo, self.audited, ['src/'])
        kinds = {row['path']: row['kind'] for row in report['ranked']}
        self.assertEqual(kinds['lib/dep'], 'submodule')
        self.assertEqual(kinds['remappings.txt'], 'config')
        self.assertEqual(kinds['src/B.sol'], 'source')
        # Root configuration governs the build whatever --scope says; a nested package does not.
        self.assertNotIn('pkg/package.json', kinds)
        self.assertNotIn('deployments/mainnet.json', kinds)
        self.assertIn('deployments/mainnet.json',
                      {row['path'] for row in bounty.delta(self.repo, self.audited)['ranked']})
        submodule = report['ranked'][0]
        self.assertEqual(submodule['path'], 'lib/dep')
        self.assertEqual((submodule['old_commit'], submodule['new_commit']), (self.v1, self.v2))
        self.assertEqual(submodule['change'], 'bumped')
        self.assertEqual(submodule['dependency_diff']['state'], 'available')
        self.assertEqual(submodule['dependency_diff']['top_changed'][0]['path'], 'src/Guard.sol')
        self.assertEqual((report['changed_submodules'], report['changed_source_files']), (1, 1))

    def test_the_cap_is_reported_never_silent(self):
        self.change()
        full = bounty.delta(self.repo, self.audited)
        capped = bounty.delta(self.repo, self.audited, limit=2)
        self.assertFalse(full['truncated'])
        self.assertEqual(full['omitted'], [])
        self.assertEqual(capped['total_changed'], full['total_changed'])
        self.assertTrue(capped['truncated'])
        self.assertEqual(len(capped['ranked']), 2)
        self.assertEqual(capped['omitted'], [row['path'] for row in full['ranked'][2:]])

    def test_config_churn_does_not_count_as_source_churn(self):
        self.change()
        (self.repo / 'deployments/mainnet.json').write_text(
            json.dumps({'abi': ['x'] * 5000}, indent=1))
        commit(self.repo, 'redeploy')
        program = self.base / 'program.json'
        program.write_text(json.dumps({'program': 'P', 'audited_revision': self.audited}))
        scored = bounty.score_target(self.repo, program)
        # One added line in src/B.sol over two in-scope lines; the 5000-line JSON is not source.
        self.assertEqual(scored['churn_share_since_audit'], 0.5)


ROUTER = ('contract Router {\n'
          '  function swap(address token, uint256 amount, address target, bytes calldata data)\n'
          '      external {\n'
          '    IERC20(token).transferFrom(msg.sender, address(this), amount);\n'
          '    (bool ok,) = target.call(data);\n'
          '    require(ok);\n  }\n}\n')


class ApprovalExposureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def score(self, source, **facts):
        repo = self.base / ('repo-' + str(len(list(self.base.iterdir()))))
        (repo / 'src').mkdir(parents=True)
        git(repo, 'init', '-q')
        (repo / 'src/Main.sol').write_text(source)
        commit(repo, 'fixture')
        program = repo.parent / (repo.name + '.json')
        program.write_text(json.dumps(dict({'program': 'P', 'in_scope_paths': ['src/']}, **facts)))
        return bounty.score_target(repo, program)

    def test_a_router_with_unmeasured_approvals_is_an_unknown_not_a_ceiling(self):
        result = self.score(ROUTER, value_at_rest_usd=1000)
        self.assertEqual(result['severity_ceiling'], [])
        self.assertEqual(result['router_signals'], ['src/Main.sol'])
        self.assertTrue(any('approval_exposure_usd' in u for u in result['unknowns']),
                        result['unknowns'])
        self.assertFalse(any('forced to deprioritise' in r for r in result['reasons']))

    def test_measured_low_approvals_still_force_the_ceiling(self):
        result = self.score(ROUTER, value_at_rest_usd=1000, approval_exposure_usd=50_000,
                            approval_exposure_source='approvals query 2026-10-01')
        self.assertEqual(result['band'], 'deprioritise')
        self.assertTrue(any('forced to deprioritise' in r for r in result['reasons']))
        self.assertTrue(any('50,000 USD in standing approvals' in c
                            for c in result['severity_ceiling']))

    def test_large_approvals_lift_the_ceiling_and_cite_their_source(self):
        result = self.score(ROUTER, value_at_rest_usd=1000, approval_exposure_usd=20_000_000,
                            approval_exposure_source='dune approvals query')
        self.assertEqual(result['severity_ceiling'], [])
        self.assertEqual(result['approval_exposure_usd'], 20_000_000)
        self.assertTrue(any('source: dune approvals query' in r for r in result['reasons']))
        unsourced = self.score(ROUTER, value_at_rest_usd=1000, approval_exposure_usd=20_000_000)
        self.assertTrue(any('approval_exposure_source not stated' in u
                            for u in unsourced['unknowns']))

    def test_a_plain_vault_with_little_at_rest_is_still_deprioritised(self):
        result = self.score(VAULT, value_at_rest_usd=1000)
        self.assertEqual(result['router_signals'], [])
        self.assertEqual(result['band'], 'deprioritise')
        self.assertTrue(any('forced to deprioritise' in r for r in result['reasons']))


if __name__ == '__main__':
    unittest.main()
