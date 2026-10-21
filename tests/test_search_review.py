"""Review of the 0.19 search plumbing. Each test names what the release still hid, merged or
dropped: a header variant read as nothing, a format example read as coverage, a bundle that told
agents not to write the lines that credit coverage, a write-up chosen by a plain sort, a copy
counted as a second reading."""
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
stack_route = load('bp_stack_route_review', 'skills/bounty-pilot/scripts/stack_route.py')


def git(repo, *args):
    subprocess.run(['git', '-C', str(repo), *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def commit(repo, message):
    git(repo, 'add', '-A')
    git(repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
        '-c', 'commit.gpgsign=false', 'commit', '-qm', message)


def head(repo):
    return subprocess.run(['git', '-C', str(repo), 'rev-parse', 'HEAD'], check=True,
                          stdout=subprocess.PIPE).stdout.decode().strip()


VAULT = ('contract Vault {\n  uint256 totalDebt;\n'
         '  function withdraw(uint256 a) external { totalDebt -= a; }\n'
         '  function deposit(uint256 a) external { totalDebt += a; }\n}\n')

RUN_FILE = """# Run {k} — solidity-auditor

<!--RUN pass={k} of={n} stamp={stamp} sha=sha{k} agents=12/12-->

Pass {k} of {n} · 2026-10-17 · `sha{k}` · 12/12 agents returned.

## Findings

<!--F key=vault|withdraw|reentrancy conf=90 kind=FINDING agents=3-->

[90] **Title from pass {k}**

`Vault.withdraw` · Confidence: 90

**Description**
Description from pass {k}.

<!--/F-->

## Leads
"""

RAW = """FINDING | contract: Vault | function: withdraw | bug_class: reentrancy | group_key: Vault | withdraw | reentrancy
proof: re-enter before totalDebt is written
description: An attacker re-enters withdraw.

LEAD | contract: Vault | function: deposit | bug_class: only-raw | group_key: Vault | deposit | only-raw
code_smells: a smell the gate dropped
"""


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        git(self.repo, 'init', '-q')
        (self.repo / 'src/Vault.sol').write_text(VAULT)
        (self.repo / 'src/Router.sol').write_text('contract Router {\n'
                                                  '  function swap() external {}\n}\n')
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

    def parse(self, *lines):
        return bounty._parse_reading('\n'.join(lines) + '\n', 'reading.md')


class HeaderVariantTests(Fixture):
    """Seven common spellings of a header were neither parsed nor listed as skipped."""

    def test_numbered_emphasised_dashed_and_lower_case_headers_parse(self):
        parsed = self.parse(
            '**FINDING 1** | contract: Vault | function: withdraw | bug_class: a-one',
            'FINDING #2 | contract: Vault | function: deposit | bug_class: a-two',
            'Finding | contract: Vault | function: deposit | bug_class: a-three',
            '### CANDIDATE 3 | lens: classic | surface: src/A.sol:A.f | bug_class: a-four',
            'CANDIDATE — lens: classic | surface: src/A.sol:A.g | bug_class: a-five',
            'FINDING (6) | contract: Vault | function: withdraw | bug_class: a-six',
            'lead | surface: src/A.sol:A.h | bug_class: a-seven')
        self.assertEqual([b['bug_class'] for b in parsed['blocks']],
                         ['a-one', 'a-two', 'a-three', 'a-four', 'a-five', 'a-six', 'a-seven'])
        self.assertEqual([b['word'] for b in parsed['blocks']][-1], 'LEAD')
        self.assertEqual(parsed['skipped'], [])

    def test_coverage_line_variants_parse(self):
        parsed = self.parse('Examined | src/A.sol:A.j', 'EXAMINED: src/A.sol:A.k',
                            '- examined: `Vault.withdraw`', 'Not reached | src/A.sol:A.m | why: x')
        self.assertEqual([e['surface'] for e in parsed['examined']],
                         ['src/A.sol:A.j', 'src/A.sol:A.k', 'Vault.withdraw'])
        self.assertEqual(parsed['not_reached'], [{'surface': 'src/A.sol:A.m', 'why': 'x'}])

    def test_prose_and_summary_tables_are_not_headers_or_noise(self):
        parsed = self.parse('Finding | Severity | Status', 'Finding: the vault is fine | ok',
                            'Examined: everything.', 'Lead time is two weeks.')
        self.assertEqual((parsed['blocks'], parsed['examined'], parsed['skipped']), ([], [], []))

    def test_what_still_looks_like_a_header_is_listed_as_skipped(self):
        parsed = self.parse('| CANDIDATE | lens: x | surface: src/A.sol:A.z | bug_class: t |',
                            'FINDING [1] | contract: Vault | function: f | bug_class: q',
                            'See finding 2 | surface: src/A.sol:A.q | bug_class: q-q')
        self.assertEqual(parsed['blocks'], [])
        self.assertEqual(len(parsed['skipped']), 3)
        self.assertIn('not at the start', parsed['skipped'][0]['reason'])
        self.assertIn('fields could not be read', parsed['skipped'][1]['reason'])

    def test_a_missing_bug_class_is_read_from_group_key(self):
        parsed = self.parse('LEAD | contract: Vault | function: withdraw | '
                            'group_key: Vault | withdraw | from-group-key')
        self.assertEqual(parsed['blocks'][0]['bug_class'], 'from-group-key')


class FormatExampleTests(Fixture):
    def test_the_shared_rules_file_contributes_nothing(self):
        for name in ('hunt-agents/_shared.md', 'hunt-agents/classic-agent.md'):
            text = (bounty.SKILL_ROOT / 'references' / name).read_text(encoding='utf-8')
            parsed = bounty._parse_reading(text, name)
            self.assertEqual((parsed['blocks'], parsed['examined'], parsed['not_reached']),
                             ([], [], []), name)

    def test_documented_spellings_are_placeholders_and_real_names_are_not(self):
        for value in ('path:Contract.otherFunction', 'Contract.anything', 'src/A.sol:Contract.f',
                      'path:Vault.withdraw', 'ContractName.functionName'):
            self.assertTrue(bounty._is_placeholder_value(value), value)
        for value in ('src/IContract.sol:IContract.f', 'MyContract.withdraw',
                      'src/Pool.sol:Pool<T>::swap', 'src/path/Vault.sol:Vault.f'):
            self.assertFalse(bounty._is_placeholder_value(value), value)

    def test_an_echoed_format_block_never_reaches_examined_json(self):
        self.reading('a.md', '```', 'EXAMINED | path:Contract.function',
                     'EXAMINED | path:Contract.otherFunction', '```',
                     'EXAMINED | src/Vault.sol:Vault.withdraw')
        self.converge()
        data = bounty.read_json(self.run / bounty.EXAMINED_FILE)
        self.assertEqual([row['surface'] for row in data['examined']],
                         ['src/Vault.sol:Vault.withdraw'])


class CoverageLineTests(Fixture):
    def test_every_surface_of_a_comma_list_is_credited(self):
        self.reading('a.md', 'EXAMINED | src/Vault.sol:Vault.withdraw, src/Vault.sol:Vault.deposit;'
                             ' Router.swap(uint256,address)')
        self.converge()
        surfaces = [row['surface'] for row in
                    bounty.read_json(self.run / bounty.EXAMINED_FILE)['examined']]
        self.assertEqual(sorted(surfaces), ['Router.swap(uint256,address)',
                                            'src/Vault.sol:Vault.deposit',
                                            'src/Vault.sol:Vault.withdraw'])

    def test_why_keeps_everything_after_it_bars_included(self):
        parsed = self.parse('NOT-REACHED | src/A.sol:A.f | why: needs | a fork at block 1 | or RPC',
                            'NOT-REACHED: src/A.sol:A.g why: budget')
        self.assertEqual([row['why'] for row in parsed['not_reached']],
                         ['needs | a fork at block 1 | or RPC', 'budget'])
        self.assertEqual(parsed['not_reached'][1]['surface'], 'src/A.sol:A.g')


class BundleInstructionTests(Fixture):
    def test_header_and_footer_ask_for_the_coverage_lines(self):
        bounty.bundle(self.repo, self.run, ['liveness'])
        text = (self.run / 'bundles/liveness-bundle.md').read_text()
        self.assertNotIn('Return only CANDIDATE and LEAD', text)
        self.assertNotIn('Emit CANDIDATE and LEAD blocks only', text)
        footer = text.rsplit('# Your task, restated', 1)[1]
        self.assertIn('`EXAMINED |`', footer)
        self.assertIn('`NOT-REACHED |`', footer)
        # The instruction itself is never read back as a coverage line.
        parsed = bounty._parse_reading(text, 'bundle.md')
        self.assertEqual(parsed['examined'], [])


class ClassicRecordsTests(Fixture):
    def test_classic_is_told_who_owns_part_b(self):
        result = bounty.bundle(self.repo, self.run, ['classic'])
        text = (self.run / 'bundles/classic-bundle.md').read_text()
        self.assertIn('## Records already in this run', text)
        self.assertIn('Part B - the classic sweep - is yours', text)
        self.assertEqual(result['bundles'][0]['records_included']['records'], 0)

    def test_classic_receives_the_imported_records_untriaged_first(self):
        runs = self.base / '.solidity-auditor/runs/20261017-101010'
        self.reading('run-1.md', RUN_FILE.format(k=1, n=1, stamp='20261017-101010'),
                     directory=runs)
        bounty.import_findings(self.run, [str(runs)], repo=self.repo)
        records = self.records()
        records.append(dict(records[0], id='BP-002', bug_class='hand-written', origin=None))
        bounty.dump(self.run / 'findings.json', records)
        result = bounty.bundle(self.repo, self.run, ['classic', 'liveness'])
        classic = (self.run / 'bundles/classic-bundle.md').read_text()
        self.assertIn("solidity-auditor's sweep is imported into this run: 1 record(s), "
                      '1 not yet triaged', classic)
        listed = json.loads(classic.split('## Records already in this run', 1)[1]
                            .split('```json\n', 1)[1].split('\n```', 1)[0])
        self.assertEqual([(row['id'], row['tool'], row['triage']) for row in listed],
                         [('BP-001', 'solidity-auditor', 'untriaged'),
                          ('BP-002', 'bounty-pilot', '')])
        info = next(b for b in result['bundles'] if b['lens'] == 'classic')['records_included']
        self.assertEqual(info, {'records': 2, 'imported_from_solidity_auditor': 1,
                                'untriaged_imports': 1, 'included': 2})
        self.assertNotIn('Records already in this run',
                         (self.run / 'bundles/liveness-bundle.md').read_text())


class AnalysisRecipientTests(Fixture):
    def setUp(self):
        super().setUp()
        bounty.dump(self.run / 'impact-paths.json',
                    {'ranked': [{'sink': f'Vault.f{n}', 'pad': 'x' * 200} for n in range(150)]})
        bounty.dump(self.run / 'coverage-priority.json', {'ranked': ['a'] * 50})
        bounty.dump(self.run / 'state-graph.json', {'symbols': ['s'] * 50})
        bounty.dump(self.run / 'odd-one-out.json', {'leads': [{'kind': 'guard-asymmetry'}]})
        bounty.dump(self.run / 'function-coverage.json', {'unexamined': ['Vault.withdraw']})

    def included(self, result, lens):
        entry = next(b for b in result['bundles'] if b['lens'] == lens)
        return sorted(item['file'] for item in entry.get('included_analysis', []))

    def test_attack_lenses_stay_near_their_own_size(self):
        result = bounty.bundle(self.repo, self.run, ['attack', 'impact-first', 'seam',
                                                     'coverage-gap'])
        self.assertEqual(self.included(result, 'privileged-path'), ['odd-one-out.json'])
        self.assertEqual(self.included(result, 'accounting'), ['odd-one-out.json'])
        self.assertEqual(self.included(result, 'external-call'), [])
        self.assertEqual(self.included(result, 'classic'),
                         ['function-coverage.json', 'odd-one-out.json'])
        self.assertEqual(self.included(result, 'impact-first'),
                         ['coverage-priority.json', 'impact-paths.json', 'state-graph.json'])
        self.assertEqual(self.included(result, 'seam'),
                         ['coverage-priority.json', 'function-coverage.json',
                          'impact-paths.json', 'odd-one-out.json', 'state-graph.json'])
        self.assertEqual(self.included(result, 'coverage-gap'), ['function-coverage.json'])
        sizes = {b['lens']: b['bytes'] for b in result['bundles']}
        self.assertLess(sizes['privileged-path'], sizes['impact-first'] - 20_000)

    def test_the_high_impact_group_hands_its_lenses_the_value_paths(self):
        result = bounty.bundle(self.repo, self.run, ['high-impact'])
        for lens in bounty.HIGH_IMPACT_LENSES:
            self.assertIn('impact-paths.json', self.included(result, lens), lens)
        self.assertNotIn('state-graph.json', self.included(result, 'privileged-path'))
        self.assertNotIn('coverage-priority.json', self.included(result, 'accounting'))


class ImportOrderTests(Fixture):
    def test_pass_ten_is_later_than_pass_two(self):
        runs = self.base / 'runs/20261017-101010'
        for k in (1, 2, 10):
            self.reading(f'run-{k}.md', RUN_FILE.format(k=k, n=10, stamp='20261017-101010'),
                         directory=runs)
        bounty.import_findings(self.run, [str(runs)], repo=self.repo)
        row = self.records()[0]
        self.assertEqual((row['title'], row['revision']), ('Title from pass 10', 'sha10'))
        self.assertTrue(row['origin']['file'].endswith('run-10.md'))

    def test_the_run_marker_decides_whatever_order_files_are_given_in(self):
        runs = self.base / 'runs/20261017-101010'
        paths = [self.reading(f'run-{k}.md', RUN_FILE.format(k=k, n=3, stamp='20261017-101010'),
                              directory=runs) for k in (1, 2, 3)]
        bounty.import_findings(self.run, [str(p) for p in reversed(paths)], repo=self.repo)
        self.assertEqual(self.records()[0]['title'], 'Title from pass 3')

    def test_natural_order_of_reading_files(self):
        for k in (10, 2, 1):
            self.reading(f'run-{k}.md', 'x')
        self.assertEqual([p.name for p in bounty._reading_files(self.readings)],
                         ['run-1.md', 'run-2.md', 'run-10.md'])


class ReadingLedgerReviewTests(Fixture):
    BODY = 'CANDIDATE | surface: src/Vault.sol:Vault.withdraw | bug_class: reentrancy'

    def test_a_copy_differing_only_in_whitespace_is_one_reading(self):
        self.reading('a.md', self.BODY)
        self.converge()
        copy = self.base / 'copy'
        (copy).mkdir()
        (copy / 'b.md').write_text('  ' + self.BODY.replace(' | ', ' |  ') + '   \r\n\n\n')
        result = self.converge(copy)
        self.assertEqual(result['readings_parsed'], 1)
        self.assertEqual(result['saturated_groups'], 0)
        self.assertEqual(len(result['this_call']['duplicate_content']), 1)

    def test_a_deleted_reading_is_flagged_and_can_be_dropped(self):
        first = self.reading('a.md', self.BODY)
        other = self.base / 'other'
        self.reading('b.md', self.BODY.replace('CANDIDATE', 'LEAD'), directory=other)
        self.converge()
        self.converge(other)
        first.unlink()
        result = self.converge(other)
        self.assertEqual(result['readings_parsed'], 2)       # still counted, by default
        self.assertEqual(result['saturated_groups'], 1)
        self.assertEqual(result['missing_sources'], [str(first.resolve())])
        self.assertTrue(any('no longer exist' in note for note in result['notes']))
        ledger = bounty.read_json(self.run / bounty.READINGS_LEDGER)
        self.assertTrue(ledger['readings'][str(first.resolve())]['missing_source'])
        self.assertEqual(self.report()['missing_sources'], [str(first.resolve())])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = bounty.main(['converge', '--readings', str(other), '--run', str(self.run),
                                '--drop-missing'])
        self.assertEqual(code, 0)
        dropped = json.loads(out.getvalue())
        self.assertEqual((dropped['readings_parsed'], dropped['saturated_groups']), (1, 0))
        self.assertEqual(dropped['missing_sources'], [])
        self.assertTrue(any('--drop-missing' in note for note in dropped['notes']))

    def test_a_moved_reading_is_re_read_at_its_new_path(self):
        first = self.reading('a.md', self.BODY)
        self.converge()
        moved = self.base / 'archive'
        moved.mkdir()
        first.rename(moved / 'a.md')
        result = self.converge(moved)
        self.assertEqual(result['readings_parsed'], 1)
        self.assertEqual(result['missing_sources'], [])
        self.assertEqual(self.report()['readings'], [str((moved / 'a.md').resolve())])
        self.assertTrue(any('moved' in note for note in result['notes']))

    def test_raw_output_beside_its_run_file_is_not_a_second_reading(self):
        runs = self.base / '.solidity-auditor/runs/20261017-101010'
        self.reading('run-1.md', RUN_FILE.format(k=1, n=1, stamp='20261017-101010'),
                     directory=runs)
        self.reading('agent-3.md', RAW, directory=runs)
        result = self.converge(runs)
        self.assertEqual(result['saturated_groups'], 0)
        groups = {g['function']: g for g in self.report()['groups']}
        self.assertEqual(groups['withdraw']['readings'], 1)
        self.assertEqual(len(groups['withdraw']['sources']), 2)
        self.assertEqual([Path(s).name for s in groups['withdraw']['folded_sources']],
                         ['agent-3.md'])
        # A mechanism only the raw output has still counts: the gate's drop is not lost.
        self.assertEqual(groups['deposit']['readings'], 1)
        self.assertEqual(groups['deposit']['folded_sources'], [])

    def test_raw_output_from_elsewhere_still_counts(self):
        runs = self.base / '.solidity-auditor/runs/20261017-101010'
        self.reading('run-1.md', RUN_FILE.format(k=1, n=1, stamp='20261017-101010'),
                     directory=runs)
        self.reading('agent-3.md', RAW)
        self.assertEqual(self.converge(runs, self.readings)['saturated_groups'], 1)


class UntriagedSaturationTests(Fixture):
    def test_an_untriaged_import_does_not_close_saturated_ground(self):
        source = self.reading('auditor.md', RAW.split('\n\n')[0])
        bounty.import_findings(self.run, [str(source)], repo=self.repo)
        for name in ('a.md', 'b.md'):
            self.reading(name, f'CANDIDATE | lens: {name[0]} | surface: '
                               'src/Vault.sol:Vault.withdraw | bug_class: reentrancy',
                         directory=self.base / 'pass')
        result = self.converge(self.base / 'pass')
        line = next(l for l in (self.run / 'saturated.md').read_text().splitlines()
                    if l.startswith('src/Vault.sol'))
        self.assertIn('record BP-001 (hypothesis) UNTRIAGED', line)
        self.assertEqual(result['saturated_untriaged'][0]['record'], 'BP-001')
        self.assertEqual(self.report()['saturated_untriaged'], 1)
        self.assertTrue(self.report()['saturated'][0]['record']['untriaged_import'])
        records = self.records()
        records[0]['origin']['triage'] = 'triaged'
        bounty.dump(self.run / 'findings.json', records)
        self.converge(self.base / 'pass')
        self.assertNotIn('UNTRIAGED - an imported',
                         (self.run / 'saturated.md').read_text().split('\n\n')[-1])


class AuditorLocationTests(Fixture):
    def import_lines(self, *lines):
        source = self.reading('raw.md', *lines)
        result = bounty.import_findings(self.run, [str(source)], repo=self.repo)
        return {row['bug_class']: row for row in self.records()}, result

    def test_paths_and_qualified_names_never_glue_into_one_token(self):
        rows, result = self.import_lines(
            'FINDING | contract: src/Vault.sol | function: withdraw | bug_class: as-path',
            'FINDING | contract: Vault.sol | function: deposit | bug_class: as-file-name',
            'FINDING | contract: Vault | function: Vault.withdraw | bug_class: qualified',
            'FINDING | contract: Vault | function: withdraw (uint256 a) | bug_class: spaced')
        self.assertEqual(result['unparsed'], 0)
        for name, function in (('as-path', 'withdraw'), ('as-file-name', 'deposit'),
                               ('qualified', 'withdraw'), ('spaced', 'withdraw')):
            self.assertEqual(rows[name]['affected_paths'], [f'src/Vault.sol:Vault.{function}'],
                             name)
            self.assertEqual(rows[name]['origin']['path_resolution'] in
                             ('reported', 'resolved-from-contract'), True)
            self.assertEqual(rows[name]['origin']['key'], f'src/vault.sol|vault|{function}|{name}')

    def test_a_spaced_surface_keeps_its_function(self):
        parsed = bounty._parse_reading(
            'CANDIDATE | surface: src/vault.sol : Vault.WITHDRAW() | bug_class: reentrancy\n',
            'a.md', bounty._TargetIndex(self.repo))
        block = parsed['blocks'][0]
        self.assertEqual((block['surface'], block['key']),
                         ('src/Vault.sol:Vault.WITHDRAW', 'src/vault.sol|vault.withdraw|reentrancy'))

    def test_split_surface_reads_a_file_name_with_a_glued_symbol(self):
        self.assertEqual(bounty._split_surface('src/Vault.sol.withdraw')[:2],
                         ('src/Vault.sol', 'withdraw'))
        self.assertEqual(bounty._split_surface('Vault.sol.deposit')[0], 'Vault.sol')
        self.assertEqual(bounty._split_surface('Vault.withdraw')[0], '')


class MessagingSignalTests(unittest.TestCase):
    def signal(self, *names, manifest=None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        files = list(names)
        if manifest:
            (root / 'Cargo.toml').write_text(manifest)
            files.append('Cargo.toml')
        return stack_route._messaging_signals(root, files)

    def test_acronym_and_camel_case_names_are_signals(self):
        for name in ('contracts/OFTAdapter.sol', 'src/IBCHandler.sol', 'src/CCTPAdapter.sol',
                     'src/XCMRouter.sol', 'src/MyOApp.sol', 'src/LayerZeroEndpoint.sol',
                     'src/WormholeReceiver.sol', 'src/HyperlaneISM.sol', 'src/CCIPReceiver.sol',
                     'src/AxelarGateway.sol', 'src/L1StandardBridge.sol', 'keeper/src/main.rs',
                     'services/keepers/run.ts', 'src/CrossDomainMessenger.sol'):
            self.assertTrue(self.signal(name), name)

    def test_words_inside_other_words_are_not(self):
        for name in ('src/libraries/BookKeeper.sol', 'src/Cambridge.sol', 'src/SoftCap.sol',
                     'src/Library.sol', 'src/Calibrated.sol'):
            self.assertEqual(self.signal(name), [], name)

    def test_dependencies_match_at_a_name_boundary(self):
        self.assertEqual(self.signal(manifest='[dependencies]\nlibc-print = "1"\n'), [])
        self.assertTrue(self.signal(manifest='[dependencies]\nstaging-xcm = "1"\n'))


class WebBundleTests(Fixture):
    def setUp(self):
        super().setUp()
        files = {
            'web/src/App.tsx': 'export const App = () => null;\n',
            'web/src/DeployButton.tsx': 'export const DeployButton = () => null;\n',
            'web/public/scripts/widget.js': 'window.widget = 1;\n',
            'web/src/config.ts': ('export const RPC = '
                                  '"https://eth-mainnet.g.alchemy.com/v2/AbCdEfGhIjKlMnOp0123456789";\n'
                                  'export const apiKey = process.env.API_KEY;\n'
                                  'export const privateKey = "0x59c6995e998f97a5a0044966f094538'
                                  '9dc9e86dae88c7a8412f4603b6b78690d";\n'),
            'scripts/deploy.ts': ('const pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae'
                                  '784d7bf4f2ff80";\n'),
            'deploy/001_vault.ts': 'export default 1;\n',
            'tasks/accounts.ts': 'task("accounts");\n',
            'web/vite.config.ts': 'export default {};\n',
            'hardhat.config.ts': 'export default {};\n',
            'web/src/deployContracts.ts': 'export {};\n',
            'src/Roles.sol': ('contract Roles {\n  bytes32 public constant SECRET_ROLE = '
                              'keccak256("SECRET_ROLE");\n}\n'),
        }
        for name, body in files.items():
            (self.repo / name).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / name).write_text(body)
        commit(self.repo, 'web and tooling')

    def test_tooling_is_not_frontend_source(self):
        result = bounty.bundle(self.repo, self.run, ['web'])
        text = (self.run / 'bundles/web-frontend-bundle.md').read_text()
        web = text.split('# In-scope web source', 1)[1]
        for name in ('web/src/App.tsx', 'web/src/DeployButton.tsx',
                     'web/public/scripts/widget.js', 'web/src/config.ts'):
            self.assertIn('### ' + name, web)
        for name in ('scripts/deploy.ts', 'deploy/001_vault.ts', 'tasks/accounts.ts',
                     'web/vite.config.ts', 'hardhat.config.ts', 'web/src/deployContracts.ts'):
            self.assertNotIn('### ' + name, web)
        self.assertEqual(result['web_files_bundled_for_web_frontend'], 4)

    def test_credentials_are_redacted_from_every_bundled_source_and_reported(self):
        result = bounty.bundle(self.repo, self.run, ['web', 'accounting'])
        for name in ('source.md', 'web-source.md', 'accounting-bundle.md',
                     'web-frontend-bundle.md'):
            text = (self.run / 'bundles' / name).read_text()
            self.assertNotIn('AbCdEfGhIjKlMnOp0123456789', text, name)
            self.assertNotIn('59c6995e998f97a5a0044966f0945389', text, name)
            self.assertNotIn('ac0974bec39a17e36ba4a6b4d238ff94', text, name)
        source = (self.run / 'bundles/source.md').read_text()
        # Code that merely names a secret is code, and stays.
        self.assertIn('SECRET_ROLE = keccak256("SECRET_ROLE")', source)
        self.assertIn('apiKey = process.env.API_KEY', source)
        self.assertIn('/v2/<redacted>', source)
        self.assertEqual(result['redacted_secrets'], [{'path': 'scripts/deploy.ts', 'count': 1},
                                                      {'path': 'web/src/config.ts', 'count': 2}])
        self.assertTrue(any('replaced by <redacted>' in note for note in result['notes']))


class DeltaScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / 'repo'
        for name, body in (('packages/contracts/src/A.sol', 'contract A {}\n'),
                           ('packages/contracts/foundry.toml', '[profile.default]\n'),
                           ('packages/web/package.json', '{"name": "web"}\n'),
                           ('deployments/mainnet.json', '{"A": "0x1"}\n'),
                           ('foundry.toml', '[profile.default]\n')):
            (self.repo / name).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / name).write_text(body)
        git(self.repo, 'init', '-q')
        commit(self.repo, 'audited')
        self.audited = head(self.repo)
        for name, body in (('packages/contracts/foundry.toml', '[profile.default]\nvia_ir = true\n'),
                           ('packages/web/package.json', '{"name": "web", "v": 2}\n'),
                           ('deployments/mainnet.json', '{"A": "0x2"}\n'),
                           ('foundry.toml', '[profile.default]\nsolc = "0.8.20"\n')):
            (self.repo / name).write_text(body)
        commit(self.repo, 'change')

    def test_scoped_delta_ranks_governing_config_and_lists_the_rest(self):
        report = bounty.delta(self.repo, self.audited, ['packages/contracts/src/'])
        ranked = {row['path'] for row in report['ranked']}
        self.assertEqual(ranked, {'packages/contracts/foundry.toml', 'foundry.toml'})
        self.assertEqual(report['changed_config_outside_scope'], 2)
        self.assertEqual(sorted(row['path'] for row in report['config_outside_scope']),
                         ['deployments/mainnet.json', 'packages/web/package.json'])
        unscoped = bounty.delta(self.repo, self.audited)
        self.assertEqual(unscoped['config_outside_scope'], [])
        self.assertEqual(unscoped['changed_config_files'], 4)


if __name__ == '__main__':
    unittest.main()
