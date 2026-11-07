"""rounding_map: rounding sites ranked by direction x repeatability.

Calibration shape (Balancer v2 Nov 2025, Bunni Sep 2025): a rounding that favours the caller by a
wei, harmless once, repeated in one transaction. The fixtures are synthetic Solidity written into
temporary git repositories; nothing is compiled or executed, so CI needs no solc.
"""
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rmap = load('bp_test_rounding_map', 'skills/bounty-pilot/scripts/rounding_map.py')

BAD_VAULT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {ERC20} from "./ERC20.sol";

contract BadVault is ERC20 {
    uint256 internal constant HALF = 1e18 / 2;
    IERC20 public asset;

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function previewWithdraw(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply();
        // shares burned for `assets`: rounds DOWN, so the owner burns too few
        return supply == 0 ? assets : assets * supply / totalAssets();
    }

    function withdraw(uint256 assets, address receiver, address owner)
        external returns (uint256 shares)
    {
        shares = previewWithdraw(assets);
        _withdraw(owner, receiver, assets, shares);
    }

    function _withdraw(address owner, address receiver, uint256 assets, uint256 shares) internal {
        _burn(owner, shares);
        asset.safeTransfer(receiver, assets);
    }

    function multicall(bytes[] calldata data) external {
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok,) = address(this).delegatecall(data[i]);
            require(ok);
        }
    }
}
"""

GOOD_VAULT = """pragma solidity ^0.8.20;
contract GoodVault is ERC20 {
    using FixedPointMathLib for uint256;
    IERC20 public asset;
    function previewWithdraw(uint256 assets) public view returns (uint256) {
        return assets.mulDivUp(totalSupply(), totalAssets());
    }
    function withdraw(uint256 assets, address receiver, address owner)
        external returns (uint256 shares)
    {
        shares = previewWithdraw(assets);
        _burn(owner, shares);
        asset.safeTransfer(receiver, assets);
    }
}
"""

OZ_CEIL = """pragma solidity ^0.8.20;
contract Lender {
    function quote(uint256 a, uint256 b, uint256 c) external returns (uint256 owed) {
        owed = Math.mulDiv(a, b, c, Math.Rounding.Ceil);
        token.safeTransferFrom(msg.sender, address(this), owed);
    }
}
"""

RAY = """pragma solidity ^0.8.20;
contract Pool {
    function borrow(uint256 amount, uint256 index) external {
        uint256 scaled = amount.rayDiv(index);
        debt[msg.sender] += scaled;
        token.safeTransfer(msg.sender, amount);
    }
}
"""

NOISE = """pragma solidity ^0.8.20;
/* a block comment with a / b and x >> amount */
contract Quiet {
    uint256 constant RATIO = 1e18 / 2;
    function f() external pure returns (uint256) {
        string memory path = "a/b/c";  // and a / here
        return 1e18 / 2;
    }
    function g() external pure returns (uint256) {
        return 2 * WAD / RAY + type(uint256).max / 3;
    }
}
"""


def git_repo(files):
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
    subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
    subprocess.run(['git', 'add', '-A'], cwd=root, check=True)
    return tmp, root


class RoundingMapTest(unittest.TestCase):
    def scan(self, files, **kw):
        tmp, root = git_repo(files)
        self.addCleanup(tmp.cleanup)
        return rmap.analyze(repo=str(root), **kw)

    def test_bad_vault_with_multicall_ranks_first(self):
        report = self.scan({'src/BadVault.sol': BAD_VAULT, 'src/Good.sol': GOOD_VAULT})
        top = report['sites'][0]
        self.assertEqual((top['contract'], top['function']), ('BadVault', 'previewWithdraw'))
        self.assertEqual(top['direction'], 'down')
        self.assertEqual(top['feeds'], 'shares-burned')
        self.assertTrue(top['favors_user'])
        self.assertTrue(top['repeatable'])
        self.assertEqual(top['tier'], 0)
        self.assertIn('BadVault.withdraw', top['entry_points'])
        withdraw = next(f for f in report['functions']
                        if f['contract'] == 'BadVault' and f['function'] == 'withdraw')
        self.assertTrue(withdraw['repeatable'])
        self.assertTrue(any('multicall' in e for e in withdraw['batching_evidence']))
        self.assertIn(top['id'], withdraw['sites'])
        self.assertEqual(report['summary']['favors_user_and_repeatable'], 1)
        self.assertIn('nothing here proves profit', report['notice'])
        self.assertIn('RepetitionDrift.t.sol', report['notice'])

    def test_hand_rolled_share_books_count_as_burn_and_mint(self):
        """`shares[msg.sender] -= s` is a burn without `_burn`. Before 0.53 it read as plain state,
        so the vault behind the RepetitionDrift calibration showed nothing but needs_reading."""
        source = (
            'pragma solidity ^0.8.20;\n'
            'contract HandVault {\n'
            '  mapping(address => uint256) public shares; uint256 public totalShares;\n'
            '  mapping(address => uint256) public debt;\n'
            '  function totalAssets() public view returns (uint256) { return 1; }\n'
            '  function deposit(uint256 a) external {\n'
            '    uint256 s = a * totalShares / totalAssets();\n'
            '    shares[msg.sender] += s; totalShares += s;\n'
            '  }\n'
            '  function withdraw(uint256 a) external {\n'
            '    uint256 s = a * totalShares / totalAssets();\n'
            '    shares[msg.sender] -= s; totalShares -= s;\n'
            '  }\n'
            '  function borrow(uint256 a) external {\n'
            '    uint256 d = a * 1e18 / totalAssets();\n'
            '    debt[msg.sender] += d;\n'
            '  }\n'
            '}\n')
        report = self.scan({'src/HandVault.sol': source})
        by_fn = {s['function']: s for s in report['sites']}
        self.assertEqual(by_fn['withdraw']['feeds'], 'shares-burned')
        self.assertEqual(by_fn['withdraw']['verdict'], 'favors_user')
        self.assertEqual(by_fn['deposit']['feeds'], 'shares-minted')
        self.assertEqual(by_fn['deposit']['verdict'], 'favors_protocol')
        # A debt book is the user paying: never read as a mint.
        self.assertNotEqual(by_fn['borrow']['feeds'], 'shares-minted')

    def test_correct_vault_rounding_up_is_not_favors_user(self):
        report = self.scan({'src/Good.sol': GOOD_VAULT})
        site = next(s for s in report['sites'] if s['function'] == 'previewWithdraw')
        self.assertEqual(site['kind'], 'mulDivUp')
        self.assertEqual(site['direction'], 'up')
        self.assertEqual(site['feeds'], 'shares-burned')
        self.assertFalse(site['favors_user'])
        self.assertEqual(site['verdict'], 'favors_protocol')

    def test_oz_rounding_ceil_is_up(self):
        report = self.scan({'src/Lender.sol': OZ_CEIL})
        site = report['sites'][0]
        self.assertEqual(site['kind'], 'mulDiv')
        self.assertEqual(site['direction'], 'up')
        self.assertEqual(site['feeds'], 'in')
        self.assertEqual(site['verdict'], 'favors_protocol')

    def test_ray_div_is_half_and_needs_reading(self):
        report = self.scan({'src/Pool.sol': RAY})
        site = report['sites'][0]
        self.assertEqual((site['kind'], site['direction']), ('rayDiv', 'half'))
        self.assertEqual(site['verdict'], 'needs_reading')
        self.assertTrue(site['repeatable'])
        self.assertEqual(site['tier'], 1)

    def test_constants_comments_and_strings_are_not_sites(self):
        report = self.scan({'src/Quiet.sol': NOISE})
        self.assertEqual(report['sites'], [], report['sites'])

    def test_test_mock_and_script_paths_are_skipped_and_counted(self):
        report = self.scan({'src/Pool.sol': RAY, 'test/Pool.t.sol': RAY,
                            'src/mocks/MockPool.sol': RAY, 'script/Deploy.s.sol': RAY,
                            'test/helpers/Helper.sol': RAY})
        self.assertEqual(report['files_scanned'], ['src/Pool.sol'])
        self.assertEqual(report['summary']['skipped'], 4)
        self.assertEqual(len(report['skipped']), 4)

    def test_scope_filters(self):
        report = self.scan({'src/Pool.sol': RAY, 'other/Pool.sol': RAY}, scope=['src'])
        self.assertEqual(report['files_scanned'], ['src/Pool.sol'])

    def test_limit_and_omitted_accounting(self):
        report = self.scan({'src/BadVault.sol': BAD_VAULT, 'src/Good.sol': GOOD_VAULT,
                            'src/Pool.sol': RAY}, limit=1)
        self.assertEqual(len(report['sites']), 1)
        self.assertEqual(report['sites'][0]['function'], 'previewWithdraw')
        total = report['summary']['sites']
        self.assertEqual(report['summary']['omitted'], total - 1)
        self.assertEqual(sum(report['summary']['omitted_by_tier'].values()), total - 1)
        kept = {s['id'] for s in report['sites']}
        for row in report['functions']:
            self.assertTrue(set(row['sites']) <= kept)

    def test_build_info_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'build-info.json'
            path.write_text(json.dumps({'input': {'sources': {
                'src/BadVault.sol': {'content': BAD_VAULT},
                'test/X.t.sol': {'content': RAY}}}}), encoding='utf-8')
            report = rmap.analyze(build_info=str(path))
        self.assertEqual(report['files_scanned'], ['src/BadVault.sol'])
        self.assertEqual(report['summary']['skipped'], 1)
        self.assertTrue(report['sites'][0]['favors_user'])

    def test_main_writes_out(self):
        tmp, root = git_repo({'src/BadVault.sol': BAD_VAULT})
        self.addCleanup(tmp.cleanup)
        out = root / 'rounding-map.json'
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            code = rmap.main(['--repo', str(root), '--scope', 'src', '--out', str(out)])
        self.assertEqual(code, 0)
        data = json.loads(out.read_text(encoding='utf-8'))
        self.assertEqual(data['schema_version'], rmap.SCHEMA_VERSION)
        self.assertTrue(data['sites'][0]['favors_user'])

    def test_empty_scan_says_so(self):
        report = self.scan({'README.md': 'x'})
        self.assertEqual(report['sites'], [])
        self.assertIn('nothing was scanned', report['notice'])

    def test_template_has_candidate_and_control(self):
        text = (ROOT / 'skills/bounty-pilot/templates/RepetitionDrift.t.sol').read_text(
            encoding='utf-8')
        self.assertIn('pragma solidity ^0.8.20', text)
        self.assertIn('forge-std/Test.sol', text)
        self.assertIn('function test_candidate', text)
        self.assertIn('function test_control', text)
        self.assertIn('_once(', text)
        self.assertNotRegex(text, r'0x[0-9a-fA-F]{40}')

    def test_reference_exists(self):
        text = (ROOT / 'skills/bounty-pilot/references/rounding-map.md').read_text(
            encoding='utf-8')
        self.assertIn('rounding-map --repo', text)
        self.assertIn('repetition', text)


if __name__ == '__main__':
    unittest.main()
