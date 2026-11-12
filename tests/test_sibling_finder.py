"""Structural near-duplicate functions with an asymmetric guard (misses.md #9)."""
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = 'skills/bounty-pilot/scripts/sibling_finder.py'

ENV = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t', GIT_COMMITTER_NAME='t',
           GIT_COMMITTER_EMAIL='t@t')


def load():
    spec = importlib.util.spec_from_file_location('sibling_finder', ROOT / SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sf = load()


def git(repo, *args):
    subprocess.run(['git', '-C', str(repo), *args], check=True, env=ENV,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write(repo, rel, text):
    path = Path(repo) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


class SiblingFinderTests(unittest.TestCase):
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

    def test_asymmetric_guard_pair_is_the_top_lead(self):
        write(self.repo, 'src/Vault.sol', '''
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) balances;

    function withdrawA(uint256 amount) public onlyOwner {
        require(amount > 0, "zero");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function withdrawB(uint256 amount) public {
        require(amount > 0, "zero");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
''')
        self.commit()
        report = sf.run(str(self.repo))
        self.assertEqual(report['functions_scanned'], 2)
        self.assertEqual(len(report['leads']), 1)
        lead = report['leads'][0]
        self.assertEqual(lead['classification'], 'ASYMMETRIC_GUARD_SIBLING_LEAD')
        names = {lead['a']['name'], lead['b']['name']}
        self.assertEqual(names, {'withdrawA', 'withdrawB'})
        guarded = lead['a'] if lead['a']['name'] == 'withdrawA' else lead['b']
        unguarded = lead['b'] if lead['a']['name'] == 'withdrawA' else lead['a']
        self.assertIn('onlyowner', guarded['guard_cues'])
        self.assertEqual(unguarded['guard_cues'], [])

    def test_identically_guarded_pair_is_structural_not_asymmetric(self):
        write(self.repo, 'src/Vault.sol', '''
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) balances;

    function withdrawA(uint256 amount) public onlyOwner {
        require(amount > 0, "zero");
        balances[msg.sender] -= amount;
    }

    function withdrawB(uint256 amount) public onlyOwner {
        require(amount > 0, "zero");
        balances[msg.sender] -= amount;
    }
}
''')
        self.commit()
        report = sf.run(str(self.repo))
        self.assertEqual(len(report['leads']), 1)
        self.assertEqual(report['leads'][0]['classification'], 'STRUCTURAL_SIBLING_LEAD')

    def test_unrelated_functions_are_not_flagged(self):
        write(self.repo, 'src/Vault.sol', '''
pragma solidity ^0.8.0;
contract Vault {
    function withdraw(uint256 amount) public onlyOwner {
        require(amount > 0, "zero");
        balances[msg.sender] -= amount;
    }

    function totalSupply() public view returns (uint256) {
        return supply;
    }
}
''')
        self.commit()
        report = sf.run(str(self.repo))
        self.assertEqual(report['functions_scanned'], 2)
        self.assertEqual(report['leads'], [])

    def test_python_functions_are_extracted_and_compared(self):
        write(self.repo, 'app/views.py', '''
def read_order_checked(order_id, actor):
    order = db.fetch(order_id)
    if order.owner_id != actor.id:
        raise PermissionError("not yours")
    items = order.line_items()
    total = sum(i.price for i in items)
    return {"order": order, "items": items, "total": total}


def read_order_export(order_id, actor):
    order = db.fetch(order_id)
    items = order.line_items()
    total = sum(i.price for i in items)
    return {"order": order, "items": items, "total": total}
''')
        self.commit()
        report = sf.run(str(self.repo))
        self.assertEqual(report['functions_scanned'], 2)
        self.assertEqual(len(report['leads']), 1)
        lead = report['leads'][0]
        self.assertEqual(lead['classification'], 'ASYMMETRIC_GUARD_SIBLING_LEAD')
        checked = lead['a'] if lead['a']['name'] == 'read_order_checked' else lead['b']
        exported = lead['b'] if lead['a']['name'] == 'read_order_checked' else lead['a']
        self.assertIn('owner_id', checked['guard_cues'])
        self.assertEqual(exported['guard_cues'], [])

    def test_untracked_and_symlinked_files_are_not_read(self):
        write(self.repo, 'src/Tracked.sol',
             'function a() public onlyOwner { require(x>0); y -= x; }\n'
             'function b() public { require(x>0); y -= x; }\n')
        self.commit()
        untracked = self.repo / 'src' / 'Untracked.sol'
        untracked.write_text(
            'function c() public onlyOwner { require(x>0); y -= x; }\n'
            'function d() public { require(x>0); y -= x; }\n', encoding='utf-8')
        report = sf.run(str(self.repo))
        self.assertEqual(report['functions_scanned'], 2)
        for lead in report['leads']:
            self.assertNotIn('Untracked.sol', (lead['a']['path'], lead['b']['path']))

    def test_min_ratio_is_bounded(self):
        write(self.repo, 'src/A.sol', 'function a() public {}\n')
        self.commit()
        with self.assertRaises(ValueError):
            sf.run(str(self.repo), min_ratio=1.5)
        with self.assertRaises(ValueError):
            sf.run(str(self.repo), min_ratio=0.1)

    def test_repo_without_git_is_rejected(self):
        with tempfile.TemporaryDirectory() as plain:
            with self.assertRaisesRegex(ValueError, 'git checkout'):
                sf.run(plain)

    def test_scope_restricts_scanned_files(self):
        write(self.repo, 'src/In.sol',
             'function a() public onlyOwner { require(x>0); y -= x; }\n'
             'function b() public { require(x>0); y -= x; }\n')
        write(self.repo, 'other/Out.sol',
             'function a() public onlyOwner { require(x>0); y -= x; }\n'
             'function b() public { require(x>0); y -= x; }\n')
        self.commit()
        report = sf.run(str(self.repo), scope=['src'])
        self.assertEqual(report['functions_scanned'], 2)
        for lead in report['leads']:
            self.assertTrue(lead['a']['path'].startswith('src/'))
            self.assertTrue(lead['b']['path'].startswith('src/'))

    def test_cli_refuses_to_overwrite_existing_output(self):
        write(self.repo, 'src/A.sol', 'function a() public onlyOwner { x = 1; }\n')
        self.commit()
        out = Path(self.tmp.name) / 'out.json'
        out.write_text('{}', encoding='utf-8')
        code = sf.main(['--repo', str(self.repo), '--out', str(out)])
        self.assertEqual(code, 2)


if __name__ == '__main__':
    unittest.main()
