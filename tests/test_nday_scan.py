"""nday-scan: upstream fixes shipped after the target's pin that the target never took.

The calibration is the Cosmos EVM incident of August 2026: a fix pushed publicly on 19 August,
six chains running the unpatched module exploited from the 20th. Every repository here is a
throwaway built in a temporary directory; the upstream's third commit is the shape of that fix,
a `require` that bounds an amount.
"""
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nday = load("bp_test_nday_scan", "skills/bounty-pilot/scripts/nday_scan.py")

VAULT_V1 = """pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balance;

    function withdraw(uint256 amount) external {
        balance[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
"""
VAULT_FIXED = VAULT_V1.replace(
    "        balance[msg.sender] -= amount;\n",
    "        require(amount <= balance[msg.sender], \"bounds\");\n"
    "        balance[msg.sender] -= amount;\n")
MATH_V1 = """library Math {
    function half(uint256 x) internal pure returns (uint256) {
        return x / 2;
    }
}
"""
MATH_RENAMED = MATH_V1.replace("half", "halve")

_CLOCK = [1700000000]


def git(cwd, *args, check=True):
    _CLOCK[0] += 3600
    env = dict(os.environ, GIT_AUTHOR_DATE=f"@{_CLOCK[0]} +0000",
               GIT_COMMITTER_DATE=f"@{_CLOCK[0]} +0000", GIT_CONFIG_NOSYSTEM="1")
    done = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                           "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false",
                           *args], cwd=str(cwd), env=env, check=check,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return done.stdout.decode().strip()


def write(root, files):
    for rel, text in files.items():
        path = Path(root, rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def commit(root, files, message):
    write(root, files)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", message)
    return git(root, "rev-parse", "HEAD")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nday-"))
        self.up = self.tmp / "up"
        self.up.mkdir()
        git(self.up, "init", "-q")
        self.c1 = commit(self.up, {"src/Vault.sol": VAULT_V1, "src/Math.sol": MATH_V1,
                                   "README.md": "upstream\n"}, "initial import")
        self.c2 = commit(self.up, {"README.md": "upstream, documented\n"}, "docs: readme")
        self.c3 = commit(self.up, {"src/Vault.sol": VAULT_FIXED},
                         "fix: add bounds check on withdraw amount")
        self.c4 = commit(self.up, {"src/Math.sol": MATH_RENAMED}, "refactor: rename helper")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def target(self, name="target"):
        root = self.tmp / name
        root.mkdir()
        git(root, "init", "-q")
        return root

    def submodule_target(self, pin):
        root = self.target()
        git(root, "-c", "protocol.file.allow=always", "submodule", "add", "-q",
            str(self.up), "lib/up")
        git(root / "lib/up", "checkout", "-q", pin)
        commit(root, {"README.md": "chain\n"}, "pin upstream")
        return root

    def vendored_target(self, vault, math, name="target"):
        root = self.target(name)
        commit(root, {"vendor/up/Vault.sol": vault, "vendor/up/Math.sol": math,
                      "app/main.sol": "contract App {}\n"}, "vendor the upstream library")
        return root

    @staticmethod
    def by_commit(entry):
        return {row["commit"]: row for row in entry["candidates"]}


class SubmodulePin(Base):
    def test_fix_after_the_pin_is_listed_absent_and_ranked_first(self):
        repo = self.submodule_target(self.c2)
        report = nday.analyze(repo, {"up": str(self.up)})
        entry = report["upstreams"][0]
        self.assertEqual(entry["resolution"], "submodule")
        self.assertEqual(entry["pinned"], self.c2)
        self.assertEqual(entry["confidence"], "high")
        rows = self.by_commit(entry)
        self.assertEqual(set(rows), {self.c3, self.c4})
        fix = rows[self.c3]
        self.assertEqual(entry["candidates"][0]["commit"], self.c3)
        self.assertEqual(fix["fix_status"], "fix_absent")
        self.assertEqual(fix["files"], ["src/Vault.sol"])
        self.assertIn("diff:adds-require-assert-revert", fix["signals"])
        self.assertIn("keyword:fix", fix["signals"])
        self.assertGreaterEqual(fix["score"], 5)
        self.assertGreater(fix["score"], rows[self.c4]["score"])
        self.assertEqual(report["repo_commit"], git(repo, "rev-parse", "HEAD"))
        self.assertIn("PRIVATELY", report["notice"])
        self.assertIn("LEAD", report["notice"])

    def test_pin_after_the_fix_lists_nothing_for_it(self):
        repo = self.submodule_target(self.c3)
        entry = nday.analyze(repo, {"up": str(self.up)})["upstreams"][0]
        self.assertEqual(entry["pinned"], self.c3)
        self.assertEqual(list(self.by_commit(entry)), [self.c4])


class VendoredPin(Base):
    def test_vendored_copy_matches_the_older_commit(self):
        repo = self.vendored_target(VAULT_V1, MATH_V1)
        report = nday.analyze(repo, [{"name": "up", "path": str(self.up),
                                      "map": ("vendor/up", "src")}])
        entry = report["upstreams"][0]
        self.assertEqual(entry["resolution"], "vendored")
        self.assertEqual(entry["pinned"], self.c1)
        self.assertEqual(entry["match"]["fraction"], 1.0)
        self.assertFalse(entry["match"]["walk_capped"])
        self.assertEqual(entry["confidence"], "high")
        fix = self.by_commit(entry)[self.c3]
        self.assertEqual(fix["fix_status"], "fix_absent")
        self.assertEqual(fix["target_files"], ["vendor/up/Vault.sol"])
        # The README commit touches nothing the target copied: counted, not listed.
        self.assertNotIn(self.c2, self.by_commit(entry))
        self.assertEqual(entry["commits_not_touching_target_files"], 1)

    def test_fix_already_applied_with_a_local_edit_reads_present(self):
        local = VAULT_FIXED.replace("contract Vault {", "// chain fork\ncontract Vault {")
        repo = self.vendored_target(local, MATH_V1)
        entry = nday.analyze(repo, [{"name": "up", "path": str(self.up),
                                     "map": "vendor/up:src"}])["upstreams"][0]
        self.assertEqual(entry["resolution"], "vendored")
        # Math.sol matches c1..c3; the tie resolves to the OLDER commit so c3 is still listed.
        self.assertEqual(entry["pinned"], self.c1)
        self.assertEqual(entry["confidence"], "low")
        rows = self.by_commit(entry)
        self.assertEqual(rows[self.c3]["fix_status"], "fix_present")
        self.assertIn("reverse-applies", rows[self.c3]["fix_status_basis"])
        self.assertEqual(rows[self.c4]["fix_status"], "fix_absent")

    def test_local_edit_without_the_fix_reads_absent(self):
        local = VAULT_V1.replace("contract Vault {", "// chain fork\ncontract Vault {")
        repo = self.vendored_target(local, MATH_V1)
        entry = nday.analyze(repo, [{"name": "up", "path": str(self.up),
                                     "map": "vendor/up:src"}])["upstreams"][0]
        fix = self.by_commit(entry)[self.c3]
        self.assertEqual(fix["fix_status"], "fix_absent")
        self.assertIn("applies cleanly", fix["fix_status_basis"])

    def test_walk_cap_is_reported(self):
        repo = self.vendored_target(VAULT_V1, MATH_V1)
        entry = nday.analyze(repo, [{"name": "up", "path": str(self.up),
                                     "map": "vendor/up:src"}], walk_cap=1)["upstreams"][0]
        self.assertTrue(entry["match"]["walk_capped"])
        self.assertIn("walk-cap", entry["match"]["walk_cap_note"])


class OtherPins(Base):
    def test_fork_sharing_history_pins_at_the_fork_point(self):
        repo = self.tmp / "fork"
        git(self.tmp, "clone", "-q", str(self.up), str(repo))
        git(repo, "reset", "-q", "--hard", self.c2)
        commit(repo, {"src/Chain.sol": "contract Chain {}\n"}, "chain-specific module")
        entry = nday.analyze(repo, {"up": str(self.up)})["upstreams"][0]
        self.assertEqual(entry["resolution"], "shared-history")
        self.assertEqual(entry["pinned"], self.c2)
        self.assertEqual(self.by_commit(entry)[self.c3]["fix_status"], "fix_absent")

    def test_go_module_pseudo_version(self):
        repo = self.target()
        commit(repo, {"go.mod": "module example.com/chain\n\ngo 1.22\n\nrequire (\n"
                                f"\tgithub.com/example/up v0.0.0-20240101000000-{self.c2[:12]}\n"
                                ")\n"}, "deps")
        entry = nday.analyze(repo, {"up": str(self.up)})["upstreams"][0]
        self.assertEqual(entry["resolution"], "go-module")
        self.assertEqual(entry["pinned"], self.c2)
        self.assertIn(self.c3, self.by_commit(entry))

    def test_go_module_replace_is_reported_not_followed(self):
        repo = self.target()
        commit(repo, {"go.mod": "module example.com/chain\n\nrequire github.com/example/up "
                                "v1.0.0\n\nreplace github.com/example/up => "
                                "github.com/chain/up v1.0.0-chain\n"}, "deps")
        entry = nday.analyze(repo, {"up": str(self.up)})["upstreams"][0]
        self.assertEqual(entry["resolution"], "unresolved")
        self.assertIn("replaces github.com/example/up", entry["reason"])


class Accounting(Base):
    def test_unresolved_upstream_is_reported_not_dropped(self):
        other = self.tmp / "other"
        other.mkdir()
        git(other, "init", "-q")
        commit(other, {"x.go": "package x\n"}, "unrelated")
        repo = self.submodule_target(self.c2)
        report = nday.analyze(repo, {"up": str(self.up), "other": str(other)})
        names = {u["name"]: u for u in report["upstreams"]}
        self.assertEqual(set(names), {"up", "other"})
        self.assertEqual(names["other"]["resolution"], "unresolved")
        self.assertIn("--map", names["other"]["reason"])
        self.assertEqual(names["other"]["candidates"], [])
        self.assertEqual(report["counts"]["unresolved"], 1)

    def test_limit_counts_and_names_the_omitted(self):
        repo = self.submodule_target(self.c2)
        entry = nday.analyze(repo, {"up": str(self.up)}, limit=1)["upstreams"][0]
        self.assertEqual([r["commit"] for r in entry["candidates"]], [self.c3])
        self.assertEqual(entry["omitted"]["count"], 1)
        self.assertEqual(entry["omitted"]["commits"], [self.c4])
        self.assertIn("--limit", entry["omitted"]["note"])

    def test_advisories(self):
        repo = self.submodule_target(self.c2)
        advisories = [
            {"id": "GHSA-aaaa-bbbb-cccc", "package": "github.com/example/up",
             "summary": "withdraw lacks a bound", "patched_commit": self.c3,
             "url": "https://example.invalid/a"},
            {"id": "GHSA-old", "name": "up", "patched_commit": self.c1},
            {"id": "GHSA-elsewhere", "package": "unrelated-lib", "patched_commit": self.c3},
        ]
        rows = {a["id"]: a for a in nday.analyze(repo, {"up": str(self.up)},
                                                  advisories=advisories)["advisories"]}
        self.assertEqual(rows["GHSA-aaaa-bbbb-cccc"]["status"], "advisory_unpatched")
        self.assertEqual(rows["GHSA-aaaa-bbbb-cccc"]["fix_status"], "fix_absent")
        self.assertEqual(rows["GHSA-old"]["status"], "patched_at_pin")
        self.assertEqual(rows["GHSA-elsewhere"]["status"], "no_matching_upstream")

    def test_fixed_version_tag(self):
        git(self.up, "tag", "v1.0.1", self.c3)
        repo = self.submodule_target(self.c2)
        path = self.tmp / "adv.json"
        path.write_text(json.dumps([{"id": "GHSA-v", "package": "up",
                                     "fixed_versions": ["1.0.1"]}]))
        row = nday.analyze(repo, {"up": str(self.up)}, advisories=str(path))["advisories"][0]
        self.assertEqual(row["status"], "advisory_unpatched")


class Cli(Base):
    def test_main_writes_the_report_and_prints_a_summary(self):
        repo = self.submodule_target(self.c2)
        out = self.tmp / "nday.json"
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = nday.main(["--repo", str(repo), "--upstream", f"up={self.up}",
                              "--out", str(out)])
        self.assertEqual(code, 0)
        summary = json.loads(buffer.getvalue())
        self.assertEqual(summary["upstreams"][0]["candidates"], 2)
        report = json.loads(out.read_text())
        self.assertEqual(report["schema_version"], 1)

    def test_usage_errors_exit_2(self):
        for argv in (["--repo", str(self.up), "--upstream", "noequals"],
                     ["--repo", str(self.up), "--upstream", f"up={self.up}",
                      "--map", "other=a:b"],
                     ["--repo", str(self.up), "--upstream", f"up={self.up}",
                      "--map", "up=nocolon"]):
            with self.assertRaises(SystemExit) as raised, redirect_stdout(io.StringIO()), \
                    redirect_stderr(io.StringIO()):
                nday.main(argv)
            self.assertEqual(raised.exception.code, 2)


class HardenedGit(Base):
    def test_target_fsmonitor_is_never_run(self):
        self.assertIn("core.fsmonitor=false", nday.GIT_HARDENING)
        self.assertIn("core.hooksPath=/dev/null", nday.GIT_HARDENING)
        repo = self.submodule_target(self.c2)
        marker = self.tmp / "fsmonitor-ran"
        script = self.tmp / "fsmonitor.sh"
        script.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n")
        script.chmod(0o755)
        git(repo, "config", "core.fsmonitor", str(script))
        git(repo, "config", "core.hooksPath", str(self.tmp))
        # Negative control: unhardened git in this checkout does run the planted program.
        git(repo, "status", "--porcelain", check=False)
        if not marker.exists():
            self.skipTest("this git does not run a core.fsmonitor command; control failed")
        marker.unlink()
        report = nday.analyze(repo, {"up": str(self.up)})
        self.assertEqual(report["upstreams"][0]["resolution"], "submodule")
        self.assertFalse(marker.exists(), "nday-scan ran the target's fsmonitor program")


if __name__ == "__main__":
    unittest.main()
