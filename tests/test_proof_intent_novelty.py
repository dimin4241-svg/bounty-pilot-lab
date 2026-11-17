import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=ROOT/"skills"/"bounty-pilot"/"scripts"
if not SCRIPTS.is_dir():
    SCRIPTS=ROOT/"scripts"
sys.path.insert(0,str(SCRIPTS))
import native_poc_pipeline as poc
import business_intent_contract as intent
import novelty_mechanism_gate as novelty

REV="a"*40


def scenario():
    return {"schema_version":1,"id":"VaultGuard","source_revision":REV,
        "fixture":{"import":"test/OwnedFixture.sol","contract":"OwnedFixture"},
        "actions":[
            {"role":"setup","target":"vault","signature":"prepare(uint256)",
             "args":[{"literal":"1"}],"actor":"alice"},
            {"role":"enabler","target":"vault","signature":"makeState(address)",
             "args":[{"fixture_ref":"mallory"}],"actor":"mallory"},
            {"role":"action","target":"vault","signature":"withdraw(uint256)",
             "args":[{"literal":10}],"actor":"alice"}],
        "observations":[{"name":"aliceFunds","target":"vault","signature":"getFunds(address)",
                         "args":[{"fixture_ref":"alice"}]}],
        "checks":{"candidate":[{"observation":"aliceFunds","relation":"lt"}],
                  "negative_control":[{"observation":"aliceFunds","relation":"eq"}]},
        "operator_reviewed_intent":True}


def report(ident,project="contest"):
    return {"id":ident,"project":project,"source_revision":REV,"impact":"stopped auto withdraw",
            "root_cause":{"component":"RevertHookTriggers", "operation":"computeTriggerTicksCore",
               "state_resource":"trigger slots 0 and 2","failure_mode":"AutoLend overwrites AutoRange triggers",
               "invariant":"each configured automation mode must retain its own trigger"}}


class ProofPipelineTests(unittest.TestCase):
    def test_render_two_native_tests(self):
        r=poc.render(scenario())
        self.assertEqual(len(r["test_names"]),2)
        self.assertIn("test_candidate_VaultGuard",r["solidity"])
        self.assertIn("test_negative_control_VaultGuard",r["solidity"])
        self.assertIn('assertLt(after_aliceFunds, before_aliceFunds',r["solidity"])
        self.assertIn('assertEq(after_aliceFunds, before_aliceFunds',r["solidity"])
        self.assertTrue(r["controls_derived_by_omitting_enabler"])
        self.assertEqual(r["classification"],"GENERATED_TESTS_UNEXECUTED")

    def test_control_skips_enabler(self):
        src=poc.render(scenario())["solidity"]
        c=src.split("function test_candidate_")[1].split("function test_negative_control_")[0]
        n=src.split("function test_negative_control_")[1]
        self.assertIn("makeState(address)",c)
        self.assertNotIn("makeState(address)",n)
        self.assertIn("withdraw(uint256)",n)

    def test_explicit_control_can_replace(self):
        d=scenario(); d["negative_control"]=[d["actions"][0]]
        r=poc.render(d)
        self.assertFalse(r["controls_derived_by_omitting_enabler"])

    def test_requires_real_control(self):
        d=scenario();d["actions"]=[d["actions"][2]]
        with self.assertRaises(ValueError):poc.render(d)

    def test_rejects_unreviewed_intent(self):
        d=scenario();d["operator_reviewed_intent"]=False
        with self.assertRaises(ValueError):poc.render(d)

    def test_blocks_signature_injection(self):
        d=scenario();d["actions"][0]["signature"]='prepare(uint256));vm.stopPrank()'
        with self.assertRaises(ValueError):poc.render(d)

    def test_blocks_variable_injection(self):
        d=scenario();d["actions"][2]["actor"]="alice); vm.startPrank(mallory"
        with self.assertRaises(ValueError):poc.render(d)

    def test_blocks_arbitrary_solidity_import(self):
        d=scenario();d["fixture"]["import"]="../evil.sol"
        with self.assertRaises(ValueError):poc.render(d)

    def test_blocks_u256_overflow(self):
        d=scenario();d["actions"][0]["args"][0]["literal"]=str(2**256)
        with self.assertRaises(ValueError):poc.render(d)

    def test_type_mismatch_and_float(self):
        d=scenario();d["actions"][0]["args"][0]["literal"]=0.5
        with self.assertRaises(ValueError):poc.render(d)

    def test_hash_determinism(self):
        a=poc.render(scenario());b=poc.render(scenario())
        self.assertEqual(a["sha256"],b["sha256"])
        self.assertEqual(a["sha256"],hashlib.sha256(a["solidity"].encode()).hexdigest())

    def test_native_plan_compatible_fields(self):
        p=poc.execution_plan(poc.render(scenario()))
        self.assertEqual({r["role"] for r in p["cases"]},{"candidate","negative-control"})
        self.assertEqual({r["pair_id"] for r in p["cases"]},{"bp-sequence-pair"})
        self.assertEqual(p["cases"][0]["argv"][0],"forge")

    def test_disposable_install_requires_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self._git_repo(root)
            d=scenario();d["source_revision"]=subprocess.check_output(["git","rev-parse","HEAD"],cwd=root,text=True).strip()
            with self.assertRaises(ValueError):poc.install_disposable(poc.render(d),root)

    @staticmethod
    def _git_repo(root):
        (root/"README").write_text("fixture checkout\n")
        for argv in (["git","init","-q"],["git","add","README"],
                     ["git","-c","user.name=Test","-c","user.email=test@example.com","commit","-qm","init"]):
            subprocess.run(argv,cwd=root,check=True,stdout=subprocess.DEVNULL)

    def test_disposable_installs_only_at_pinned_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self._git_repo(root)
            (root/".bounty-pilot-disposable-proof").write_text("I_CONTROL_THIS_DISPOSABLE_CHECKOUT\n")
            with self.assertRaises(ValueError):poc.install_disposable(poc.render(scenario()),root)
            d=scenario();d["source_revision"]=subprocess.check_output(["git","rev-parse","HEAD"],cwd=root,text=True).strip()
            bundle=poc.render(d)
            result=poc.install_disposable(bundle,root)
            self.assertEqual(result["classification"],"SOURCE_INSTALLED_NOT_COMPILED_OR_EXECUTED")
            self.assertTrue((root/bundle["test_file"]).exists())
            with self.assertRaises(ValueError):poc.install_disposable(bundle,root)

    def test_emit_create_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/"bundle"
            r=poc.emit(scenario(),out)
            self.assertEqual((out/"BPSequence.t.sol").read_text(),poc.render(scenario())["solidity"])
            self.assertTrue((out/"runner-plan.json").exists())
            with self.assertRaises(ValueError):poc.emit(scenario(),out)


class IntentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        (self.root/"docs").mkdir();(self.root/"src").mkdir()
        self.spec="Positions must retain protection after replacement.\nThe interface can display an animation.\n"
        self.source="contract Hook {\n function migrate() external {}\n}\n"
        (self.root/"docs/spec.md").write_text(self.spec)
        (self.root/"src/Hook.sol").write_text(self.source)
        for argv in (["git","init","-q"], ["git","add","."],
                     ["git","-c","user.name=Test","-c","user.email=test@example.com","commit","-qm","init"]):
            subprocess.run(argv,cwd=self.root,check=True,stdout=subprocess.DEVNULL)
        self.rev=subprocess.check_output(["git","rev-parse","HEAD"],cwd=self.root,text=True).strip()

    def tearDown(self):self.tmp.cleanup()

    def manifest(self):
        return {"schema_version":1,"source_revision":self.rev,"requirements":[{
            "id":"REQ-001","kind":"lifecycle_rights",
            "basis":{"file":"docs/spec.md","line":1,
                     "quote":"Positions must retain protection after replacement.",
                     "sha256":hashlib.sha256(self.spec.encode()).hexdigest()},
            "source_anchors":[{"file":"src/Hook.sol","line":2,"needle":"migrate()",
                               "sha256":hashlib.sha256(self.source.encode()).hexdigest()}],
            "expected_behavior":"Protection still executes for successor position",
            "negative_control":"Position without migration retains its protection",
            "operator_reviewed":True}]}

    def test_extract_grounded(self):
        r=intent.extract(self.root,["docs/spec.md"])
        self.assertEqual(r["source_revision"],self.rev)
        self.assertEqual(r["requirements"][0]["cue_strength"],"strong")
        self.assertTrue(any(x["cue_strength"]=="weak" for x in r["requirements"]))

    def test_source_anchored_review(self):
        r=intent.verify(self.root,self.manifest())
        self.assertEqual(r["requirements"][0]["status"],"SOURCE_ANCHORED_REVIEWED_INTENT_NOT_VERIFIED")

    def test_hash_drift_refused(self):
        m=self.manifest();(self.root/"docs/spec.md").write_text(self.spec+"extra\n")
        with self.assertRaises(ValueError):intent.verify(self.root,m)

    def test_line_drift_refused(self):
        m=self.manifest();m["requirements"][0]["source_anchors"][0]["line"]=1
        with self.assertRaises(ValueError):intent.verify(self.root,m)

    def test_unreviewed_stays_unreviewed(self):
        m=self.manifest();m["requirements"][0]["operator_reviewed"]=False
        r=intent.verify(self.root,m)
        self.assertEqual(r["requirements"][0]["status"],"INTENT_NEEDS_OPERATOR_REVIEW")

    def test_observation_not_counted_as_native(self):
        r=intent.verify(self.root,self.manifest())
        o={"source_revision":self.rev,"results":[{"requirement_id":"REQ-001",
            "candidate":{"satisfies":False},"negative_control":{"satisfies":True}}]}
        out=intent.compare(r,o)
        self.assertEqual(out["comparisons"][0]["status"],"REPORTED_INTENT_CONFLICT_REQUIRES_NATIVE_PAIR")
        self.assertIn("independent economic impact",out["comparisons"][0]["missing_evidence"])

    def test_rev_mismatch_refused(self):
        m=self.manifest();m["source_revision"]=REV
        with self.assertRaises(ValueError):intent.verify(self.root,m)

    def test_no_escape(self):
        with self.assertRaises(ValueError):intent._file(self.root,"../etc/passwd")


class NoveltyTests(unittest.TestCase):
    def test_exact_mechanism_different_impact(self):
        c=report("30");k=report("63");k["impact"]="remint at unconfigured tick"
        out=novelty.analyze({"schema_version":1,"candidate":c,"known":[k]})
        self.assertEqual(out["duplicate_risk"],"REVIEW_LIKELY_DUPLICATE")
        self.assertTrue(out["matches"][0]["impact_differs"])

    def test_title_irrelevant(self):
        a=report("30");b=report("63");a["title"]="automation stops";b["title"]="wrong ticks"
        self.assertEqual(novelty.analyze({"schema_version":1,"candidate":a,"known":[b]})["match_count"],1)

    def test_other_project_not_duplicate(self):
        out=novelty.analyze({"schema_version":1,"candidate":report("30"),"known":[report("63","other-contest")]})
        self.assertEqual(out["match_count"],0)

    def test_unknown_remote_never_unique(self):
        out=novelty.analyze({"schema_version":1,"candidate":report("30"),"known":[]})
        self.assertEqual(out["duplicate_risk"],"NO_LOCAL_MATCH_REMOTE_UNCHECKED")

    def test_distinct_mechanism_not_match(self):
        k=report("63");k["root_cause"]["failure_mode"]="oracle sign verification bypass"
        k["root_cause"]["state_resource"]="permit signature nonce"
        out=novelty.analyze({"schema_version":1,"candidate":report("30"),"known":[k]})
        self.assertEqual(out["match_count"],0)

    def test_duplicate_record_rejected(self):
        k=report("63")
        with self.assertRaises(ValueError):novelty.analyze({"schema_version":1,"candidate":report("30"),"known":[k,k]})

    def test_fingerprint_stable(self):
        d={"schema_version":1,"candidate":report("30"),"known":[]}
        self.assertEqual(novelty.analyze(d)["mechanism_sha256"],novelty.analyze(d)["mechanism_sha256"])


if __name__=="__main__":unittest.main()