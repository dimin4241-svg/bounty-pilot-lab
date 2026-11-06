"""Synthetic, offline tests for conservative cross-contract lead generation."""
import importlib.util
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "cross_contract_seams.py"
spec = importlib.util.spec_from_file_location("cross_contract_seams", MODULE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def fn(fid, name, body):
    return {"nodeType": "FunctionDefinition", "id": fid, "name": name,
            "visibility": "public", "src": "0:10:0", "body": {"nodeType": "Block", "statements": body}}

def call(typ, member):
    return {"nodeType": "FunctionCall", "src": "1:2:0", "expression": {
        "nodeType": "MemberAccess", "memberName": member,
        "expression": {"nodeType": "Identifier", "name": "target",
                       "typeDescriptions": {"typeString": typ}}}}

def fixture():
    return {"output": {"sources": {"src/System.sol": {"ast": {"nodes": [
        {"nodeType": "ContractDefinition", "id": 1, "name": "Router", "nodes": [
            fn(10, "withdraw", [call("contract Vault", "release")])]},
        {"nodeType": "ContractDefinition", "id": 2, "name": "Vault", "nodes": [
            fn(20, "release", [{"nodeType": "Assignment", "src": "4:2:0",
                                 "leftHandSide": {"nodeType": "Identifier", "referencedDeclaration": 99}}])]}
    ]}}}}}

class CrossContractSeamTests(unittest.TestCase):
    def test_typed_edge_and_review_lead(self):
        result = mod.analyze(fixture())
        self.assertEqual(len(result["edges"]), 1)
        self.assertEqual(result["paths"], [["1", "2"]])
        self.assertEqual(result["leads"][0]["status"], "UNVERIFIED")
        self.assertEqual(result["leads"][0]["contracts"], ["1", "2"])

    def test_unresolved_call_never_invents_edge(self):
        data = fixture()
        expression = data["output"]["sources"]["src/System.sol"]["ast"]["nodes"][0]["nodes"][0]["body"]["statements"][0]["expression"]["expression"]
        expression["typeDescriptions"]["typeString"] = "address"
        result = mod.analyze(data)
        self.assertFalse(result["edges"])
        self.assertEqual(len(result["unresolved_calls"]), 1)

    def test_no_state_write_no_lead(self):
        data = fixture()
        data["output"]["sources"]["src/System.sol"]["ast"]["nodes"][1]["nodes"][0]["body"]["statements"] = []
        result = mod.analyze(data)
        self.assertEqual(len(result["edges"]), 1)
        self.assertFalse(result["leads"])

    def test_depth_bounds(self):
        with self.assertRaises(ValueError):
            mod.analyze(fixture(), max_depth=9)

if __name__ == "__main__":
    unittest.main()
