import unittest
from review_form import template, evaluate, SECTIONS

def filled():
    form=template()
    form["review_id"]="example"
    form["reviewer"]="operator"
    for key in SECTIONS:
        form["sections"][key]={"status":"documented","note":"Manually recorded example","sources":["local-note"]}
    return form

class ReviewFormTests(unittest.TestCase):
    def test_blank_form_incomplete(self):
        result=evaluate(template())
        self.assertFalse(result["documentation_complete"])
        self.assertEqual(len(result["unresolved_sections"]),15)
        self.assertEqual(result["technical_validity"],"not_assessed")

    def test_complete_is_not_proof(self):
        result=evaluate(filled())
        self.assertTrue(result["documentation_complete"])
        self.assertEqual(result["technical_validity"],"not_assessed")

    def test_core_cause_cannot_be_skipped(self):
        form=filled()
        form["sections"]["root_cause"]["status"]="not_applicable"
        result=evaluate(form)
        self.assertFalse(result["documentation_complete"])
        self.assertIn("root_cause",result["unresolved_sections"])

    def test_optional_not_applicable_requires_note(self):
        form=filled()
        form["sections"]["negative_control"]={"status":"not_applicable","note":"Not applicable to this documentation review","sources":[]}
        self.assertTrue(evaluate(form)["documentation_complete"])
        form["sections"]["negative_control"]["note"]=""
        self.assertFalse(evaluate(form)["documentation_complete"])

    def test_documented_requires_reference(self):
        form=filled()
        form["sections"]["impact"]["sources"]=[]
        self.assertIn("impact",evaluate(form)["missing_fields"])

    def test_malformed_and_duplicate_sources(self):
        form=filled()
        del form["sections"]["root_cause"]
        with self.assertRaises(ValueError):
            evaluate(form)
        form=filled()
        form["sections"]["root_cause"]["sources"]=["local-note","local-note"]
        with self.assertRaises(ValueError):
            evaluate(form)

    def test_open_question_blocks_completeness(self):
        form=filled()
        form["sections"]["limitations"]["status"]="unresolved"
        self.assertFalse(evaluate(form)["documentation_complete"])

if __name__=="__main__":
    unittest.main()
