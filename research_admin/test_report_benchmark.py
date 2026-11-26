import unittest
from report_benchmark import score, compare, adjudicate

TASKS=[
    {"id":"a","question":"Was the order delivered?","documents":{"d":"Delivery confirmed."}},
    {"id":"b","question":"Was a refund issued?","documents":{"d":"Refund was declined."}},
    {"id":"c","question":"Was a receipt signed?","documents":{"d":"Receipt status not recorded."}}
]
REFS=[
    {"id":"a","label":"supported","source_ids":["d"]},
    {"id":"b","label":"refuted","source_ids":["d"]},
    {"id":"c","label":"unresolved","source_ids":["d"]}
]
def answer(key,label,sources=None,reason="Document reviewed"):
    return {"id":key,"label":label,"source_ids":["d"] if sources is None else sources,"reason":reason}

class BenchmarkTests(unittest.TestCase):
    def test_complete(self):
        data=score(TASKS,REFS,[answer("a","supported"),answer("b","refuted"),answer("c","unresolved")])
        self.assertEqual(data["passed"],3)
        self.assertEqual(data["accuracy"],1)

    def test_missing_cases_not_ignored(self):
        data=score(TASKS,REFS,[answer("a","supported")])
        self.assertEqual(data["cases"],3)
        self.assertEqual(data["passed"],1)
        self.assertEqual(data["answered"],1)
        self.assertEqual(score(TASKS,REFS,[])["passed"],0)

    def test_false_sources_and_empty_reason(self):
        data=score(TASKS,REFS,[answer("a","supported",["fake"]),answer("b","refuted",reason=" "),answer("c","supported")])
        self.assertEqual(data["passed"],0)

    def test_duplicate_and_unknown_ids_rejected(self):
        for answers in ([answer("a","supported")]*2,[answer("z","supported")]):
            with self.assertRaises(ValueError):
                score(TASKS,REFS,answers)

    def test_comparison_regression(self):
        a=[answer("a","supported"),answer("b","refuted")]
        b=[answer("b","refuted"),answer("c","unresolved")]
        result=compare(TASKS,REFS,a,b)
        self.assertEqual(result["delta"],0)
        self.assertEqual(result["regressed"],1)
        self.assertEqual(result["improved"],1)
        self.assertFalse(result["no_regression"])

    def test_reference_mismatch(self):
        with self.assertRaises(ValueError):
            score(TASKS,REFS[:-1],[])
        with self.assertRaises(ValueError):
            score(TASKS,[dict(r,source_ids=["bad"]) for r in REFS],[])

    def test_manual_review_rejects_wrong_explanation(self):
        answers = [answer("a", "supported", reason="The order was never delivered")]
        reviews = [{"id":"a","decision":"rejected","reviewer":"human",
                    "note":"Explanation contradicts the document"}]
        result = adjudicate(TASKS, REFS, answers, reviews)
        self.assertEqual(result["passed"], 1)
        self.assertEqual(result["reviewed_passed"], 0)
        self.assertTrue(result["review_complete"])

    def test_pending_and_uncertain_reviews(self):
        answers = [answer("a","supported"), answer("b","refuted")]
        reviews = [{"id":"a","decision":"uncertain","reviewer":"human","note":"Needs review"}]
        result = adjudicate(TASKS, REFS, answers, reviews)
        self.assertFalse(result["review_complete"])
        self.assertEqual(result["reviewed_passed"], 0)
        self.assertFalse(adjudicate(TASKS, REFS, [], [])["review_complete"])

    def test_accepted_review_does_not_override_structural_error(self):
        answers = [answer("a","refuted"), answer("b","refuted")]
        reviews = [{"id":key,"decision":"accepted","reviewer":"human","note":"Reviewed"}
                   for key in ("a","b")]
        result = adjudicate(TASKS, REFS, answers, reviews)
        self.assertEqual(result["reviewed_passed"], 1)
        self.assertAlmostEqual(result["reviewed_accuracy"], 1/3)

    def test_invalid_manual_reviews(self):
        answers = [answer("a","supported")]
        review = {"id":"a","decision":"accepted","reviewer":"human","note":"Reviewed"}
        for reviews in ([dict(review,id="b")], [review,review],
                        [dict(review,note="")], [dict(review,decision="unknown")]):
            with self.subTest(reviews=reviews), self.assertRaises(ValueError):
                adjudicate(TASKS, REFS, answers, reviews)

if __name__=="__main__":
    unittest.main()
