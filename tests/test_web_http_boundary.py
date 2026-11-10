"""Offline paired HTTP-parser observations: no network or payload delivery."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts"
SPEC = importlib.util.spec_from_file_location("web_http_boundary_for_tests",
                                              SCRIPTS / "web_http_boundary.py")
http = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(http)


def capture(name, *, offset=42, auth="user-a", body=None, count=1):
    rows = []
    if count:
        rows.append({"start_offset": 0, "end_offset": offset,
                     "method": "GET", "canonical_route": "/api/own",
                     "authority": "lab.local", "auth_context": auth,
                     "cache_key": "own", "body_sha256": body})
    return {"parser_id": name, "parser_build": name + "-fixture-v1",
            "input_sha256": "a" * 64,
            "request_count": count, "consumed_bytes": offset if count else 0,
            "requests": rows}


def trial(front=None, back=None):
    return {"front": front or capture("front"), "back": back or capture("back")}


def document(candidate=None, control=None):
    return {"schema_version": 1, "environment": "researcher_owned_isolated_lab",
            "pairs": [{"pair_id": "p-01",
                       "candidate": candidate or trial(capture("front"), capture("back", offset=45)),
                       "negative_control": control or trial()}]}


class HTTPBoundaryTests(unittest.TestCase):
    def test_controlled_framing_disagreement(self):
        r = http.compare(document())
        self.assertEqual(r["controlled_difference_leads"], 1)
        self.assertEqual(r["results"][0]["candidate_differences"],
                         ["HTTP_MESSAGE_BOUNDARY_DIFFERENCE"])
        self.assertEqual(r["confirmed_vulnerabilities"], 0)
        self.assertEqual(r["network_requests"], 0)
        self.assertEqual(r["results"][0]["status"],
                         "CONTROLLED_PARSER_DIFFERENCE_IN_SUPPLIED_TRACES")

    def test_control_also_differs_is_not_promoted(self):
        bad_control = trial(capture("front"), capture("back", offset=45))
        r = http.compare(document(control=bad_control))
        self.assertEqual(r["controlled_difference_leads"], 0)
        self.assertEqual(r["results"][0]["status"], "INCONCLUSIVE_CONTROL_ALSO_DIFFERS")

    def test_no_difference(self):
        result = http.compare(document(candidate=trial()))
        self.assertEqual(result["results"][0]["candidate_differences"], [])

    def test_auth_and_cache_context_differences(self):
        r = http.compare(document(candidate=trial(
            capture("front"), capture("back", auth="user-b"))))
        self.assertEqual(r["results"][0]["candidate_differences"],
                         ["HTTP_AUTHORIZATION_CONTEXT_DIFFERENCE"])
        back = capture("back")
        back["requests"][0]["cache_key"] = "cross-account-cache"
        r = http.compare(document(candidate=trial(capture("front"), back)))
        self.assertEqual(r["results"][0]["candidate_differences"],
                         ["HTTP_CACHE_KEY_DIFFERENCE"])

    def test_reject_mismatched_input_hash(self):
        x = document()
        x["pairs"][0]["candidate"]["back"]["input_sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "same input"):
            http.compare(x)

    def test_reject_different_parser_build_between_candidate_and_control(self):
        x = document()
        x["pairs"][0]["negative_control"]["front"]["parser_build"] = "altered"
        with self.assertRaises(ValueError):
            http.compare(x)

    def test_reject_invalid_environment_and_hidden_fields(self):
        x = document()
        x["environment"] = "production"
        with self.assertRaises(ValueError):
            http.compare(x)
        x = document()
        x["pairs"][0]["candidate"]["front"]["raw_http"] = "SECRET"
        with self.assertRaises(ValueError):
            http.compare(x)

    def test_reject_overlapping_boundaries_and_invalid_counts(self):
        x = document()
        c = x["pairs"][0]["candidate"]["front"]
        c["request_count"] = 2
        c["requests"].append(dict(c["requests"][0]))
        with self.assertRaises(ValueError):
            http.compare(x)

    def test_output_never_contains_raw_auth_or_request_bodies(self):
        doc = document()
        result = http.compare(doc)
        self.assertNotIn("user-a", json.dumps(result))
        self.assertNotIn("lab.local", json.dumps(result))
        self.assertNotIn("/api/own", json.dumps(result))

    def test_private_create_only_output_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "result.json"
            http._save(p, http.compare(document()))
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                http._save(p, {})


if __name__ == "__main__":
    unittest.main()
