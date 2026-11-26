import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from sarif_summary import summarize, read_local, MAX_BYTES

def raw(runs):
    return json.dumps({"version":"2.1.0","runs":runs}).encode()

class SarifSummaryTests(unittest.TestCase):
    def test_inventory(self):
        data = raw([{"results":[{"level":"warning"},{"level":"note"},{}]},
                    {"results":[{"level":"error"}]}])
        result = summarize(data)
        self.assertEqual(result["runs"],2)
        self.assertEqual(result["result_count"],4)
        self.assertEqual(result["reported_levels"]["warning"],1)
        self.assertEqual(result["reported_levels"]["unspecified"],1)
        self.assertEqual(result["sha256"],hashlib.sha256(data).hexdigest())
        self.assertEqual(result["technical_validity"],"not_assessed")

    def test_no_content_export(self):
        data = raw([{"results":[{"level":"note","message":{"text":"PRIVATE_TEXT"},
            "locations":[{"physicalLocation":{"artifactLocation":{"uri":"PRIVATE_URI"}}}]}]}])
        summary = json.dumps(summarize(data))
        self.assertNotIn("PRIVATE_TEXT",summary)
        self.assertNotIn("PRIVATE_URI",summary)

    def test_empty(self):
        self.assertEqual(summarize(raw([{}]))["result_count"],0)

    def test_invalid(self):
        for data in (b"{}", b"[]", b"not JSON", raw([None]), raw([{"results":None}]),
                     raw([{"results":[{"level":"unknown"}]}]), raw([{"results":[1]}])):
            with self.subTest(data=data), self.assertRaises(ValueError):
                summarize(data)

    def test_size_limit(self):
        with self.assertRaises(ValueError):
            summarize(b" " * (MAX_BYTES+1))

    def test_regular_file_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"fixture.sarif"
            p.write_bytes(raw([]))
            self.assertEqual(read_local(p),raw([]))
            link=Path(tmp)/"link.sarif"
            link.symlink_to(p)
            with self.assertRaises(OSError):
                read_local(link)
            fifo=Path(tmp)/"pipe"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                read_local(fifo)

if __name__=="__main__":
    unittest.main()
