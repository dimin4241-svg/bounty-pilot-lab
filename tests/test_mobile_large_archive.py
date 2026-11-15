"""Memory-bounded archive inventory regression tests."""
import hashlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "bounty-pilot" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import mobile_lab

XML = (b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
       b'package="fixture"><application><activity android:name=".Main" '
       b'android:exported="false"/></application></manifest>')


class LargeArchiveTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.path = Path(t.name) / "large.apk"

    def _archive(self, prefix_size=0):
        if prefix_size:
            # ZIP allows a leading arbitrary self-extracting prefix. Seek to
            # create a *sparse* file: no big fixture bytes or peak allocations.
            with self.path.open("wb") as f:
                f.seek(prefix_size)
                f.write(b"Z")
        with zipfile.ZipFile(self.path, "a", allowZip64=True) as z:
            z.writestr("AndroidManifest.xml", XML)
            z.writestr("classes.dex", b"dex\n035\0")
        return self.path

    def test_large_apk_streaming_over_old_200_mib_limit(self):
        path = self._archive(201 * 1024 * 1024)
        self.assertGreater(path.stat().st_size, 200 * 1024 * 1024)
        with mock.patch.object(mobile_lab, "_regular_file", side_effect=AssertionError(
                "archive should never be read whole")):
            result, meta = mobile_lab._inspect_artifact(path)
        self.assertEqual(result["package"], "fixture")
        self.assertEqual(meta["artifact_bytes"], path.stat().st_size)
        self.assertEqual(len(meta["artifact_sha256"]), 64)
        self.assertEqual(meta["dex_entries"], 1)
        self.assertFalse(meta["binary_code_inspected"])

    def test_stream_digest_matches_sha256(self):
        self._archive()
        digest, count = mobile_lab._regular_digest_stream(self.path, mobile_lab.MAX_ARCHIVE)
        self.assertEqual(count, self.path.stat().st_size)
        self.assertEqual(digest, hashlib.sha256(self.path.read_bytes()).hexdigest())

    def test_rejects_declared_uncompressed_bomb(self):
        self._archive()
        with mock.patch.object(mobile_lab, "MAX_TOTAL_UNCOMPRESSED", 2):
            with self.assertRaisesRegex(ValueError, "uncompressed"):
                mobile_lab._inspect_artifact(self.path)

    def test_rejects_symlink_source(self):
        self._archive()
        link = self.path.with_name("symlink.apk")
        link.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            mobile_lab._inspect_artifact(link)

    def test_rejects_archive_above_bound(self):
        self._archive()
        with mock.patch.object(mobile_lab, "MAX_ARCHIVE", 100):
            with self.assertRaisesRegex(ValueError, "size limit"):
                mobile_lab._inspect_artifact(self.path)


if __name__ == "__main__":
    unittest.main()
