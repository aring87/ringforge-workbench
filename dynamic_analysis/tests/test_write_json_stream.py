"""`write_json` streams, and writes exactly what it wrote before.

Amadey `5d2d7935d6fa` (29 Sep) died on MemoryError inside `json.dumps` while
writing a 1,697 MB Procmon capture's parsed events: `dumps` builds the whole
document as one string before writing. `write_json` now uses `json.dump`.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from dynamic_analysis import utils
from dynamic_analysis.utils import write_json

SAMPLE = {
    "events": [{"pid": i, "path": f"C:\\Users\\x\\f{i}.txt", "ok": i % 2 == 0,
                "note": None, "size": i * 1.5} for i in range(50)],
    "unicode": "Cotización -- \u00e9\u4e2d",
    "empty": {}, "nested": [[], [1, [2, {"k": "v"}]]],
}


class WriteJsonTests(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="rf-wj-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def test_bytes_identical_to_the_old_writer(self) -> None:
        """Every JSON file the pipeline writes goes through here; a reader
        comparing hashes across old and new runs must see no difference."""
        old = self.tmp / "old.json"
        old.write_text(json.dumps(SAMPLE, indent=2), encoding="utf-8")
        new = write_json(self.tmp / "new.json", SAMPLE)
        self.assertEqual(new.read_bytes(), old.read_bytes())

    def test_it_never_builds_the_whole_document(self) -> None:
        """`json.dumps` is what ran out of memory. It must not be called."""
        with mock.patch.object(utils.json, "dumps",
                               side_effect=AssertionError("dumps was called")):
            path = write_json(self.tmp / "x.json", SAMPLE)
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), SAMPLE)

    def test_parent_directories_are_created(self) -> None:
        path = write_json(self.tmp / "a" / "b" / "c.json", [1, 2])
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), [1, 2])

    def test_no_byte_order_mark(self) -> None:
        path = write_json(self.tmp / "bom.json", SAMPLE)
        self.assertFalse(path.read_bytes().startswith(b"\xef\xbb\xbf"))


if __name__ == "__main__":
    unittest.main()
