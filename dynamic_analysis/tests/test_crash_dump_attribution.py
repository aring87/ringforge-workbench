"""A crash dump of the sample's *child* must attribute to the sample.

Run `d7cc5044` produced `RegSvcs.exe.9132.dmp` -- the only image of the hollowed
process the whole run managed to capture -- and recorded
`attributed_to_sample: false`. Pid 9132's parent was the sample and
`missed_descendants` said so. The tree was known; the collector was the only
thing not being told about it.

Two bugs stacked, which is why it looked like one:

  * the PID never parsed. The code read index 1 of the dotted name, right for
    `RegSvcs.10784.dmp` and wrong for `RegSvcs.exe.9132.dmp` where index 1 is
    `"exe"`. WER writes both shapes.
  * attribution was by image name alone, against a set seeded from the sample's
    own name and the processes the memory watcher *observed* -- so a child it
    never got to see, which is precisely the short-lived hollowing target these
    dumps exist to capture, could not be in it.
"""
import unittest

from dynamic_analysis.crash_evidence import _parse_wer_dump_name


class WerDumpNames(unittest.TestCase):
    """Both shapes WER writes, and the digits-in-the-image-name case."""

    def test_the_shape_from_run_d7cc5044(self):
        self.assertEqual(_parse_wer_dump_name("RegSvcs.exe.9132.dmp"),
                         ("regsvcs.exe", 9132))

    def test_the_shape_the_old_comment_described(self):
        self.assertEqual(_parse_wer_dump_name("RegSvcs.10784.dmp"),
                         ("regsvcs.exe", 10784))

    def test_an_image_name_containing_digits(self):
        # The PID is the *last* numeric component, not the first one found.
        self.assertEqual(_parse_wer_dump_name("7z.exe.99.dmp"), ("7z.exe", 99))

    def test_a_dotted_image_name(self):
        self.assertEqual(_parse_wer_dump_name("my.app.exe.512.dmp"),
                         ("my.app.exe", 512))

    def test_the_extension_is_kept(self):
        # The bare stem "regsvcs" is not in HOLLOWING_TARGETS, which once scored
        # a crash-dump image `present` where a live dump of the same image
        # scored `strong`.
        name, _pid = _parse_wer_dump_name("RegSvcs.exe.9132.dmp")
        self.assertTrue(name.endswith(".exe"))

    def test_no_pid_in_the_name_is_none_not_a_guess(self):
        self.assertEqual(_parse_wer_dump_name("notepad.dmp"), ("notepad.exe", None))


def _collector(tmp, dumps):
    """A collector primed with `dumps` as newly-appeared files."""
    from pathlib import Path

    from dynamic_analysis.crash_evidence import CrashDumpCollector

    folder = Path(tmp) / "werdumps"
    folder.mkdir(parents=True, exist_ok=True)
    c = CrashDumpCollector(dump_folder=folder, output_dir=Path(tmp) / "out")
    c.snapshot()
    for name in dumps:
        (folder / name).write_bytes(b"MDMP" + bytes(64))
    return c


class Attribution(unittest.TestCase):
    def setUp(self):
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = self._tmp.name

    def _one(self, **kwargs):
        c = _collector(self.tmp, ["RegSvcs.exe.9132.dmp"])
        result = c.collect(**kwargs)
        self.assertEqual(len(result["dumps"]), 1)
        return result["dumps"][0]

    def test_the_regression_a_child_of_the_sample_attributes_by_pid(self):
        record = self._one(sample_names={"sample.exe"}, sample_pids={11136, 9132})
        self.assertTrue(record["attributed_to_sample"])
        self.assertEqual(record["pid"], 9132)

    def test_name_only_would_still_have_failed(self):
        # The old behaviour, isolated: the child's name is not the sample's, and
        # the watcher never observed it, so the name set cannot contain it.
        record = self._one(sample_names={"sample.exe"}, sample_pids=None)
        self.assertFalse(record["attributed_to_sample"])

    def test_name_still_works_when_lineage_is_unavailable(self):
        record = self._one(sample_names={"regsvcs.exe"}, sample_pids=None)
        self.assertTrue(record["attributed_to_sample"])

    def test_an_unrelated_crash_is_not_attributed(self):
        c = _collector(self.tmp, ["chrome.exe.4242.dmp"])
        record = c.collect(sample_names={"sample.exe"}, sample_pids={11136})["dumps"][0]
        self.assertFalse(record["attributed_to_sample"])
        self.assertEqual(record["pid"], 4242)

    def test_no_lineage_at_all_attributes_everything(self):
        # The documented degrade: unknown tree means count it, never drop it.
        record = self._one(sample_names=None, sample_pids=None)
        self.assertTrue(record["attributed_to_sample"])

    def test_the_attributed_count_follows(self):
        c = _collector(self.tmp, ["RegSvcs.exe.9132.dmp", "chrome.exe.4242.dmp"])
        result = c.collect(sample_names={"sample.exe"}, sample_pids={9132})
        self.assertEqual(result["counts"]["attributed"], 1)
        self.assertEqual(result["counts"]["dumps"], 2)


if __name__ == "__main__":
    unittest.main()
