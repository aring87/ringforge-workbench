"""The split-API rule: does it fire on the thing it was written for?

The rule's own header said "**This has not yet been scanned against a real
memory dump**", and the proven/unproven ledger in docs/HANDOFF.md carried it as
*no false positives on real dumps; detection still untested*. Its subject had
never been in memory on a run that scanned -- the parent died before its spawn
image could be taken -- so nine months of clean scans said nothing about whether
it can detect.

That is answerable without a detonation. Stage 2 is on the artifact drive, and
this host has ordinary processes to use as negative controls.

**The negative control cannot be a dump of this process**, and the first attempt
made exactly that mistake: it matched before the payload was added. Two reasons,
both guaranteed rather than unlucky --

  * stage 2 gets unwrapped into this process's heap in order to scan it, so a
    self-dump contains it; and
  * the compiled rules hold `"kernel "`, `"Virtual "` and the rest as literals,
    so the scanner's address space matches the scanner's own rules.

A scanner scanning itself always matches. The control has to be a process that
has touched neither the rules nor the sample.

Stage 2 is live malware. It is XOR-wrapped on the artifact drive and unwrapped
**in memory only**; nothing here writes a runnable copy out.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import pytest

pytestmark = pytest.mark.slow

RULES = (Path(__file__).resolve().parents[2] / "tools" / "yara" / "local"
         / "ringforge_split_api_loader.yar")
STAGE2 = Path(r"G:\ringforge-artifacts\422e30ed_stage2"
              r"\stage2_assembly_e139c422.xor9")

SPLIT_API = "RingForge_Split_API_Injection_Loader"
STAGE2_RULE = "RingForge_Loader_422e30ed_Stage2"


def _requirements():
    yara = pytest.importorskip("yara", reason="yara-python not installed")
    if not RULES.is_file():
        pytest.skip(f"rule file not present: {RULES}")
    if not STAGE2.is_file():
        pytest.skip(f"stage 2 not on the artifact drive: {STAGE2}")
    return yara


def _stage2_bytes() -> bytes:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
    from dotnet_meta import xor_unwrap

    return xor_unwrap(STAGE2.read_bytes())


class SplitApiRuleDetects(unittest.TestCase):
    def setUp(self):
        self.yara = _requirements()
        self.rules = self.yara.compile(filepath=str(RULES))

    def test_it_fires_on_stage_2(self):
        """The claim the ledger could not make: it detects its own subject."""
        hits = {m.rule for m in self.rules.match(data=_stage2_bytes())}
        self.assertIn(SPLIT_API, hits)
        self.assertIn(STAGE2_RULE, hits)

    def test_every_split_fragment_is_present(self):
        """Not just "the condition passed" -- each fragment the rule keys on.

        A condition can pass on a subset. If the fragments ever stop appearing
        because the loader changed its splitting, this says which one went.
        """
        matches = [m for m in self.rules.match(data=_stage2_bytes())
                   if m.rule == SPLIT_API]
        self.assertTrue(matches)
        found = {s.identifier for s in matches[0].strings}
        for ident in ("$k_kernel", "$k_dll", "$f_virtual", "$resolve",
                      "$f_write", "$f_process", "$f_alloc", "$f_memory"):
            self.assertIn(ident, found, f"{ident} no longer matches")

    def _benign_dumps(self, count=3):
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
        from benign_baseline import DEFAULT_MAX_VIRTUAL, _candidates, _dump_process

        out = []
        with tempfile.TemporaryDirectory() as tmp:
            for pid, name in _candidates(count + 2, DEFAULT_MAX_VIRTUAL):
                path = Path(tmp) / f"{Path(name).stem}_{pid}.dmp"
                ok, _why = _dump_process(pid, path)
                if ok:
                    out.append((f"{name} ({pid})", path.read_bytes()))
                if len(out) >= count:
                    break
        return out

    def test_unrelated_processes_do_not_match(self):
        dumps = self._benign_dumps()
        if not dumps:
            self.skipTest("could not dump any unrelated process")
        for label, blob in dumps:
            hits = [m.rule for m in self.rules.match(data=blob)]
            self.assertEqual(hits, [], f"false positive on {label}")

    def test_it_fires_when_the_payload_is_resident_in_a_real_dump(self):
        """A dump is scanned as raw bytes, so a genuine process image with the
        assembly appended is a faithful stand-in for the payload being resident:
        same surrounding noise, same size class, same encodings."""
        dumps = self._benign_dumps()
        if not dumps:
            self.skipTest("could not dump any unrelated process")
        stage2 = _stage2_bytes()
        for label, blob in dumps:
            hits = {m.rule for m in self.rules.match(data=blob + stage2)}
            self.assertIn(SPLIT_API, hits, f"missed the payload in {label}")


if __name__ == "__main__":
    unittest.main()
