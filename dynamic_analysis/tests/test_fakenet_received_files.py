"""What the sample uploads has to end up in the case directory.

AgentTesla authenticated to the simulated FTP server and uploaded its
stolen-data report. FakeNet's FTP listener is a real FTP server rooted at a real
directory, so the file was written to:

    tools/fakenet/defaultFiles/FakeNet.html

over the top of FakeNet's own default page. Nothing in the case directory
recorded that a file had arrived at all. It was found by hand, and the next
`vm_snapshot.ps1 -Baseline` would have destroyed it -- the single most valuable
artifact the run produced, sitting outside everything the run collects.

Two details drive the design:

* The upload *overwrote* a file that was already there, so watching for new
  names alone would have missed it. The roots are snapshotted by size and mtime
  before launch, and a changed file counts.
* The roots live inside the FakeNet installation, not the case directory, so
  they have to be located from the config before the sample runs. After the
  fact there is no way to tell an uploaded file from one FakeNet ships with.
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from dynamic_analysis.fakenet_runner import (
    MAX_RECEIVED_FILE_BYTES,
    FakeNetSession,
    listener_roots,
)

CONFIG = """[FakeNet]
DivertTraffic: Yes

[Diverter]
NetworkMode: SingleHost

[DNS Server]
Enabled:  True
Listener: DNSListener

[HTTPListener80]
Enabled:  True
Listener: HTTPListener
Webroot:  defaultFiles/

[FTPListener21]
Enabled:  True
Listener: FTPListener
FTPRoot:  defaultFiles/
"""


class _Install:
    """A FakeNet installation laid out the way the real one is."""

    def __init__(self, tmp: str, config_text: str = CONFIG):
        self.root = Path(tmp) / "fakenet"
        self.configs = self.root / "configs"
        self.default_files = self.root / "defaultFiles"
        self.configs.mkdir(parents=True)
        self.default_files.mkdir(parents=True)

        self.binary = self.root / "fakenet.exe"
        self.binary.write_bytes(b"MZ")

        self.config = self.configs / "default.ini"
        self.config.write_text(config_text, encoding="utf-8")

        # What FakeNet ships with and serves.
        self.served = self.default_files / "FakeNet.html"
        self.served.write_text("<html>FakeNet default page</html>", encoding="utf-8")


class ListenerRootTests(unittest.TestCase):
    def test_roots_come_from_the_config(self) -> None:
        with TemporaryDirectory() as tmp:
            install = _Install(tmp)
            roots = listener_roots(config_path=install.config, binary=install.binary)

            self.assertIn(install.default_files.resolve(), roots)

    def test_a_root_is_reported_once_however_many_listeners_share_it(self) -> None:
        # Webroot and FTPRoot both point at defaultFiles/, and collecting the
        # same directory twice would report every upload twice.
        with TemporaryDirectory() as tmp:
            install = _Install(tmp)
            roots = listener_roots(config_path=install.config, binary=install.binary)

            self.assertEqual(len(roots), 1)

    def test_the_default_root_is_watched_without_a_config(self) -> None:
        # A run with no readable config is exactly the run where an upload
        # would otherwise go uncollected.
        with TemporaryDirectory() as tmp:
            install = _Install(tmp)
            roots = listener_roots(config_path=None, binary=install.binary)

            self.assertIn(install.default_files.resolve(), roots)

    def test_an_absent_installation_yields_no_roots(self) -> None:
        with TemporaryDirectory() as tmp:
            missing = Path(tmp) / "nope" / "fakenet.exe"
            self.assertEqual(listener_roots(config_path=None, binary=missing), [])


class ReceivedFileTests(unittest.TestCase):
    def _session(self, tmp: str, install: _Install) -> FakeNetSession:
        """A session with its pre-launch snapshot already taken.

        start() cannot run here -- it launches FakeNet -- so the snapshot step
        it performs is reproduced directly.
        """
        session = FakeNetSession(
            output_dir=Path(tmp) / "case" / "network",
            fakenet_path=install.binary,
            config_path=install.config,
        )
        session.output_dir.mkdir(parents=True, exist_ok=True)
        session._listener_roots = listener_roots(
            config_path=install.config, binary=install.binary
        )
        session._root_snapshots = {
            str(root): {
                str(path.relative_to(root)): (path.stat().st_size, path.stat().st_mtime_ns)
                for path in root.rglob("*")
                if path.is_file()
            }
            for root in session._listener_roots
        }
        return session

    def test_an_overwritten_served_file_is_collected(self) -> None:
        with TemporaryDirectory() as tmp:
            install = _Install(tmp)
            session = self._session(tmp, install)

            # The AgentTesla case: STOR lands on FakeNet's own default page.
            install.served.write_text(
                "Time: 2026-08-01\r\nHost: mail.example.com\r\nPassword: hunter2",
                encoding="utf-8",
            )

            result = session._collect_received_files()

            self.assertTrue(result["collected"])
            self.assertEqual(result["counts"]["files"], 1)
            self.assertEqual(result["counts"]["overwritten"], 1)

            entry = result["files"][0]
            self.assertEqual(entry["name"], "FakeNet.html")
            self.assertEqual(entry["state"], "overwritten")
            self.assertTrue(entry["copied"])
            self.assertIn("hunter2", Path(entry["saved_as"]).read_text(encoding="utf-8"))

    def test_a_new_upload_is_collected(self) -> None:
        with TemporaryDirectory() as tmp:
            install = _Install(tmp)
            session = self._session(tmp, install)

            (install.default_files / "report.txt").write_text("stolen", encoding="utf-8")

            result = session._collect_received_files()

            self.assertEqual(result["counts"]["files"], 1)
            self.assertEqual(result["counts"]["new"], 1)
            self.assertEqual(result["files"][0]["state"], "new")

    def test_the_original_is_left_where_FakeNet_serves_it(self) -> None:
        # Files are copied, never moved: the roots belong to FakeNet, and the
        # next run must still find the files it serves.
        with TemporaryDirectory() as tmp:
            install = _Install(tmp)
            session = self._session(tmp, install)
            install.served.write_text("uploaded", encoding="utf-8")

            session._collect_received_files()

            self.assertTrue(install.served.exists())

    def test_files_FakeNet_shipped_with_are_not_reported_as_uploads(self) -> None:
        with TemporaryDirectory() as tmp:
            install = _Install(tmp)
            session = self._session(tmp, install)

            result = session._collect_received_files()

            self.assertTrue(result["collected"])
            self.assertEqual(result["counts"]["files"], 0)
            self.assertIn("watched", result["note"])

    def test_an_oversized_file_is_recorded_and_left_in_place(self) -> None:
        with TemporaryDirectory() as tmp:
            install = _Install(tmp)
            session = self._session(tmp, install)

            big = install.default_files / "huge.bin"
            big.write_bytes(b"\x00" * (MAX_RECEIVED_FILE_BYTES + 1))

            result = session._collect_received_files()

            entry = result["files"][0]
            self.assertFalse(entry["copied"])
            self.assertIn("exceeds", entry["error"])
            self.assertEqual(result["counts"]["not_copied"], 1)

    def test_no_watchable_root_says_so_rather_than_reporting_nothing(self) -> None:
        # Silence must be distinguishable from absence: "no upload arrived" and
        # "we were not watching anywhere" are opposite conclusions.
        with TemporaryDirectory() as tmp:
            install = _Install(tmp)
            session = self._session(tmp, install)
            session._listener_roots = []
            session._root_snapshots = {}

            result = session._collect_received_files()

            self.assertFalse(result["collected"])
            self.assertIn("No FakeNet listener root", result["note"])


if __name__ == "__main__":
    unittest.main()
