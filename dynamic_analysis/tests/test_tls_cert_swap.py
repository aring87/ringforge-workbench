"""Swapping FakeNet's certificate for one the implant will accept -- `0bw`.

Run `7ae41ca7` established the need: the listener answered with its certificate
flight and the implant sent FIN 50 ms later, every time, without writing a byte
of its request. FakeNet's `RawListener` hardcodes the two file paths it serves
from, so replacing the files is the only lever there is.

These cover the replacement, not the cryptography. The generator shells out to
`openssl` and is exercised separately when one is present; what has to be right
here is that FakeNet's originals survive, because there is no way to get them
back short of reinstalling it.
"""

import tempfile
import unittest
from pathlib import Path

from scripts.make_tls_cert import (
    BACKUP_SUFFIX,
    LEAF_CERT_NAME,
    LEAF_KEY_NAME,
    CertError,
    install,
    restore,
    ssl_utils_dir,
)


def _fake_fakenet(root: Path, with_originals: bool = True) -> Path:
    target = root / "listeners" / "ssl_utils"
    target.mkdir(parents=True)
    if with_originals:
        (target / LEAF_CERT_NAME).write_text("FAKENET ORIGINAL CERT", encoding="ascii")
        (target / LEAF_KEY_NAME).write_text("FAKENET ORIGINAL KEY", encoding="ascii")
    return target


def _our_certs(root: Path) -> Path:
    out = root / "tls"
    out.mkdir(parents=True)
    (out / LEAF_CERT_NAME).write_text("RINGFORGE LEAF CERT", encoding="ascii")
    (out / LEAF_KEY_NAME).write_text("RINGFORGE LEAF KEY", encoding="ascii")
    return out


class LocatingSslUtils(unittest.TestCase):
    def test_it_finds_the_directory_under_the_install_root(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        target = _fake_fakenet(tmp)

        self.assertEqual(ssl_utils_dir(tmp), target)

    def test_it_also_finds_a_nested_fakenet_layout(self) -> None:
        # Source checkouts put the package a level down; a frozen build does not.
        tmp = Path(tempfile.mkdtemp())
        target = _fake_fakenet(tmp / "fakenet")

        self.assertEqual(ssl_utils_dir(tmp), target)

    def test_a_wrong_root_says_so_rather_than_creating_one(self) -> None:
        tmp = Path(tempfile.mkdtemp())

        with self.assertRaises(CertError):
            ssl_utils_dir(tmp)


class SwappingTheCertificate(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.target = _fake_fakenet(self.tmp / "fakenet_install")
        self.certs = _our_certs(self.tmp)
        self.root = self.tmp / "fakenet_install"

    def test_our_leaf_is_what_fakenet_will_serve(self) -> None:
        install(self.certs, self.root)

        self.assertEqual((self.target / LEAF_CERT_NAME).read_text(), "RINGFORGE LEAF CERT")
        self.assertEqual((self.target / LEAF_KEY_NAME).read_text(), "RINGFORGE LEAF KEY")

    def test_the_originals_are_kept(self) -> None:
        install(self.certs, self.root)
        backup = self.target / (LEAF_CERT_NAME + BACKUP_SUFFIX)

        self.assertEqual(backup.read_text(), "FAKENET ORIGINAL CERT")

    def test_a_second_install_refuses_rather_than_backing_up_our_own_leaf(self) -> None:
        # The failure this guard exists for: installing twice would copy *our*
        # leaf over the backup, and FakeNet's real certificate would be gone
        # with no way back short of reinstalling it.
        install(self.certs, self.root)

        with self.assertRaises(CertError) as caught:
            install(self.certs, self.root)
        self.assertIn("already exists", str(caught.exception))

        backup = self.target / (LEAF_CERT_NAME + BACKUP_SUFFIX)
        self.assertEqual(backup.read_text(), "FAKENET ORIGINAL CERT")

    def test_restore_puts_the_original_back_and_clears_the_backup(self) -> None:
        install(self.certs, self.root)
        restored = restore(self.root)

        self.assertEqual((self.target / LEAF_CERT_NAME).read_text(), "FAKENET ORIGINAL CERT")
        self.assertFalse((self.target / (LEAF_CERT_NAME + BACKUP_SUFFIX)).exists())
        self.assertEqual(len(restored), 2)

    def test_install_restore_install_is_safe(self) -> None:
        # The realistic cycle across two runs. The originals must survive it.
        install(self.certs, self.root)
        restore(self.root)
        install(self.certs, self.root)

        self.assertEqual((self.target / (LEAF_CERT_NAME + BACKUP_SUFFIX)).read_text(),
                         "FAKENET ORIGINAL CERT")

    def test_restoring_without_a_backup_is_not_an_error(self) -> None:
        self.assertEqual(restore(self.root), [])

    def test_a_missing_generated_file_stops_before_touching_anything(self) -> None:
        (self.certs / LEAF_KEY_NAME).unlink()

        with self.assertRaises(CertError):
            install(self.certs, self.root)

        # The cert half must not have been swapped on the way to failing.
        self.assertEqual((self.target / LEAF_CERT_NAME).read_text(),
                         "FAKENET ORIGINAL CERT")


if __name__ == "__main__":
    unittest.main()
