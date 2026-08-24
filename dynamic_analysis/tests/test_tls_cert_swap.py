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
    CA_CERT_NAME,
    CA_KEY_NAME,
    DEFAULT_HOSTNAME,
    DEFAULT_HOSTNAMES,
    DEFAULT_SINK_HOST,
    LEAF_CERT_NAME,
    LEAF_KEY_NAME,
    CertError,
    ca_status,
    find_openssl,
    generate,
    install,
    normalise_hostnames,
    restore,
    san_line,
    ssl_utils_dir,
)


def _openssl_or_none():
    try:
        return find_openssl()
    except CertError:
        return None


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


class TheNamesTheLeafCovers(unittest.TestCase):
    """The SAN, which is the half of the certificate clients actually match.

    Run `7ae41ca7` established what a name the leaf does not cover costs: a
    silent FIN, no request, and a result indistinguishable from an implant that
    pins. These run without openssl because the extension file is built before
    openssl is ever invoked, and it is the part that can be quietly wrong.
    """

    def test_the_default_covers_the_rpc_host_and_the_sink(self) -> None:
        # A `bare_host` answer sends the implant to the sink over a scheme it
        # picks itself. If it picks https, the leaf has to already cover it --
        # there is no second chance inside one detonation.
        line = san_line(DEFAULT_HOSTNAMES)

        self.assertIn("DNS:" + DEFAULT_HOSTNAME, line)
        self.assertIn("DNS:" + DEFAULT_SINK_HOST, line)

    def test_the_sink_matches_the_one_phase_2_actually_serves(self) -> None:
        # The constant is duplicated here rather than imported, because this
        # script runs on the guest before the repo root is necessarily on
        # sys.path. This is the assertion that pays for that duplication: a
        # leaf minted for the wrong sink fails at the handshake, which is the
        # most expensive place in this bench to discover a typo.
        from dynamic_analysis.jsonrpc_answer import SINK_HOST

        self.assertEqual(DEFAULT_SINK_HOST, SINK_HOST)

    def test_the_extension_line_is_comma_separated(self) -> None:
        self.assertEqual(san_line(["a.test", "b.test"]),
                         "subjectAltName=DNS:a.test,DNS:b.test")

    def test_repeats_are_dropped_because_openssl_rejects_them(self) -> None:
        # --hostname is repeatable, so passing the default plus an explicit copy
        # of it is the obvious thing to do and must not produce a SAN openssl
        # refuses to parse.
        self.assertEqual(normalise_hostnames(["a.test", "A.TEST", " a.test "]),
                         ["a.test"])

    def test_order_is_kept_because_the_first_name_becomes_the_cn(self) -> None:
        self.assertEqual(normalise_hostnames(["b.test", "a.test"]),
                         ["b.test", "a.test"])

    def test_no_usable_name_is_an_error_rather_than_an_empty_san(self) -> None:
        # An empty SAN is accepted by openssl and rejected by every client, so
        # it would fail as a handshake problem hours later rather than here.
        with self.assertRaises(CertError):
            san_line(["", "   "])


class ReusingTheCertificateAuthority(unittest.TestCase):
    """Re-minting the CA is the way this script breaks a working bench.

    The guest trusts an anchor by its key. Mint a second one and the root store
    still holds the first, so the leaf being served no longer chains to anything
    trusted -- and the symptom is a silent FIN after the certificate flight,
    which is this project's own signature for an implant that pins. A run would
    be read as an answer when it is a defect.

    Regenerating the *leaf* is routine: `--hostname` changes as soon as a
    sample resolves somewhere new. So the common operation had to stop taking
    the anchor with it.
    """

    def setUp(self) -> None:
        self.out = Path(tempfile.mkdtemp()) / "tls"

    def _write_ca(self, cert: bool = True, key: bool = True) -> None:
        self.out.mkdir(parents=True, exist_ok=True)
        if cert:
            (self.out / CA_CERT_NAME).write_text("CA CERT", encoding="ascii")
        if key:
            (self.out / CA_KEY_NAME).write_text("CA KEY", encoding="ascii")

    def test_an_empty_directory_mints(self) -> None:
        action, reason = ca_status(self.out)

        self.assertEqual(action, "mint")
        self.assertIn("no CA", reason)

    def test_a_complete_ca_is_reused(self) -> None:
        self._write_ca()

        action, _ = ca_status(self.out)

        self.assertEqual(action, "reuse")

    def test_new_ca_overrides_a_complete_one_and_says_which_lever_did_it(self) -> None:
        self._write_ca()

        action, reason = ca_status(self.out, force_new=True)

        self.assertEqual(action, "mint")
        self.assertIn("--new-ca", reason)

    def test_a_certificate_with_no_key_mints_and_names_what_is_missing(self) -> None:
        # Half a CA cannot sign. Minting is right; reporting it as routine is
        # not, because the root store entry is about to stop matching.
        self._write_ca(key=False)

        action, reason = ca_status(self.out)

        self.assertEqual(action, "mint")
        self.assertIn(CA_KEY_NAME, reason)

    def test_a_key_with_no_certificate_mints_too(self) -> None:
        self._write_ca(cert=False)

        action, reason = ca_status(self.out)

        self.assertEqual(action, "mint")
        self.assertIn(CA_CERT_NAME, reason)


@unittest.skipUnless(_openssl_or_none(), "needs openssl")
class TheAnchorSurvivesARegeneratedLeaf(unittest.TestCase):
    """The regression itself, measured rather than reasoned about.

    Everything above tests the decision; this tests that acting on it keeps the
    anchor byte-for-byte and still produces a leaf that chains to it. Those are
    two different ways to be wrong and only one of them is a decision.
    """

    def test_a_second_run_with_different_names_keeps_the_same_ca(self) -> None:
        out = Path(tempfile.mkdtemp()) / "tls"
        first = generate(out, ["one.test"])
        ca_bytes = Path(first["ca_cert"]).read_bytes()
        leaf_bytes = Path(first["leaf_cert"]).read_bytes()

        second = generate(out, ["two.test"])

        self.assertEqual(first["ca_action"], "mint")
        self.assertEqual(second["ca_action"], "reuse")
        self.assertEqual(Path(second["ca_cert"]).read_bytes(), ca_bytes)
        # The leaf is expected to change -- that is what was asked for.
        self.assertNotEqual(Path(second["leaf_cert"]).read_bytes(), leaf_bytes)

    def test_new_ca_really_does_replace_it(self) -> None:
        # The escape hatch has to work, or the only way to rotate the anchor is
        # to delete files by hand and hope the right ones were chosen.
        out = Path(tempfile.mkdtemp()) / "tls"
        first = generate(out, ["one.test"])
        ca_bytes = Path(first["ca_cert"]).read_bytes()

        second = generate(out, ["one.test"], force_new_ca=True)

        self.assertEqual(second["ca_action"], "mint")
        self.assertNotEqual(Path(second["ca_cert"]).read_bytes(), ca_bytes)


if __name__ == "__main__":
    unittest.main()
