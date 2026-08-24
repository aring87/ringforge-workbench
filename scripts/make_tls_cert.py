"""A certificate the implant will accept -- `0bw`, after run `7ae41ca7`.

**The measured problem.** On run `7ae41ca7` the bench worked and the sample
still said no: the `EtherHidingRPC` listener started, `UseSSL: Yes` negotiated,
and the server sent its certificate flight (1,323 bytes). The implant read it,
sent **FIN 50 ms later**, and never wrote a byte of its request -- identically
on every retry. FakeNet's `RawListener` serves a hardcoded self-signed cert from
`listeners/ssl_utils/server.pem`, whose CN is not
`data-seed-prebsc-1-s1.binance.org` and whose issuer nothing trusts.

So the request cannot be captured over the network until the certificate is
acceptable. This builds one.

**A CA plus a leaf, not a self-signed leaf.** Trusting a self-signed server cert
means importing a new trust anchor every time the hostname changes; trusting a
CA is one action that covers this host, the beacon host, and whatever the next
sample resolves. The CA is installed into the guest's root store *once* and the
leaf is regenerated freely.

**And the CA is reused when one is already present, because re-minting it is
what quietly breaks a bench.** The guest trusts a CA by its key. A fresh one
leaves the root store holding an anchor that no longer signs the leaf being
served, and nothing errors: the handshake fails exactly as run `7ae41ca7` did,
silent FIN and no request written -- which is this file's own description of an
implant that pins. That is the worst shape a bench defect can take, a plausible
negative produced by a collector that has been made incapable of a positive.
Re-mint deliberately with `--new-ca`; the script then says the anchor is new and
that the guest needs it imported again.

**OpenSSL from Git rather than `pip install cryptography`.** The guest is
contained for a detonation, and adding a Python dependency means arming the
network, pulling from PyPI and disarming again -- three chances to leave the
bench in the state that cost run `b610dea4`. Git ships `openssl.exe` and the
guest already has Git.

**What this cannot fix.** If the implant pins a certificate or carries its own
trust bundle, it will abort exactly as it does now and no network responder will
ever reach the request. That is not a failure of this script; it is the other
answer, and the pcap tells the two apart -- a trusted cert produces application
data after the handshake, a pinned one produces the same silent FIN.

**Never point this at a host you do not control.** It mints a certificate that a
machine will trust for a name it does not own. That is the right thing inside a
contained analysis guest and wrong everywhere else, which is why the CA is
generated per-bench rather than shipped in the repository.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

#: The host the implant asks for, taken from the SNI in run `7ae41ca7`'s
#: ClientHello rather than from the config block, so it matches what is actually
#: on the wire.
DEFAULT_HOSTNAME = "data-seed-prebsc-1-s1.binance.org"

#: The phase 2 sink, which must equal `jsonrpc_answer.SINK_HOST`.
#:
#: **Duplicated rather than imported.** This runs on the guest, from `scripts/`,
#: often before anything has put the repo root on `sys.path`; a cross-package
#: import here would make certificate generation fail for a reason that has
#: nothing to do with certificates. `test_tls_cert_swap` asserts the two agree,
#: which is the cheap half of that trade.
DEFAULT_SINK_HOST = "c0ffee-sink.ringforge.test"

#: **Both, by default, because a `bare_host` run needs both.**
#:
#: A single SAN is enough while the only TLS connection is the `eth_call`. It
#: stops being enough the moment `getData()` is answered with a hostname: the
#: implant supplies its own scheme, and if it picks `https://` the beacon opens
#: a second connection to a name the leaf does not cover. That handshake fails
#: exactly as run `7ae41ca7` did -- silent FIN, no request -- one layer further
#: in, and the run yields nothing while reading like a rejected answer.
DEFAULT_HOSTNAMES = (DEFAULT_HOSTNAME, DEFAULT_SINK_HOST)

#: FakeNet's `RawListener` hardcodes these two paths -- they are not config
#: keys. Controlling the files is therefore the only way to control the cert it
#: serves, which is why this installs by replacement rather than by setting an
#: option.
SSL_UTILS_RELATIVE = Path("listeners") / "ssl_utils"
LEAF_CERT_NAME = "server.pem"
LEAF_KEY_NAME = "privkey.pem"

#: Kept alongside the originals. Its presence is what makes a second install
#: refuse: overwriting a backup that already holds our leaf would destroy
#: FakeNet's real files with no way back.
BACKUP_SUFFIX = ".ringforge-original"

#: The CA's two files. Named as constants because *whether one already exists*
#: is a separate question from generating it, and the answer decides whether the
#: guest's trust store still means anything.
CA_CERT_NAME = "ringforge_ca.crt"
CA_KEY_NAME = "ringforge_ca.key"


class CertError(RuntimeError):
    pass


def find_openssl(configured: str | Path | None = None) -> Path:
    """Locate an `openssl` binary, preferring the one Git already installed."""
    if configured:
        candidate = Path(configured)
        if candidate.exists():
            return candidate
        raise CertError(f"no openssl at {candidate}")

    found = shutil.which("openssl")
    if found:
        return Path(found)

    for candidate in (
        Path(r"C:\Program Files\Git\usr\bin\openssl.exe"),
        Path(r"C:\Program Files (x86)\Git\usr\bin\openssl.exe"),
        Path(r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"),
    ):
        if candidate.exists():
            return candidate

    raise CertError(
        "openssl not found. Git for Windows ships one at "
        r"C:\Program Files\Git\usr\bin\openssl.exe -- pass --openssl if yours "
        "is elsewhere."
    )


def _run(openssl: Path, args: list[str], cwd: Path) -> None:
    result = subprocess.run(
        [str(openssl)] + args, cwd=str(cwd),
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise CertError(
            f"openssl {' '.join(args[:2])} failed ({result.returncode}):\n"
            f"{result.stderr.strip()[:800]}"
        )


def normalise_hostnames(hostnames: Sequence[str]) -> list[str]:
    """Trim, drop blanks and de-duplicate, keeping the order given.

    Order matters because the first name becomes the CN. De-duplication matters
    because `--hostname` is repeatable: openssl rejects a SAN carrying the same
    entry twice, and it reports that as a parse failure on the extension file
    rather than as the duplicate it is.
    """
    seen: set[str] = set()
    names: list[str] = []
    for raw in hostnames:
        name = str(raw or "").strip()
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        names.append(name)
    if not names:
        raise CertError("at least one hostname is required for the leaf's SAN")
    return names


def san_line(hostnames: Sequence[str]) -> str:
    """The `subjectAltName` line covering every name the leaf answers for."""
    return "subjectAltName=" + ",".join(
        "DNS:" + name for name in normalise_hostnames(hostnames))


def ca_status(out_dir: Path, force_new: bool = False) -> tuple[str, str]:
    """Decide whether the CA in `out_dir` can be reused, and say why.

    Split out of `generate` so it can be exercised without openssl. It is the
    half that goes wrong invisibly -- a re-mint produces a perfectly valid CA,
    and the only symptom is a guest that has stopped trusting the leaf.

    Returns `("reuse" | "mint", reason)`. The reason is printed, so it is
    written as an account rather than a status word.
    """
    ca_crt = out_dir / CA_CERT_NAME
    ca_key = out_dir / CA_KEY_NAME

    if force_new:
        return "mint", "--new-ca was given"

    have_crt, have_key = ca_crt.is_file(), ca_key.is_file()
    if have_crt and have_key:
        return "reuse", f"{CA_CERT_NAME} and {CA_KEY_NAME} are both present"
    if not have_crt and not have_key:
        return "mint", f"no CA in {out_dir} yet"

    # Half a CA cannot sign anything, so minting is the only way forward -- but
    # it is still a *new* anchor and that has to be said. Reporting it as an
    # ordinary mint would let someone skip the import on the strength of a root
    # store entry that no longer matches.
    present, missing = ((CA_CERT_NAME, CA_KEY_NAME) if have_crt
                        else (CA_KEY_NAME, CA_CERT_NAME))
    return "mint", (f"{present} is present but {missing} is not, so the "
                    f"existing CA cannot sign a leaf")


def generate(
    out_dir: Path,
    hostnames: Sequence[str] = DEFAULT_HOSTNAMES,
    openssl: Path | None = None,
    days: int = 825,
    force_new_ca: bool = False,
) -> dict[str, object]:
    """Mint a leaf covering every name in `hostnames`, reusing the CA if there.

    The returned `ca_action` is `"reuse"` or `"mint"`, and callers are meant to
    act on it: a mint invalidates whatever the guest already trusts.
    """
    names = normalise_hostnames(hostnames)
    binary = openssl or find_openssl()
    out_dir.mkdir(parents=True, exist_ok=True)

    ca_key = out_dir / CA_KEY_NAME
    ca_crt = out_dir / CA_CERT_NAME
    ca_action, ca_reason = ca_status(out_dir, force_new_ca)
    leaf_key = out_dir / LEAF_KEY_NAME
    leaf_crt = out_dir / LEAF_CERT_NAME
    csr = out_dir / "leaf.csr"

    if ca_action == "mint":
        # `-nodes` leaves the key unencrypted, which is required: FakeNet loads
        # it with no way to supply a passphrase.
        _run(binary, [
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
            "-days", "3650",
            "-keyout", ca_key.name, "-out", ca_crt.name,
            "-subj", "/CN=RingForge Analysis CA/O=RingForge",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ], out_dir)

    _run(binary, [
        "req", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-keyout", leaf_key.name, "-out", csr.name,
        # The CN is vestigial -- modern clients ignore it and match the SAN
        # below -- so the first name is as good as any.
        "-subj", f"/CN={names[0]}/O=RingForge",
    ], out_dir)

    # **The SAN is the part that matters.** Modern clients ignore CN entirely
    # and match on subjectAltName; a leaf without one is rejected by a correct
    # client even when the CA is trusted, which would read exactly like pinning
    # and send this investigation down the wrong path.
    ext = out_dir / "leaf.ext"
    ext.write_text(
        san_line(names) + "\n"
        "basicConstraints=CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n",
        encoding="ascii",
    )

    _run(binary, [
        "x509", "-req", "-in", csr.name,
        "-CA", ca_crt.name, "-CAkey", ca_key.name, "-CAcreateserial",
        "-out", leaf_crt.name, "-days", str(days), "-sha256",
        "-extfile", ext.name,
    ], out_dir)

    for path in (csr, ext):
        path.unlink(missing_ok=True)

    return {"ca_cert": ca_crt, "ca_key": ca_key,
            "leaf_cert": leaf_crt, "leaf_key": leaf_key,
            "ca_action": ca_action, "ca_reason": ca_reason}


def ssl_utils_dir(fakenet_root: Path) -> Path:
    """Where `RawListener` looks, from the FakeNet installation root."""
    for base in (fakenet_root, fakenet_root / "fakenet"):
        candidate = base / SSL_UTILS_RELATIVE
        if candidate.is_dir():
            return candidate
    raise CertError(
        f"no {SSL_UTILS_RELATIVE} under {fakenet_root} -- point --fakenet at "
        "the directory holding fakenet.exe"
    )


def install(cert_dir: Path, fakenet_root: Path) -> dict[str, object]:
    """Swap our leaf in, keeping FakeNet's originals beside it.

    Refuses when a backup already exists. A second install would otherwise
    back up *our* leaf over FakeNet's real files and there would be no way
    back short of reinstalling it.
    """
    target = ssl_utils_dir(fakenet_root)
    names = (LEAF_CERT_NAME, LEAF_KEY_NAME)

    # **Every check before any write.** A cert and a key are one unit: swapping
    # the cert and then failing on the key leaves FakeNet serving a certificate
    # whose private key does not match it, which fails the handshake in a way
    # that looks nothing like a half-finished install -- and the backup guard
    # then blocks the retry that would fix it.
    for name in names:
        if not (cert_dir / name).is_file():
            raise CertError(f"generated file missing: {cert_dir / name}")
        backup = target / (name + BACKUP_SUFFIX)
        if backup.exists():
            raise CertError(
                f"{backup.name} already exists -- a previous install is still "
                f"in place. Run --restore first, or delete the backup only if "
                f"you are certain it is not FakeNet's original."
            )

    swapped, backed_up = [], []
    for name in names:
        destination = target / name
        backup = target / (name + BACKUP_SUFFIX)
        if destination.exists():
            shutil.copyfile(destination, backup)
            backed_up.append(backup)
        shutil.copyfile(cert_dir / name, destination)
        swapped.append(destination)

    return {"target": target, "swapped": swapped, "backed_up": backed_up}


def restore(fakenet_root: Path) -> list[Path]:
    """Put FakeNet's own certificate back."""
    target = ssl_utils_dir(fakenet_root)
    restored = []
    for name in (LEAF_CERT_NAME, LEAF_KEY_NAME):
        destination = target / name
        backup = destination.with_suffix(destination.suffix + BACKUP_SUFFIX)
        if backup.exists():
            shutil.copyfile(backup, destination)
            backup.unlink()
            restored.append(destination)
    return restored


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=r"C:\fakenet-0bw\tls",
                        help="where the CA and leaf are written")
    parser.add_argument("--hostname", action="append", dest="hostnames",
                        metavar="HOST",
                        help="a name the leaf must answer for; repeat for more "
                             "than one. Defaults to the RPC host and the phase "
                             "2 sink, which is what a bare_host run needs.")
    parser.add_argument("--openssl", default="",
                        help="path to openssl.exe; found automatically otherwise")
    parser.add_argument("--fakenet", default="",
                        help="FakeNet installation root. Given, the leaf is "
                             "swapped into listeners/ssl_utils with a backup")
    parser.add_argument("--restore", action="store_true",
                        help="put FakeNet's original certificate back and exit")
    parser.add_argument("--new-ca", action="store_true", dest="new_ca",
                        help="re-mint the CA even though one is present. The "
                             "guest's trust store must then be updated, or "
                             "every handshake fails looking like pinning")
    args = parser.parse_args(argv)

    try:
        if args.restore:
            if not args.fakenet:
                print("--restore needs --fakenet")
                return 1
            restored = restore(Path(args.fakenet))
            if restored:
                for path in restored:
                    print(f"restored : {path}")
            else:
                print("nothing to restore -- no backup found")
            return 0

        out_dir = Path(args.out)
        hostnames = normalise_hostnames(args.hostnames or DEFAULT_HOSTNAMES)
        made = generate(out_dir, hostnames,
                        Path(args.openssl) if args.openssl else None,
                        force_new_ca=args.new_ca)
        minted_ca = made["ca_action"] == "mint"
        print(f"hostnames: {', '.join(hostnames)}")
        print(f"CA cert  : {made['ca_cert']}")
        print(f"CA       : {'NEWLY MINTED' if minted_ca else 'reused'}"
              f" -- {made['ca_reason']}")
        print(f"leaf     : {made['leaf_cert']}")

        if args.fakenet:
            result = install(out_dir, Path(args.fakenet))
            print(f"installed: {result['target']}")
            for path in result["backed_up"]:            # type: ignore[union-attr]
                print(f"  backup : {path.name}")
    except CertError as error:
        print(f"failed: {error}")
        return 1

    if minted_ca:
        print("\nThe CA is NEW, so anything the guest already trusts is stale.")
        print("Install it in the GUEST's trust store, elevated:")
        print(f"    certutil -addstore -f Root \"{Path(args.out) / CA_CERT_NAME}\"")
    else:
        print("\nThe CA is unchanged, so a guest that already trusts it needs")
        print("nothing -- only the leaf was regenerated. Importing again is")
        print("harmless if this is a fresh guest, or if you are unsure:")
        print(f"    certutil -addstore -f Root \"{Path(args.out) / CA_CERT_NAME}\"")
    print("\nThen restart FakeNet and re-run. Reading the result:")
    print("  application data after the handshake -> it trusts the CA, and the")
    print("    request is finally capturable.")
    print("  the same silent FIN after the certificate flight -> it pins, and no")
    print("    network responder can reach it. That is an answer, not a failure.")
    print("\nUndo with --restore --fakenet <root>; the CA can be removed with")
    print("    certutil -delstore Root \"RingForge Analysis CA\"")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
