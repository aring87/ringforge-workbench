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

#: The host the implant asks for, taken from the SNI in run `7ae41ca7`'s
#: ClientHello rather than from the config block, so it matches what is actually
#: on the wire.
DEFAULT_HOSTNAME = "data-seed-prebsc-1-s1.binance.org"

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


def generate(
    out_dir: Path,
    hostname: str = DEFAULT_HOSTNAME,
    openssl: Path | None = None,
    days: int = 825,
) -> dict[str, Path]:
    """Mint a CA and a leaf for `hostname`, into `out_dir`."""
    binary = openssl or find_openssl()
    out_dir.mkdir(parents=True, exist_ok=True)

    ca_key = out_dir / "ringforge_ca.key"
    ca_crt = out_dir / "ringforge_ca.crt"
    leaf_key = out_dir / LEAF_KEY_NAME
    leaf_crt = out_dir / LEAF_CERT_NAME
    csr = out_dir / "leaf.csr"

    # `-nodes` leaves the key unencrypted, which is required: FakeNet loads it
    # with no way to supply a passphrase.
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
        "-subj", f"/CN={hostname}/O=RingForge",
    ], out_dir)

    # **The SAN is the part that matters.** Modern clients ignore CN entirely
    # and match on subjectAltName; a leaf without one is rejected by a correct
    # client even when the CA is trusted, which would read exactly like pinning
    # and send this investigation down the wrong path.
    ext = out_dir / "leaf.ext"
    ext.write_text(
        f"subjectAltName=DNS:{hostname}\n"
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
            "leaf_cert": leaf_crt, "leaf_key": leaf_key}


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
    parser.add_argument("--hostname", default=DEFAULT_HOSTNAME)
    parser.add_argument("--openssl", default="",
                        help="path to openssl.exe; found automatically otherwise")
    parser.add_argument("--fakenet", default="",
                        help="FakeNet installation root. Given, the leaf is "
                             "swapped into listeners/ssl_utils with a backup")
    parser.add_argument("--restore", action="store_true",
                        help="put FakeNet's original certificate back and exit")
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
        made = generate(out_dir, args.hostname,
                        Path(args.openssl) if args.openssl else None)
        print(f"hostname : {args.hostname}")
        print(f"CA cert  : {made['ca_cert']}")
        print(f"leaf     : {made['leaf_cert']}")

        if args.fakenet:
            result = install(out_dir, Path(args.fakenet))
            print(f"installed: {result['target']}")
            for path in result["backed_up"]:            # type: ignore[union-attr]
                print(f"  backup : {path.name}")
    except CertError as error:
        print(f"failed: {error}")
        return 1

    print("\nInstall the CA in the GUEST's trust store, elevated:")
    print(f"    certutil -addstore -f Root \"{Path(args.out) / 'ringforge_ca.crt'}\"")
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
