r"""Reassemble carved payloads exported from the guest as base64.

Guest side writes <name>.b64 into the shared folder; this decodes each one into
G:\ringforge-artifacts\c14cb5b6_carved\, prints size + sha256 so the transfer can
be checked against the run summary, and leaves the raw files for 7-Zip to wrap.
"""
import base64
import hashlib
import pathlib
import sys

SRC = pathlib.Path(r"C:\Users\aring\Downloads\ringforge\outputs")
DST = pathlib.Path(r"G:\ringforge-artifacts\c14cb5b6_carved")


def main() -> int:
    blobs = sorted(SRC.glob("*.b64"))
    if not blobs:
        print(f"no .b64 files in {SRC} -- has the guest script been run?")
        return 1

    DST.mkdir(parents=True, exist_ok=True)
    for blob in blobs:
        raw = base64.b64decode(blob.read_text(), validate=True)
        out = DST / blob.name[: -len(".b64")]
        out.write_bytes(raw)
        print(f"{out.name}\n    {len(raw)} bytes  sha256={hashlib.sha256(raw).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
