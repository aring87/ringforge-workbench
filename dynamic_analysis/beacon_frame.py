"""The `ce0d08be...` wire frame, as read out of `stuff.dll`.

`Stuff.PacketFrame.Encode` and `.Decode`, disassembled 01 Sep from the copy
Costura unpacked into `%TEMP%`:

    uint32   magic           0xDEADBEEF   -- "Invalid magic" on mismatch
    int32    payloadLength                -- length of the bytes on the wire
    int32    originalSize                 -- length before compression
    uint8    flagCompressed               -- 0 raw, 1 Deflate
    bytes[]  payload
    uint32   crc32                        -- "CRC mismatch" on failure

`Stuff.PacketCompressor` deflates only above `MinSizeToCompress` = 256 bytes,
at `CompressionLevel.Fastest`, and sets the flag accordingly.

**This model has never been seen on the wire.** It is read from IL, and the
sample has never had anything to talk to: 212 connection attempts to
`127.0.0.1:7372` in an hour, every one dying at the SYN because nothing
listens. So the first job of anything using this module is to *test* the model,
not to assume it -- which is why `parse_frame` reports a CRC mismatch as a
finding and returns the frame anyway, rather than raising and discarding the
first real evidence this project has ever had about the protocol.

**The CRC polynomial is an assumption and is labelled as one.** `stuff.dll`
builds its own table (`Crc32.BuildTable`, `Compute`) rather than calling the
framework, and the table's constants were not read. Standard IEEE CRC-32 is the
overwhelmingly likely choice and is what `crc32` here computes; if a real frame
mismatches, the polynomial is the first thing to suspect and the payload bytes
are still intact for checking it.
"""

from __future__ import annotations

import struct
import zlib
from typing import Any

#: `ldc.i4 -559038737` in both Encode and Decode.
MAGIC = 0xDEADBEEF

#: `Stuff.PacketCompressor.Compress`: below this it ships raw and flags 0.
MIN_SIZE_TO_COMPRESS = 256

#: magic, payloadLength, originalSize, flagCompressed
HEADER = struct.Struct("<IiiB")

#: the trailing checksum
TRAILER = struct.Struct("<I")

HEADER_SIZE = HEADER.size
TRAILER_SIZE = TRAILER.size


def crc32(data: bytes) -> int:
    """IEEE CRC-32, which is what the sample's own table is assumed to be."""
    return zlib.crc32(data) & 0xFFFFFFFF


def build_frame(payload: bytes, compress: bool | None = None) -> bytes:
    """Encode a frame the way `PacketFrame.Encode` does.

    ``compress`` defaults to the sample's own rule -- Deflate above 256 bytes --
    and can be forced either way to test how the client reacts to a flag that
    disagrees with the size, which is the sort of thing a hand-rolled decoder
    gets wrong.

    Deflate here is raw, with no zlib header, because `DeflateStream` is raw
    Deflate and a zlib wrapper would fail on the far side for a reason that
    looks like a protocol mismatch rather than a framing one.
    """
    original_size = len(payload)

    if compress is None:
        compress = original_size > MIN_SIZE_TO_COMPRESS

    if compress:
        compressor = zlib.compressobj(zlib.Z_BEST_SPEED, zlib.DEFLATED, -zlib.MAX_WBITS)
        body = compressor.compress(payload) + compressor.flush()
        flag = 1
    else:
        body = payload
        flag = 0

    head = HEADER.pack(MAGIC, len(body), original_size, flag)
    return head + body + TRAILER.pack(crc32(body))


def frame_length(header: bytes) -> int:
    """Total bytes of the frame whose header this is, or 0 if it is short."""
    if len(header) < HEADER_SIZE:
        return 0
    _, payload_length, _, _ = HEADER.unpack(header[:HEADER_SIZE])
    if payload_length < 0:
        return 0
    return HEADER_SIZE + payload_length + TRAILER_SIZE


def parse_frame(data: bytes) -> dict[str, Any]:
    """Decode a frame, reporting every disagreement instead of raising.

    The sample's own `Decode` throws `Invalid magic` and `CRC mismatch`. This
    does not: the first frame this project ever receives is evidence, and a
    parser that discards evidence because a field disagreed with a model built
    from IL is answering the wrong question. Every mismatch becomes an entry in
    ``problems`` and the decoded parts come back regardless.
    """
    result: dict[str, Any] = {
        "ok": False,
        "problems": [],
        "magic": None,
        "payload_length": None,
        "original_size": None,
        "compressed": None,
        "payload": b"",
        "decompressed": b"",
        "crc_stated": None,
        "crc_computed": None,
        "trailing_bytes": 0,
    }

    if len(data) < HEADER_SIZE:
        result["problems"].append(
            f"short: {len(data)} bytes, header alone is {HEADER_SIZE}"
        )
        return result

    magic, payload_length, original_size, flag = HEADER.unpack(data[:HEADER_SIZE])
    result["magic"] = magic
    result["payload_length"] = payload_length
    result["original_size"] = original_size
    result["compressed"] = bool(flag)

    if magic != MAGIC:
        result["problems"].append(
            f"magic is 0x{magic:08x}, expected 0x{MAGIC:08x} -- the sample calls "
            "this 'Invalid magic'"
        )

    if flag not in (0, 1):
        result["problems"].append(f"compression flag is {flag}, expected 0 or 1")

    end = HEADER_SIZE + max(payload_length, 0)
    body = data[HEADER_SIZE:end]
    result["payload"] = body

    if len(body) < payload_length:
        result["problems"].append(
            f"payload truncated: {len(body)} of {payload_length} bytes"
        )
        return result

    if len(data) < end + TRAILER_SIZE:
        result["problems"].append("no CRC trailer")
        return result

    (stated,) = TRAILER.unpack(data[end:end + TRAILER_SIZE])
    computed = crc32(body)
    result["crc_stated"] = stated
    result["crc_computed"] = computed
    result["trailing_bytes"] = len(data) - (end + TRAILER_SIZE)

    if stated != computed:
        result["problems"].append(
            f"CRC-32 stated 0x{stated:08x}, computed 0x{computed:08x} -- the "
            "sample calls this 'CRC mismatch'. If the payload is otherwise "
            "sane, suspect the polynomial: stuff.dll builds its own table and "
            "its constants were never read"
        )

    if flag == 1 and body:
        try:
            result["decompressed"] = zlib.decompress(body, -zlib.MAX_WBITS)
        except zlib.error as error:
            result["problems"].append(f"Deflate failed: {error}")
        else:
            if len(result["decompressed"]) != original_size:
                result["problems"].append(
                    f"originalSize says {original_size}, inflated to "
                    f"{len(result['decompressed'])}"
                )
    elif flag == 0:
        result["decompressed"] = body
        if len(body) != original_size:
            result["problems"].append(
                f"uncompressed frame states originalSize {original_size} but "
                f"carries {len(body)} bytes"
            )

    result["ok"] = not result["problems"]
    return result
