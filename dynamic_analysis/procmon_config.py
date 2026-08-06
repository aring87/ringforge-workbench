"""Read and rewrite the operation filter inside a Procmon `.pmc` config.

This exists because of where gap 4's second half actually blocks. The handoff
said the missing piece was `INTERESTING_OPS` not carrying `RegQueryValue`, and
that is true but not the binding constraint: `tools/procmon-configs/
dynamic_default.pmc` carries **sixteen Operation *include* rules**, and
`DestructiveFilter` is 1. So a registry read is dropped at capture time, never
reaches `export.csv`, and no amount of parser work can find one. Every PML this
project has ever written is missing them, which is also why a second export pass
over an old capture cannot recover them.

A `.pmc` is a flat sequence of self-describing entries:

    [entry_size u32][header_size u32=16][data_offset u32][data_size u32]
    [name utf-16le, null-terminated][data]

and the `FilterRules` entry's data is:

    [reserved u8][rule_count u32] then, per rule:
    [column u32][relation u32][action u8][value_size u32]
    [value utf-16le, null-terminated][reserved 8 bytes]

Editing that by hand in Procmon's GUI is possible, but it produces a binary blob
with no diff and no record of what changed -- which is the opposite of how every
other filter in this pipeline is maintained. `dynamic_registry_reads.pmc` is
generated from the default by this module, so the difference between the two
configs is a line of code rather than a click somebody has to remember.

Round-tripping is byte-exact and `test_procmon_config.py` asserts it, which is
the only cheap evidence available that this model of the format is right: the
real test is whether Procmon loads the result, and that happens in the guest.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


#: Filter columns, as Procmon numbers them. Only the ones this module needs.
COLUMN_PROCESS_NAME = 40053
COLUMN_OPERATION = 40055
COLUMN_RESULT = 40056
COLUMN_PATH = 40071

#: Relations. 0 is `is`, and it is the only one used for an operation include.
RELATION_IS = 0
RELATION_BEGINS_WITH = 4
RELATION_ENDS_WITH = 5
RELATION_CONTAINS = 6

ACTION_EXCLUDE = 0
ACTION_INCLUDE = 1

_FILTER_RULES_ENTRY = "FilterRules"
_HEADER_SIZE = 16
_RULE_TRAILER = b"\x00" * 8

#: The registry read operations worth capturing, and no others.
#:
#: A value read and a key-existence check are the two shapes every VM-artifact
#: check in the wild takes: `RegQueryValue` on `SystemBiosVersion`, `RegOpenKey`
#: on `...\Services\VBoxGuest`. `RegEnumKey`, `RegEnumValue` and `RegQueryKey`
#: are deliberately left out -- they are enumeration, they cost the most volume
#: of any registry operation, and no common check needs them. The parser
#: classifies them as reads anyway, so a config that does include them still
#: works.
REGISTRY_READ_OPERATIONS = ("RegQueryValue", "RegOpenKey")


@dataclass
class FilterRule:
    column: int
    relation: int
    action: int
    value: str

    def encode(self) -> bytes:
        encoded = self.value.encode("utf-16-le") + b"\x00\x00"
        return (
            struct.pack("<II", self.column, self.relation)
            + bytes([self.action])
            + struct.pack("<I", len(encoded))
            + encoded
            + _RULE_TRAILER
        )


@dataclass
class _Entry:
    name: str
    data: bytes
    data_offset: int

    def encode(self) -> bytes:
        name = self.name.encode("utf-16-le") + b"\x00\x00"
        # The observed files pad the name out to `data_offset`; preserving the
        # original offset keeps a round trip byte-exact instead of merely
        # equivalent.
        padding = self.data_offset - _HEADER_SIZE - len(name)
        if padding < 0:
            raise ValueError(f"data_offset {self.data_offset} too small for {self.name!r}")
        size = self.data_offset + len(self.data)
        return (
            struct.pack("<IIII", size, _HEADER_SIZE, self.data_offset, len(self.data))
            + name
            + b"\x00" * padding
            + self.data
        )


def _parse_entries(blob: bytes) -> list[_Entry]:
    entries: list[_Entry] = []
    offset = 0
    while offset + _HEADER_SIZE <= len(blob):
        size, header_size, data_offset, data_size = struct.unpack_from("<IIII", blob, offset)
        if size == 0 or header_size != _HEADER_SIZE:
            raise ValueError(f"unreadable .pmc entry at offset {offset}")
        raw_name = blob[offset + _HEADER_SIZE : offset + data_offset]
        name = raw_name.decode("utf-16-le", errors="replace").rstrip("\x00")
        data = blob[offset + data_offset : offset + data_offset + data_size]
        entries.append(_Entry(name=name, data=data, data_offset=data_offset))
        offset += size
    if offset != len(blob):
        raise ValueError(f"trailing bytes in .pmc: {len(blob) - offset}")
    return entries


def _parse_rules(data: bytes) -> list[FilterRule]:
    rules: list[FilterRule] = []
    offset = 1  # the leading reserved byte
    (count,) = struct.unpack_from("<I", data, offset)
    offset += 4

    for _ in range(count):
        column, relation = struct.unpack_from("<II", data, offset)
        offset += 8
        action = data[offset]
        offset += 1
        (value_size,) = struct.unpack_from("<I", data, offset)
        offset += 4
        value = data[offset : offset + value_size].decode("utf-16-le").rstrip("\x00")
        offset += value_size + len(_RULE_TRAILER)
        rules.append(FilterRule(column=column, relation=relation, action=action, value=value))

    if offset != len(data):
        raise ValueError(f"filter rules parsed to {offset} of {len(data)} bytes")
    return rules


def _encode_rules(rules: Iterable[FilterRule]) -> bytes:
    rules = list(rules)
    body = b"".join(rule.encode() for rule in rules)
    return b"\x01" + struct.pack("<I", len(rules)) + body


def read_filter_rules(config_path: str | Path) -> list[FilterRule]:
    """Every filter rule in the config, in file order."""
    blob = Path(config_path).read_bytes()
    for entry in _parse_entries(blob):
        if entry.name == _FILTER_RULES_ENTRY:
            return _parse_rules(entry.data)
    raise ValueError(f"no {_FILTER_RULES_ENTRY} entry in {config_path}")


def included_operations(rules: Iterable[FilterRule]) -> list[str]:
    return [
        rule.value
        for rule in rules
        if rule.column == COLUMN_OPERATION
        and rule.relation == RELATION_IS
        and rule.action == ACTION_INCLUDE
    ]


def with_operations_included(rules: Iterable[FilterRule], operations: Iterable[str]) -> list[FilterRule]:
    """The same rules, plus an include for each operation not already there.

    Inserted after the last existing operation include rather than appended at
    the end, because the exclude rules that follow are the default Procmon set
    and reading the file later is easier when the two groups stay separate.
    """
    rules = list(rules)
    existing = {op.lower() for op in included_operations(rules)}
    additions = [
        FilterRule(COLUMN_OPERATION, RELATION_IS, ACTION_INCLUDE, op)
        for op in operations
        if op.lower() not in existing
    ]
    if not additions:
        return rules

    last_include = max(
        (
            index
            for index, rule in enumerate(rules)
            if rule.column == COLUMN_OPERATION
            and rule.relation == RELATION_IS
            and rule.action == ACTION_INCLUDE
        ),
        default=len(rules) - 1,
    )
    return rules[: last_include + 1] + additions + rules[last_include + 1 :]


def write_filter_rules(
    source_path: str | Path,
    rules: Iterable[FilterRule],
    output_path: str | Path,
) -> Path:
    """Copy ``source_path`` with its filter rules replaced.

    Only the `FilterRules` entry changes; every other setting -- columns, fonts,
    symbol path, `DestructiveFilter` -- is carried across untouched, so the two
    configs differ in exactly the thing being changed.
    """
    blob = Path(source_path).read_bytes()
    entries = _parse_entries(blob)

    rebuilt: list[bytes] = []
    replaced = False
    for entry in entries:
        if entry.name == _FILTER_RULES_ENTRY:
            entry = _Entry(
                name=entry.name,
                data=_encode_rules(rules),
                data_offset=entry.data_offset,
            )
            replaced = True
        rebuilt.append(entry.encode())

    if not replaced:
        raise ValueError(f"no {_FILTER_RULES_ENTRY} entry in {source_path}")

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"".join(rebuilt))
    return out


def rewrite_unchanged(config_path: str | Path) -> bytes:
    """The config re-encoded from its parsed form, for the round-trip test."""
    blob = Path(config_path).read_bytes()
    return b"".join(entry.encode() for entry in _parse_entries(blob))


def describe_procmon_filter(config_path: str | Path | None) -> dict[str, Any]:
    """What the config in force will and will not capture.

    In the run summary because of a run that could not be diagnosed without it.
    On 06 Aug 21:15 the registry-read pass reported `collection_available: false`
    and two explanations fitted equally: the config field was still on the
    default, or the generated config was selected and Procmon ignored the rules
    added to it. The event mix is identical under both, and the summary recorded
    the dump offsets, the process cap and the re-dump delay while saying nothing
    about the one setting that decides whether a whole pass can see anything.

    `captures_registry_reads` is the field that answers it. Read the *file* rather
    than trusting the filename, since a config can be renamed or edited.
    """
    result: dict[str, Any] = {
        "config_path": str(config_path or ""),
        "readable": False,
        "operations": [],
        "captures_registry_reads": False,
        "note": "",
    }

    if not config_path:
        result["note"] = (
            "No Procmon config was given, so Procmon used whatever filter it "
            "had saved. What was captured cannot be read from this run."
        )
        return result

    path = Path(config_path)
    if not path.exists():
        result["note"] = f"Procmon config not found: {path}"
        return result

    try:
        operations = included_operations(read_filter_rules(path))
    except Exception as error:
        result["note"] = f"Procmon config could not be read: {error}"
        return result

    reads = sorted(
        op for op in operations
        if op.lower() in {o.lower() for o in REGISTRY_READ_OPERATIONS}
        or op.lower().startswith("regquery")
        or op.lower() in {"regopenkey", "regenumkey", "regenumvalue"}
    )

    result["readable"] = True
    result["operations"] = operations
    result["captures_registry_reads"] = bool(reads)
    result["registry_read_operations"] = reads
    result["note"] = (
        f"{len(operations)} operation(s) included; registry reads captured "
        f"({', '.join(reads)})."
        if reads
        else (
            f"{len(operations)} operation(s) included and no registry read among "
            "them, so a VM-artifact check could not have been seen. "
            "tools/procmon-configs/dynamic_registry_reads.pmc captures them."
        )
    )
    return result


def _main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("config", help="path to a Procmon .pmc")
    parser.add_argument(
        "--add-registry-reads",
        metavar="OUT",
        help=f"write a copy including {', '.join(REGISTRY_READ_OPERATIONS)}",
    )
    args = parser.parse_args(argv)

    rules = read_filter_rules(args.config)
    print(f"{len(rules)} rules; operations included: {', '.join(included_operations(rules))}")

    if args.add_registry_reads:
        updated = with_operations_included(rules, REGISTRY_READ_OPERATIONS)
        out = write_filter_rules(args.config, updated, args.add_registry_reads)
        print(f"wrote {out} with {len(updated)} rules")

    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
