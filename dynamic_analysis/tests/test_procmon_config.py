"""The registry reads have to exist before anything can collect them.

The handoff put gap 4's blocker in `INTERESTING_OPS`, and that was half of it.
The binding constraint is `tools/procmon-configs/dynamic_default.pmc`: sixteen
Operation *include* rules, none of them a read, with `DestructiveFilter` set to 1
so a filtered event is dropped from the log rather than merely hidden. A
`RegQueryValue` never reaches `export.csv`, and no parser change can find one --
nor can a second export pass over any PML this project has already written.

So the config is generated rather than clicked. These tests check the format
model, byte-exactly, because the only other test of it is whether Procmon loads
the result and that happens in the guest.
"""

import unittest
from pathlib import Path

from dynamic_analysis.procmon_config import (
    ACTION_INCLUDE,
    COLUMN_OPERATION,
    COLUMN_PATH,
    COLUMN_PROCESS_NAME,
    REGISTRY_READ_OPERATIONS,
    RELATION_IS,
    included_operations,
    read_filter_rules,
    rewrite_unchanged,
    with_operations_included,
    write_filter_rules,
)

CONFIGS = Path(__file__).resolve().parents[2] / "tools" / "procmon-configs"
DEFAULT = CONFIGS / "dynamic_default.pmc"
WITH_READS = CONFIGS / "dynamic_registry_reads.pmc"


class RoundTripTests(unittest.TestCase):
    def test_the_default_config_re_encodes_byte_for_byte(self) -> None:
        # The whole basis for trusting the writer. If the entry model were wrong
        # anywhere -- a padding byte, a size field, the rule trailer -- this
        # fails, and a config Procmon silently ignores is indistinguishable from
        # a run where the sample checked nothing.
        original = DEFAULT.read_bytes()

        self.assertEqual(rewrite_unchanged(DEFAULT), original)

    def test_the_default_operations_are_the_sixteen_it_ships_with(self) -> None:
        operations = included_operations(read_filter_rules(DEFAULT))

        self.assertEqual(len(operations), 16)
        self.assertIn("RegSetValue", operations)
        self.assertNotIn("RegQueryValue", operations)
        self.assertNotIn("RegOpenKey", operations)

    def test_the_exclude_rules_survive_a_rewrite(self) -> None:
        # The Procmon defaults -- IRP_MJ_, $Mft, the tooling's own process names.
        # Losing them would multiply the volume of every run.
        rules = read_filter_rules(DEFAULT)

        process_excludes = [r.value for r in rules if r.column == COLUMN_PROCESS_NAME]
        path_excludes = [r.value for r in rules if r.column == COLUMN_PATH]

        self.assertIn("Procmon64.exe", process_excludes)
        self.assertIn("$Mft", path_excludes)


class AddOperationTests(unittest.TestCase):
    def test_the_reads_are_added_as_operation_includes(self) -> None:
        updated = with_operations_included(read_filter_rules(DEFAULT), REGISTRY_READ_OPERATIONS)

        for operation in REGISTRY_READ_OPERATIONS:
            with self.subTest(operation=operation):
                self.assertIn(operation, included_operations(updated))

    def test_adding_twice_adds_nothing(self) -> None:
        once = with_operations_included(read_filter_rules(DEFAULT), REGISTRY_READ_OPERATIONS)
        twice = with_operations_included(once, REGISTRY_READ_OPERATIONS)

        self.assertEqual(len(once), len(twice))

    def test_the_new_rules_sit_with_the_other_operation_includes(self) -> None:
        # Not appended at the end, where they would be interleaved with the
        # default exclude set and much harder to read back.
        updated = with_operations_included(read_filter_rules(DEFAULT), REGISTRY_READ_OPERATIONS)
        operation_includes = [
            index
            for index, rule in enumerate(updated)
            if rule.column == COLUMN_OPERATION
            and rule.relation == RELATION_IS
            and rule.action == ACTION_INCLUDE
        ]

        self.assertEqual(operation_includes, list(range(len(operation_includes))))

    def test_a_written_config_parses_back(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "generated.pmc"
            rules = with_operations_included(read_filter_rules(DEFAULT), REGISTRY_READ_OPERATIONS)
            write_filter_rules(DEFAULT, rules, out)

            reparsed = read_filter_rules(out)

            self.assertEqual([r.value for r in reparsed], [r.value for r in rules])
            self.assertEqual(rewrite_unchanged(out), out.read_bytes())


class ShippedConfigTests(unittest.TestCase):
    def test_the_registry_reads_config_is_the_default_plus_the_reads(self) -> None:
        # It is checked in, so it can drift from the default. This is what says
        # so: everything but the two added rules must be identical.
        expected = with_operations_included(read_filter_rules(DEFAULT), REGISTRY_READ_OPERATIONS)
        shipped = read_filter_rules(WITH_READS)

        self.assertEqual(
            [(r.column, r.relation, r.action, r.value) for r in shipped],
            [(r.column, r.relation, r.action, r.value) for r in expected],
        )

    def test_it_does_not_include_the_enumeration_operations(self) -> None:
        # RegEnumKey and RegEnumValue are the most expensive registry operations
        # there are and no common VM check needs them. The parser understands
        # them if a config does capture them; this config does not.
        operations = included_operations(read_filter_rules(WITH_READS))

        self.assertNotIn("RegEnumKey", operations)
        self.assertNotIn("RegEnumValue", operations)


if __name__ == "__main__":
    unittest.main()
