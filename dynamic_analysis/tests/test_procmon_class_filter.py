"""An operation include cannot overcome an excluded event class.

On 01 Sep a gated capture recorded no TCP event in 600 seconds, and
`describe_procmon_filter`'s `operations` list -- which contains `TCP Connect` --
was read as evidence that the capture covered the network. The silence was
therefore filed as a fact about the sample.

It was not. The payload had not begun beaconing, which the socket timeline had
already measured as starting about 88 minutes in, and the capture watched six.
Network capture worked throughout: 2,481 `UDP Send` events were recorded in the
same file.

The description was still incomplete in a way that could produce exactly the
error it was blamed for. Procmon's toolbar toggles are exclude rules on the
event class column, and a class excluded there is not captured whatever the
operation includes say -- so a config could list `TCP Connect` and capture
nothing, and this function would have described it the same way either way.
"""

import unittest
from pathlib import Path

from dynamic_analysis.procmon_config import (
    ACTION_EXCLUDE,
    ACTION_INCLUDE,
    COLUMN_EVENT_CLASS,
    COLUMN_OPERATION,
    COLUMN_PROCESS_NAME,
    FilterRule,
    RELATION_IS,
    describe_procmon_filter,
    excluded_event_classes,
    included_operations,
    with_operations_replaced,
)

CONFIG = (
    Path(__file__).resolve().parent.parent.parent
    / "tools" / "procmon-configs" / "dynamic_registry_reads.pmc"
)


def _rule(column, value, action):
    return FilterRule(column=column, relation=RELATION_IS, action=action, value=value)


class ExcludedClasses(unittest.TestCase):
    def test_it_finds_a_class_exclude(self) -> None:
        rules = [
            _rule(COLUMN_OPERATION, "TCP Connect", ACTION_INCLUDE),
            _rule(COLUMN_EVENT_CLASS, "Network", ACTION_EXCLUDE),
        ]

        self.assertEqual(excluded_event_classes(rules), ["Network"])

    def test_an_operation_include_is_not_a_class_exclude(self) -> None:
        rules = [_rule(COLUMN_OPERATION, "TCP Connect", ACTION_INCLUDE)]

        self.assertEqual(excluded_event_classes(rules), [])

    def test_a_class_include_is_not_an_exclude(self) -> None:
        """Only excludes gate the class. An include on the same column is the
        operator narrowing what is shown, not switching a class off."""
        rules = [_rule(COLUMN_EVENT_CLASS, "Network", ACTION_INCLUDE)]

        self.assertEqual(excluded_event_classes(rules), [])

    def test_duplicates_collapse(self) -> None:
        rules = [
            _rule(COLUMN_EVENT_CLASS, "Profiling", ACTION_EXCLUDE),
            _rule(COLUMN_EVENT_CLASS, "Profiling", ACTION_EXCLUDE),
        ]

        self.assertEqual(excluded_event_classes(rules), ["Profiling"])


class Description(unittest.TestCase):
    @unittest.skipUnless(CONFIG.exists(), "the shipped config is not present")
    def test_the_shipped_config_excludes_only_profiling(self) -> None:
        """The config the gated run used. Network is *not* switched off in it,
        which is what the run's own UDP events independently confirm."""
        described = describe_procmon_filter(CONFIG)

        self.assertEqual(described["excluded_classes"], ["Profiling"])
        self.assertIn("TCP Connect", described["operations"])

    def test_the_note_says_an_excluded_class_overrides_the_operations(self) -> None:
        described = describe_procmon_filter(CONFIG)

        self.assertIn("Profiling", described["note"])
        self.assertIn("whatever the operations above say", described["note"])

    def test_a_missing_config_is_still_described(self) -> None:
        described = describe_procmon_filter("nowhere/at/all.pmc")

        self.assertFalse(described["readable"])
        self.assertEqual(described["excluded_classes"], [])
        self.assertIn("not found", described["note"])


class NetworkOnlyConfig(unittest.TestCase):
    """The config built to watch a beacon nothing has yet seen.

    `ce0d08be...` attempts a connection every 17 seconds but does not begin for
    about 88 minutes, so the instrument has to be cheap enough to leave running
    for hours. The registry-read config measured ~29 MB/min -- 1.7 GB an hour --
    and the gated run's 600-second window was six and a half minutes against a
    behaviour that starts at eighty-eight.
    """

    NETWORK_ONLY = CONFIG.parent / "dynamic_network_only.pmc"

    def test_replacing_drops_the_old_includes(self) -> None:
        rules = [
            _rule(COLUMN_OPERATION, "RegQueryValue", ACTION_INCLUDE),
            _rule(COLUMN_OPERATION, "RegOpenKey", ACTION_INCLUDE),
            _rule(COLUMN_PROCESS_NAME, "Procmon.exe", ACTION_EXCLUDE),
        ]

        replaced = with_operations_replaced(rules, ["TCP Connect"])
        operations = included_operations(replaced)

        self.assertEqual(operations, ["TCP Connect"])
        self.assertNotIn("RegQueryValue", operations)

    def test_the_exclude_rules_survive(self) -> None:
        """They are noise suppression that applies whatever is captured, and
        rebuilding them by hand is how a config stops excluding the analyzer."""
        rules = [
            _rule(COLUMN_OPERATION, "RegQueryValue", ACTION_INCLUDE),
            _rule(COLUMN_PROCESS_NAME, "Procmon.exe", ACTION_EXCLUDE),
            _rule(COLUMN_EVENT_CLASS, "Profiling", ACTION_EXCLUDE),
        ]

        replaced = with_operations_replaced(rules, ["TCP Connect"])

        self.assertIn(
            "Procmon.exe",
            [r.value for r in replaced if r.column == COLUMN_PROCESS_NAME],
        )
        self.assertEqual(excluded_event_classes(replaced), ["Profiling"])

    def test_it_is_idempotent(self) -> None:
        rules = [_rule(COLUMN_OPERATION, "TCP Connect", ACTION_INCLUDE)]

        once = with_operations_replaced(rules, ["TCP Connect"])
        twice = with_operations_replaced(once, ["TCP Connect"])

        self.assertEqual(included_operations(twice), ["TCP Connect"])
        self.assertEqual(len(once), len(twice))

    @unittest.skipUnless(NETWORK_ONLY.exists(), "the network config is not generated")
    def test_the_shipped_network_config_captures_connects_and_lineage(self) -> None:
        described = describe_procmon_filter(self.NETWORK_ONLY)

        self.assertIn("TCP Connect", described["operations"])
        self.assertIn("Process Create", described["operations"])
        self.assertNotIn("RegQueryValue", described["operations"])

    @unittest.skipUnless(NETWORK_ONLY.exists(), "the network config is not generated")
    def test_it_says_it_cannot_see_registry_reads(self) -> None:
        """A capture under this config that reports no VM artefact has not
        looked for one. The manifest has to say so, or the next reader will
        take the zero for a result -- which is the mistake this whole file is
        the record of."""
        described = describe_procmon_filter(self.NETWORK_ONLY)

        self.assertFalse(described["captures_registry_reads"])
        self.assertIn("no registry read", described["note"])


if __name__ == "__main__":
    unittest.main()
