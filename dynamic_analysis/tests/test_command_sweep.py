"""The sweep generator's job is to refuse, and these are the refusals.

A commands file is a sequence of instructions to a live RAT down a session
that cannot be reopened: the client does not reconnect when a session ends and
its `ONLOGON` task only relaunches it at the next logon. So the expensive
mistakes are not crashes here, they are things that reach the wire -- a field
name the client does not read, which arrives as null, and a sub-action that
changes the guest while wearing a read-only command's name.

Both were paid for once already. `Report` read `Name` from a bare packet and
the null ended the session eight commands into a sweep.
"""

import unittest

from scripts.build_command_sweep import (
    HANDLER_FIELDS,
    REFUSED_SUB_ACTIONS,
    RISKY_TAIL,
    SAFE_FIELDS,
    SUB_DISPATCHERS,
    check,
)

#: A table of the shape `load_table` returns, covering what the fixtures use.
TABLE = {
    "ProcessSpy": set(),
    "RegistryRequest": set(),
    "Shell": {"Command"},
    "Report": {"Name"},
}


class FieldNames(unittest.TestCase):
    def test_a_field_the_dispatcher_reads_passes(self) -> None:
        self.assertEqual(check([("Shell", [("Command", "ver")], "")], TABLE), [])

    def test_a_field_nothing_reads_is_refused(self) -> None:
        """The failure this exists for: it would arrive as null."""
        problems = check([("Shell", [("Commnad", "ver")], "")], TABLE)

        self.assertEqual(len(problems), 1)
        self.assertIn("Commnad", problems[0])
        self.assertIn("read by nothing", problems[0])

    def test_a_handler_field_passes_though_the_table_shows_none(self) -> None:
        """The table sees one level. Five commands read theirs one level down."""
        self.assertEqual(TABLE["ProcessSpy"], set())

        self.assertEqual(
            check([("ProcessSpy", [("Command", "List")], "")], TABLE), []
        )

    def test_a_command_not_in_the_table_is_refused(self) -> None:
        problems = check([("Nonesuch", [], "")], TABLE)

        self.assertIn("not a command in the table", problems[0])


class SubActions(unittest.TestCase):
    """Withholding by command name cannot see these."""

    def test_a_destructive_sub_action_is_refused(self) -> None:
        problems = check(
            [("RegistryRequest", [("Action", "DeleteKey")], "")], TABLE
        )

        self.assertTrue(any("DeleteKey" in p for p in problems))

    def test_the_read_sub_action_passes(self) -> None:
        self.assertEqual(
            check([("RegistryRequest", [("Action", "GetRoots")], "")], TABLE), []
        )

    def test_every_refused_sub_action_belongs_to_a_known_handler(self) -> None:
        self.assertEqual(
            set(REFUSED_SUB_ACTIONS) - set(HANDLER_FIELDS), set()
        )

    def test_every_refused_sub_action_is_one_the_handler_accepts(self) -> None:
        """A refusal for an action that does not exist protects nothing."""
        for command, refused in REFUSED_SUB_ACTIONS.items():
            known = set()
            for values in HANDLER_FIELDS[command].values():
                known.update(values)
            self.assertEqual(refused - known, set(), command)


class TheSweepItself(unittest.TestCase):
    def test_no_group_emits_a_refused_sub_action(self) -> None:
        """The shipped sweep must pass its own check, not just be able to."""
        for _, fields, _ in SUB_DISPATCHERS + SAFE_FIELDS + RISKY_TAIL:
            for command, refused in REFUSED_SUB_ACTIONS.items():
                for _, value in fields:
                    self.assertNotIn(value, refused)

    def test_close_port_never_targets_the_session(self) -> None:
        """It kills the process owning the port, and 7372 is this session."""
        ports = [value for name, fields, _ in SAFE_FIELDS if name == "ClosePort"
                 for key, value in fields if key == "Port"]

        self.assertTrue(ports)
        self.assertNotIn("7372", ports)

    def test_hosts_only_ever_carries_the_read_magic(self) -> None:
        """Any other Content is base64-decoded over the hosts file."""
        contents = [value for name, fields, _ in SAFE_FIELDS if name == "Hosts"
                    for key, value in fields if key == "Content"]

        self.assertEqual(contents, ["123ratonpro"])

    def test_report_is_last(self) -> None:
        """It is the one command known to have ended a session."""
        self.assertEqual(RISKY_TAIL[-1][0], "Report")

    def test_report_carries_a_name(self) -> None:
        """Sending it bare again would repeat the mistake it is here to test."""
        fields = dict(RISKY_TAIL[-1][1])

        self.assertTrue(fields.get("Name"))


if __name__ == "__main__":
    unittest.main()
