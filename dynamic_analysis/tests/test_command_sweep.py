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
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.build_command_sweep import (
    HANDLER_FIELDS,
    load_table,
    REFUSED_SUB_ACTIONS,
    RISKY_TAIL,
    SAFE_FIELDS,
    SUB_DISPATCHERS,
    check,
)

#: A table of the shape `load_table` returns: {command: {field: type}}.
TABLE = {
    "ProcessSpy": {},
    "RegistryRequest": {},
    "Shell": {"Command": "String"},
    "Report": {"Name": "String"},
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
        self.assertEqual(TABLE["ProcessSpy"], {})

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

    def test_custom_gdi_is_last(self) -> None:
        """Measured 02 Sep: it paints an overlay that cannot be stopped.

        The client takes no commands outside a session and does not reconnect
        after one ends, so anything after `CustomGDI` is unreachable and the
        payload has to be killed to clear the screen. It ran second-to-last
        that day and cost the guest.
        """
        self.assertEqual(RISKY_TAIL[-1][0], "CustomGDI")

    def test_report_carries_a_name(self) -> None:
        """Sending it bare ends the session, measured twice over."""
        fields = dict(
            next(f for name, f, _ in RISKY_TAIL if name == "Report")
        )

        self.assertTrue(fields.get("Name"))

    def test_chat_precedes_chat_message(self) -> None:
        """ChatMessage answers 'The chat is closed, nice try...' without it."""
        names = [name for name, _, _ in RISKY_TAIL]

        self.assertIn("Chat", names)
        self.assertLess(names.index("Chat"), names.index("ChatMessage"))


class AccessorTypes(unittest.TestCase):
    """The table knew `Volume:Integer` all along and nothing read it.

    That is the whole finding of the 02 Sep field sweep: the type was parsed
    out of the dispatcher on the day the table was written, sat in column two,
    and the generator dropped it. `Volume=50` went out as two characters and
    `BitConverter.ToInt32` threw on the two-byte array.
    """

    TYPED = {
        "Volume": {"Volume": "Integer"},
        "PlayAudio": {"Audio": "ByteArray"},
        "Shell": {"Command": "String"},
    }

    def test_an_integer_sent_as_text_is_refused(self) -> None:
        problems = check([("Volume", [("Volume", "50")], "")], self.TYPED)

        self.assertEqual(len(problems), 1)
        self.assertIn("int:", problems[0])

    def test_a_tagged_integer_passes(self) -> None:
        self.assertEqual(
            check([("Volume", [("Volume", "int:50")], "")], self.TYPED), []
        )

    def test_a_bytearray_sent_as_text_is_refused(self) -> None:
        problems = check([("PlayAudio", [("Audio", "ringforge")], "")], self.TYPED)

        self.assertEqual(len(problems), 1)
        self.assertIn("b64:", problems[0])

    def test_a_string_needs_no_tag(self) -> None:
        self.assertEqual(
            check([("Shell", [("Command", "ver")], "")], self.TYPED), []
        )

    def test_the_table_parser_keeps_the_type(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "command_table.tsv"
            path.write_text(
                "# comment\nVolume\tVolume:Integer\tSetVolume\n"
                "Shell\tCommand:String\tCmdShell\nBeep\t\t\n",
                encoding="utf-8",
            )
            table = load_table(path)

        self.assertEqual(table["Volume"], {"Volume": "Integer"})
        self.assertEqual(table["Shell"], {"Command": "String"})
        self.assertEqual(table["Beep"], {})


class TheShippedSweepIsTyped(unittest.TestCase):
    """Regression on the exact fields that ended the run."""

    #: Field names the dispatcher reads with a typed accessor.
    INTEGER_FIELDS = {"Volume", "Cam", "Port", "w", "h", "ProcessId", "Index"}
    BYTES_FIELDS = {"img", "Audio", "Image", "Data"}

    def _shipped(self):
        return SUB_DISPATCHERS + SAFE_FIELDS + RISKY_TAIL

    def test_every_integer_field_carries_its_tag(self) -> None:
        for name, fields, _ in self._shipped():
            for key, value in fields:
                if key in self.INTEGER_FIELDS:
                    self.assertTrue(
                        value.startswith("int:"),
                        f"{name}.{key} = {value!r} is an Integer sent as text",
                    )

    def test_every_bytearray_field_carries_its_tag(self) -> None:
        for name, fields, _ in self._shipped():
            for key, value in fields:
                # `Image` is a String on CustomGDI (base64 text the handler
                # decodes itself) and a ByteArray on Lock, which is withheld.
                if key in self.BYTES_FIELDS and name != "CustomGDI":
                    self.assertTrue(
                        value.startswith("b64:"),
                        f"{name}.{key} = {value!r} is a ByteArray sent as text",
                    )

    def test_start_shell_comes_before_shell(self) -> None:
        """CmdShell returns immediately when there is no live shell."""
        names = [name for name, _, _ in SAFE_FIELDS]

        self.assertIn("StartShell", names)
        self.assertLess(names.index("StartShell"), names.index("Shell"))


if __name__ == "__main__":
    unittest.main()
