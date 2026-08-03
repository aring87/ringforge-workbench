"""What FakeNet will serve comes from its config, not from its log.

A healthy mimikatz run reported exactly one listener, "DNS Server", which read
as though the simulated internet was answering nothing but DNS. It was a
parsing artifact. The pattern required the literal word "Listener" or "Server"
inside the module tag, and FakeNet 3.5 tags modules by short name:

    12:12:40 PM [           FakeNet] Loaded configuration file: ...default.ini
    12:12:40 PM [          Diverter] Capturing traffic to packets_...pcap
    12:12:41 PM [        DNS Server] Hiding logs from blacklisted processes
    12:12:42 PM [               FTP] concurrency model: multi-thread

"DNS Server" matched only because it happens to contain "Server". FTP was
starting up one line below and never counted, and HTTP logged nothing at all
at startup.

The deeper problem is that no pattern fixes this: a listener that boots quietly
leaves no line to match. The config FakeNet loaded is the authority for what
will be served, and it names its own path on the first line of the log.

This mattered because the next sample was AgentTesla, which exfiltrates over
SMTP or HTTP. "No HTTP listener" and "the sample never phoned home" produce the
same quiet report.
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from dynamic_analysis.fakenet_runner import (
    _CONFIG_PATH_RE,
    _MODULE_TAG_RE,
    _enabled_listeners,
)

#: Verbatim from the mimikatz.upx run.
REAL_LOG = """08/01/26 12:12:40 PM [           FakeNet] Loaded configuration file: C:\\rf\\tools\\fakenet\\configs\\default.ini
08/01/26 12:12:40 PM [          Diverter] Capturing traffic to packets_20260801_121240.pcap
08/01/26 12:12:41 PM [        DNS Server] Hiding logs from blacklisted processes
08/01/26 12:12:42 PM [               FTP] concurrency model: multi-thread
08/01/26 12:12:42 PM [               FTP] masquerade (NAT) address: None
08/01/26 12:12:42 PM [          Diverter] Set DNS server 0.0.0.0 on the adapter: Ethernet 2
"""

CONFIG = """[FakeNet]
DivertTraffic: Yes

[Diverter]
NetworkMode: SingleHost

[DNS Server]
Enabled:  True
Port:     53
Protocol: UDP
Listener: DNSListener

[HTTPListener80]
Enabled:  True
Port:     80
Protocol: TCP
Listener: HTTPListener

[SMTPListener25]
Enabled:  True
Port:     25
Protocol: TCP
Listener: SMTPListener

[FTPListener21]
Enabled:  False
Port:     21
Protocol: TCP
Listener: FTPListener
"""


class ModuleTagTests(unittest.TestCase):
    def test_short_tags_are_picked_up_now(self) -> None:
        tags = _MODULE_TAG_RE.findall(REAL_LOG)

        self.assertIn("FTP", tags)
        self.assertIn("DNS Server", tags)

    def test_the_config_path_is_recovered_from_the_first_line(self) -> None:
        match = _CONFIG_PATH_RE.search(REAL_LOG)

        self.assertIsNotNone(match)
        self.assertEqual(
            match.group(1), r"C:\rf\tools\fakenet\configs\default.ini"
        )


class EnabledListenerTests(unittest.TestCase):
    def _config(self, tmp: str, text: str = CONFIG) -> str:
        path = Path(tmp) / "default.ini"
        path.write_text(text, encoding="utf-8")
        return str(path)

    def test_enabled_listeners_come_back(self) -> None:
        with TemporaryDirectory() as tmp:
            found = _enabled_listeners(self._config(tmp))

        self.assertIn("DNS Server", found)
        self.assertIn("HTTPListener80", found)
        self.assertIn("SMTPListener25", found)

    def test_a_disabled_listener_is_excluded(self) -> None:
        with TemporaryDirectory() as tmp:
            found = _enabled_listeners(self._config(tmp))

        self.assertNotIn("FTPListener21", found)

    def test_plumbing_sections_are_not_listeners(self) -> None:
        # [FakeNet] and [Diverter] carry no Listener key, which is what
        # separates them from a protocol handler.
        with TemporaryDirectory() as tmp:
            found = _enabled_listeners(self._config(tmp))

        self.assertNotIn("FakeNet", found)
        self.assertNotIn("Diverter", found)

    def test_a_missing_config_costs_the_list_and_nothing_else(self) -> None:
        self.assertEqual(_enabled_listeners(r"C:\nope\default.ini"), [])
        self.assertEqual(_enabled_listeners(""), [])

    def test_unparseable_config_does_not_raise(self) -> None:
        with TemporaryDirectory() as tmp:
            path = self._config(tmp, "this is not an ini file at all\n\x00\x01")
            self.assertEqual(_enabled_listeners(path), [])


if __name__ == "__main__":
    unittest.main()
