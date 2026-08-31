"""A dotted name is not a hostname, and case is the only thing that says so.

`embedded_network_indicators` fires on 71.7% of malware and 77.0% of third-party
software -- 1.0x, no discrimination at all -- and the reason turned out to be
partly what the extractor calls a domain. `Microsoft.CodeAnalysis.CSharp` has
the same shape as a hostname and appears in the same strings dump.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ioc_extract import _is_valid_domain, _looks_like_dotted_code


class ADottedNameIsNotAHostname(unittest.TestCase):
    """Nothing structural separates these two, which is why case has to.

        au-v20.events.endpoint.security.microsoft.com      a real Defender host
        microsoft.codeanalysis.csharp.symbols.metadata.pe  a C# namespace

    Both have six labels and a real suffix -- `.pe` is Peru -- so a label cap or
    a suffix check rejects one only by rejecting the other.
    """

    def test_a_pascal_case_namespace_is_code(self) -> None:
        name = "Microsoft.CodeAnalysis.CSharp.Symbols.Metadata.PE"

        self.assertFalse(_is_valid_domain(name.lower(), original=name))

    def test_a_real_host_of_the_same_shape_survives(self) -> None:
        name = "au-v20.events.endpoint.security.microsoft.com"

        self.assertTrue(_is_valid_domain(name.lower(), original=name))

    def test_go_runtime_symbols_are_code(self) -> None:
        # `reflect.Value.Int` appears in every Go binary and was being reported
        # as a network indicator on eight malware samples -- it even survived a
        # prevalence-based exclusion, because benign Go binaries are rare in
        # these corpora and it looked like a signal.
        name = "reflect.Value.Int"

        self.assertFalse(_is_valid_domain(name.lower(), original=name))

    def test_one_capital_is_not_enough(self) -> None:
        # A sentence-cased mention of a real host in a comment or a message is
        # still a host. Two capitalised labels is the bar, not one.
        self.assertFalse(_looks_like_dotted_code("Discord.com"))
        self.assertFalse(_looks_like_dotted_code("Ip-api.com"))

    def test_two_labels_are_left_to_the_older_rule(self) -> None:
        # `System.IO` and `paint.net` are handled by `_looks_like_namespace`,
        # which predates this and keys on a namespace root rather than on case.
        self.assertFalse(_looks_like_dotted_code("System.IO"))

    def test_case_is_gone_by_the_time_the_domain_is_folded(self) -> None:
        # The regression this guards: the call site lowercased the match before
        # validation, so the check could not run even though its docstring said
        # it did. Without the original, the namespace is indistinguishable.
        name = "Microsoft.CodeAnalysis.CSharp.Symbols.Metadata.PE"

        self.assertTrue(_is_valid_domain(name.lower()))
        self.assertFalse(_is_valid_domain(name.lower(), original=name))


if __name__ == "__main__":
    unittest.main()
