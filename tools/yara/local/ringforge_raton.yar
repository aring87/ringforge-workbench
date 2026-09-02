/*
   Raton, a .NET RAT. Written 02 Sep 2026 against
   ce0d08be516376f5decc3bf6d8970fa493c925bc013a088c2a4eb8ed9f9fc3f1.

   WHAT THESE RULES ARE BUILT FROM, AND WHAT THEY ARE NOT VALIDATED AGAINST.

   One sample. Its C2 protocol was driven end to end on 02 Sep -- TLS, a
   0xDEADBEEF frame, a key-value body -- and its dispatcher was decompiled, so
   the strings below are understood rather than merely present.

   BENIGN RATE, MEASURED: 0 of 9,091 PE files. System32, both .NET Framework
   trees, the dotnet install and this repository, scanned 02 Sep. Managed code
   is the negative set that matters here, since every anchor is a .NET metadata
   string -- scanning only System32 would have been the easy version of this
   check and the wrong one.

   That is a floor, not a benign rate in the sense this project usually means:
   one machine's software, not a corpus of installers and third-party
   applications. It is enough to say these rules are not noisy on a Windows
   install with a developer toolchain on it.

   Every string was checked against the real bytes in both encodings before it
   was written down. That check is not ceremony: the payload's family strings
   live in the .NET #US heap and are **UTF-16LE only**, so an ascii pattern for
   any of them matches nothing. The type names and the PDB path are ascii, in
   #Strings. Getting that backwards is what `ringforge_formbook_stage4.yar`
   exists to remember.

   THE FRAME IS NOT A NETWORK SIGNATURE, THOUGH IT LOOKS LIKE ONE.

   The wire format is magic 0xDEADBEEF, compressed length, original size, a
   compression flag, payload, CRC-32. It is tempting to write `EF BE AD DE` as
   a traffic rule and it would match nothing: the client opens with a TLS
   ClientHello and every frame is inside the session. Measured 02 Sep -- five
   silent connections produced ClientHellos and no frames. The frame is useful
   against **memory and files**, not packets, unless a build is found that
   omits TLS.

   AN ANALYZER-ARTIFACT WARNING.

   The ascii forms of several of these strings appear in this project's own
   outputs: `HandlePacket.decompiled.cs` and `command_table.tsv` on the artifact
   drive both contain the command vocabulary in plain text. A sweep of the bench
   will match them and it is not malware. The payload rule uses wide-only
   patterns partly for that reason.
*/

rule RingForge_Raton_Client
{
    meta:
        author      = "RingForge"
        date        = "2026-09-02"
        description = "Raton .NET RAT client -- family strings, not config"
        reference   = "G:/ringforge-artifacts/ce0d08be-payload/"
        sample      = "ce0d08be516376f5decc3bf6d8970fa493c925bc013a088c2a4eb8ed9f9fc3f1"
        benign_rate = "0 of 9,091 PE files, 02 Sep -- see the header"

    strings:
        // The family naming itself. Recovered from the #US heap and confirmed
        // on the wire: the check-in's UID was Raton_Fcm7JziU, and Raton_ is the
        // literal it is built from.
        $name1 = ".BotKillerRaton" wide
        $name2 = "Raton_" wide

        // Protocol vocabulary. `listinfo` is the check-in packet type; the
        // other two are the client's own reply strings, observed on 02 Sep
        // when the dispatcher was driven.
        $proto1 = "listinfo" wide
        $proto2 = "Unknown packet type: " wide
        $proto3 = "You are already an admin" wide
        $proto4 = "PluginMessage" wide

        // Behaviour, in its own words.
        $act1 = "Add-MpPreference -ExclusionProcess" wide
        $act2 = "Ransomware started" wide
        $act3 = "This client was shared to you from someone" wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 20MB
        and (
            // Either name is close to conclusive on its own, but neither is
            // required: a build that renames itself keeps the protocol.
            any of ($name*)
            or 3 of ($proto*)
        )
        and any of ($proto*, $act*)
}

rule RingForge_Raton_Transport
{
    meta:
        author      = "RingForge"
        date        = "2026-09-02"
        description = "Stuff.dll, Raton's framing and config library"
        sample      = "d8ee0fc96ce8de2e37bc8fdc051da7c1852b9a510270e663ba17281de23f049b"
        note        = "the unpacked dll only; does NOT fire on the client"

        // Tested, because the obvious assumption was wrong. Costura embeds
        // stuff.dll in the client and some of its strings do survive into the
        // image -- `PacketCompressor` ascii, `Invalid magic` wide -- but only
        // one of the four type names does, so `2 of ($t*)` is not met and the
        // client does not match. That is the correct outcome: the client is
        // caught by RingForge_Raton_Client, and this rule keeps its meaning as
        // "the transport library, as a file on disk or in memory".

    strings:
        // Type names, ascii in #Strings.
        $t1 = "PacketFrame" ascii
        $t2 = "PacketCompressor" ascii
        $t3 = "PacketSerializer" ascii
        $t4 = "MinSizeToCompress" ascii

        // The two exceptions Decode throws, wide in #US. These are what a
        // silent listener sees when it answers with the wrong shape.
        $e1 = "Invalid magic" wide
        $e2 = "CRC mismatch" wide

        // The frame's magic as it appears in code, both orders. Present in the
        // IL as the ldc.i4 operand; NOT a network pattern, see the header.
        $magic = { EF BE AD DE }

    condition:
        uint16(0) == 0x5A4D
        and filesize < 20MB
        and 2 of ($t*)
        and (any of ($e*) or $magic)
}

/*
   This build only. Not family indicators -- an operator's builder sets all
   three, and a different campaign will differ. Kept separate so a hit here
   means something narrower and more useful: the same build, or the same
   operator.

   The password is the more interesting of them. The 02 Sep check-in reported
   `Pass` as empty while this literal sits in the image, so it is either unused
   in that direction or is an authentication step on the reply path that has
   not been tested.
*/
rule RingForge_Raton_Build_ce0d08be
{
    meta:
        author      = "RingForge"
        date        = "2026-09-02"
        description = "Raton, the ce0d08be build -- operator config, not family"
        confidence  = "build-specific by construction"

    strings:
        $pass     = "bbch4f57swBUEpVWfwKEKxJ" wide
        $telegram = "https://t.me/sillyisafed" wide
        $tag      = "silly21" wide
        $guid     = "5CDF2C82-841E-4546-9722-0CF74078229A" wide
        $box      = "raton client message box" wide

    condition:
        uint16(0) == 0x5A4D and 2 of them
}
