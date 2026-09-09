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

   RE-MEASURED 02 Sep after `$gate1` was added: 0 of 13,174 PE files over the
   same roots. The figure moved because the sweep took more extensions, not
   because the corpus did -- and it was re-run rather than carried over
   because a new anchor is a new way to fire, so the old number would have
   been a claim about a rule that no longer existed.

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
        benign_rate = "0 of 13,174 PE files, 02 Sep -- see the header"

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

        // A hardcoded gate constant, not operator config: `case "Hosts"` reads
        // `Content` and returns the hosts file only when it equals this.
        // Anything else is base64-decoded over the file, so the same command
        // reads or overwrites depending on one literal. Wide-only, once in the
        // image, and not a word anyone else uses -- which is why it anchors.
        $gate1 = "123ratonpro" wide

        // Behaviour, in its own words.
        $act1 = "Add-MpPreference -ExclusionProcess" wide
        $act2 = "Ransomware started" wide
        $act3 = "This client was shared to you from someone" wide

        // A builder placeholder left unpatched. The published source
        // (codeberg.org/Raton/Raton, Client/Things/Config.cs) initialises every
        // config field to `silly1`..`silly21` and the builder overwrites what
        // the operator sets; anything untouched ships as its literal. So this
        // is a family string that happens to be evidence of a lazily
        // configured build, not the operator tag it was first read as.
        // Corroborating only -- on its own it is three syllables of nothing.
        $cfg1 = "silly21" wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 20MB
        and (
            // Either name is close to conclusive on its own, but neither is
            // required: a build that renames itself keeps the protocol.
            any of ($name*)
            or $gate1
            or 3 of ($proto*)
        )
        and any of ($proto*, $act*, $cfg*)
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
   A RATON BUILD WITH THE BUILDER'S DEFAULTS LEFT IN PLACE.

   THIS RULE WAS `RingForge_Raton_Build_ce0d08be` AND CLAIMED TO IDENTIFY AN
   OPERATOR. It did not, and the renaming is the point: three of its four
   original strings turned out to be things the builder ships, not things a
   customer chose. Kept, because "the operator changed nothing" is a real and
   useful property -- just not the one the old name asserted.

   What left it, and why, because the pattern is the whole lesson:

     silly21          02 Sep. The published source initialises every config
                      field to a placeholder `silly1`..`silly21`. The string is
                      a field left unset, so it identifies the builder and
                      belongs in the family rule, where it now sits.

     5CDF2C82-...     02 Sep. Not this operator's anything: the IID of
                      IAudioEndpointVolume, loaded by the payload's own
                      SetVolume to reach the Core Audio API. Found by reading
                      SetVolume while chasing an unrelated crash, which is the
                      only reason it was ever questioned.

     t.me/sillyisafed 02 Sep. THE AUTHOR'S CHANNEL, not the operator's. It is
                      hardcoded in the client as a status string --
                      `case "Telegram"` reports "Sending messages to
                      sillyisafed..." before calling TdataFinder.CheckAndSend
                      -- and a builder does not patch status messages. The
                      channel is named "Silly", 356 subscribers, and links a
                      shop at raton.fun. So the config `Website` carrying it is
                      the builder's default, exactly like silly21.

   WHAT IS LEFT AND WHAT IT MEANS.

   `$box` is placeholder prose: the image carries "Hello, i'm the description
   of your raton client message box" and "Hello, im a title for your message
   box". Nobody writes that on purpose for a victim; it is what the builder
   puts in the field when the operator does not.

   `$pass` is the only string here that might be the operator's, and it is not
   established that it is -- a builder that generates a random password per
   build would produce exactly this. The 02 Sep check-in reported `Pass` as
   empty while the literal sits in the image, so it is either unused in that
   direction or an authentication step on the reply path that has not been
   tested.

   SO A HIT MEANS: a Raton build that shipped with its message-box text and its
   Website field untouched. It does NOT mean the same operator, and it must not
   be used to link campaigns.
*/
rule RingForge_Raton_Default_Config
{
    meta:
        author      = "RingForge"
        date        = "2026-09-02"
        description = "Raton shipped with builder defaults -- NOT an operator link"
        confidence  = "identifies an unconfigured build, not a campaign"
        renamed_from = "RingForge_Raton_Build_ce0d08be, 02 Sep -- see the header"
        sample      = "ce0d08be516376f5decc3bf6d8970fa493c925bc013a088c2a4eb8ed9f9fc3f1"

    strings:
        // Builder defaults, all three.
        $telegram = "https://t.me/sillyisafed" wide
        $box      = "raton client message box" wide
        $boxtitle = "Hello, im a title for your message box" wide

        // Possibly the operator's, possibly builder-generated. Unresolved.
        $pass     = "bbch4f57swBUEpVWfwKEKxJ" wide

    condition:
        uint16(0) == 0x5A4D and 2 of them
}
