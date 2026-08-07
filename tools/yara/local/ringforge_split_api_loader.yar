/*
   Loaders that fragment their API names to defeat a string search.

   Written against a payload this pipeline recovered on 07 Aug 2026, from the
   loader `422e30ed...`. Nine runs of that sample reported "no plaintext
   indicators at all" and matched no rule in the downloaded set, and the
   conclusion drawn at the time was that the ruleset was not at fault because
   there was nothing for a signature to key on.

   That was true of the 82 KB stage examined then and false of the chain. The
   892 KB stage recovered by the parent-at-spawn dump carries the whole injection
   API set as UTF-16 literals, split into fragments:

       'Virtual ' + 'Alloc'              -> VirtualAlloc
       'Write ' + 'Process ' + 'Memory'  -> WriteProcessMemory
       'Open ' + 'Process'               -> OpenProcess
       'Virtual ' + 'Protect'            -> VirtualProtect
       'Close ' + 'Handle'               -> CloseHandle
       'kernel ' + '32.dll'              -> kernel32.dll

   reassembled at runtime and resolved through GetDelegateForFunctionPointer.
   The fragments are what a signature can key on, and the splitting is a property
   of the evasion rather than of the family -- which is why this rule is written
   against the technique and not against that sample.

   Two things about the encodings, both load-bearing:

   `wide` is not optional and ascii is not usable. These are .NET user-string
   literals, so they exist only as UTF-16LE. `Alloc` and `Handle` also occur 42
   and 63 times as *ascii* inside the assembly's generated identifier names, so
   an ascii-or-wide rule would match on the decoy padding and say nothing.

   The trailing spaces are the signature. A normal program does not hold
   `"kernel "` and `"32.dll"` as two separate UTF-16 literals. Do not "tidy"
   them away.

   No `pe` module anywhere. These rules have to match a raw process dump, where
   the module cannot parse anything and a `pe`-gated condition matches zero
   times while looking like a clean scan.

   Checked against 120 genuine assemblies under C:\Windows\Microsoft.NET and
   Framework64 before being committed: zero matches.

   That clean set is PE files, and the scan target that matters here is a process
   dump. `"Open "` and `"Close "` in UTF-16 are ordinary UI text and a 150 MB dump
   of any GUI process will hold plenty of both, so the condition does not let the
   common fragments carry a match: `"kernel "`, `"32.dll"` and `"Virtual "` are all
   mandatory, and those three together are not something a normal process holds
   as separate UTF-16 literals. **This has not yet been scanned against a real
   memory dump.** The next run puts it against ten to twelve of them, and that is
   where a false positive would show; until then treat a hit on a dump as
   unconfirmed. Both controls in test_specs\ will exercise it too.

   Rules in tools\yara\local\ survive bootstrap_yara_rules.ps1, which replaces
   the downloaded rules directory.
*/

rule RingForge_Split_API_Injection_Loader
{
    meta:
        author = "RingForge"
        description = "Managed loader holding injection APIs as split UTF-16 fragments"
        reference = "docs/HANDOFF.md - loader reference data, 07 Aug 2026 run f3d26e46"
        technique = "T1055 process injection, T1027 obfuscated files or information"
        confidence = "medium"

    strings:
        // The split fragments. Trailing spaces are deliberate.
        $f_virtual  = "Virtual " wide
        $f_write    = "Write "   wide
        $f_process  = "Process " wide
        $f_open     = "Open "    wide
        $f_close    = "Close "   wide
        $f_find     = "Find "    wide

        $f_alloc    = "Alloc"    wide
        $f_protect  = "Protect"  wide
        $f_memory   = "Memory"   wide
        $f_handle   = "Handle"   wide

        // The library name, split the same way. Together these two are the
        // strongest single indicator here.
        $k_kernel   = "kernel "  wide
        $k_dll      = "32.dll"   wide

        // How a reassembled name is turned into something callable without a
        // P/Invoke declaration for a scanner to find.
        $resolve    = "GetDelegateForFunctionPointer" ascii wide

    condition:
        // Mandatory, and chosen for rarity rather than for completing a set: a
        // library name split across two UTF-16 literals, plus the one API prefix
        // that is not also ordinary UI text.
        $k_kernel and $k_dll and $f_virtual
        and $resolve
        // Then enough of the rest to show this is a reassembly scheme and not a
        // coincidence. `Open ` and `Close ` can help reach the threshold but
        // cannot reach it alone.
        and 3 of ($f_write, $f_process, $f_open, $f_close, $f_find)
        and 3 of ($f_alloc, $f_protect, $f_memory, $f_handle)
}

rule RingForge_Loader_422e30ed_Stage2
{
    meta:
        author = "RingForge"
        description = "The 892 KB stage-2 assembly of loader 422e30ed, forged as MemCompress Pro"
        reference = "docs/HANDOFF.md - loader reference data"
        sha256 = "e139c422121c32d68424f57e55b410d6c4a40376f4316bd9f2d2b43b77b80a2b"
        confidence = "high"

    strings:
        // Forged vendor and product. No such company or product exists; the
        // 82 KB stage of the same chain forged Microsoft branding instead, so
        // the decoy identity varies while the theme -- a system optimisation
        // utility -- does not.
        $v_product  = "MemCompress Pro"   ascii wide
        $v_company  = "RAMTech Solutions" ascii wide
        $v_comment  = "Advanced Windows memory compression and optimization service" ascii wide

        // The single encrypted resource: 284,673 bytes, entropy 7.998, one flag
        // byte followed by exactly 17,792 AES blocks.
        $res_name   = "na3PRqPuA2" ascii wide
        $aes        = "System.Security.Cryptography.AesCryptoServiceProvider" ascii wide

        // Two toolchains in one assembly: every decoy WinForms resource is read
        // by mscorlib 2.0.0.0 and the encrypted payload resource by 4.0.0.0.
        $mixed_20   = "mscorlib, Version=2.0.0.0" ascii
        $mixed_40   = "mscorlib, Version=4.0.0.0" ascii

    condition:
        (2 of ($v_*))
        or ($res_name and $aes)
        or ($res_name and $mixed_20 and $mixed_40)
}
