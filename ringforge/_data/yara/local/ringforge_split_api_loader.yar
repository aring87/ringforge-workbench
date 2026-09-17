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
   as separate UTF-16 literals.

   **Scanned against real memory dumps at last, on run 38f27025, 16 Aug 2026.**
   This read "has not yet been scanned against a real memory dump... until then
   treat a hit on a dump as unconfirmed" for nine days and seven runs, and the
   reason was not that nobody got round to it: rules in tools\yara\local\ reach
   the scan only when bootstrap_yara_rules.ps1 copies them to
   tools\yara\rules\local\, and that directory had never existed on the guest.
   Every run this project had done scanned 1542 downloaded rules and none of its
   own. Found by rescanning the run's dumps with scripts\rescan_memory_yara.py.

   Result over 11 dumps: it matched the launcher at t1, t25 and t34_atspawn and
   powershell.exe at t34, and did not match conhost, WerFault or either RegSvcs
   image. The feared false positive -- "Open " and "Close " as ordinary UTF-16 UI
   text in a large GUI process dump -- did not appear, which is what the
   mandatory-fragment condition was for. Treat a hit as confirmed.

   And it is MEMORY-ONLY: the 1,029,120-byte packed launcher on disk matches
   nothing, so the fragments exist only once the assembly is in memory. That is
   the delta this rule was written to expose, measured rather than assumed.

   RingForge_Loader_422e30ed_Stage2 below fired on the same run, on the
   t34_atspawn dump, and had never fired before: only the parent-at-spawn
   trigger reaches the 892 KB image.

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
        // `GetDelegateForFunctionPointer` is present in any managed process,
        // so it is a prerequisite and never evidence on its own.
        $resolve
        // Enough of the API set to show a reassembly scheme. `Open ` and
        // `Close ` can help reach the threshold but cannot reach it alone.
        and 3 of ($f_write, $f_process, $f_open, $f_close, $f_find)
        and 3 of ($f_alloc, $f_protect, $f_memory, $f_handle)

        // **PROXIMITY IS THE SIGNATURE, and its absence cost a false
        // positive on 17 Sep.** The presence test above says these fragments
        // exist somewhere in the scanned bytes, and the comment at the top of
        // this file explains why that was thought rare: a normal program does
        // not hold `kernel ` and `32.dll` as two separate UTF-16 literals.
        // True -- but only because in this loader they are *consecutive
        // literals in the user-string heap*. Nothing here required that, and
        // presence alone does not survive a large process dump.
        //
        // Measured. In the true positive (stage2 e139c422, 892 KB) every
        // fragment occurs exactly once, inside a 196-byte window, and
        // `kernel ` -> `32.dll` is a 16-byte gap. In a 51 MB WerFault.exe
        // dump of a *benign* signed Windows binary: `handle` 235 hits,
        // `32.dll` 196, `protect` 158, `kernel ` 64, scattered from offset
        // 10 KB to 51 MB -- and the whole rule fired. Across five benign
        // dumps the closest forward `kernel ` -> `32.dll` gap ran from
        // 106,080 to 952,742 bytes, and not one had a pair within 32.
        //
        // So: the library name must be split across two *adjacent* literals,
        // with the API fragments in the same heap region. 64 bytes is four
        // times the observed 16 and still three orders of magnitude below the
        // nearest benign coincidence.
        and for any i in (1..#k_kernel) : (
            for any j in (1..#k_dll) : (
                @k_dll[j] > @k_kernel[i]
                and @k_dll[j] - @k_kernel[i] <= 64
                // And `Virtual ` in the same neighbourhood, so a chance
                // adjacency somewhere else in a dump cannot carry a match.
                // Written as additions rather than subtractions: offsets are
                // unsigned in spirit and a near-zero anchor must not wrap.
                and for any v in (1..#f_virtual) : (
                    @f_virtual[v] + 2048 > @k_kernel[i]
                    and @k_kernel[i] + 2048 > @f_virtual[v]
                )
            )
        )
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
