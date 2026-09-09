/*
   The 422e30ed chain's framework body, in memory.

   Written 16 Aug 2026 against `stage4_mapped_b454edc7.xor9` on the artifact
   drive, and validated against six real minidumps from run bb51babb.

   IT DOES NOT IDENTIFY A STAGE, AND AN EARLIER VERSION OF THIS FILE CLAIMED IT
   DID. It was named ..._Stage4_ContextCookie and read as a stage 4 detector.
   Measured afterwards: aligned on the seed, `stage4_mapped_b454edc7` and
   `stage3_alloc_at540M_dc038cc7` -- stage 3's own allocation, decrypted in
   place at 540M blocks -- are **97.5% byte-identical**, 266,597 of 273,408
   bytes, and every one of the four anchors below falls inside a shared run
   (the seed in a 16,444-byte run, the other three in an 87,806-byte one).
   Stage 3 and stage 4 are the same framework body carrying different data.

   So a match says *this chain is decrypted in this process*. It does not say
   which stage. That distinction is the chain's central open question -- stage 3
   crashes on the guest before it decrypts stage 4, in all nine detonations --
   and the six dumps this rule was validated against come from run bb51babb,
   which crashed like the rest. **What matched there was stage 3.** A rule
   reporting that as stage 4 would answer the open question wrongly while
   looking like evidence.

   Distinguishing the stages was investigated and cannot be done from these
   artifacts. The 6,811 differing bytes are not stage-4 code -- they are stage
   4's UNDECRYPTED REMAINDER. Across 0x11e0b-0x1215a stage 4 measures entropy
   7.42/7.47 against stage 3's 5.59/5.72, and at 0x11f89 stage 3 disassembles as
   ordinary code (`mov [ebp-0x340],eax ... sub ecx,[esi+0x6d8]`) where stage 4
   decodes as `pop di / outsd / lcall / iretd`. The packed side is stage 4's.
   No relocation deltas either. This is the loader rewriting ~98.8% of the
   region and not the rest.

   So a stage-4-only anchor would have to key on ciphertext, which is this
   build's keystream -- a hash wearing a signature's clothes. Being
   stage-agnostic is the honest ceiling here, not a temporary compromise. It
   changes when stage 4 runs its own decoders, which is the same thing the
   runtime IOC strings are waiting on.

   WHY THIS RULE IS NOT MADE OF THE IOCs.

   The 16 Aug FLOSS pass recovered this stage's first real indicators -- the
   Nokia5130c-2 user agent, the sqlite.org DLL fetch, IntelliForms, Chrome's
   `Local State`. The obvious rule is those strings, and it would match nothing.
   Measured, not assumed:

     - 30 candidate strings, ascii and wide, against the decrypted stage:
       ZERO hits. Not even as the 4-byte `mov [ebp-X], imm32` chunks a stack
       string leaves behind, so they are not stack-built literals in this image
       at all -- they come out of decoders that FLOSS reaches by emulating
       functions individually.
     - Against all sixteen minidumps on hand, including the six RegSvcs.exe
       images in which this stage was resident: ZERO hits.
     - Emulated from `after_handshake.state` through 42,072,701 blocks of stage 4
       to its fault in ntdll, then swept every mapped region: ZERO hits. The only
       matches anywhere were `windir`, `ProgramFiles`, `Program Files` and
       `SysWOW64` in ntdll's and kernel32's own images -- Windows' strings, in
       every process on the machine, and a false positive in any rule that lists
       them.

   So an IOC rule is a prediction about a code path nothing here has executed.
   It would also be indistinguishable from a broken scan, which is the failure
   this chain has manufactured four times already. The IOCs are recorded in
   docs/HANDOFF.md and in the artifact drive README, where they belong; they are
   deliberately not signatures.

   WHAT THE RULE IS MADE OF INSTEAD.

   The framework encodes pointers and handles against a per-instance cookie held
   at `[esi+0x6d8]` in its context struct, seeded with a hardcoded constant:

       mov  dword ptr [esi+0x6d8], 0x32dfd514      ; seed
       mov  eax, dword ptr [esi+0x744]             ; a stored, encoded field
       xor  eax, dword ptr [esi+0x6d8]             ; decode it
       cmp  ebx, eax                               ; compare against the live value

   That scheme is compiled in, so it is present wherever the framework is mapped
   and decrypted, whether or not the stealer ever ran. The seeding instruction is
   byte-identical in `stage3_alloc_at540M_dc038cc7.xor9` at 0x1605f and in
   `stage4_mapped_b454edc7.xor9` at 0x1447e -- same constant, same
   `push esi / call` shape after it. That is the shared body described above, not
   a coincidence between two stages.

   THE BARE OFFSET IS NOT USABLE AND THE HANDOFF SHOULD NOT BE READ AS SAYING SO.
   `[esi+0x6d8]` on its own appears in 168 of 7,014 PE files under System32 and
   SysWOW64, and 3 to 14 times in every single minidump measured -- benign ones
   included. It is good corroboration for a human reading a disassembly and a
   guaranteed false positive as a condition. Only the sequences below discriminate.

   MEASURED RESULTS

     matches   6/6   RegSvcs.exe dumps from run bb51babb (scheduled, exit, and
                     two WER crash dumps) -- the hollowed injection target.
                     That run crashed in stage 3, so these are stage 3 matches
     matches   2/2   decrypted framework artifacts (stage4_mapped,
                     stage3_alloc540M), which is the point: it reads both
     clean    10/10  other dumps from the same run: the sample's own launcher at
                     t1 and t25, conhost x3, powershell x4, and an unrelated
                     process dump
     clean     2/2   the encrypted twin `injected_source_98cc576c` and the
                     packed `stage3_native` -- so it reads decrypted, not stored
     clean  7014/7014 PE files under C:\Windows\System32 and SysWOW64

   The launcher dumps being clean is correct rather than a miss: the payload is
   section-mapped into RegSvcs.exe and was never in the launcher's address space.

   No `pe` module, no `uint16(0) == 0x5a4d`, no filesize bound. A minidump starts
   with `MDMP`, has no PE for the module to parse, and is two orders of magnitude
   larger than the on-disk file any of those conditions would have been written
   for -- each of the three silently reduces a rule to zero matches on the exact
   target this one exists for.

   Rules in tools\yara\local\ survive bootstrap_yara_rules.ps1, which replaces
   the downloaded rules directory.
*/

rule RingForge_FormBook_422e30ed_ContextCookie
{
    meta:
        author = "RingForge"
        description = "The 422e30ed chain decrypted in memory, by its [esi+0x6d8] context cookie. Stage-agnostic: stages 3 and 4 share 97.5% of their bytes and every anchor is in the shared body"
        reference = "docs/HANDOFF.md - Stage 4 is recovered, 16 Aug 2026"
        sha256 = "b454edc72887282752d53dd6712553cd41d69c5ff0a9c713129f4d2cd22ef78d"
        family = "FormBook"
        technique = "T1055.012 process hollowing, T1027 obfuscated files or information"
        confidence = "high"
        target = "process memory image -- validated on minidumps, not on files"
        caveat = "a match does not establish that stage 4 was reached"

    strings:
        // mov dword ptr [esi+0x6d8], 0x32dfd514
        // The cookie seed. The constant is the most specific thing in the image
        // and appears exactly once per mapped copy.
        $seed = { c7 86 d8 06 00 00 14 d5 df 32 }

        // mov eax, [esi+0x744] ; xor eax, [esi+0x6d8]
        // Decoding a stored field against the cookie. Twice per copy.
        $decode_744 = { 8b 86 44 07 00 00 33 86 d8 06 00 00 }

        // mov eax, [esi+0x6d8] ; xor eax, ebx
        // The same scheme in the other direction -- encoding a live value.
        $encode_ebx = { 8b 86 d8 06 00 00 33 c3 }

        // xor eax, [esi+0x6d8] ; cmp ebx, eax ; jne
        // Decode-and-check, the guard shape this stage uses before acting.
        $check = { 33 86 d8 06 00 00 3b d8 75 }

    condition:
        // The seed alone is strong -- a hardcoded 32-bit constant written to a
        // specific struct offset -- but one 10-byte sequence should not carry a
        // family attribution by itself, so require the scheme to be present too.
        // Both halves held in all six positive dumps and in both stage
        // artifacts, and neither fired anywhere else.
        ($seed and 1 of ($decode_744, $encode_ebx, $check))
        or all of ($decode_744, $encode_ebx, $check)
}
