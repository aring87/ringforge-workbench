"""Crack stage 3's CRC-32/MPEG-2 name hashes -- dictionary sweep, then exhaustive.

Two things this does that the earlier sweeps in docs/HANDOFF.md did not.

**Bare stems.** `0x5c4ee455` turned out to be `"wow64"`, not `wow64.dll`. Every
earlier brute force in that document iterated *filenames*, extensions included,
so a hash over a bare stem could not have matched however large the wordlist
was. Every corpus name here is expanded into a set of variants -- full name,
one extension stripped, all extensions stripped -- and the stem forms are what
the sweep actually leans on.

**An exhaustive search with a stated bound.** CRC-32 is affine and each byte
step is invertible, so a meet-in-the-middle search over L unknown characters
costs 39^ceil(L/2) rather than 39^L. That turns "no dictionary matched" into
"no string of at most N characters over [a-z0-9._-] hashes to this", which is a
different and much stronger negative. Past that bound the search stops being an
answer: at 39^L candidates against a 32-bit space the expected number of
accidental preimages passes 1 around L=6 and reaches ~1250 by L=8, so the
report prints the expected collision count next to every hit and refuses to
present long-length noise as a finding.

Self-tested against names whose hashes this project already measured -- notably
`"wow64"`, the one bare stem known to be right -- because a cracker checked only
by whether it finds something will always find something.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------- the hash

POLY = 0x04C11DB7


def _build_table() -> list[int]:
    tab = []
    for i in range(256):
        c = i << 24
        for _ in range(8):
            c = ((c << 1) ^ POLY) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
        tab.append(c)
    return tab


TAB = _build_table()
NPTAB = np.array(TAB, dtype=np.uint32)


def crc(name: bytes) -> int:
    """CRC-32/MPEG-2: init 0xFFFFFFFF, non-reflected, poly 0x04C11DB7, final NOT."""
    c = 0xFFFFFFFF
    for ch in name:
        c = ((c << 8) & 0xFFFFFFFF) ^ TAB[((c >> 24) ^ ch) & 0xFF]
    return (~c) & 0xFFFFFFFF


# The byte step is invertible: tab[i] & 0xFF is a bijection in i, so the low
# byte of the new state names the table entry that was mixed in.
_INV_LOW = {}
for _i, _v in enumerate(TAB):
    _INV_LOW[_v & 0xFF] = _i
assert len(_INV_LOW) == 256, "tab[i] & 0xFF is not a bijection; inversion is wrong"
NPINV = np.zeros(256, dtype=np.uint32)
for _low, _i in _INV_LOW.items():
    NPINV[_low] = _i


# ------------------------------------------------------------- self-tests

# Measured elsewhere in this project and recorded in docs/HANDOFF.md.
KNOWN = {
    "wow64": 0x5C4EE455,          # not a stem after all -- a 5-char substring
    "sychpe32": 0x79DBE71D,       # its 8-char sibling; both are arch directories
    "regsvcs.exe": 0xE2E77DAF,
    "ntdll.dll": 0x0B4E1AE2,
    "wow64.dll": 0x80515AD9,
    "wow64base.dll": 0x42D73626,
    "wow64win.dll": 0xCBEDD56F,
    "wow64con.dll": 0x4EF3B040,
    "wow64cpu.dll": 0x79069242,
    "kernel32.dll": 0xADEDAB08,
    "kernelbase.dll": 0x21094B62,
    "sbiedll.dll": 0xE11DA208,     # confirmed against Stormshield's published table
    "sharedintapp.exe": 0x9CB95240,  # Parallels; FormBook blocklist position 14
    "aqtd9dq.dll": 0xE11DA208,     # the solved GF(2) preimage, not a real name
}


def self_test() -> None:
    bad = [(n, h, crc(n.encode())) for n, h in KNOWN.items() if crc(n.encode()) != h]
    if bad:
        for n, want, got in bad:
            print(f"  FAIL {n}: want {want:#010x} got {got:#010x}")
        sys.exit("hash function does not reproduce known values; nothing below would mean anything")
    print(f"self-test: {len(KNOWN)} known name/hash pairs reproduced")


# ------------------------------------------------------------ the targets

# The blocklist is the canonical FormBook 20-entry list in the canonical order:
# 14 of 20 positions hash-match the published table exactly. The six below are
# this variant's substitutions, and the position names the slot each one filled.
TARGETS = {
    0xE11DA208: "module lookup -- the gate on the crash branch",
    0xD0C58467: "blocklist pos 3  (published: vboxservice.exe)",
    0xA8D123C8: "blocklist pos 4  (published: vboxtray.exe)",
    0xC72CE2D5: "blocklist pos 11 (published: prl_tools_service.exe)",
    0x0263178B: "blocklist pos 12 (published: prl_tools.exe)",
    0x57585356: "blocklist pos 13 (published: prl_cc.exe)",
    0x0CC39FEF: "blocklist pos 15 (published: vmtoolsd.exe)",
}

# Analysis, sandbox, VM and AV process names. The thirteen already recovered are
# included so a regression in the corpus shows up as those going missing.
TOOL_NAMES = """
procmon procmon64 procexp procexp64 procexplorer regmon filemon
wireshark tshark dumpcap netmon netmon.exe rawcap smsniff windump tcpdump
fiddler charles httpdebugger httpanalyzerstdv7 networkminer ettercap
ollydbg ollyice x32dbg x64dbg x96dbg windbg windbgx immunitydebugger
idaq idaq64 idaw idaw64 ida ida64 idag idag64 idau idau64 ghidra ghidrarun
radare2 r2 cutter binaryninja hopper dnspy dnspy-x86 dnspyex ilspy reflector
de4dot megadumper scylla scylla_x64 scylla_x86 importrec impre lordpe
petools pestudio peid exeinfope protection_id die diec resourcehacker
cff cffexplorer x64_dbg dbgview dbgview64 debugview
sysanalyzer sniff_hit joeboxcontrol joeboxserver joebox
sandboxiedcomlaunch sandboxierpcss sandboxiecrypto sandboxiedrv sbiesvc
sbiectrl sandman cuckoo cuckoomon agent agent.py analyzer
python python3 pythonw perl ruby wscript cscript
vmwareuser vmwareservice vmwaretray vmtoolsd vmsrvc vmusrvc vmacthlp
vmware vmware-authd vmware-hostd vmware-tray vmware-vmx vmwareuser.exe
vboxservice vboxtray vboxcontrol vboxguest vboxsf vboxvideo virtualbox
virtualboxvm vboxheadless vboxmanage vboxsvc qemu qemu-ga xenservice
prl_cc prl_tools prl_deskctl parallels df5serv joeboxserver
wpe wpespy apimonitor apimonitor-x86 apimonitor-x64 apispy winapioverride32
regshot autoruns autorunsc tcpview tcpvcon portmon handle listdlls
processhacker processhacker2 systemexplorer systeminformer taskmgr
perfmon resmon procdump procdump64 livekd rammap vmmap
ksdumperclient ksdumper hookexplorer multi_pot capturebat
fakenet fakenet-ng inetsim honeyd dumpcap.exe
lordpe.exe qemu-ga.exe xenservice.exe
avp avpui egui ekrn nod32krn mcshield avgui avgsvc avastui avastsvc
bdagent vsserv bdservicehost mbam mbamservice msmpeng nissrv
sysinspector proc_analyzer sniff_hit multi_pot capturebat df5serv
joeboxcontrol joeboxserver hookexplorer importrec petools lordpe
autorunsc dumpcap idaq64 idaw64 immunitydebugger regshot32 apispy32
""".split()

# Modules a sandbox, AV or instrumentation tool *injects into other processes*.
# This is the class a PEB walk looking up a module by hash is actually for, and
# the corpus above had none of it -- `0xe11da208` is `sbiedll.dll`, Sandboxie's
# injected DLL, and no amount of System32 filenames or tool process names would
# ever have contained it.
INJECTED_DLLS = """
sbiedll.dll sbiedll sbiehost.dll sbiesvc.dll
api_log.dll dir_watch.dll pstorec.dll vmcheck.dll wpespy.dll
cmdvrt32.dll cmdvrt64.dll guard32.dll guard64.dll
snxhk.dll snxhk64.dll aswhook.dll aswhooka.dll
avghookx.dll avghooka.dll avghookx64.dll
sxin.dll sf2.dll sysfer.dll sysferthunk.dll
dbghelp.dll dbk32.dll dbk64.dll
vboxhook.dll vboxmrxnp.dll vboxdisp.dll vboxogl.dll vboxoglpackspu.dll
vboxguest.dll vboxsf.dll vboxservice.dll vboxtray.dll
vmcheck32.dll vmhgfs.dll vmmousetrap.dll vmtools.dll vmwarebase.dll
prl_cc.dll prl_tools.dll prleth.dll prlfs.dll
frida-agent.dll frida-gadget.dll frida-helper.dll
pinvm.dll pin.dll detoured.dll detours.dll
log_api.dll log_api32.dll log_api64.dll
winhook.dll hookdll.dll deploy.dll martini.dll
cuckoomon.dll capemon.dll analyzer.dll
qmemulator.dll qmon.dll
sandbox.dll sandboxie.dll
npf.dll npf.sys packet.dll wpcap.dll npcap.dll pktmon.dll
vmci.dll vsocklib.dll hgfs.dll vmguestlib.dll vmstatsprovider.dll
vmwaredmd.dll vmnat.dll vmnetbridge.dll vmrawdsk.dll vmdesched.dll
atcuf32.dll atcuf64.dll bdhkm.dll bdsandbox.dll
a2hooks32.dll kloehk.dll klsihk.dll mchinjdrv.dll
tmmon.dll tmumh.dll pavshld.dll wrusr.dll mbae.dll mbamext.dll
sophos_detoured.dll sophos_detoured_x64.dll
speedhack-i386.dll wined3d.dll winex11.drv
hmpalert.dll hmpalert.sys hmpsched.exe
avcuf32.dll avcuf64.dll bdsnmp.dll gzflt.sys trufos.sys bdselfpr.sys
ashldres.dll aswsp.sys aswmonflt.sys aswsnx.sys aswrdr2.sys
avghookx64.dll avgtpx86.sys avgtpx64.sys
a2hooks64.dll a2acc.dll a2util32.dll
eamsi.dll eguiproxy.dll ekrnepfw.sys epfwwfp.sys ehdrv.sys eamonm.sys
kl1.sys klif.sys klflt.sys klwtblfs.sys klhk.sys klupd.dll
mfehcthe.dll mfehidk.sys hipi.dll hipsdll.dll mvbcf.dll epehshim.dll
mfeavfk.sys mfewfpk.sys mfencbdc.sys
tmactmon.sys tmevtmgr.sys tmmon64.dll tmcomm.sys tmtdi.sys
fshook32.dll fshook64.dll fsdfw.sys fsatp.sys fsgk.sys
symamsi.dll symefasi.sys symevnt.sys srtsp.sys ccsetx86.dll
wrdll.dll wrcore.dll wrpdlla.dll wrkrn.sys
mbae64.dll mbae-api.dll mbae-api-na.dll mbamswissarmy.sys mwac.sys
panda_url_filtering.dll pavdrv.sys pavproc.sys
360base.dll safemon.dll sysdiag.sys 360avflt.sys qutmdrv.sys
csagent.sys umppc.dll cbstream.sys cbk7.sys carbonblackk.sys
inprocessclient.dll inprocessclient64.dll sentinelmonitor.sys
cyvrfsfd.sys cyverak.sys cyvrmtgn.sys tlaworker.dll cyoptics.sys
cylancememdef.dll cymemdef.dll cymemdef64.dll
rapportgp.dll rapportcerberus.dll dgapi.dll dgagent.dll
sysferthunk64.dll cmdguard.sys cmdhlp.sys
bsa.dll iprtprocess.dll netredirect.dll
vboxoglcrutil.dll vboxoglerrorspu.dll vboxoglfeedbackspu.dll
vboxoglpassthroughspu.dll vboxdispd3d.dll vboxnine.dll vboxsvga.dll
vboxwddm.sys vboxmouse.sys vboxvideo.sys vboxguest.sys vboxsf.sys
vm3dgl.dll vm3dum.dll vm3dum_10.dll vm3dum_loader.dll vmguestlibjava.dll
vmusbmouse.sys vmmouse.sys vmhgfs.sys vmwsclnt.dll vmtray.dll vmx_svga.dll
xenvbd.sys xennet.sys xenevtchn.sys xenbus.sys xeniface.dll
dynamorio.dll drpreinject.dll drinjectlib.dll vehdebug-i386.dll
qmemulator32.dll snxhk32.dll sf2_32.dll
""".split()


# Anti-analysis artifacts that are not filenames. Window classes, driver device
# paths and named pipes are all checked by the same families that check for
# `sbiedll.dll`, and none of them would appear in any filename or export corpus.
# Case is preserved deliberately -- a window class comparison is usually exact.
MISC_ARTIFACTS = """
OLLYDBG WinDbgFrameClass ID Zeta_Debugger Rock_Debugger ObsidianGUI
PROCEXPL PROCMON_WINDOW_CLASS TFormFileMon TFormRegmon Filemon Regmon
SandboxieControlWndClass Sandboxie gdkWindowToplevel wireshark
Afx:400000:0 TIdaWindow TApplication TWinControl
\\\\.\\VBoxGuest \\\\.\\VBoxMiniRdrDN \\\\.\\VBoxTrayIPC \\\\.\\HGFS \\\\.\\vmci
\\\\.\\pipe\\cuckoo \\\\.\\NPF_NdisWanIp \\\\.\\NPF \\\\.\\SICE \\\\.\\SIWDEBUG
\\\\.\\NTICE \\\\.\\REGVXD \\\\.\\FILEVXD \\\\.\\TRW \\\\.\\ICEEXT
VBoxGuest VBoxMiniRdrDN VBoxTrayIPC HGFS vmci SICE NTICE SIWDEBUG TRW ICEEXT
VBoxService VBoxTray VBoxSF VBoxMouse VBoxVideo VBoxWddm
SbieDll SbieSvc SbieCtrl BoxedAppSDK
Sandboxie_DefaultBox Sandboxie_Session0
_SB_SVC_MUTEX_ Frz_State DBWinMutex
VMwareService VMwareTray VMwareUser vmtoolsd
""".split()


# ----------------------------------------------------------- the corpus

def variants(raw: str) -> set[str]:
    """Every reading of one filename the hash might have been taken over."""
    n = raw.strip().lstrip("\ufeff").lower()
    if not n:
        return set()
    out = {n}
    # one extension off -- "wow64.dll" -> "wow64", the case that started this
    stem, dot, _ext = n.rpartition(".")
    if dot and stem:
        out.add(stem)
    # every extension off -- "accessibility.ni.dll" -> "accessibility"
    out.add(n.split(".")[0])
    return {v for v in out if v}


def build_corpus(verbose: bool = True, exports: bool = False) -> dict[str, list[str]]:
    """name -> the sources it came from, so a hit can be traced back."""
    corpus: dict[str, list[str]] = {}

    def add(name: str, source: str) -> None:
        for v in variants(name):
            corpus.setdefault(v, [])
            if source not in corpus[v]:
                corpus[v].append(source)

    def add_exact(name: str, source: str) -> None:
        """For export names: no extension stripping, but both cases.

        An API name is not a filename. `variants` would turn
        `RtlGetVersion` into itself and nothing useful, but it would also
        mangle anything containing a dot -- ordinal-style and C++ decorated
        exports both do -- so those go in verbatim.
        """
        for v in (name, name.lower()):
            corpus.setdefault(v, [])
            if source not in corpus[v]:
                corpus[v].append(source)

    counts = {}

    for rel in ("docs/guestloaded.txt", "guestloaded.txt"):
        p = REPO / rel
        if not p.exists():
            continue
        before = len(corpus)
        lines = p.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        for line in lines:
            add(line, rel)
        counts[rel] = (len(lines), len(corpus) - before)

    for d in (r"C:\Windows\SysWOW64", r"C:\Windows\System32",
              r"C:\Windows\SysWOW64\drivers", r"C:\Windows\System32\drivers"):
        before = len(corpus)
        n = 0
        try:
            for f in os.listdir(d):
                if f.lower().endswith((".dll", ".exe", ".sys", ".ocx", ".drv", ".cpl", ".node")):
                    add(f, d)
                    n += 1
        except OSError:
            continue
        counts[d] = (n, len(corpus) - before)

    before = len(corpus)
    for t in TOOL_NAMES:
        add(t, "tool list")
        add(t + ".exe", "tool list")
        add(t + ".dll", "tool list")
        add(t + ".sys", "tool list")
    counts["tool list"] = (len(TOOL_NAMES), len(corpus) - before)

    before = len(corpus)
    for t in INJECTED_DLLS:
        add(t, "injected-DLL list")
        if not t.endswith(".dll"):
            add(t + ".dll", "injected-DLL list")
    counts["injected-DLL list"] = (len(INJECTED_DLLS), len(corpus) - before)

    before = len(corpus)
    for t in MISC_ARTIFACTS:
        add_exact(t, "artifact list")
        add(t, "artifact list")
    counts["artifact list"] = (len(MISC_ARTIFACTS), len(corpus) - before)

    # Every export of every system DLL, not the twelve `decode_name_hashes.py`
    # used. `0x79dbe71d` came off the same decoder as 43 hashes that turned out
    # to be API names, so "it is a module name" was only ever an assumption
    # inherited from the two hashes either side of it.
    if exports:
        import pefile
        before = len(corpus)
        files = 0
        for d in (r"C:\Windows\SysWOW64", r"C:\Windows\System32"):
            try:
                entries = os.listdir(d)
            except OSError:
                continue
            for f in entries:
                if not f.lower().endswith((".dll", ".exe", ".ocx", ".drv", ".cpl")):
                    continue
                path = os.path.join(d, f)
                try:
                    pe = pefile.PE(path, fast_load=True)
                    pe.parse_data_directories([0])
                    syms = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
                    if syms:
                        for e in syms.symbols:
                            if e.name:
                                add_exact(e.name.decode("ascii", "replace"),
                                          "system export tables")
                    pe.close()
                    files += 1
                except Exception:
                    continue
        counts["system export tables"] = (files, len(corpus) - before)

    if verbose:
        for src, (read, added) in counts.items():
            print(f"  {added:>7,} new names from {read:,} entries  {src}")
        print(f"  {len(corpus):>7,} distinct candidate names in the corpus")
    return corpus


def dictionary_sweep(corpus: dict[str, list[str]], targets: dict[int, str]) -> dict[int, list[str]]:
    hits: dict[int, list[str]] = {}
    for name, sources in corpus.items():
        h = crc(name.encode())
        if h in targets:
            hits.setdefault(h, []).append(f"{name!r}  (from {', '.join(sources)})")
    return hits


# ------------------------------------------- exhaustive meet-in-the-middle

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789._-"

#: The lowercase bound says nothing about a name that was never lowercased.
#: `get_module_base_by_hash` lowercases its input, but 43 of the 45 hashes off
#: the same decoder are API names, which are case-sensitive -- so a mixed-case
#: preimage is only excluded once it is actually searched for.
ALPHABET_MIXED = ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                  "0123456789._-")


def _fwd(states: np.ndarray, chars: np.ndarray) -> np.ndarray:
    """Append one character: index becomes c * len(states) + old_index."""
    s = states[None, :]
    idx = ((s >> np.uint32(24)) ^ chars[:, None]) & np.uint32(0xFF)
    return (((s << np.uint32(8)) & np.uint32(0xFFFFFFFF)) ^ NPTAB[idx]).ravel()


def _bwd(states: np.ndarray, chars: np.ndarray) -> np.ndarray:
    """Strip one character off the end: which state would have led here."""
    s = states[None, :]
    idx = NPINV[s & np.uint32(0xFF)]
    b = (s ^ NPTAB[idx]) >> np.uint32(8)
    a = (idx ^ chars[:, None]) & np.uint32(0xFF)
    return ((a << np.uint32(24)) | b).ravel()


def _decode(index: int, n: int, reverse: bool, alphabet: str = ALPHABET) -> str:
    """Little-endian base-39; digit k is the k-th character that was added.

    `reverse` is about which end characters were added at. The forward half adds
    them left to right, so its digits come out already in string order. The
    backward half strips them off the end, so its first digit is the *last*
    character and the digits have to be flipped.
    """
    chars = []
    for _ in range(n):
        index, d = divmod(index, len(alphabet))
        chars.append(alphabet[d])
    return "".join(reversed(chars)) if reverse else "".join(chars)


def mitm(target: int, unknown: int, prefix: str = "", suffix: str = "",
         alphabet: str = ALPHABET) -> list[str]:
    """Every string prefix + <unknown chars over alphabet> + suffix hashing to target."""
    chars = np.array([ord(c) for c in alphabet], dtype=np.uint32)

    start = np.uint32(0xFFFFFFFF)
    for ch in prefix.encode():
        start = np.uint32(((int(start) << 8) & 0xFFFFFFFF) ^ TAB[((int(start) >> 24) ^ ch) & 0xFF])

    goal = np.uint32((~target) & 0xFFFFFFFF)
    for ch in reversed(suffix.encode()):
        i = int(NPINV[int(goal) & 0xFF])
        goal = np.uint32(((((int(goal) ^ TAB[i]) >> 8)) | ((i ^ ch) << 24)) & 0xFFFFFFFF)

    p = unknown // 2
    s = unknown - p

    f = np.array([start], dtype=np.uint32)
    for _ in range(p):
        f = _fwd(f, chars)
    b = np.array([goal], dtype=np.uint32)
    for _ in range(s):
        b = _bwd(b, chars)

    order_f = np.argsort(f, kind="stable")
    fs = f[order_f]
    pos = np.searchsorted(fs, b)
    pos_clipped = np.clip(pos, 0, len(fs) - 1)
    match = fs[pos_clipped] == b

    out = []
    for bi in np.flatnonzero(match):
        v = b[bi]
        lo = np.searchsorted(fs, v, side="left")
        hi = np.searchsorted(fs, v, side="right")
        for fi in order_f[lo:hi]:
            cand = (prefix
                    + _decode(int(fi), p, reverse=False, alphabet=alphabet)
                    + _decode(int(bi), s, reverse=True, alphabet=alphabet)
                    + suffix)
            if crc(cand.encode()) == target:      # never trust the index arithmetic
                out.append(cand)
    return sorted(set(out))


def expected_collisions(unknown: int, alphabet: str = ALPHABET) -> float:
    return len(alphabet) ** unknown / 2 ** 32


def mitm_self_test() -> None:
    """The search must rediscover the one bare stem already known to be right."""
    got = mitm(0x5C4EE455, unknown=5)
    if "wow64" not in got:
        sys.exit(f"MITM failed to find 'wow64' at length 5; found {got}")
    got2 = mitm(0xADEDAB08, unknown=8, suffix=".dll")
    if "kernel32.dll" not in got2:
        sys.exit(f"MITM failed to find 'kernel32.dll'; found {got2}")
    got3 = mitm(crc(b"Sleep"), unknown=5, alphabet=ALPHABET_MIXED)
    if "Sleep" not in got3:
        sys.exit(f"MITM failed to find mixed-case 'Sleep'; found {got3}")
    print("MITM self-test: rediscovered 'wow64' (bare stem) and 'kernel32.dll' (suffixed)")


def compose_self_test() -> None:
    """Must recover blocklist names already cracked, from their morphemes."""
    # The last two are synthetic and deliberate: a 3- and a 4-token name can
    # only be reassembled through the (1,2)/(2,1) and (2,2) splits, so without
    # them a reconstruction bug in the deeper levels hides behind the crc guard
    # as a silent miss rather than showing up as a wrong answer.
    for name in ("vmwareservice.exe", "procmon.exe", "sandboxierpcss.exe",
                 "sandnetmonitor.exe", "vmboxnetspy.exe"):
        got = [c for c, _ in compose_search(crc(name.encode()), [".exe"])]
        if name not in got:
            sys.exit(f"composition search failed to rebuild {name!r}; found {got}")
    print("composition self-test: rebuilt 5 names from tokens, "
          "including a 3- and a 4-token split")


# ------------------------------------------------- composition over tokens

# Raw brute force dies at seven characters: 39^L against a 32-bit space passes
# one expected accidental preimage at L=6 and reaches ~1250 by L=8, so a hit
# stops being a finding. Real tool names are longer than that but they are not
# random -- `sandboxiedcomlaunch`, `vmwareservice`, `processhacker` are all
# concatenated morphemes. Searching compositions of a vocabulary instead of
# arbitrary strings reaches names of any length while keeping the candidate
# count, and therefore the noise floor, low.
VOCAB = """
a b c d e f g h i j k l m n o p q r s t u v w x y z
0 1 2 3 4 5 6 7 8 9 32 64 86 x86 x64 x32 win32 win64 _x86 _x64 -x86 -x64
vm vmware vbox virtual virtualbox box sand sandbox sandboxie sbie
qemu xen hyperv parallels prl wine bochs kvm virtualpc vpc
proc process processes procs task tasks image exe app
mon monitor monitoring watch watcher observe view viewer
exp explorer explore hack hacker hacking inform informer
wire shark sniff sniffer sniffing capture cap packet net network
tcp udp ip http https dns port ports conn connection
debug debugger dbg dbgv ida olly ollydbg windbg gdb lldb x64dbg x32dbg
disasm disassembler decompile decompiler dump dumper dumping memdump
spy spyer trace tracer tracing hook hooker hooking inject injector
scan scanner scanning analy analyz analyze analyzer analysis
agent guest tools tool tray service services svc srv serv host helper
ctl control controller daemon server client manager mgr launch launcher
com dcom rpc rpcss crypto crypt drv driver sys system
py python perl ruby java node script wscript cscript powershell
cuckoo joe joebox anubis threat expert threatexpert sunbelt norman
fake fakenet inet inetsim honey honeyd apate
reg registry regshot file files filemon regmon
auto autorun autoruns start startup boot
api win windows nt user kernel base core
av anti antivirus virus malware defender secure security sec
kav kaspersky avp eset nod nod32 avast avg mcafee symantec norton
bit bitdefender bd malwarebytes mbam sophos trend micro comodo panda
emu emulator emulate sim simulate simulator
log logger logging record recorder report reporter
res resource hacker studio pe peid pestudio lord lordpe
imp import rec importrec scylla mega megadumper protect protection
detect detector detection ident identify identifier
""".split()


def compose_search(target: int, suffixes: list[str], max_tokens: int = 4,
                   vocab: list[str] | None = None) -> list[tuple[str, int]]:
    """Every concatenation of <= max_tokens vocabulary tokens hashing to target."""
    vocab = vocab or VOCAB
    v = len(vocab)
    toks = [t.encode() for t in vocab]

    def fwd(states: np.ndarray, tok: bytes) -> np.ndarray:
        for ch in tok:
            idx = ((states >> np.uint32(24)) ^ np.uint32(ch)) & np.uint32(0xFF)
            states = ((states << np.uint32(8)) & np.uint32(0xFFFFFFFF)) ^ NPTAB[idx]
        return states

    def bwd(states: np.ndarray, tok: bytes) -> np.ndarray:
        for ch in reversed(tok):
            i = NPINV[states & np.uint32(0xFF)]
            b = (states ^ NPTAB[i]) >> np.uint32(8)
            a = (i ^ np.uint32(ch)) & np.uint32(0xFF)
            states = (a << np.uint32(24)) | b
        return states

    out: list[tuple[str, int]] = []
    for suffix in suffixes:
        goal = np.uint32((~target) & 0xFFFFFFFF)
        goal = bwd(np.array([goal], dtype=np.uint32), suffix.encode())

        # F[k] = states after k tokens; index is little-endian base-v, digit 0
        # being the *last* token appended. B[k] likewise, digit 0 the first
        # token of the tail.
        F = [np.array([0xFFFFFFFF], dtype=np.uint32)]
        B = [goal]
        for _ in range(max_tokens // 2):
            F.append(np.concatenate([fwd(F[-1], t) for t in toks]))
            B.append(np.concatenate([bwd(B[-1], t) for t in toks]))

        # Both index spaces are little-endian base-v, and digit 0 is the token
        # touched *first* by the pass that built them. The forward pass appends
        # left to right, so its digits are already in string order; the backward
        # pass strips off the end, so digit 0 is the tail's last token and its
        # digits have to be flipped.
        def name_f(index: int, k: int) -> str:
            parts = []
            for _ in range(k):
                index, d = divmod(index, v)
                parts.append(vocab[d])
            return "".join(parts)

        def name_b(index: int, k: int) -> str:
            parts = []
            for _ in range(k):
                index, d = divmod(index, v)
                parts.append(vocab[d])
            return "".join(reversed(parts))

        for a in range(len(F)):
            for b_ in range(len(B)):
                if not 1 <= a + b_ <= max_tokens:
                    continue
                fa, bb = F[a], B[b_]
                order = np.argsort(fa, kind="stable")
                fs = fa[order]
                pos = np.clip(np.searchsorted(fs, bb), 0, len(fs) - 1)
                for bi in np.flatnonzero(fs[pos] == bb):
                    lo = np.searchsorted(fs, bb[bi], side="left")
                    hi = np.searchsorted(fs, bb[bi], side="right")
                    for fi in order[lo:hi]:
                        cand = name_f(int(fi), a) + name_b(int(bi), b_) + suffix
                        if crc(cand.encode()) == target:
                            out.append((cand, a + b_))
    return sorted(set(out))


# ---------------------------------------------------------------- driver

SUFFIXES = ["", ".exe", ".dll", ".sys"]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--max-len", type=int, default=7,
                    help="longest unknown-character run to search exhaustively (default 7)")
    ap.add_argument("--dict-only", action="store_true")
    ap.add_argument("--exports", action="store_true",
                    help="also sweep every export of every system DLL (~2 min)")
    ap.add_argument("--hash", type=lambda s: int(s, 16), action="append",
                    help="crack this hash instead of the standing target list")
    args = ap.parse_args()

    print("=" * 78)
    self_test()
    if not args.dict_only:
        mitm_self_test()
        compose_self_test()

    targets = ({h: "requested on the command line" for h in args.hash}
               if args.hash else dict(TARGETS))

    print("\n" + "=" * 78)
    print("corpus")
    corpus = build_corpus(exports=args.exports)

    print("\n" + "=" * 78)
    print("dictionary sweep, every name in stem and suffixed form")
    hits = dictionary_sweep(corpus, targets)
    for h, why in targets.items():
        if h in hits:
            print(f"  {h:#010x}  MATCH  {'; '.join(hits[h])}")
        else:
            print(f"  {h:#010x}  --     {why}")

    remaining = {h: w for h, w in targets.items() if h not in hits}
    if args.dict_only or not remaining:
        return

    print("\n" + "=" * 78)
    print(f"exhaustive search, [{ALPHABET}], unknown runs of 1..{args.max_len}")
    print("expected accidental preimages per target, by unknown length:")
    for n in range(1, args.max_len + 1):
        e = expected_collisions(n)
        print(f"  {n}: {e:>12.4f}" + ("   <-- past here, hits are mostly noise" if e > 1 else ""))

    for h, why in remaining.items():
        print(f"\n{h:#010x}  {why}")
        found = False
        for suffix in SUFFIXES:
            for n in range(1, args.max_len + 1):
                for cand in mitm(h, n, suffix=suffix):
                    e = expected_collisions(n)
                    flag = "" if e < 0.05 else f"   [{e:.2f} expected by chance at this length]"
                    print(f"    {cand!r}{flag}")
                    found = True
        if not found:
            print(f"    no preimage of <= {args.max_len} chars"
                  f" (plus {'/'.join(s or '<none>' for s in SUFFIXES)}) over this alphabet")

    print("\n" + "=" * 78)
    mixed_max = 6
    print(f"exhaustive search, mixed case [a-zA-Z0-9._-], unknown runs of 1..{mixed_max}")
    print("  the lowercase bound above says nothing about a name never lowercased")
    for h, why in remaining.items():
        found = []
        for suffix in SUFFIXES:
            for n in range(1, mixed_max + 1):
                for cand in mitm(h, n, suffix=suffix, alphabet=ALPHABET_MIXED):
                    e = expected_collisions(n, ALPHABET_MIXED)
                    found.append(f"    {cand!r}"
                                 + ("" if e < 0.05 else f"   [{e:.1f} expected by chance]"))
        print(f"\n{h:#010x}  {why}")
        print("\n".join(found) if found
              else f"    no preimage of <= {mixed_max} mixed-case chars")

    print("\n" + "=" * 78)
    v = len(VOCAB)
    print(f"composition search, up to 4 tokens from a {v}-token vocabulary")
    print(f"  candidate space {v ** 4:,.0f}; "
          f"~{v ** 4 / 2 ** 32:.1f} accidental preimages expected per target per suffix")
    for h, why in remaining.items():
        print(f"\n{h:#010x}  {why}")
        got = compose_search(h, SUFFIXES)
        for cand, ntok in got:
            print(f"    {cand!r}   ({ntok} tokens)")
        if not got:
            print("    nothing composes to it")


if __name__ == "__main__":
    main()
