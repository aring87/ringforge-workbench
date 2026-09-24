"""The guest agent's progress reporting, run as shipped.

`guest_run_agent.ps1` had no tests, and every bug found in it cost a
45-minute run. These exercise the functions added on 23 Sep, after two malware
runs sat in the detonation for two hours and brought home nothing but
`ringforge-ready`: `Send-Progress`, `Write-Heartbeat` and `Invoke-Watched`.

The agent cannot be dot-sourced -- it would run -- so each test parses the
real file with PowerShell's own parser, defines every function it contains,
and then calls them. What is tested is the shipped definition, not a copy.

Windows PowerShell 5.1 specifically, because that is what the guest runs and
both traps pinned here are 5.1 behaviour. Skipped where it is absent.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

AGENT = Path(__file__).resolve().parents[2] / "scripts" / "guest_run_agent.ps1"
POWERSHELL = shutil.which("powershell.exe") if os.name == "nt" else None

# Lifts every function out of the agent by AST. A parse error fails loudly
# rather than leaving the test to call a function that was never defined.
PRELUDE = r"""
$ErrorActionPreference = 'Stop'
$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{agent}', [ref]$null, [ref]$errs)
if ($errs) {{ throw "agent does not parse: $($errs[0].Message)" }}
$defs = $ast.FindAll({{ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }}, $true)
foreach ($f in $defs) {{ . ([scriptblock]::Create($f.Extent.Text)) }}
$T = '{tmp}'
"""


@unittest.skipUnless(POWERSHELL, "needs Windows PowerShell")
class GuestAgentTests(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="rf-agent-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def ps(self, body: str, timeout: int = 60) -> str:
        script = PRELUDE.format(agent=str(AGENT).replace("'", "''"),
                                tmp=str(self.tmp).replace("'", "''")) + body
        path = self.tmp / "t.ps1"
        path.write_text(script, encoding="utf-8-sig")
        done = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
             "Bypass", "-File", str(path)],
            capture_output=True, text=True, timeout=timeout)
        self.assertEqual(done.returncode, 0,
                         f"stdout:\n{done.stdout}\nstderr:\n{done.stderr}")
        return done.stdout

    # --- Invoke-Watched --------------------------------------------------

    def test_exit_code_survives_the_passthru_trap(self) -> None:
        """The reason `.Handle` is read. Without it 5.1 returns an empty
        ExitCode, and an empty code is not 4, so a containment refusal would
        be carried on past."""
        out = self.ps(r"""
$code = Invoke-Watched -FilePath cmd.exe -ArgumentList @('/c', 'exit', '4') `
  -StdOut "$T\o.txt" -StdErr "$T\e.txt" -HeartbeatSeconds 1
"code=[$code]"
""")
        self.assertIn("code=[4]", out)

    def test_ticks_while_running_and_once_after(self) -> None:
        out = self.ps(r"""
$script:ticks = @()
$code = Invoke-Watched -FilePath powershell.exe `
  -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep', '-Seconds', '3;', 'exit', '3') `
  -StdOut "$T\o.txt" -StdErr "$T\e.txt" -HeartbeatSeconds 1 `
  -OnTick { param($p) $script:ticks += $p.HasExited }
"code=[$code]"
"running_ticks=$(@($script:ticks | Where-Object { -not $_ }).Count)"
"last=$($script:ticks[-1])"
""")
        self.assertIn("code=[3]", out)
        running = int(out.split("running_ticks=")[1].split()[0])
        self.assertGreaterEqual(running, 2)
        # The closing tick sees the exit, so the last heartbeat says so.
        self.assertIn("last=True", out)

    def test_a_failing_or_chatty_tick_changes_nothing(self) -> None:
        """A heartbeat that throws, or writes output, must not fail the run
        or leak into the returned exit code."""
        out = self.ps(r"""
$code = Invoke-Watched -FilePath powershell.exe `
  -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep', '-Seconds', '2;', 'exit', '0') `
  -StdOut "$T\o.txt" -StdErr "$T\e.txt" -HeartbeatSeconds 1 `
  -OnTick { 'noise'; throw 'tick failed' }
"code=[$code] type=$($code.GetType().Name)"
""")
        self.assertIn("code=[0] type=Int32", out)

    def test_returns_when_its_process_exits_not_when_its_children_do(self) -> None:
        """The likely cause of mal-112's two-hour timeouts. `Start-Process
        -Wait` waits for descendants too, so resident malware -- a descendant
        of the orchestrator -- held the old agent until the host gave up.

        The parent here exits at once and leaves a child that lives ~15s.
        The control proves the child really outlives it, so a pass cannot
        come from a child that happened to die early."""
        out = self.ps(r"""
$childArgs = @('/c', 'start', '""', '/b', 'ping', '-n', '16', '127.0.0.1', '>nul')
$t = [Diagnostics.Stopwatch]::StartNew()
$code = Invoke-Watched -FilePath cmd.exe -ArgumentList $childArgs `
  -StdOut "$T\o.txt" -StdErr "$T\e.txt" -HeartbeatSeconds 1
"watched=$([int]$t.Elapsed.TotalSeconds) code=[$code]"
$t = [Diagnostics.Stopwatch]::StartNew()
$null = Start-Process -FilePath cmd.exe -ArgumentList $childArgs -NoNewWindow -Wait `
  -RedirectStandardOutput "$T\o2.txt" -RedirectStandardError "$T\e2.txt"
"control=$([int]$t.Elapsed.TotalSeconds)"
""", timeout=120)
        watched = int(out.split("watched=")[1].split()[0])
        control = int(out.split("control=")[1].split()[0])
        self.assertIn("code=[0]", out)
        self.assertLessEqual(watched, 3, out)
        self.assertGreaterEqual(control, 12, out)

    def test_ontick_sees_the_callers_variables(self) -> None:
        """The agent's tick reads `$work`, `$localRoot` and friends from the
        script scope. Proves that resolves through `Invoke-Watched`."""
        out = self.ps(r"""
$work = 'from-the-caller'
$script:seen = ''
$null = Invoke-Watched -FilePath cmd.exe -ArgumentList @('/c', 'exit', '0') `
  -StdOut "$T\o.txt" -StdErr "$T\e.txt" -HeartbeatSeconds 1 `
  -OnTick { $script:seen = $work }
"seen=[$script:seen]"
""")
        self.assertIn("seen=[from-the-caller]", out)

    # --- Send-Progress ---------------------------------------------------

    def test_copies_the_log_and_a_stderr_still_being_written(self) -> None:
        out = self.ps(r"""
$work = New-Item -ItemType Directory "$T\work"
$local = New-Item -ItemType Directory "$T\local"
Set-Content "$T\agent.log" 'stage one'
# Held open for writing, as the redirect holds it while the child runs.
$w = [IO.File]::Open("$local\detonate.stderr.txt", 'Create', 'Write', 'Read')
$b = [Text.Encoding]::UTF8.GetBytes("Exporting Procmon CSV`n"); $w.Write($b, 0, $b.Length); $w.Flush()
$r = Send-Progress -Work $work -LocalRoot $local -LogFile "$T\agent.log"
$w.Dispose()
"output=[$r]"
"log=[$((Get-Content "$work\agent.log" -Raw).Trim())]"
"stderr=[$((Get-Content "$work\detonate.stderr.txt" -Raw).Trim())]"
""")
        self.assertIn("output=[]", out)
        self.assertIn("log=[stage one]", out)
        self.assertIn("stderr=[Exporting Procmon CSV]", out)

    def test_never_throws(self) -> None:
        """No work directory yet, a missing log, an unreachable exchange."""
        out = self.ps(r"""
Send-Progress -Work '' -LocalRoot '' -LogFile ''
Send-Progress -Work "$T\missing\dir" -LocalRoot "$T\nope" -LogFile "$T\no.log"
Send-Progress -Work 'Z:\no\such\share' -LocalRoot '' -LogFile "$T\no.log"
'survived'
""")
        self.assertIn("survived", out)

    # --- Write-Heartbeat -------------------------------------------------

    def test_heartbeat_names_new_processes_and_liveness(self) -> None:
        out = self.ps(r"""
$work = New-Item -ItemType Directory "$T\work"
$baseline = @(Get-Process | ForEach-Object { $_.Id })
$p = Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep 5') -PassThru -WindowStyle Hidden
$null = $p.Handle
Write-Heartbeat -Work $work -Since (Get-Date).AddSeconds(-90) -Process $p -BaselinePids $baseline
$running = [IO.File]::ReadAllBytes("$work\ringforge-heartbeat")
$p.Kill(); $p.WaitForExit()
Write-Heartbeat -Work $work -Since (Get-Date).AddSeconds(-90) -Process $p -BaselinePids $baseline
$after = Get-Content "$work\ringforge-heartbeat" -Raw
"bom=$($running[0] -eq 0xEF)"
"---running"
[Text.Encoding]::UTF8.GetString($running)
"---after"
$after
"pid=$($p.Id)"
""")
        running = out.split("---running")[1].split("---after")[0]
        after = out.split("---after")[1]
        pid = out.split("pid=")[1].split()[0]
        self.assertIn("bom=False", out)
        self.assertIn(f"detonate  pid {pid} alive True", running)
        self.assertRegex(running, rf"\n\s+{pid} powershell")
        self.assertRegex(running, r"elapsed   9\ds")
        self.assertIn(f"detonate  pid {pid} alive False", after)

    def test_heartbeat_never_throws(self) -> None:
        out = self.ps(r"""
Write-Heartbeat -Work '' -Since (Get-Date) -Process $null -BaselinePids @()
Write-Heartbeat -Work "$T\no\such" -Since (Get-Date) -Process $null -BaselinePids @()
Write-Heartbeat -Work 'Z:\no\such\share' -Since (Get-Date) -Process $null -BaselinePids @()
'survived'
""")
        self.assertIn("survived", out)

    def test_heartbeat_is_never_taken_for_a_sample(self) -> None:
        """`Get-DeliveredSample` picks the newest file that is not ours, so a
        heartbeat newer than the sample must still be excluded by name.

        `agent.log` and `detonate.stderr.txt` are NOT excluded, and need not
        be: the agent looks for the sample only before `ready`, which is
        before `Send-Progress` first writes either, and the host clears the
        directory before every run."""
        out = self.ps(r"""
$work = New-Item -ItemType Directory "$T\work"
Set-Content "$work\abc123.exe" 'MZ'
(Get-Item "$work\abc123.exe").LastWriteTime = (Get-Date).AddMinutes(-5)
Write-Heartbeat -Work $work -Since (Get-Date) -Process $null -BaselinePids @()
"heartbeat=$(Test-Path "$work\ringforge-heartbeat")"
"picked=$((Get-DeliveredSample -Work $work).Name)"
""")
        self.assertIn("heartbeat=True", out)
        self.assertIn("picked=abc123.exe", out)


if __name__ == "__main__":
    unittest.main()
