<#
  RingForge memory-dump self-test.

  Detonate this as a dynamic analysis sample to verify that the memory-versus-
  disk comparison works. It is completely benign: it builds a marker string,
  holds it in memory, and sleeps.

  The point is the split assignment below. The full marker never appears in this
  file, so scanning the sample on disk cannot match it, while any dump of this
  process can. That is precisely the signal the tier exists to detect -- a
  payload readable only once the process is running -- reproduced without
  malware.

  Expected outcome of a run with Memory dump and Memory YARA enabled:

    - Rules Only In Memory      1
    - memory_only_rules         RingForge_Memory_Canary
    - Severity                  Medium (raised by the severity floor)
    - Verdict                   Needs Review

  Anything else means the pipeline is broken rather than the sample being clean.
  A match against the file on disk means the split below has been folded into a
  single literal, most likely by an editor or a copy/paste.

  This also exercises the case both real detonations so far have missed: the
  launched process itself stays alive long enough to be dumped, rather than
  handing off to a child and exiting.
#>

$ErrorActionPreference = "Stop"

# Deliberately split. Do not join these into one literal.
$markerHead = 'RINGFORGE_MEMORY'
$markerTail = '_ONLY_CANARY_9f3a2b'
$marker = $markerHead + $markerTail

# Held in a live variable so it stays resident in the working set rather than
# being collected before the first dump offset comes due.
$resident = @($marker) * 500

Write-Host "RingForge canary running."
Write-Host "  marker length: $($marker.Length)"
Write-Host "  resident copies: $($resident.Count)"
Write-Host "  pid: $PID"
Write-Host "Sleeping so the dump offsets can fire..."

Start-Sleep -Seconds 90

Write-Host "Canary exiting. Resident copies still held: $($resident.Count)"
