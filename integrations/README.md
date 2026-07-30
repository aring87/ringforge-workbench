# Shipping static triage into Splunk

Watch a folder, statically triage whatever lands in it, and index one event per
sample in `malware_analysis`.

## Why static first

Static triage never executes the sample. That removes every constraint the
dynamic pipeline has: no VM snapshot revert between samples, no containment
check, no arm/disarm, and no need to serialise against a single analysis VM.
What is left is a queue and a shipper, which is why this is buildable now and
the dynamic equivalent is not.

## Where to run it

Not on the OneDrive host. Bitdefender there will quarantine samples out from
under the queue, and the inbox is by definition full of files nobody has
vouched for yet.

The analysis VM is the natural home -- Defender is already off by policy with
path exclusions, and static triage does not detonate anything, so none of the
detonation hygiene applies. If Splunk is reachable on the **host-only** adapter
(the `192.168.56.0/24` side, where the Wazuh agent already ships), this works
with the internet-facing adapter disarmed, which is the containment-safe
arrangement. Shipping to a cloud Splunk means arming, and arming means nothing
should be detonating at that moment.

## Splunk-side setup

Create the index and an HEC token scoped to it. Then set the sourcetype to parse
the JSON, or every event lands as one opaque blob:

```
[ringforge:static]
KV_MODE = json
SHOULD_LINEMERGE = false
TRUNCATE = 0
```

The shipper sets `time` from the analysis timestamp, so events land at the time
of analysis rather than the time of delivery. That matters when replaying a
backlog after the SIEM has been unreachable -- a replayed batch should not all
pile up at the moment the link came back.

## Configuration

Everything comes from the environment, matching how `TriageConfig` resolves its
paths. No token is ever written into the repository.

| Variable | Default | Notes |
| --- | --- | --- |
| `SPLUNK_HEC_URL` | *(unset)* | e.g. `https://splunk.lab.local:8088` |
| `SPLUNK_HEC_TOKEN` | *(unset)* | |
| `SPLUNK_HEC_INDEX` | `malware_analysis` | |
| `SPLUNK_HEC_SOURCETYPE` | `ringforge:static` | |
| `SPLUNK_HEC_SOURCE` | `ringforge` | |
| `SPLUNK_HEC_VERIFY_TLS` | `true` | Set `false` only for a self-signed lab cert |
| `SPLUNK_HEC_TIMEOUT` | `30` | Seconds |

TLS verification defaults to **on** and has to be disabled deliberately. Lab
Splunk instances almost always present a self-signed certificate, and the
tempting default is to turn verification off once and never think about it
again.

## Running

Check the wiring first without sending anything. This still performs the full
analysis, so use a file you do not mind spending the time on:

```bash
python scripts\auto_static_triage.py --once --dry-run
```

A single pass over the inbox:

```bash
python scripts\auto_static_triage.py --once
```

Continuous:

```bash
python scripts\auto_static_triage.py --watch --interval 60
```

If Splunk was down, the events were kept rather than dropped:

```bash
python scripts\auto_static_triage.py --replay-failed
```

## Behaviour worth knowing

**Deduplication is by SHA-256, computed before analysis.** The same bytes
arriving twice under different names is one sample. Re-triaging costs minutes of
capa and FLOSS time to produce an event identical apart from its timestamp. Use
`--force` to override, for example after a ruleset update.

**Files must stop changing before they are picked up.** A file still being
copied into the inbox would otherwise be hashed and analysed half-written. The
queue waits for five seconds of no modification.

**Samples that fail analysis are moved to `failed/`.** Left in the inbox they
are retried on every pass forever, and one malformed file stalls everything
queued behind it.

**A shipping failure never fails the analysis.** The case is complete on disk
either way. This matters here more than in most environments, because the
analysis VM spends most of its life deliberately disconnected.

## What is deliberately not shipped

The event carries findings and identifiers, never payload: hashes, rule names,
counts, verdicts, and IOCs. It does **not** carry decoded strings, extracted
file contents, or the sample itself.

That line is drawn on purpose. Decoded strings are the most interesting thing in
a case directory and the most dangerous thing to accumulate in a system analysts
trust -- they are attacker-controlled bytes, and an index is forever. `case_dir`
on every event is the pivot back to the full case when someone actually needs
it.

Every list is capped, so no single event can grow past the HEC payload limit.
The caps live at the top of `static_event.py`.

## Useful searches

Everything the queue has seen, worst first:

```
index=malware_analysis sourcetype=ringforge:static
| stats latest(verdict) as verdict latest(risk_score) as score latest(file_name) as name by sha256
| sort - score
```

Signed but unverified -- often more interesting than plainly unsigned:

```
index=malware_analysis sourcetype=ringforge:static signature_present=true signature_verified=false
| table _time file_name signer signature_status risk_score verdict
```

Detected by the local ruleset but unknown to VirusTotal:

```
index=malware_analysis sourcetype=ringforge:static yara_matched=true vt_found=false
| table _time file_name sha256 yara_rules risk_score
```

## Next

`schema_version` is on every event so a later change can be found rather than
silently drifting. The dynamic equivalent should ship as
`ringforge:dynamic` into the same index, sharing `sha256` and `dedupe_key` so a
static verdict and a detonation verdict for the same bytes join cleanly.

That work is gated on VM snapshot automation, not on anything here.
