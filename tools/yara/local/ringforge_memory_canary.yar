/*
   RingForge control rule.

   This is a self-test, not a detection. It exists to prove that the dynamic
   run's memory-versus-disk comparison actually works, using a marker that
   cannot appear in a sample on disk.

   Pair it with test_specs\memory_canary\canary.ps1, which assembles the marker
   string at runtime from two halves. The literal therefore exists only in the
   process's memory, never in the file, so a correct pipeline reports this rule
   under "matched in memory but not on disk" and nowhere else.

   The `wide` modifier is not optional. PowerShell holds strings as UTF-16LE in
   memory, so an ascii-only rule matches the dump of a working canary zero
   times and looks exactly like a broken pipeline.

   Rules placed in tools\yara\local\ survive bootstrap_yara_rules.ps1, which
   replaces the downloaded rules directory on every run.
*/

rule RingForge_Memory_Canary
{
    meta:
        author = "RingForge"
        description = "Control rule: must match process memory and never a file on disk"
        reference = "test_specs/memory_canary/canary.ps1"
        purpose = "self-test"

    strings:
        $canary = "RINGFORGE_MEMORY_ONLY_CANARY_9f3a2b" ascii wide

    condition:
        $canary
}
