rule Test_Notepad_Import
{
    meta:
        author = "Adam"
        description = "Basic test rule for notepad string match"

    strings:
        $mz = "This program cannot be run in DOS mode"

    condition:
        $mz
}