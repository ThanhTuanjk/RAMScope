rule PE_Header_In_Memory
{
    strings:
        $mz = { 4D 5A }
        $pe = "This program cannot be run in DOS mode"
    condition:
        $mz at 0 or $pe
}
