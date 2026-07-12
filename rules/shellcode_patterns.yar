rule Simple_Shellcode_Like_Strings
{
    strings:
        $rwx = "PAGE_EXECUTE_READWRITE" nocase
        $virtualalloc = "VirtualAlloc" nocase
        $createthread = "CreateThread" nocase
    condition:
        any of them
}
