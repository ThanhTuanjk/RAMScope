/*
  RAMScope memory triage YARA pack.
  Scope: suspicious dump files produced by Volatility windows.malfind --dump.
  Caution: these rules create triage indicators only; every hit requires analyst validation.
*/

rule SUSP_Win_Memory_PowerShell_EncodedCommand
{
    meta:
        description = "Detects PowerShell encoded-command indicators in suspicious memory dumps"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $ps = "powershell" ascii wide nocase
        $enc1 = "-enc" ascii wide nocase
        $enc2 = "-encodedcommand" ascii wide nocase
        $b64 = "FromBase64String" ascii wide nocase
    condition:
        filesize < 50MB and $ps and (any of ($enc*) or $b64)
}

rule SUSP_Win_Memory_PowerShell_DownloadExecute
{
    meta:
        description = "Detects PowerShell download-and-execute style string clusters"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $ps = "powershell" ascii wide nocase
        $dl1 = "DownloadString" ascii wide
        $dl2 = "DownloadFile" ascii wide
        $wc = "Net.WebClient" ascii wide
        $iex = "IEX" ascii wide
        $invoke = "Invoke-Expression" ascii wide nocase
    condition:
        filesize < 50MB and $ps and any of ($dl*) and ($wc or $iex or $invoke)
}

rule SUSP_Win_Memory_PowerShell_AMSI_Bypass
{
    meta:
        description = "Detects PowerShell AMSI bypass related strings in suspicious memory dumps"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $a1 = "AmsiUtils" ascii wide
        $a2 = "amsiInitFailed" ascii wide
        $a3 = "amsi.dll" ascii wide nocase
        $a4 = "AmsiScanBuffer" ascii wide
    condition:
        filesize < 50MB and 2 of ($a*)
}

rule SUSP_Win_Memory_PowerShell_Reflection_Load
{
    meta:
        description = "Detects PowerShell reflection assembly loading indicators"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $r1 = "System.Reflection.Assembly" ascii wide
        $r2 = "Load(" ascii wide
        $r3 = "FromBase64String" ascii wide
        $r4 = "GzipStream" ascii wide
    condition:
        filesize < 50MB and $r1 and $r2 and ($r3 or $r4)
}

rule SUSP_Win_Memory_Base64_PE_Payload
{
    meta:
        description = "Detects base64-encoded PE header markers near decoder indicators"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $mz1 = "TVqQAAMAAAAEAAAA" ascii
        $mz2 = "TVpQAA" ascii
        $dec = "FromBase64String" ascii wide
        $ps = "powershell" ascii wide nocase
    condition:
        filesize < 50MB and any of ($mz*) and ($dec or $ps)
}

rule SUSP_Win_Memory_HTTP_C2_Composite
{
    meta:
        description = "Detects HTTP C2-like string clusters in suspicious memory dumps"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $h1 = "http://" ascii wide nocase
        $h2 = "https://" ascii wide nocase
        $ua = "User-Agent:" ascii wide nocase
        $post = "POST " ascii wide
        $php = ".php" ascii wide nocase
        $gate = "/gate" ascii wide nocase
        $beacon = "beacon" ascii wide nocase
    condition:
        filesize < 50MB and any of ($h*) and $ua and ($post or $php or $gate or $beacon)
}

rule SUSP_Win_Memory_Onion_Tor_Client
{
    meta:
        description = "Detects Tor/onion network indicators in suspicious memory dumps"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $onion = ".onion" ascii wide nocase
        $socks = "socks5" ascii wide nocase
        $tor = "tor.exe" ascii wide nocase
    condition:
        filesize < 50MB and $onion and ($socks or $tor)
}

rule SUSP_Win_Memory_WinINet_Download_API
{
    meta:
        description = "Detects Windows HTTP download API clusters in suspicious memory dumps"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $api1 = "InternetOpenUrl" ascii wide
        $api2 = "URLDownloadToFile" ascii wide
        $api3 = "WinHttpOpen" ascii wide
        $api4 = "HttpSendRequest" ascii wide
        $api5 = "InternetReadFile" ascii wide
    condition:
        filesize < 50MB and 2 of ($api*)
}

rule SUSP_Win_Memory_ProcessInjection_API_Cluster
{
    meta:
        description = "Detects process injection API clusters in suspicious memory dumps"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "OpenProcess" ascii wide
        $api5 = "QueueUserAPC" ascii wide
        $api6 = "NtCreateThreadEx" ascii wide
    condition:
        filesize < 50MB and 3 of ($api*)
}

rule SUSP_Win_Memory_NtAPI_Injection_Cluster
{
    meta:
        description = "Detects native API injection and mapping clusters in suspicious memory dumps"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $nt1 = "NtProtectVirtualMemory" ascii wide
        $nt2 = "NtWriteVirtualMemory" ascii wide
        $nt3 = "NtMapViewOfSection" ascii wide
        $nt4 = "RtlCreateUserThread" ascii wide
        $nt5 = "ZwUnmapViewOfSection" ascii wide
    condition:
        filesize < 50MB and 3 of ($nt*)
}

rule SUSP_Win_Memory_Shellcode_PEB_Walk
{
    meta:
        description = "Detects common x86/x64 PEB access byte patterns used by shellcode"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $x86 = { 64 A1 30 00 00 00 }
        $x64 = { 65 48 8B 04 25 60 00 00 00 }
    condition:
        filesize < 50MB and any of them
}

rule SUSP_Win_Memory_MZ_PE_Header_At_Start
{
    meta:
        description = "Detects a PE-like MZ header at the start of a suspicious memory dump"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $dos = "This program cannot be run in DOS mode" ascii
    condition:
        filesize > 2 and filesize < 100MB and uint16(0) == 0x5A4D and ($dos or filesize < 20MB)
}

rule SUSP_Win_Memory_ReflectiveLoader_Strings
{
    meta:
        description = "Detects reflective loader strings in suspicious memory dumps"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $r1 = "ReflectiveLoader" ascii wide
        $r2 = "ReflectiveDllMain" ascii wide
        $r3 = "ReflectiveLoader.c" ascii wide
    condition:
        filesize < 50MB and any of them
}

rule SUSP_Win_Memory_CobaltStrike_Beacon_Strings
{
    meta:
        description = "Detects Cobalt Strike Beacon-related strings in suspicious memory dumps"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $b1 = "beacon.x64.dll" ascii wide nocase
        $b2 = "beacon.x86.dll" ascii wide nocase
        $b3 = "beacon.dll" ascii wide nocase
        $b4 = "Malleable C2" ascii wide
    condition:
        filesize < 50MB and any of them
}

rule SUSP_Win_Memory_CobaltStrike_Profile_Keys
{
    meta:
        description = "Detects Malleable C2 profile key strings in suspicious memory dumps"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $p1 = "spawnto_x86" ascii wide
        $p2 = "spawnto_x64" ascii wide
        $p3 = "sleeptime" ascii wide
        $p4 = "jitter" ascii wide
        $p5 = "maxdns" ascii wide
    condition:
        filesize < 50MB and 2 of ($p*)
}

rule SUSP_Win_Memory_Meterpreter_Strings
{
    meta:
        description = "Detects Meterpreter-related string clusters in suspicious memory dumps"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $m1 = "metsrv" ascii wide
        $m2 = "stdapi_" ascii wide
        $m3 = "priv_fs_" ascii wide
        $m4 = "ext_server" ascii wide
    condition:
        filesize < 50MB and 2 of ($m*)
}

rule SUSP_Win_Memory_Mimikatz_Strings
{
    meta:
        description = "Detects Mimikatz command strings in suspicious memory dumps"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $m1 = "sekurlsa::" ascii wide
        $m2 = "privilege::debug" ascii wide
        $m3 = "lsadump::" ascii wide
        $m4 = "kerberos::" ascii wide
        $m5 = "mimikatz" ascii wide nocase
    condition:
        filesize < 50MB and any of them
}

rule SUSP_Win_Memory_LSASS_Dump_Command
{
    meta:
        description = "Detects LSASS dump command indicators in suspicious memory dumps"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $lsass = "lsass.exe" ascii wide nocase
        $d1 = "procdump" ascii wide nocase
        $d2 = "comsvcs.dll" ascii wide nocase
        $d3 = "MiniDump" ascii wide
    condition:
        filesize < 50MB and $lsass and any of ($d*)
}

rule SUSP_Win_Memory_Regsvr32_Scriptlet_Download
{
    meta:
        description = "Detects regsvr32 scriptlet download command indicators"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $reg = "regsvr32" ascii wide nocase
        $scrobj = "scrobj.dll" ascii wide nocase
        $h1 = "http://" ascii wide nocase
        $h2 = "https://" ascii wide nocase
    condition:
        filesize < 50MB and $reg and $scrobj and any of ($h*)
}

rule SUSP_Win_Memory_Mshta_Remote_Scriptlet
{
    meta:
        description = "Detects mshta remote scriptlet indicators"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $hta = "mshta" ascii wide nocase
        $h1 = "http://" ascii wide nocase
        $h2 = "https://" ascii wide nocase
        $s1 = "scriptlet" ascii wide nocase
        $s2 = ".sct" ascii wide nocase
    condition:
        filesize < 50MB and $hta and any of ($h*) and any of ($s*)
}

rule SUSP_Win_Memory_Rundll32_URL_Handler
{
    meta:
        description = "Detects rundll32 URL or script handler indicators"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $rundll = "rundll32" ascii wide nocase
        $u1 = "url.dll,FileProtocolHandler" ascii wide nocase
        $u2 = "javascript:" ascii wide nocase
        $u3 = "http://" ascii wide nocase
    condition:
        filesize < 50MB and $rundll and any of ($u*)
}

rule SUSP_Win_Memory_WMI_Persistence_Consumer
{
    meta:
        description = "Detects WMI persistence consumer strings"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $w1 = "__EventFilter" ascii wide
        $w2 = "CommandLineEventConsumer" ascii wide
        $w3 = "ActiveScriptEventConsumer" ascii wide
        $w4 = "__FilterToConsumerBinding" ascii wide
    condition:
        filesize < 50MB and 2 of ($w*)
}

rule SUSP_Win_Memory_RunKey_Persistence
{
    meta:
        description = "Detects Run key persistence strings with user-writable paths"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $run = "\\CurrentVersion\\Run" ascii wide nocase
        $p1 = "\\AppData\\" ascii wide nocase
        $p2 = "\\Temp\\" ascii wide nocase
        $p3 = "\\Users\\Public\\" ascii wide nocase
    condition:
        filesize < 50MB and $run and any of ($p*)
}

rule SUSP_Win_Memory_Schtasks_Create
{
    meta:
        description = "Detects scheduled task creation command clusters"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $s1 = "schtasks" ascii wide nocase
        $s2 = "/create" ascii wide nocase
        $s3 = "/sc" ascii wide nocase
        $s4 = "/tn" ascii wide nocase
        $s5 = "/tr" ascii wide nocase
    condition:
        filesize < 50MB and $s1 and $s2 and 2 of ($s3,$s4,$s5)
}

rule SUSP_Win_Memory_Service_Persistence_Command
{
    meta:
        description = "Detects service creation persistence strings"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $svc1 = "CreateService" ascii wide
        $svc2 = "StartService" ascii wide
        $svc3 = "sc.exe create" ascii wide nocase
        $svc4 = "New-Service" ascii wide nocase
    condition:
        filesize < 50MB and ($svc1 and $svc2 or any of ($svc3,$svc4))
}

rule SUSP_Win_Memory_Credential_Path_Cluster
{
    meta:
        description = "Detects browser credential store path clusters in suspicious memory dumps"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $c1 = "Login Data" ascii wide
        $c2 = "Local State" ascii wide
        $c3 = "Cookies" ascii wide
        $c4 = "Chrome\\User Data" ascii wide
        $c5 = "Firefox\\Profiles" ascii wide
    condition:
        filesize < 50MB and 2 of ($c*)
}

rule SUSP_Win_Memory_WiFi_Key_Export
{
    meta:
        description = "Detects WiFi key export command indicators"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $n1 = "netsh" ascii wide nocase
        $n2 = "wlan" ascii wide nocase
        $n3 = "key=clear" ascii wide nocase
        $n4 = "export profile" ascii wide nocase
    condition:
        filesize < 50MB and $n1 and $n2 and ($n3 or $n4)
}

rule SUSP_Win_Memory_AntiDebug_API_Cluster
{
    meta:
        description = "Detects anti-debug API clusters in suspicious memory dumps"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $d1 = "IsDebuggerPresent" ascii wide
        $d2 = "CheckRemoteDebuggerPresent" ascii wide
        $d3 = "NtQueryInformationProcess" ascii wide
        $d4 = "OutputDebugString" ascii wide
    condition:
        filesize < 50MB and 2 of ($d*)
}

rule SUSP_Win_Memory_UPX_Packed_PE
{
    meta:
        description = "Detects UPX-packed PE section markers in suspicious memory dumps"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $u1 = "UPX0" ascii
        $u2 = "UPX1" ascii
        $u3 = "UPX!" ascii
    condition:
        filesize > 2 and filesize < 100MB and uint16(0) == 0x5A4D and 2 of ($u*)
}

rule SUSP_Win_Memory_PostEx_NamedPipe
{
    meta:
        description = "Detects post-exploitation named pipe string clusters"
        author = "RAMScope"
        reference = "RAMScope baseline memory triage"
        date = "2026-07-09"
    strings:
        $pipe = "\\\\.\\pipe\\" ascii wide nocase
        $p1 = "postex_" ascii wide nocase
        $p2 = "msagent_" ascii wide nocase
        $p3 = "status_" ascii wide nocase
    condition:
        filesize < 50MB and $pipe and any of ($p*)
}
