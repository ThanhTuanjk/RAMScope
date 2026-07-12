from __future__ import annotations

from ramscope.models import Finding, ProcessProfile

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
LOLBINS = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "installutil.exe", "msbuild.exe", "wmic.exe", "forfiles.exe", "reg.exe", "schtasks.exe"}
SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "services.exe", "winlogon.exe", "csrss.exe", "smss.exe"}
TYPO_NAMES = {"svhost.exe", "scvhost.exe", "lsas.exe", "expl0rer.exe"}


class ProcessAnalyzer:
    def analyze(self, profiles: list[ProcessProfile]) -> list[Finding]:
        findings = []
        for profile in profiles:
            name = profile.name.lower()
            parent = profile.parent_name.lower()
            cmd = profile.command_line.lower()
            if name == "powershell.exe" and any(token in cmd for token in [" -enc", "-encodedcommand", "frombase64string", " iex", "iex "]):
                findings.append(Finding("", profile.pid, profile.name, "Suspicious PowerShell command-line indicators", "High", 50, "likely", "cmdline", [{"source": "windows.cmdline", "detail": "PowerShell command line contains encoded or dynamic execution indicators."}]))
            if parent in OFFICE and name in LOLBINS:
                findings.append(Finding("", profile.pid, profile.name, "Office process spawned a script-capable child process", "High", 45, "likely", "process", [{"source": "windows.pstree", "detail": "Office parent process spawned a LOLBin/script-capable child process."}]))
            if parent == "explorer.exe" and name in {"rundll32.exe", "regsvr32.exe", "mshta.exe"}:
                findings.append(Finding("", profile.pid, profile.name, "Explorer spawned a LOLBin requiring review", "Medium", 35, "possible", "process", [{"source": "windows.pstree", "detail": "Explorer spawning rundll32/regsvr32/mshta can be benign or suspicious depending on context."}]))
            if name in SYSTEM_NAMES and profile.image_path and "c:\\windows\\system32" not in profile.image_path.lower():
                findings.append(Finding("", profile.pid, profile.name, "System-like process running from unusual path", "High", 45, "possible", "process", [{"source": "windows.pslist", "detail": "System process name appears outside expected System32 path."}]))
            if name in TYPO_NAMES:
                findings.append(Finding("", profile.pid, profile.name, "Process name resembles a Windows system process typo", "Medium", 30, "possible", "process", [{"source": "windows.pslist", "detail": "Process name resembles a common system process but is misspelled."}]))
        return findings
