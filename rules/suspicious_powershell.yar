rule Suspicious_PowerShell_Indicators
{
    strings:
        $enc = "-enc" nocase
        $encoded = "-encodedcommand" nocase
        $b64 = "FromBase64String" nocase
        $iex = "IEX" nocase
    condition:
        any of them
}
