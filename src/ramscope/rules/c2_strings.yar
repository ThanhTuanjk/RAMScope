rule Simple_C2_Strings
{
    strings:
        $http = "http://" nocase
        $https = "https://" nocase
        $useragent = "User-Agent:" nocase
    condition:
        any of them
}
