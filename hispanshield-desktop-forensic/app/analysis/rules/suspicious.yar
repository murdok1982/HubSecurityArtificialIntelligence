rule SUSPICIOUS_STRINGS {
    meta:
        description = "Detects common suspicious strings in malware"
        author = "MalwareAnalysisApp"
        date = "2023-10-27"
    strings:
        $s1 = "VirtualAlloc" ascii wide
        $s2 = "WriteProcessMemory" ascii wide
        $s3 = "CreateRemoteThread" ascii wide
        $s4 = "ShellExecute" ascii wide
        $s5 = "powershell" nocase ascii wide
        $s6 = "cmd.exe" nocase ascii wide
        $s7 = "http://" ascii wide
    condition:
        2 of them
}

rule PACKER_INDICATORS {
    meta:
        description = "Detects common packer section names"
    strings:
        $p1 = "UPX0"
        $p2 = "UPX1"
        $p3 = ".aspack"
    condition:
        any of them
}
