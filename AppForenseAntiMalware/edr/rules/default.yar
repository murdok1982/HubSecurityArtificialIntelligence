rule Potential_Webshell_PHP {
    strings:
        $a = "eval(base64_decode"
        $b = "system($_GET"
        $c = "shell_exec("
    condition:
        any of them
}

rule Generic_Malware_Strings {
    strings:
        $a = "GetProcAddress"
        $b = "LoadLibrary"
        $c = "WriteProcessMemory"
    condition:
        all of them
}
