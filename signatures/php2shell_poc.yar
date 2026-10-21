rule PHP2Shell_PoC_Tooling_2026
{
    meta:
        description = "Detects the PHP-UP-2026 php2shell PoC/framework source and generated request bodies. This is exploit TOOLING, not a dropped webshell."
        author = "W_PhpShellIntel (Lyra)"
        date = "2026-10-21"
        reference = "https://jackalsyn.com/posts/php-up-2026.html"
        reference2 = "https://x.com/uwu_underground/status/2112764701553971582"
        status = "tested against the extracted bundle and /usr/bin; untested against live capture"
        note = "The PoC calls system() and echoes the command output. It does not write a webshell file, so there is no dropped-webshell rule in this pack."
    strings:
        $ua618 = "php2shell-109618" ascii
        $ua619 = "php2shell-109619" ascii
        $b618  = "B7kQpoc618" ascii
        $b619  = "B7kQpoc619" ascii
        $mark  = "JACKALPOC" ascii
        $field = "PHP_SESSION_UPLOAD_PROGRESS" ascii
        $fw    = "php_up_framework" ascii
        $uaf   = "session.upload_progress UAF" ascii nocase
        $poct  = "poc0_109618" ascii
        $poc1  = "poc1_109619" ascii
    condition:
        (2 of ($ua618, $ua619, $b618, $b619)) or
        ($mark and $field) or
        ($fw and $uaf) or
        ($poct and $poc1)
}

rule PHP2Shell_RequestBody_2026
{
    meta:
        description = "Detects a captured php2shell request body/header blob by its exact PoC markers."
        author = "W_PhpShellIntel (Lyra)"
        date = "2026-10-21"
        reference = "https://jackalsyn.com/posts/php-up-2026.html"
        status = "untested against live capture"
    strings:
        $hdr_ua  = "php2shell-1096" ascii nocase
        $hdr_bt  = "boundary=B7kQpoc" ascii nocase
        $field   = "PHP_SESSION_UPLOAD_PROGRESS" ascii
        $sess    = "PHPSESSID=" ascii
        $cmd     = "JACKALPOC" ascii
    condition:
        ($hdr_ua or $hdr_bt) and $field or ($field and $sess and $cmd)
}
