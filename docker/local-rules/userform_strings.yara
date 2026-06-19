rule Maldoc_UserForm_Payload
{
    meta:
        description = "Suspicious strings hidden in VBA UserForm control data"
        score       = 40
        author      = "yarad"

    strings:
        $marker  = "USERFORM-STRINGS"
        $url     = /https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}/
        $cmd     = "cmd.exe" nocase
        $ps      = "powershell" nocase
        $wscript = "wscript" nocase
        $shell   = "Shell" nocase

    condition:
        $marker and any of ($url, $cmd, $ps, $wscript, $shell)
}
