/*
  Tiny script-stub downloader / executor heuristics — pure YARA over the raw
  .ps1/.vbs/.bat body. Targets the small first-stage stubs (55-152 bytes) the
  upstream feeds (yaraforge / signature-base / anyrun / yaraify) miss on the live
  mail stream: no obfuscation, just one or two lines that fetch+run a second
  stage. Each rule pins a SPECIFIC malicious construct (not a lone keyword) so
  benign admin one-liners do not fire. Tagged `suspicious heuristic` so yara.lua
  classify() routes to YARA_SUSPICIOUS. Heuristics, NOT family attribution.

  Closed live MalwareBazaar 0-hit misses (.ps1/.vbs corpus 2026):
    f9bfd95b (iex irm cradle); 846a1b1c/8a588666/81a5042f/b4d94ab1 (GetObject
    scriptlet self-delete); badbafb9/0f090af0/19aacecf (msiexec remote /q,
    unicode-homoglyph -Package evasion); b9d3147f/217d39d1 (WScript.Run Temp .bat).
*/

rule PS1_IEX_IRM_DownloadCradle : powershell downloader heuristic suspicious
{
    meta:
        author="yarad"
        description="PowerShell one-line download cradle: iex(irm <url>) / Invoke-Expression(Invoke-RestMethod)"
        score="65"
    strings:
        $a = /iex\s*\(\s*irm[ (]/ ascii wide nocase
        $b = /Invoke-Expression\s*\(\s*Invoke-RestMethod/ ascii wide nocase
        $c = /iex\s*\(\s*iwr[ (]/ ascii wide nocase
    condition:
        filesize < 64KB and any of them
}

rule VBS_GetObject_Scriptlet_SelfDelete : vbs downloader heuristic suspicious
{
    meta:
        author="yarad"
        description="VBS remote scriptlet loader GetObject(\"script:http...\") that self-deletes via DeleteFile WScript.ScriptFullName"
        score="70"
    strings:
        $g = /GetObject\(\s*"script:https?:\/\//  ascii wide nocase
        $d = "DeleteFile WScript.ScriptFullName" ascii wide nocase
    condition:
        filesize < 64KB and $g and $d
}

rule Script_MSIExec_Remote_Package_Silent : downloader heuristic suspicious
{
    meta:
        author="yarad"
        description="msiexec installing a remote package over http(s) silently (/q) — incl unicode-homoglyph -Package evasion"
        score="65"
    strings:
        $m = /msiexec/ ascii wide nocase
        $u = /https?:\/\// ascii wide nocase
        $q = /\s\/q\b/ ascii wide nocase
    condition:
        filesize < 4KB and $m and $u and $q
}

rule VBS_WScriptShell_Run_TempBat_Hidden : vbs dropper heuristic suspicious
{
    meta:
        author="yarad"
        description="VBS WScript.Shell.Run launching a .bat from AppData\\Local\\Temp hidden and non-blocking (0, False)"
        score="65"
    strings:
        $shell = "WScript.Shell" ascii wide nocase
        $run  = /\.Run\b/ ascii wide nocase
        $temp = /AppData\\Local\\Temp\\/ ascii wide nocase
        $bat  = ".bat" ascii wide nocase
        $hid  = /,\s*0,\s*False/ ascii wide nocase
    condition:
        filesize < 64KB and $shell and $run and $temp and $bat and $hid
}
