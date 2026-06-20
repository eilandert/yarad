/*
  RTF evasion heuristics — synthetic marker rules (PR-12).

  The extract package normalises RTF control-word obfuscation (fake/empty
  groups, \*\dest optional-destination groups, \bin<N> binary runs, \'XX
  hex escapes with interleaved whitespace) and emits one ASCII marker stream
  per detected high-signal evasion control word. These rules match those
  synthetic streams.

  Why synthetic markers: raw RTF byte-scanning cannot reliably find obfuscated
  control words; the normaliser collapses split/wrapped forms before matching,
  so a single string rule here covers the obfuscated and plain variants alike.

  FP mitigation: each marker prefix ("RTF-OBJUPDATE", "RTF-DDEAUTO", "RTF-DDE")
  is never present in raw RTF bytes or in any other extract output — it is only
  emitted by rtfDetectEvasion, so a match is zero-FP by construction.

  Heuristic, not family attribution — tagged `suspicious heuristic` so
  yara.lua classify() routes to YARA_SUSPICIOUS (operator-tunable).

  References:
    https://attack.mitre.org/techniques/T1559/002/ (DDE)
    https://attack.mitre.org/techniques/T1221/       (Template Injection / OLE link)
    CVE-2017-0199, CVE-2017-11882 (RTF OLE/DDE exploitation)
*/

/*
  RTF_ObjUpdate -- \objupdate control word (auto-updating OLE link).

  An RTF document with \objupdate causes the embedded OLE object to refresh
  its data from the linked source whenever the document is opened. Attackers
  use this to pull a remote OLE object (UNC path or HTTP URL) at open time,
  achieving code execution without user interaction beyond opening the file.
  Legitimate documents almost never use \objupdate; it is a reliable
  high-signal indicator.

  score 65 = high confidence (extremely rare in benign documents, direct
  exploitation primitive for remote-template / OLE-link attacks).
*/
rule RTF_ObjUpdate : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "RTF document contains \\objupdate control word (auto-updating OLE link, remote object fetch)"
        reference   = "https://attack.mitre.org/techniques/T1221/"
        date        = "2026-06-20"
        score       = "65"
        tags        = "maldoc heuristic suspicious"
    strings:
        $marker = "RTF-OBJUPDATE" ascii
    condition:
        filesize < 16MB and $marker
}

/*
  RTF_DDEAuto -- \ddeauto control word (DDE auto-execute field).

  \ddeauto in RTF triggers DDE code execution automatically when the document
  opens, without requiring user interaction beyond opening the file. This is
  the RTF equivalent of the OOXML DDEAUTO field vector and is used in the
  same malware delivery campaigns.

  score 70 = high confidence (\ddeauto is almost exclusively a malware
  indicator in RTF; benign documents do not use this control word).
*/
rule RTF_DDEAuto : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "RTF document contains \\ddeauto control word (DDE auto-execute, command injection)"
        reference   = "https://attack.mitre.org/techniques/T1559/002/"
        date        = "2026-06-20"
        score       = "70"
        tags        = "maldoc heuristic suspicious"
    strings:
        $marker = "RTF-DDEAUTO" ascii
    condition:
        filesize < 16MB and $marker
}

/*
  RTF_DDE -- \dde control word (DDE field, manual or auto execution).

  \dde in RTF creates a DDE link that may execute commands either automatically
  or on user interaction. While slightly less severe than \ddeauto (requires a
  user click on some configurations), it is still a high-signal maldoc
  indicator. Legitimate business documents rarely embed raw DDE control words.

  score 55 = mid-high confidence (less certain than \ddeauto because some
  legacy word processors emit \dde for linked data; operator can tune).
*/
rule RTF_DDE : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "RTF document contains \\dde control word (DDE field, possible command injection)"
        reference   = "https://attack.mitre.org/techniques/T1559/002/"
        date        = "2026-06-20"
        score       = "55"
        tags        = "maldoc heuristic suspicious"
    strings:
        $marker = "RTF-DDE" ascii
    condition:
        filesize < 16MB and $marker
}
