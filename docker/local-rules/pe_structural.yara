/*
  PE and ELF structural anomaly markers.

  yarad's extract.analyzeBinaries runs saferwall/pe structural analysis on every
  PE stream (including base64-carved children) and emits typed markers into
  Result.Streams. Every literal below is emitted ONLY by yarad -> matching is
  zero-FP by construction; heuristics mirror oletools' malpev checks and the
  saferwall/pe anomaly detector.

  - PE-SECTION-PACKED       : section entropy ≥ 7.2 — packing / encryption
  - PE-SECTION-HIGH-ENTROPY : section entropy ≥ 7.0 and < 7.2 — elevated but
                              below typical packer threshold
  - PE-OVERLAY              : data appended past last section (dropper/loader trait)
  - PE-VIRTUAL-SECTION      : SizeOfRawData=0 + VirtualSize>0 (FormBook .ndata /
                              hollow-process trait)
  - PE-DOTNET               : CLR data directory present (.NET assembly)
  - PE-ANOMALY              : saferwall/pe anomaly detector fired
  - ELF-EXECUTABLE          : valid ELF header in a mail attachment stream

  Reference: MITRE ATT&CK T1027 (Obfuscated Files), T1055 (Process Injection),
             T1059 (Command Scripting), T1204 (User Execution)
*/

rule PE_Section_Packed : pe packed heuristic malware marker
{
    meta:
        author      = "yarad"
        description = "PE section with entropy >= 7.2 — characteristic of packed/encrypted code"
        reference   = "https://attack.mitre.org/techniques/T1027/"
        score       = "70"
    strings:
        $marker = "PE-SECTION-PACKED" ascii
    condition:
        filesize < 16MB and $marker
}

rule PE_Section_High_Entropy : pe entropy heuristic suspicious marker
{
    meta:
        author      = "yarad"
        description = "PE section with entropy >= 7.0 (below packing threshold but above normal)"
        reference   = "https://attack.mitre.org/techniques/T1027/"
        score       = "50"
    strings:
        $marker = "PE-SECTION-HIGH-ENTROPY" ascii
    condition:
        filesize < 16MB and $marker
}

rule PE_Overlay : pe overlay heuristic suspicious marker
{
    meta:
        author      = "yarad"
        description = "PE file with non-empty overlay — data appended past the last section (common dropper/loader trait)"
        reference   = "https://attack.mitre.org/techniques/T1027/"
        score       = "50"
    strings:
        $marker = "PE-OVERLAY" ascii
    condition:
        filesize < 16MB and $marker
}

rule PE_Virtual_Section : pe formbook heuristic suspicious marker
{
    meta:
        author      = "yarad"
        description = "PE section with SizeOfRawData=0 and VirtualSize>0 (FormBook .ndata / hollow-process trait)"
        reference   = "https://attack.mitre.org/techniques/T1055/"
        score       = "60"
    strings:
        $marker = "PE-VIRTUAL-SECTION" ascii
    condition:
        filesize < 16MB and $marker
}

rule PE_DotNet : pe dotnet heuristic suspicious marker
{
    meta:
        author      = "yarad"
        description = "PE file contains a CLR data directory (.NET assembly) — common for managed-code malware loaders"
        reference   = "https://attack.mitre.org/techniques/T1059/001/"
        score       = "40"
    strings:
        $marker = "PE-DOTNET" ascii
    condition:
        filesize < 16MB and $marker
}

rule PE_Anomaly : pe anomaly heuristic suspicious marker
{
    meta:
        author      = "yarad"
        description = "PE file contains structural anomalies detected by saferwall/pe (malformed headers, future timestamps, etc.)"
        reference   = "https://attack.mitre.org/techniques/T1027/"
        score       = "50"
    strings:
        $marker = "PE-ANOMALY" ascii
    condition:
        filesize < 16MB and $marker
}

rule ELF_Executable : elf linux heuristic suspicious marker
{
    meta:
        author      = "yarad"
        description = "Valid ELF executable found embedded in a mail attachment container — Linux malware dropper"
        reference   = "https://attack.mitre.org/techniques/T1204/002/"
        score       = "55"
    strings:
        $marker = "ELF-EXECUTABLE" ascii
    condition:
        filesize < 16MB and $marker
}
