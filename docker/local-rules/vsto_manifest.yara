/*
  VSTO_Remote_Codebase -- remote-payload VSTO/ClickOnce add-in manifest heuristic.

  A .vsto deployment manifest (ClickOnce, an XML file) names the Office add-in
  assembly to load via a <dependentAssembly ... codebase="..."> entry. Mailing a
  .vsto manifest whose codebase points at a remote http(s) host turns Office
  add-in side-loading into a download-and-execute primitive: opening the manifest
  registers the VSTO add-in and pulls the attacker DLL from that URL, with no
  macro and no embedded payload in the attachment itself (MITRE T1137.006).

  Benign VSTO add-ins are deployed from a trusted local path / UNC share or a
  signed publisher URL through the installer -- a raw .vsto attachment carrying a
  remote codebase is the attack.

  FP-firewall:
   - Requires a VSTO-specific manifest namespace (vstav3 /
     urn:schemas-microsoft-com:vsta) -- a plain ClickOnce app does not match.
   - AND the ClickOnce <assemblyIdentity structural anchor.
   - AND a remote http(s) codebase (attribute or inside a dependentAssembly tag).
     A local-path / UNC codebase does not match.
   - filesize cap keeps it off large binaries (manifests are tiny XML).

  Heuristic, tagged `suspicious heuristic`; score 60 = mid-high confidence.
  Reference: https://attack.mitre.org/techniques/T1137/006/
*/
rule VSTO_Remote_Codebase : maldoc heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "VSTO/ClickOnce Office add-in (.vsto) manifest with a remote http(s) codebase -- add-in side-load download-exec vector"
        reference   = "https://attack.mitre.org/techniques/T1137/006/"
        tier        = "suspicious"
        score       = "60"
    strings:
        // VSTO-specific manifest namespace / element prefix.
        $vsta1 = "urn:schemas-microsoft-com:vsta" ascii nocase
        $vsta2 = "vstav3:" ascii nocase

        // ClickOnce manifest structural anchor.
        $asm = "<assemblyIdentity" ascii nocase

        // Remote payload pointer: a codebase attribute pointing at http(s),
        // or a dependentAssembly tag carrying a remote URL.
        $cb_http  = /codebase\s*=\s*["']https?:\/\//  nocase
        $dep_http = /<dependentAssembly[^>]{0,400}https?:\/\//  nocase
    condition:
        filesize < 256KB and
        $asm and
        any of ($vsta1, $vsta2) and
        any of ($cb_http, $dep_http)
}
