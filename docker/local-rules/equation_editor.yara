rule Exploit_EquationEditor
{
    meta:
        description = "OLE2 document with Equation Editor object (CVE-2017-11882 / CVE-2018-0802 attack surface)"
        score       = 50
        author      = "yarad"

    strings:
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $eq_native = "Equation Native" wide
        $eq_clsid  = { 02 CE 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }

    condition:
        $ole_magic at 0 and ($eq_native or $eq_clsid)
}

rule Exploit_EquationEditor_MTEF
{
    meta:
        description = "Equation Editor with MTEF bytecode — likely CVE-2017-11882 exploit"
        score       = 70
        author      = "yarad"

    strings:
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $eq_native = "Equation Native" wide
        $mtef_hdr  = { 03 01 01 03 0A }

    condition:
        $ole_magic at 0 and $eq_native and $mtef_hdr
}
