package extract

import (
	"bytes"
	"os"
	"testing"
)

// ole_clsid_cve.yara lints — the unit suite does not link libyara; actual
// compile+match runs in the Docker `full` CI stage (compile-rules.sh).
// These guards catch authoring errors that have silently broken rules before:
// bad hex literals, missing rule names, backreferences yarac rejects.

func loadOLECLSIDCVERule(t *testing.T) []byte {
	t.Helper()
	for _, p := range []string{
		"../../../../docker/local-rules/ole_clsid_cve.yara",
		"../../../docker/local-rules/ole_clsid_cve.yara",
		"../../docker/local-rules/ole_clsid_cve.yara",
	} {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Skip("ole_clsid_cve.yara not found relative to test dir")
	return nil
}

func TestOLECLSIDCVERule_Present(t *testing.T) {
	data := loadOLECLSIDCVERule(t)
	for _, want := range []string{
		"rule OLE_ShellExplorer_CLSID",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("ole_clsid_cve.yara missing %q", want)
		}
	}
}

func TestOLECLSIDCVERule_CLSIDAnchors(t *testing.T) {
	data := loadOLECLSIDCVERule(t)
	// Binary form: {EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B} LE wire bytes.
	// Data1 LE: C3 2A B2 EA; Data2 LE: C1 30; Data3 LE: CF 11; Data4 BE.
	// hex string in rule source (no spaces, lowercase).
	for _, anchor := range []string{
		"C3 2A B2 EA C1 30 CF 11 A7 EB 00 00 C0 5B AE 0B", // binary form in rule
		"c32ab2eac130cf11a7eb0000c05bae0b",                // hex-string form in rule
		"CVE-2026-21509",                                  // reference in meta
	} {
		if !bytes.Contains(data, []byte(anchor)) {
			t.Errorf("ole_clsid_cve.yara missing anchor %q", anchor)
		}
	}
}

func TestOLECLSIDCVERule_NoBackreference(t *testing.T) {
	data := loadOLECLSIDCVERule(t)
	for _, bad := range [][]byte{[]byte(`\1`), []byte(`\2`)} {
		if bytes.Contains(data, bad) {
			t.Errorf("ole_clsid_cve.yara contains backreference %q — yarac rejects it", bad)
		}
	}
}

// TestOLECLSIDCVERule_SyntheticMatch verifies the CLSID byte sequence
// the rule targets is exactly what the OLE LE wire encoding of
// {EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B} produces.  The rule must contain
// these 16 bytes verbatim (as a hex literal in the .yara source) so that a
// document embedding the Shell.Explorer CLSID matches.  This is a unit-speed
// fixture — actual YARA execution runs in the Docker CI stage.
func TestOLECLSIDCVERule_SyntheticMatch(t *testing.T) {
	data := loadOLECLSIDCVERule(t)

	// {EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B} serialised as OLE LE wire bytes:
	//   Data1 EAB22AC3 → C3 2A B2 EA
	//   Data2 30C1      → C1 30
	//   Data3 11CF      → CF 11
	//   Data4 A7EB 0000C05BAE0B → A7 EB 00 00 C0 5B AE 0B  (BE, unchanged)
	clsidLE := []byte{
		0xC3, 0x2A, 0xB2, 0xEA,
		0xC1, 0x30,
		0xCF, 0x11,
		0xA7, 0xEB,
		0x00, 0x00, 0xC0, 0x5B, 0xAE, 0x0B,
	}
	// The rule source must contain these bytes spelled out as a hex literal.
	// Build the expected hex-literal substring from the byte slice.
	var hexLit []byte
	for i, b := range clsidLE {
		if i > 0 {
			hexLit = append(hexLit, ' ')
		}
		hexLit = append(hexLit, []byte{
			"0123456789ABCDEF"[b>>4],
			"0123456789ABCDEF"[b&0xF],
		}...)
	}
	if !bytes.Contains(data, hexLit) {
		t.Errorf("ole_clsid_cve.yara does not contain LE CLSID hex literal %q; "+
			"a document embedding Shell.Explorer CLSID would NOT match", hexLit)
	}
}
