package extract

import (
	"bytes"
	"os"
	"testing"
)

// vsto_manifest.yara lints — the unit suite does not link libyara; actual
// compile+match runs in the Docker `full` CI stage (compile-rules.sh). These
// guards pin the VSTO namespace anchors, the remote-codebase patterns, and the
// FP-gates so an edit cannot silently weaken the rule (dropping the VSTO
// namespace would FP on every benign ClickOnce app; dropping the http gate would
// fire on local-path manifests).

func loadVSTOManifestRule(t *testing.T) []byte {
	t.Helper()
	for _, p := range []string{
		"../../../../docker/local-rules/vsto_manifest.yara",
		"../../../docker/local-rules/vsto_manifest.yara",
		"../../docker/local-rules/vsto_manifest.yara",
	} {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Skip("vsto_manifest.yara not found relative to test dir")
	return nil
}

func TestVSTOManifestRule_Present(t *testing.T) {
	data := loadVSTOManifestRule(t)
	for _, want := range []string{
		"rule VSTO_Remote_Codebase",
		// VSTO-specific namespace anchors.
		"urn:schemas-microsoft-com:vsta",
		"vstav3:",
		// ClickOnce structural anchor.
		"<assemblyIdentity",
		// Remote-codebase patterns.
		`codebase\s*=\s*["']https?:\/\/`,
		`<dependentAssembly[^>]{0,400}https?:\/\/`,
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("vsto_manifest.yara missing %q", want)
		}
	}
}

// FP firewall: VSTO namespace + filesize cap must stay, else benign ClickOnce
// apps and large binaries would match.
func TestVSTOManifestRule_Gates(t *testing.T) {
	data := loadVSTOManifestRule(t)
	for _, want := range []string{
		"filesize < 256KB",
		"any of ($vsta1, $vsta2)",
		"any of ($cb_http, $dep_http)",
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("vsto_manifest.yara missing FP gate %q", want)
		}
	}
}

func TestVSTOManifestRule_NoBackreference(t *testing.T) {
	data := loadVSTOManifestRule(t)
	for _, bad := range [][]byte{[]byte(`\1`), []byte(`\2`)} {
		if bytes.Contains(data, bad) {
			t.Errorf("vsto_manifest.yara contains backreference %q — yarac rejects it", bad)
		}
	}
}
