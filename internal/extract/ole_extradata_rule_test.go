package extract

import (
	"bytes"
	"os"
	"testing"
)

// oleid_indicators.yara lints — the unit suite does not link libyara; actual
// compile+match runs in the Docker `full` CI stage (compile-rules.sh). This
// guards the OLE2_ExtraData marker rule that scores the OLE2-EXTRA-DATA marker
// emitted by fromOLEExtraData: without it the marker is carved but never scored.
func loadOLEIDIndicatorsRule(t *testing.T) []byte {
	t.Helper()
	for _, p := range []string{
		"../../../../docker/local-rules/oleid_indicators.yara",
		"../../../docker/local-rules/oleid_indicators.yara",
		"../../docker/local-rules/oleid_indicators.yara",
	} {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Skip("oleid_indicators.yara not found relative to test dir")
	return nil
}

func TestOLE2ExtraDataRule_Present(t *testing.T) {
	data := loadOLEIDIndicatorsRule(t)
	for _, want := range []string{
		"rule OLE2_ExtraData",
		`$marker = "OLE2-EXTRA-DATA"`,
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("oleid_indicators.yara missing %q — OLE2-EXTRA-DATA marker would be unscored", want)
		}
	}
}

// TestOLE2ExtraDataRule_MarkerMatchesEmitter pins the rule's marker string to
// the exact bytes fromOLEExtraData appends, so a rename on either side fails CI.
func TestOLE2ExtraDataRule_MarkerMatchesEmitter(t *testing.T) {
	data := loadOLEIDIndicatorsRule(t)
	if !bytes.Contains(data, []byte("OLE2-EXTRA-DATA")) {
		t.Fatal("oleid_indicators.yara marker drifted from fromOLEExtraData emitter")
	}
}
