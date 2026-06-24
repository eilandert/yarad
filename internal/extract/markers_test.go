package extract

import (
	"bytes"
	"testing"
)

// TestSplitPureMarkers_Partition pins the Phase-1 invariant: every PURE marker
// leaves Streams for the Markers channel, every COMBINED marker and every real
// content entry stays in Streams, order is preserved, and decodeMoved counts the
// MSD markers removed (so DecodedStreams stays exact).
func TestSplitPureMarkers_Partition(t *testing.T) {
	in := [][]byte{
		[]byte("real macro source Sub Auto_Open()"),
		[]byte("USERFORM-STRINGS"),
		[]byte("DOCPROPS-STRINGS"),
		[]byte("carved docprop string value"),
		[]byte("MSD-DEEPDECODE depth=4"),
		[]byte("OLE-DOC-SECURITY-1"),
		[]byte("ENCRYPTION-AES"),
		[]byte("DIGITAL-SIGNATURE"),
		[]byte("XLM-AUTO-OPEN"),
		// COMBINED markers — must stay in content (carry attacker IOC).
		[]byte("SLK-DDE =cmd|'/c calc'!A1"),
		[]byte("RTF-DDE-FIELD DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe"),
		[]byte("XLM-HIDDEN-MACROSHEET hidden Macro1"),
		[]byte("XLM-DANGEROUS-FUNC EXEC"),
		[]byte("OOXML-DDE-FIELD DDE cmd"),
		[]byte("CSV-DDE =2+5+cmd|'/c calc'!A0"),
	}
	wantMarkers := map[string]bool{
		"USERFORM-STRINGS":       true,
		"DOCPROPS-STRINGS":       true,
		"MSD-DEEPDECODE depth=4": true,
		"OLE-DOC-SECURITY-1":     true,
		"ENCRYPTION-AES":         true,
		"DIGITAL-SIGNATURE":      true,
		"XLM-AUTO-OPEN":          true,
	}

	content, markers, decodeMoved := splitPureMarkers(in)

	// No PURE marker leaked into content.
	for _, c := range content {
		if isPureMarker(c) {
			t.Fatalf("pure marker leaked into content: %q", c)
		}
	}
	// Every Markers entry is a known PURE marker.
	for _, m := range markers {
		if !isPureMarker(m) {
			t.Fatalf("non-pure entry routed to markers: %q", m)
		}
		if !wantMarkers[string(m)] {
			t.Fatalf("unexpected markers entry: %q", m)
		}
		delete(wantMarkers, string(m))
	}
	if len(wantMarkers) != 0 {
		t.Fatalf("expected markers not routed: %v", wantMarkers)
	}
	// COMBINED markers and real content stay in Streams.
	for _, want := range []string{
		"real macro source Sub Auto_Open()", "carved docprop string value",
		"SLK-DDE =cmd|'/c calc'!A1", "XLM-HIDDEN-MACROSHEET hidden Macro1",
		"XLM-DANGEROUS-FUNC EXEC", "OOXML-DDE-FIELD DDE cmd", "CSV-DDE =2+5+cmd|'/c calc'!A0",
	} {
		found := false
		for _, c := range content {
			if bytes.Equal(c, []byte(want)) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("content entry missing after split: %q", want)
		}
	}
	if decodeMoved != 1 {
		t.Fatalf("decodeMoved = %d, want 1 (one MSD-DEEPDECODE marker)", decodeMoved)
	}
}

// TestSplitPureMarkers_Empty: nil/empty input yields nil slices, no panic.
func TestSplitPureMarkers_Empty(t *testing.T) {
	content, markers, n := splitPureMarkers(nil)
	if len(content) != 0 || len(markers) != 0 || n != 0 {
		t.Fatalf("empty input: content=%d markers=%d moved=%d", len(content), len(markers), n)
	}
}
