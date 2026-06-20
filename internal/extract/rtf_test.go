package extract

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// wrapRTFObjData builds a minimal RTF document embedding blob as the hex payload
// of a `{\object ... {\*\objdata <hex>}}` group, with the hex broken across lines
// (as real RTF writers do) to exercise the whitespace-skipping decoder.
func wrapRTFObjData(blob []byte) []byte {
	h := hex.EncodeToString(blob)
	var sb strings.Builder
	sb.WriteString("{\\rtf1\\ansi\\ansicpg1252\n{\\object\\objemb{\\*\\objdata\n")
	for i := 0; i < len(h); i += 64 {
		end := i + 64
		if end > len(h) {
			end = len(h)
		}
		sb.WriteString(h[i:end])
		sb.WriteByte('\n')
	}
	sb.WriteString("}}}\n")
	return []byte(sb.String())
}

// A bare Ole10Native blob hex-embedded in an RTF \objdata group must be decoded
// and its native data carved (the CVE-2017-0199/-11882 / OLE2Link delivery path).
func TestExtractRTFOle10Native(t *testing.T) {
	payload := []byte("MZ\x90\x00 rtf embedded objdata dropper payload calc.exe")
	stream := buildOle10Native("calc.exe", "C:\\evil\\calc.exe", "C:\\Temp\\calc.exe", payload, 0)
	buf := wrapRTFObjData(stream)
	res := Extract(buf, time.Time{})
	if !res.IsDoc {
		t.Fatal("RTF not flagged IsDoc")
	}
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	if !res.IsOLEPackage {
		t.Fatal("bare Ole10Native via RTF not flagged IsOLEPackage")
	}
	if !streamsContain(res, "rtf embedded objdata dropper payload") {
		t.Errorf("carved native data not surfaced; got %d streams", len(res.Streams))
	}
}

// A full OLE2 (CFB) compound file embedded in an RTF \objdata group must run the
// same OLE2 package extraction — the embedded doc's Ole10Native stream is carved.
func TestExtractRTFEmbeddedCFB(t *testing.T) {
	payload := []byte("MZ embedded cfb-in-rtf dropper payload")
	stream := buildOle10Native("x.exe", "x.exe", "x.exe", payload, 0)
	cfb := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "\x01Ole10Native", mse: 2, data: stream},
	})
	buf := wrapRTFObjData(cfb)
	res := Extract(buf, time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	if !res.IsOLEPackage {
		t.Fatal("embedded CFB package not flagged IsOLEPackage")
	}
	if !streamsContain(res, "embedded cfb-in-rtf dropper payload") {
		t.Errorf("CFB-in-RTF native data not surfaced; got %d streams", len(res.Streams))
	}
}

// An RTF with a leading BOM/whitespace must still be recognised.
func TestExtractRTFLeadingWhitespace(t *testing.T) {
	if !isRTF([]byte("  \r\n{\\rtf1}")) {
		t.Error("RTF with leading whitespace not recognised")
	}
	if isRTF([]byte("not an rtf {\\rtf1}")) {
		t.Error("non-RTF prefix wrongly recognised")
	}
	// UTF-8 BOM-prefixed RTF must be recognised.
	if !isRTF([]byte{0xEF, 0xBB, 0xBF, '{', '\\', 'r', 't', 'f', '1', '}'}) {
		t.Error("BOM-prefixed RTF not recognised")
	}
}

// A hostile RTF stuffed with empty \objdata groups must be bounded by
// maxRTFObjects (no per-group decode/index work beyond the cap) and yield no
// streams — fail-open, no resource exhaustion.
func TestExtractRTFManyEmptyObjects(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("{\\rtf1")
	for i := 0; i < maxRTFObjects*4; i++ {
		sb.WriteString("{\\object{\\*\\objdata }}")
	}
	sb.WriteString("}")
	res := Extract([]byte(sb.String()), time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	if len(res.Streams) != 0 {
		t.Errorf("empty-object flood yielded %d streams", len(res.Streams))
	}
}

// An RTF with no \objdata group is still flagged IsRTF but yields no streams.
func TestExtractRTFNoObject(t *testing.T) {
	buf := []byte("{\\rtf1\\ansi plain document, no embedded object}")
	res := Extract(buf, time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	if len(res.Streams) != 0 {
		t.Errorf("expected no streams, got %d", len(res.Streams))
	}
}

// A truncated / garbage \objdata hex run must be skipped without panic (fail-open).
func TestExtractRTFGarbageObjData(t *testing.T) {
	// Odd-length, non-OLE, non-Ole10Native hex — must not panic or over-read.
	buf := []byte("{\\rtf1{\\object{\\*\\objdata 4d5a90zzz}}}")
	res := Extract(buf, time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	// No valid payload — no crash is the assertion; streams may be empty.
	_ = res.Streams
}

// ---------- RTF evasion detection (PR-12) ----------

// Plain \objupdate must emit the RTF-OBJUPDATE marker stream.
func TestRTFObjUpdatePlain(t *testing.T) {
	buf := []byte(`{\rtf1\ansi {\object\objlink\objupdate {\*\objdata 4d5a}}}`)
	res := Extract(buf, time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	if !streamsContain(res, "RTF-OBJUPDATE") {
		t.Errorf("plain \\objupdate: RTF-OBJUPDATE marker not emitted; streams=%d", len(res.Streams))
	}
}

// \objupdate split by an empty group obfuscation must still emit the marker.
func TestRTFObjUpdateObfuscated(t *testing.T) {
	// Obfuscation: \objup{}date — empty group between control-word fragments.
	buf := []byte(`{\rtf1\ansi {\object\objlink\objup{}date {\*\objdata 4d5a}}}`)
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "RTF-OBJUPDATE") {
		t.Errorf("obfuscated \\objupdate (empty group split): RTF-OBJUPDATE not emitted; streams=%d", len(res.Streams))
	}
}

// Plain \ddeauto must emit RTF-DDEAUTO (and RTF-DDE, since \dde is a prefix).
func TestRTFDDEAutoPlain(t *testing.T) {
	buf := []byte(`{\rtf1\ansi {\field{\*\fldinst \ddeauto "cmd" "/k calc"}}}`)
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "RTF-DDEAUTO") {
		t.Errorf("plain \\ddeauto: RTF-DDEAUTO not emitted; streams=%d", len(res.Streams))
	}
}

// \ddeauto split by {\*\foo} optional-destination group must still be detected.
func TestRTFDDEAutoObfuscated(t *testing.T) {
	// Obfuscation: \dde{\*\junk}auto — optional-destination group in the middle.
	buf := []byte(`{\rtf1\ansi {\field{\*\fldinst \dde{\*\junk}auto "cmd" "/k calc"}}}`)
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "RTF-DDEAUTO") {
		t.Errorf("obfuscated \\ddeauto (\\*\\junk split): RTF-DDEAUTO not emitted; streams=%d", len(res.Streams))
	}
}

// Plain \dde (without auto) must emit RTF-DDE.
func TestRTFDDEPlain(t *testing.T) {
	buf := []byte(`{\rtf1\ansi {\field{\*\fldinst \dde "Excel.exe" "Sheet1!R1C1"}}}`)
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "RTF-DDE") {
		t.Errorf("plain \\dde: RTF-DDE not emitted; streams=%d", len(res.Streams))
	}
}

// \dde with \bin<N> binary run injected before the keyword must still be detected.
func TestRTFDDEObfuscatedBin(t *testing.T) {
	// Obfuscation: \bin3XXX\dde — 3-byte binary run before the control word.
	buf := []byte("{\x5crtf1\\ansi {\\field{\\*\\fldinst \\bin3\x00\x00\x00\\dde \"cmd\" \"/k calc\"}}}")
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "RTF-DDE") {
		t.Errorf("obfuscated \\dde (\\bin<N> prefix): RTF-DDE not emitted; streams=%d", len(res.Streams))
	}
}

// A benign RTF with no evasion control words must NOT emit any evasion markers.
func TestRTFEvasionBenign(t *testing.T) {
	buf := []byte(`{\rtf1\ansi\ansicpg1252\deff0 {\fonttbl{\f0\fswiss Arial;}}` +
		`{\colortbl ;\red0\green0\blue0;}` +
		`\f0\fs24 Hello, this is a normal document with no malicious fields.\par}`)
	res := Extract(buf, time.Time{})
	if !res.IsRTF {
		t.Fatal("RTF not flagged IsRTF")
	}
	for _, s := range res.Streams {
		switch string(s) {
		case "RTF-OBJUPDATE", "RTF-DDEAUTO", "RTF-DDE":
			t.Errorf("benign RTF emitted evasion marker: %q", s)
		}
	}
}

// Multiple \objdata groups are each carved, bounded by maxRTFObjects.
func TestExtractRTFMultipleObjects(t *testing.T) {
	s1 := buildOle10Native("a.exe", "a.exe", "a.exe", []byte("MZ first rtf objdata payload"), 0)
	s2 := buildOle10Native("b.exe", "b.exe", "b.exe", []byte("MZ second rtf objdata payload"), 0)
	h1 := hex.EncodeToString(s1)
	h2 := hex.EncodeToString(s2)
	buf := []byte("{\\rtf1{\\object{\\*\\objdata " + h1 + "}}{\\object{\\*\\objdata " + h2 + "}}}")
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "first rtf objdata payload") || !streamsContain(res, "second rtf objdata payload") {
		t.Errorf("expected both objdata payloads carved; got %d streams", len(res.Streams))
	}
}
