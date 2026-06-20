package extract

import (
	"bytes"
	"strings"
	"time"

	"www.velocidex.com/golang/oleparse"
)

// RTF embedded-object carve. A classic maldoc trick (CVE-2017-0199,
// CVE-2017-11882, OLE2Link/malrtf) embeds an OLE object inside an RTF document
// as an `{\object ... {\*\objdata <hex>}}` group: the `\objdata` control word is
// followed by the object's OLESaveToStream bytes encoded as ASCII hex. Those
// bytes are an OLENativeStream/Ole10Native payload or a full OLE2 (CFB) compound
// document — neither of which raw-byte scanning of the RTF source can see,
// because the dropped file is hex-text, not binary.
//
// fromRTF decodes every `\objdata` hex blob and surfaces (a) the OLE2 streams if
// the blob is a CFB compound file (reusing the same VBA/MSI/.msg/package
// extraction the OLE path uses) and (b) the carved Ole10Native native-data if the
// blob is a bare OLENativeStream. This is the sibling of the OLE Package carve
// (#14), which only covered the OLE2-storage case; here the package rides inside
// RTF hex instead of inside an Office document's storage.
//
// RTF evasion heuristics (PR-12): fromRTF also detects three high-signal evasion
// control words — \objupdate (auto-updating OLE link), \ddeauto, and \dde — and
// emits synthetic ASCII marker streams for each so YARA rules match them.
// Control-word obfuscation (fake/empty groups, \* groups, \bin<N> runs, hex with
// interleaved whitespace) is handled by rtfNormalise before matching. Bounded
// by the same maxRTF* caps; fail-open.
//
// Best-effort and fail-open: a malformed group is skipped, never fatal (Extract's
// recover still covers a panic).

const (
	// rtfObjData is the control word introducing the hex-encoded object bytes.
	rtfObjDataKW = "\\objdata"

	// maxRTFObjects bounds how many \objdata groups we carve from one document.
	maxRTFObjects = 64
	// maxBytesPerRTFObject caps one decoded object blob (raw scan covers the rest).
	maxBytesPerRTFObject = 16 << 20
	// maxTotalRTF caps cumulative carved/decoded bytes from one document.
	maxTotalRTF = 48 << 20

	// maxRTFNormalise caps the prefix of RTF text fed through rtfNormalise for
	// evasion-control-word detection. A full-document scan is not needed because
	// the control words of interest appear near the document root.
	maxRTFNormalise = 256 << 10 // 256 KiB

	// Synthetic ASCII markers emitted to res.Streams so YARA rules can match
	// the high-signal evasion control words without needing to parse RTF syntax.
	rtfMarkerObjUpdate = "RTF-OBJUPDATE"
	rtfMarkerDDEAuto   = "RTF-DDEAUTO"
	rtfMarkerDDE       = "RTF-DDE"
)

// utf8BOM is the UTF-8 byte-order mark some editors prepend to RTF.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// isRTF reports whether buf opens an RTF document: `{\rt` after an optional
// UTF-8 BOM and leading whitespace. RTF has no binary magic, so the signature
// group header is the recogniser. We accept `{\rtf` and the rare `{\rtxxx`
// variants by matching the `{\rt` prefix.
func isRTF(buf []byte) bool {
	buf = bytes.TrimPrefix(buf, utf8BOM)
	i := 0
	for i < len(buf) && (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\r' || buf[i] == '\n') {
		i++
	}
	return bytes.HasPrefix(buf[i:], []byte("{\\rt"))
}

// fromRTF scans an RTF document for `\objdata` groups, hex-decodes each one, and
// surfaces the embedded object's payload to res.Streams. For a CFB blob it runs
// the same OLE2 extraction as a standalone document (macros + package + MSI +
// .msg); for a bare OLENativeStream it carves the native file via
// carveOle10Native. Sets res.IsRTF whenever the buffer is RTF (whether or not any
// object decoded). Bounded by the maxRTF* caps.
//
// Also detects RTF evasion control words (\objupdate, \ddeauto, \dde) after
// normalising out common obfuscation (interleaved groups, \bin<N> skips, hex
// whitespace) and emits synthetic ASCII marker streams for YARA matching.
func fromRTF(buf []byte, res *Result, deadline time.Time) {
	res.IsRTF = true

	// Evasion detection: normalise a bounded prefix of the RTF and scan for
	// high-signal control words. Each marker is emitted at most once.
	rtfDetectEvasion(buf, res)

	var total, objs int
	rest := buf
	for {
		// Bound both the cumulative byte/stream work AND the number of \objdata
		// groups examined — a hostile message stuffed with thousands of empty/
		// malformed groups yields no streams, so a stream-count guard alone would
		// never trip; objs caps the decode/index work regardless of yield.
		if objs >= maxRTFObjects || len(res.Streams) >= maxStreams || total >= maxTotalRTF || expired(deadline) {
			break
		}
		idx := bytes.Index(rest, []byte(rtfObjDataKW))
		if idx < 0 {
			break
		}
		objs++
		// Advance past the control word; the hex run starts after any control-word
		// delimiter (a space, or the bytes up to the next `{`/`}`/`\`).
		rest = rest[idx+len(rtfObjDataKW):]
		blob := decodeRTFHex(rest)
		if len(blob) == 0 {
			continue
		}
		if len(blob) > maxBytesPerRTFObject {
			blob = blob[:maxBytesPerRTFObject]
		}
		total += len(blob)
		carveRTFObject(blob, res, deadline)
	}
}

// rtfNormalise strips common RTF control-word obfuscation from a bounded prefix
// of buf and returns a lowercase string suitable for keyword scanning. It removes:
//   - \* optional-destination groups and their closing brace (e.g. {\*\foo ...})
//   - Entire empty groups {}
//   - \bin<N> binary runs (skip N raw bytes following the control word)
//   - Hex runs \'XX (already-ASCII-hex encoded characters — decoded to actual char)
//   - Whitespace between \ and the next letter (some obfuscators insert CR/LF)
//
// The result is NOT a parseable RTF document; it is only useful for detecting the
// presence of specific control words within the first maxRTFNormalise bytes.
func rtfNormalise(buf []byte) string {
	if len(buf) > maxRTFNormalise {
		buf = buf[:maxRTFNormalise]
	}
	var sb strings.Builder
	sb.Grow(len(buf))
	i := 0
	for i < len(buf) {
		c := buf[i]
		switch {
		case c == '\\' && i+1 < len(buf):
			next := buf[i+1]
			if next == '\'' && i+3 < len(buf) {
				// \'XX hex escape — decode to the actual byte value (printable range).
				hi := hexNibble(buf[i+2])
				lo := hexNibble(buf[i+3])
				if hi >= 0 && lo >= 0 {
					sb.WriteByte(byte(hi<<4 | lo)) // #nosec G115 -- hi∈[0,15] lo∈[0,15]; max 255, fits byte
					i += 4
					continue
				}
			}
			if next == '*' {
				// \* optional-destination marker: drop '\*' and the destination
				// control word that follows (e.g. {\*\junk} or {\*\fldinst}).
				// Surrounding {} are dropped by the '{'/'}' cases below.
				// We keep the group's remaining content so keywords like \dde
				// inside {\*\fldinst \ddeauto ...} are still visible, and so
				// mid-keyword obfuscation like \dde{\*\junk}auto collapses to
				// \ddeauto (braces dropped, \*\junk dropped, tokens merge).
				i += 2 // skip '\' + '*'
				// The destination name is itself a control word: skip its '\'.
				if i < len(buf) && buf[i] == '\\' {
					i++
				}
				// Skip the control-word letters (e.g. "junk", "fldinst").
				for i < len(buf) && buf[i] >= 'a' && buf[i] <= 'z' {
					i++
				}
				// Skip optional numeric parameter.
				for i < len(buf) && buf[i] >= '0' && buf[i] <= '9' {
					i++
				}
				// Skip the single control-word delimiter (one space or CR/LF).
				if i < len(buf) && (buf[i] == ' ' || buf[i] == '\r' || buf[i] == '\n') {
					i++
				}
				continue
			}
			if next == '\r' || next == '\n' {
				// Whitespace injected between '\' and keyword letters — skip newline.
				i += 2
				continue
			}
			// Check for \bin<N>: consume N raw bytes after the control word.
			if next >= 'a' && next <= 'z' {
				j := i + 1
				for j < len(buf) && buf[j] >= 'a' && buf[j] <= 'z' {
					j++
				}
				kw := string(buf[i+1 : j])
				if kw == "bin" {
					// Parse the numeric argument.
					k := j
					for k < len(buf) && buf[k] >= '0' && buf[k] <= '9' {
						k++
					}
					n := 0
					for _, d := range buf[j:k] {
						n = n*10 + int(d-'0')
						if n > maxRTFNormalise {
							n = maxRTFNormalise
							break
						}
					}
					i = k + n // skip delimiter + binary bytes
					if i > len(buf) {
						i = len(buf)
					}
					continue
				}
			}
			sb.WriteByte('\\')
			i++
		case c == '{' || c == '}':
			// Drop group markers; they break control-word recognition across group
			// boundaries (e.g. `\dde{}auto`).
			i++
		default:
			sb.WriteByte(c)
			i++
		}
	}
	return strings.ToLower(sb.String())
}

// hexNibble returns the value 0-15 of an ASCII hex digit, or -1 if not hex.
func hexNibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// rtfDetectEvasion normalises a bounded RTF prefix and emits synthetic ASCII
// marker streams for each detected evasion control word. Each marker is appended
// at most once (duplicate check against existing streams is not needed — the
// function itself guards via local booleans, and YARA string matches are not
// counted). Bounded by maxRTFNormalise; fail-open (no panic on malformed input).
func rtfDetectEvasion(buf []byte, res *Result) {
	norm := rtfNormalise(buf)

	// \objupdate — auto-updating OLE link (loads remote resource on open).
	if strings.Contains(norm, `\objupdate`) {
		res.Streams = append(res.Streams, []byte(rtfMarkerObjUpdate))
	}

	// \ddeauto — DDE auto-execute field (match before \dde to avoid double-emit).
	hasDDEAuto := strings.Contains(norm, `\ddeauto`)
	if hasDDEAuto {
		res.Streams = append(res.Streams, []byte(rtfMarkerDDEAuto))
	}

	// \dde — DDE field (emit even when \ddeauto is absent; both are high-signal).
	if strings.Contains(norm, `\dde`) {
		res.Streams = append(res.Streams, []byte(rtfMarkerDDE))
	}
}

// decodeRTFHex reads the ASCII-hex run that follows an `\objdata` control word
// and returns the decoded bytes. It accepts hex digits, skips RTF whitespace
// (space, CR, LF, tab) and the control-word leading space, and stops at the first
// non-hex/non-whitespace byte (the group's closing `}` or a nested control word).
// An odd trailing nibble is dropped. Bounded by maxBytesPerRTFObject so a hostile
// multi-MiB hex run can't exhaust memory.
func decodeRTFHex(b []byte) []byte {
	out := make([]byte, 0, 256)
	var hi byte
	var haveHi bool
	for _, c := range b {
		switch {
		case c == ' ' || c == '\r' || c == '\n' || c == '\t':
			continue
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			c = c - 'A' + 10
		default:
			// End of the hex run (closing brace, control word, etc.).
			return out
		}
		if !haveHi {
			hi = c
			haveHi = true
			continue
		}
		out = append(out, hi<<4|c)
		haveHi = false
		if len(out) >= maxBytesPerRTFObject {
			break
		}
	}
	return out
}

// carveRTFObject inspects one decoded \objdata blob and surfaces its payload. The
// blob is an OLESaveToStream image: it may be a full OLE2 (CFB) compound file or a
// bare OLENativeStream/Ole10Native. Try OLE2 first (covers the embedded-doc and
// OLE-package cases via the existing helpers); fall back to a direct Ole10Native
// carve for the bare-stream case. Best-effort; a parse failure is skipped.
func carveRTFObject(blob []byte, res *Result, deadline time.Time) {
	// An OLENativeStream begins with the OLE2 magic only when it wraps a CFB; the
	// bare Packager form does not. Many \objdata blobs are prefixed with an
	// OLEStream header before the CFB magic, so search rather than require a prefix.
	if i := bytes.Index(blob, oleMagic); i >= 0 {
		if ole, err := oleparse.NewOLEFile(blob[i:]); err == nil {
			// Reuse the full OLE2 extraction surface: macros, embedded package,
			// MSI and .msg. Each helper is a no-op when the OLE2 isn't theirs.
			if mods, err := oleparse.ExtractMacros(ole); err == nil {
				res.Streams = codes(mods, res.Streams)
			}
			fromOLEPackage(ole, res, deadline)
			if !fromMSG(ole, res, deadline) {
				fromMSI(ole, res, deadline)
			}
			return
		}
	}
	// Not a CFB: treat the blob as a bare Ole10Native/OLENativeStream and carve the
	// native file data directly (sibling of the #14 OLE2-storage path).
	if data := carveOle10Native(blob); len(data) > 0 {
		res.IsOLEPackage = true
		res.Streams = append(res.Streams, append([]byte(nil), data...))
	}
}
