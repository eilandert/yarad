package extract

import "bytes"

// PLAN-marker-channel Phase 1: yarad emits two kinds of synthetic entries into
// Result.Streams — PURE markers (a fixed yarad literal, no attacker bytes) and
// COMBINED markers (a marker tag concatenated with a real attacker IOC). Only
// PURE markers are safe to route to the out-of-band Markers channel; COMBINED
// ones carry attacker data a content rule keys on, so they stay in Streams until
// the Phase 2 per-rule split. Real extracted content (macro source, carved
// strings, decoded blobs) is never a marker.

// pureMarkerLiterals is the exact set of yarad PURE marker strings. Each is an
// emitted-as-is constant with no variable data. Keep in sync with the emit
// sites (encsig.go, oleid.go, userform.go, docprops.go, ppt.go, rtf.go,
// xlm.go, defaultpw.go).
var pureMarkerLiterals = map[string]struct{}{
	"USERFORM-STRINGS":    {}, // userform.go
	"DOCPROPS-STRINGS":    {}, // docprops.go
	"OLEID-OBJECTPOOL":    {}, // oleid.go
	"OLEID-FLASH":         {}, // oleid.go
	"OLEID-VBA-PRESENT":   {}, // extract.go appendOLEIDMarker
	"OLEID-EXTREL":        {}, // extract.go appendOLEIDMarker
	"OLEID-DDE":           {}, // extract.go appendOLEIDMarker
	"OLEID-XLM-PRESENT":   {}, // extract.go appendOLEIDMarker
	"PPT-VBA-EXTRACTED":   {}, // ppt.go
	"RTF-OBJUPDATE":       {}, // rtf.go
	"DEFAULTPW-DECRYPTED": {}, // defaultpw.go
	"DIGITAL-SIGNATURE":   {}, // encsig.go
	"ENCRYPTION-AES":      {}, // encsig.go
	"ENCRYPTION-RC4":      {}, // encsig.go
	"ENCRYPTION-XOR":      {}, // encsig.go
	"XLM-AUTO-OPEN":       {}, // xlm.go
	"XLM-AUTO-CLOSE":      {}, // xlm.go
}

// msdDeepDecodePrefix is the PURE marker emitted by the static-decode pass; the
// trailing "depth=N" is a yarad-derived integer, not attacker bytes.
const msdDeepDecodePrefix = "MSD-DEEPDECODE depth="

// pureMarkerPrefixes are PURE markers of the form <yarad-literal><yarad-number>.
var pureMarkerPrefixes = []string{
	msdDeepDecodePrefix,   // decode.go
	oleDocSecMarkerPrefix, // docprops.go ("OLE-DOC-SECURITY-")
}

// isPureMarker reports whether s is a yarad-emitted PURE marker entry.
func isPureMarker(s []byte) bool {
	if _, ok := pureMarkerLiterals[string(s)]; ok {
		return true
	}
	for _, p := range pureMarkerPrefixes {
		if bytes.HasPrefix(s, []byte(p)) {
			return true
		}
	}
	return false
}

// splitPureMarkers partitions streams into real content vs PURE markers,
// preserving order within each. decodeMoved counts how many moved entries were
// MSD-DEEPDECODE markers (those were tallied into Result.DecodedStreams), so the
// caller can keep that metric exact after the markers leave Streams. Phase 1:
// both slices are scanned against the full ruleset; the split is the
// prerequisite for the Phase 2 collision filter and Phase 3 compiled partition.
func splitPureMarkers(streams [][]byte) (content, markers [][]byte, decodeMoved int) {
	for _, s := range streams {
		if isPureMarker(s) {
			markers = append(markers, s)
			if bytes.HasPrefix(s, []byte(msdDeepDecodePrefix)) {
				decodeMoved++
			}
			continue
		}
		content = append(content, s)
	}
	return content, markers, decodeMoved
}
