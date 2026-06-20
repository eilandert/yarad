package extract

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// makeMoniker builds a synthetic StdURLMoniker stream: CLSID, DWORD byte-length,
// then the UTF-16LE URL (null-terminated, as Office serialises it).
func makeMoniker(url string) []byte {
	u16 := utf16.Encode([]rune(url + "\x00"))
	body := make([]byte, len(u16)*2)
	for i, c := range u16 {
		binary.LittleEndian.PutUint16(body[i*2:], c)
	}
	var b bytes.Buffer
	b.Write([]byte("junkpadding")) // CLSID need not be at offset 0
	b.Write(stdURLMonikerCLSID)
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, uint32(len(body)))
	b.Write(length)
	b.Write(body)
	return b.Bytes()
}

func TestMonikerURL(t *testing.T) {
	const want = "http://evil.example.com/a.hta"
	got := monikerURL(makeMoniker(want))
	if string(got) != want {
		t.Errorf("monikerURL = %q, want %q", got, want)
	}
}

func TestMonikerURLNoCLSID(t *testing.T) {
	if got := monikerURL([]byte("no moniker here, just text")); got != nil {
		t.Errorf("monikerURL on non-moniker data = %q, want nil", got)
	}
}

func TestMonikerURLOversizedLengthRejected(t *testing.T) {
	// CLSID + a length field that runs past the buffer must not over-read.
	b := append([]byte{}, stdURLMonikerCLSID...)
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, 0xFFFFFFFF)
	b = append(b, length...)
	b = append(b, 0x68, 0x00) // a couple of bytes, far short of the claimed length
	if got := monikerURL(b); got != nil {
		t.Errorf("monikerURL with out-of-bounds length = %q, want nil", got)
	}
}

func TestMonikerURLDecoyCLSID(t *testing.T) {
	// A decoy CLSID with a non-decodable (out-of-bounds) length precedes the real
	// moniker; detection must skip the decoy and find the genuine URL.
	const want = "https://payload.example/x.sct"
	decoy := append([]byte{}, stdURLMonikerCLSID...)
	bad := make([]byte, 4)
	binary.LittleEndian.PutUint32(bad, 0xFFFFFFFF)
	decoy = append(decoy, bad...) // claims a huge length, no body follows
	data := append(decoy, makeMoniker(want)...)
	if got := monikerURL(data); string(got) != want {
		t.Errorf("monikerURL past decoy = %q, want %q", got, want)
	}
}

func TestMonikerURLLengthCapped(t *testing.T) {
	// A valid-but-huge URL is truncated to maxOLE2LinkURL, never copied whole.
	huge := string(bytes.Repeat([]byte("a"), maxOLE2LinkURL*4))
	got := monikerURL(makeMoniker(huge))
	if len(got) > maxOLE2LinkURL {
		t.Errorf("URL not capped: got %d bytes, want <= %d", len(got), maxOLE2LinkURL)
	}
}
