package extract

import (
	"bytes"
	"testing"
	"time"

	yekazip "github.com/yeka/zip"
)

// childMarker is a recognisable string placed inside every encrypted-archive test
// payload; finding it in the result proves the member was decrypted AND its
// plaintext was surfaced (and recursed) for scanning.
const childMarker = "ARCHIVE_PW_CHILD_OK"

const testPW = "infected"

// pwOpts builds Options with the archive-password feature enabled and the given
// candidate list, at full depth with no deadline.
func pwOpts(cands ...string) *Options {
	o := FullOptions(time.Time{})
	o.ArchivePWEnabled = true
	o.PWCandidates = cands
	return o
}

// buildYekaZip writes a real encrypted zip (ZipCrypto or WinZip-AES) with one
// member, using yeka/zip's own writer — the same library that decrypts, plus the
// CLI-built fixtures prove cross-tool interop.
func buildYekaZip(t testing.TB, name, pw string, enc yekazip.EncryptionMethod, body []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := yekazip.NewWriter(&b)
	w, err := zw.Encrypt(name, pw, enc)
	if err != nil {
		t.Fatalf("yeka Encrypt: %v", err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatalf("write member: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return b.Bytes()
}

// --- the core contract: enabled + right candidate -> decrypt + surface + recurse.

func TestDecryptZipCryptoYeka(t *testing.T) {
	buf := buildYekaZip(t, "secret.exe", testPW, yekazip.StandardEncryption, []byte("MZ "+childMarker))
	res := ExtractWithOptions(buf, pwOpts("wrong", testPW))
	if !res.DecryptedArchive {
		t.Fatal("ZipCrypto member not decrypted")
	}
	if !streamsContain(res, childMarker) {
		t.Error("decrypted plaintext not surfaced")
	}
	if !streamsContain(res, "ARCHIVE-DECRYPTED") {
		t.Error("ARCHIVE-DECRYPTED marker not emitted")
	}
}

func TestDecryptAES256Yeka(t *testing.T) {
	buf := buildYekaZip(t, "secret.exe", testPW, yekazip.AES256Encryption, []byte("MZ "+childMarker))
	res := ExtractWithOptions(buf, pwOpts(testPW))
	if !res.DecryptedArchive || !streamsContain(res, childMarker) {
		t.Error("AES-256 member not decrypted/surfaced")
	}
}

// CLI-built ZipCrypto fixture (cross-tool: written by `zip -P`, decrypted by yeka).
func TestDecryptZipCryptoCLIFixture(t *testing.T) {
	buf := readFixture(t, "zipcrypto-pw.zip")
	res := ExtractWithOptions(buf, pwOpts(testPW))
	if !res.DecryptedArchive || !streamsContain(res, childMarker) {
		t.Error("CLI ZipCrypto fixture not decrypted/surfaced")
	}
}

// CLI-built 7z fixtures: content-encrypted and header-encrypted (-mhe=on, the
// whole listing hidden — exercises the reader-construction crack path).
func TestDecrypt7zCLIFixtures(t *testing.T) {
	for _, name := range []string{"sevenzip-pw.7z", "sevenzip-pwhe.7z"} {
		t.Run(name, func(t *testing.T) {
			res := ExtractWithOptions(readFixture(t, name), pwOpts(testPW))
			if !res.DecryptedArchive {
				t.Fatalf("%s: not decrypted", name)
			}
			if !streamsContain(res, childMarker) {
				t.Errorf("%s: decrypted plaintext not surfaced", name)
			}
		})
	}
}

// --- the OFF / miss paths must preserve the ARCHIVE-ENCRYPTED signal exactly.

func TestDecryptDisabledKeepsEncryptedMarker(t *testing.T) {
	buf := buildYekaZip(t, "secret.exe", testPW, yekazip.StandardEncryption, []byte("MZ "+childMarker))
	// Feature OFF (default Options): must behave exactly as before — flag + marker,
	// no decrypt, no child plaintext.
	res := ExtractWithOptions(buf, FullOptions(time.Time{}))
	if res.DecryptedArchive {
		t.Error("decrypted with feature disabled")
	}
	if !res.EncryptedArchive || !streamsContain(res, "ARCHIVE-ENCRYPTED") {
		t.Error("disabled path lost the ARCHIVE-ENCRYPTED signal")
	}
	if streamsContain(res, childMarker) {
		t.Error("plaintext surfaced with feature disabled")
	}
}

func TestDecryptEnabledNoCandidatesKeepsEncrypted(t *testing.T) {
	buf := buildYekaZip(t, "secret.exe", testPW, yekazip.StandardEncryption, []byte("MZ "+childMarker))
	res := ExtractWithOptions(buf, pwOpts()) // enabled but empty candidate list
	if res.DecryptedArchive {
		t.Error("decrypted with no candidates")
	}
	if !res.EncryptedArchive {
		t.Error("no-candidate path lost the ARCHIVE-ENCRYPTED signal")
	}
}

func TestDecryptWrongPasswordKeepsEncrypted(t *testing.T) {
	buf := buildYekaZip(t, "secret.exe", testPW, yekazip.AES256Encryption, []byte("MZ "+childMarker))
	res := ExtractWithOptions(buf, pwOpts("nope", "alsonope"))
	if res.DecryptedArchive {
		t.Error("AES member decrypted with only wrong passwords")
	}
	if !res.EncryptedArchive || !streamsContain(res, "ARCHIVE-ENCRYPTED") {
		t.Error("wrong-password path lost the ARCHIVE-ENCRYPTED signal")
	}
	if streamsContain(res, childMarker) {
		t.Error("plaintext surfaced on wrong password")
	}
}

// A 7z given only WRONG passwords must NOT report DecryptedArchive: opening the
// reader (even NewReaderWithPassword succeeding) does not prove the password for a
// content-encrypted 7z — only a successful member READ does. Regression for the
// "open success == password success" false positive.
func TestDecrypt7zWrongPasswordNoFalsePositive(t *testing.T) {
	for _, name := range []string{"sevenzip-pw.7z", "sevenzip-pwhe.7z"} {
		t.Run(name, func(t *testing.T) {
			res := ExtractWithOptions(readFixture(t, name), pwOpts("nope", "wrong"))
			if res.DecryptedArchive {
				t.Errorf("%s: ARCHIVE-DECRYPTED falsely set on wrong passwords", name)
			}
			if streamsContain(res, childMarker) {
				t.Errorf("%s: payload surfaced on wrong passwords", name)
			}
			if !res.EncryptedArchive {
				t.Errorf("%s: lost the ARCHIVE-ENCRYPTED signal", name)
			}
		})
	}
}

// --- security bounds.

// The global attempt cap must bound the brute loop: a zip with one ZipCrypto
// member and a candidate list far longer than maxDecryptAttempts must stop once
// the budget is spent rather than trying every candidate.
func TestDecryptAttemptCapHonoured(t *testing.T) {
	buf := buildYekaZip(t, "secret.exe", testPW, yekazip.StandardEncryption, []byte("MZ "+childMarker))
	// Many wrong candidates, real password LAST and beyond the cap -> never reached.
	cands := make([]string, 0, maxDecryptAttempts+10)
	for i := 0; i < maxDecryptAttempts+5; i++ {
		cands = append(cands, "wrong-pw-filler")
	}
	cands = append(cands, testPW)
	res := ExtractWithOptions(buf, pwOpts(cands...))
	if res.DecryptedArchive {
		t.Error("attempt cap not honoured: decrypt succeeded past maxDecryptAttempts")
	}
	if !res.EncryptedArchive {
		t.Error("capped path lost the ARCHIVE-ENCRYPTED signal")
	}
}

// The KDF sub-cap is tighter than the global cap: an AES member with a candidate
// list longer than maxKDFDecryptAttempts (but the real pw beyond it) must stop at
// the lower bound. (Cheap ZipCrypto is NOT subject to this lower cap.)
func TestDecryptKDFSubCapHonoured(t *testing.T) {
	buf := buildYekaZip(t, "secret.exe", testPW, yekazip.AES256Encryption, []byte("MZ "+childMarker))
	cands := make([]string, 0, maxKDFDecryptAttempts+5)
	for i := 0; i < maxKDFDecryptAttempts+2; i++ {
		cands = append(cands, "wrong-kdf-filler")
	}
	cands = append(cands, testPW)
	res := ExtractWithOptions(buf, pwOpts(cands...))
	if res.DecryptedArchive {
		t.Error("KDF sub-cap not honoured: AES decrypt succeeded past maxKDFDecryptAttempts")
	}
}

// A past deadline must stop the brute loop immediately — no candidate is tried.
func TestDecryptDeadlineStops(t *testing.T) {
	buf := buildYekaZip(t, "secret.exe", testPW, yekazip.StandardEncryption, []byte("MZ "+childMarker))
	o := pwOpts(testPW)
	o.Deadline = time.Now().Add(-time.Second)
	res := ExtractWithOptions(buf, o)
	if res.DecryptedArchive {
		t.Error("decrypt ran past an expired deadline")
	}
}

// A malformed/garbage member that claims encryption must fail open (no panic, no
// decrypt) — exercises the recover wrap. We feed the CLI zip truncated.
func TestDecryptMalformedFailsOpen(t *testing.T) {
	buf := readFixture(t, "zipcrypto-pw.zip")
	if len(buf) > 40 {
		buf = buf[:len(buf)-20] // truncate the central directory / member body
	}
	// Must not panic; result is best-effort (decrypt may or may not be possible).
	res := ExtractWithOptions(buf, pwOpts(testPW))
	_ = res // the assertion is "did not panic / crash"; reaching here passes.
}

// FuzzDecryptArchive drives the password-decrypt path with arbitrary archive bytes
// AND attacker-shaped candidate passwords, the feature ON. The third-party decrypt
// libs (yeka/zip, sevenzip, rardecode) are fed hostile ciphertext + wrong keys;
// the contract is "never panic out, always bounded by the deadline + attempt caps".
func FuzzDecryptArchive(f *testing.F) {
	f.Add(buildYekaZip(f, "x.exe", testPW, yekazip.StandardEncryption, []byte("MZ "+childMarker)), []byte(testPW))
	f.Add([]byte("PK\x03\x04 garbage encrypted-ish"), []byte("pw1\npw2\n"))
	f.Add([]byte("7z\xbc\xaf\x27\x1c bogus header-encrypted"), []byte("infected"))
	f.Add([]byte("Rar!\x1a\x07\x00 bogus"), []byte(""))

	f.Fuzz(func(t *testing.T, buf, rawcands []byte) {
		// Split the candidate blob into a bounded list, mirroring the scanner's cap.
		cands := []string{}
		for _, line := range bytes.Split(rawcands, []byte("\n")) {
			if len(line) > 0 && len(line) <= 64 {
				cands = append(cands, string(line))
			}
			if len(cands) >= 64 {
				break
			}
		}
		var res Result
		opts := FullOptions(fuzzDeadline())
		opts.ArchivePWEnabled = true
		opts.PWCandidates = cands
		res.childOpts = opts
		bud := &archiveBudget{}
		fromArchive(buf, &res, bud, 0, fuzzDeadline())
		checkResult(t, &res)
		// The attempt budget must never be exceeded regardless of input shape.
		if bud.decryptAttempts > maxDecryptAttempts {
			t.Fatalf("decryptAttempts %d exceeded maxDecryptAttempts %d", bud.decryptAttempts, maxDecryptAttempts)
		}
	})
}
