package extract

import (
	"testing"
	"time"
)

func benchDeadline() time.Time { return time.Now().Add(10 * time.Second) }

// BenchmarkExtractClean benchmarks extraction of a clean (non-container) buffer.
// Extract must return quickly with no streams for random-ish bytes.
func BenchmarkExtractClean(b *testing.B) {
	buf := make([]byte, 4096)
	for i := range buf {
		buf[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Extract(buf, benchDeadline())
	}
}

// BenchmarkExtractOLE2 benchmarks extraction of a minimal OLE2 container.
// This exercises the CFB parse + stream iteration path without a real Office
// document fixture. buildCFB is defined in msg_test.go (same package).
func BenchmarkExtractOLE2(b *testing.B) {
	var dummy testing.T
	buf := buildCFB(&dummy, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "BenchStream", mse: 2, data: []byte("VBA bench payload content for the extractor benchmark loop")},
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Extract(buf, benchDeadline())
	}
}
