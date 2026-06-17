package yarad

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ScanEngine is what the server dispatches a request to. *Scanner is the
// production implementation; tests inject a fake to exercise the HTTP layer
// without libyara.
type ScanEngine interface {
	Scan(buf []byte) ([]Match, error)
	RuleCount() int64
	// Fingerprint identifies the active rule set; it is mixed into the cache key
	// so a reload that changes the rules invalidates old verdicts (L1 and Redis).
	Fingerprint() string
	// ExtractMetrics reports the OLE/OOXML pre-extraction counters for /metrics.
	ExtractMetrics() ExtractMetrics
}

// scanResponse is the JSON the rspamd plugin parses. Matches is empty (not
// null) when nothing matched, so the plugin can branch on length alone.
type scanResponse struct {
	Matches []Match `json:"matches"`
}

// Server is the HTTP front-end: auth, body limits, the bounded-concurrency
// gate, and fail-open dispatch to the scanner. It mirrors gozer's server so the
// two backends behave identically to operators and to the rspamd plugins.
type Server struct {
	cfg     *Config
	engine  ScanEngine
	cache   Cache
	flights flightGroup
	sem     chan struct{}
	metrics struct {
		scans, matches, errors, busy        atomic.Uint64
		cacheHit, cacheMiss, cacheCoalesced atomic.Uint64
	}
	info *log.Logger // access/info — stdout when YARAD_LOG_STDOUT, else stderr
	errl *log.Logger // errors/warnings — always stderr
}

func newLoggers(cfg *Config) (info, errl *log.Logger) {
	var infoW io.Writer = os.Stderr
	if cfg.LogStdout {
		infoW = os.Stdout
	}
	return log.New(infoW, "[yarad] ", 0), log.New(os.Stderr, "[yarad] ", 0)
}

// NewServer builds the server around an engine (the compiled scanner) and a
// verdict cache built from cfg. The scanner is also used to flush the cache on
// a rules reload when it supports it (see CacheFlusher).
func NewServer(cfg *Config, engine ScanEngine) *Server {
	cfg.sanitize()
	info, errl := newLoggers(cfg)
	s := &Server{
		cfg:    cfg,
		engine: engine,
		sem:    make(chan struct{}, cfg.MaxConcurrent),
		info:   info,
		errl:   errl,
	}
	s.cache = NewCache(cfg, s.errf)
	return s
}

// FlushCache drops the verdict cache. main wires this to the SIGHUP reload so a
// new rule set never serves verdicts computed against the old rules.
func (s *Server) FlushCache() {
	if s.cache != nil {
		s.cache.Flush()
	}
}

func (s *Server) logf(format string, a ...any) { s.info.Printf(format, a...) }
func (s *Server) errf(format string, a ...any) { s.errl.Printf(format, a...) }
func (s *Server) vlogf(format string, a ...any) {
	if s.cfg.Verbose {
		s.logf(format, a...)
	}
}

// ListenAndServe binds and serves until the process is signalled.
func (s *Server) ListenAndServe() error {
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	srv := &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second, // Slowloris guard
		ReadTimeout:       s.cfg.BackendTimeout + 20*time.Second,
		WriteTimeout:      s.cfg.BackendTimeout + 25*time.Second,
		IdleTimeout:       60 * time.Second,
	}
	s.logStartup(addr)
	return srv.ListenAndServe()
}

func (s *Server) logStartup(addr string) {
	if s.cfg.Token == "" {
		s.errf("WARNING: no YARAD_TOKEN configured — /scan will refuse all requests (503). " +
			"Set YARAD_TOKEN or YARAD_TOKEN_FILE.")
	}
	cache := "off"
	if s.cfg.CacheTTL > 0 {
		cache = "memory"
		if s.cfg.RedisURL != "" {
			cache = "redis+memory"
		}
	}
	s.logf("listening on %s (rules=%d, timeout=%s, scan_timeout=%s, max_concurrent=%d, max_body=%dB, cache=%s ttl=%s size=%d, auth=%t)",
		addr, s.engine.RuleCount(), s.cfg.BackendTimeout, s.cfg.ScanTimeout,
		s.cfg.MaxConcurrent, s.cfg.MaxBody, cache, s.cfg.CacheTTL, s.cfg.CacheSize, s.cfg.Token != "")

	// Worst-case request-buffer memory: each in-flight scan can hold a full body
	// plus its extracted macro streams, on top of the loaded-rules RSS. Surface
	// it so an operator can see whether MAX_CONCURRENT × MAX_BODY fits the
	// container limit — with MAX_CONCURRENT=auto (CPU count) a many-core host can
	// reserve far more buffer memory than a small mem_limit allows (memory != rule
	// count). When the cgroup memory limit is known, warn if the buffers alone
	// would take more than half of it (leaving no room for rules RSS + GC + burst).
	peakMiB := (int64(s.cfg.MaxConcurrent) * s.cfg.MaxBody) >> 20
	s.logf("est. peak request-buffer memory ~%d MiB (max_concurrent=%d × max_body=%d MiB) on top of rules RSS",
		peakMiB, s.cfg.MaxConcurrent, s.cfg.MaxBody>>20)
	if limitMiB := cgroupMemLimitMiB(); limitMiB > 0 && peakMiB > limitMiB/2 {
		s.errf("WARNING: request buffers alone (~%d MiB) exceed half the %d MiB container memory limit; lower YARAD_MAX_CONCURRENT (or set a number instead of auto) / YARAD_MAX_BODY, or raise mem_limit",
			peakMiB, limitMiB)
	} else if limitMiB == 0 && peakMiB > 512 {
		s.errf("WARNING: max_concurrent × max_body alone is ~%d MiB of buffers; lower YARAD_MAX_CONCURRENT or YARAD_MAX_BODY", peakMiB)
	}
	s.logf("repo: %s", RepoURL)
}

// RepoURL is the project's source, logged at startup when log-stdout is on.
const RepoURL = "https://github.com/eilandert/rspamd-yarad"

// cgroupMemLimitMiB returns the container memory limit in MiB, or 0 if there is
// no enforced limit or it can't be read. Supports cgroup v2 (memory.max) and v1
// (memory.limit_in_bytes); "max" or the kernel's no-limit sentinel is unlimited.
func cgroupMemLimitMiB() int64 {
	for _, p := range []string{
		"/sys/fs/cgroup/memory.max",                   // cgroup v2
		"/sys/fs/cgroup/memory/memory.limit_in_bytes", // cgroup v1
	} {
		b, err := os.ReadFile(p) // #nosec G304 -- fixed cgroup pseudo-file paths, not user input
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(b))
		if s == "" || s == "max" {
			return 0
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 || n >= 1<<62 { // huge value = kernel "no limit" sentinel
			return 0
		}
		return n >> 20
	}
	return 0
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/health":
		// Healthy only when a rule set is actually loaded; a scanner with zero
		// rules is broken and should fail the container HEALTHCHECK.
		if s.engine.RuleCount() < 1 {
			writeText(w, http.StatusServiceUnavailable, "no rules")
			return
		}
		writeText(w, http.StatusOK, "ok")
	case r.Method == http.MethodGet && r.URL.Path == "/metrics":
		s.serveMetrics(w)
	case r.Method == http.MethodPost && r.URL.Path == "/scan":
		s.handleScan(w, r)
	default:
		writeText(w, http.StatusNotFound, "not found")
	}
}

// maxBodyHardLimit is a constant ceiling above any MaxBody so the int(length)
// conversion in handleScan is provably bounded for the static analyzer.
const maxBodyHardLimit = 1 << 30 // 1 GiB

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	ok, configured := s.authed(r)
	if !configured {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "yarad token not configured"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	length, err := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)
	if err != nil || length <= 0 || length > s.cfg.MaxBody || length > maxBodyHardLimit {
		s.metrics.errors.Add(1)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad length"})
		return
	}

	// Acquire a concurrency slot before buffering the body so a burst of large
	// uploads can't hold unbounded memory while never consuming a slot.
	if !s.acquire() {
		s.metrics.busy.Add(1)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "busy"})
		s.errf("/scan 503 busy (max_concurrent=%d reached)", s.cfg.MaxConcurrent)
		return
	}
	defer func() { <-s.sem }()

	buf := make([]byte, int(length))
	if _, err := io.ReadFull(r.Body, buf); err != nil {
		s.metrics.errors.Add(1)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read error"})
		return
	}

	t0 := time.Now()
	s.metrics.scans.Add(1)

	// Mix the active ruleset fingerprint into the cache key so a SIGHUP reload
	// that changes the rules invalidates old verdicts in both L1 and Redis L2
	// (old keys orphan and TTL-expire; no stale "clean" after a rule update).
	key := s.engine.Fingerprint() + ":" + sha256key(buf)
	matches, cacheStatus := s.lookupOrScan(key, buf)

	if len(matches) > 0 {
		s.metrics.matches.Add(1)
	}
	if cacheStatus == "hit" || cacheStatus == "coalesced" {
		w.Header().Set("X-YARAD-Cache", cacheStatus)
	}
	// Always emit a JSON array (never null) so the rspamd plugin can branch on
	// length without a nil check.
	if matches == nil {
		matches = []Match{}
	}
	writeJSON(w, http.StatusOK, scanResponse{Matches: matches})
	// Log the matched rule NAMES (not just a count) whenever something fires, at
	// info level — this is the cheap, accurate way to see which rules fire on
	// real mail and spot over-firing/FP rules to tune or demote. A per-rule
	// Prometheus metric is deliberately avoided: ~10k rules would blow label
	// cardinality. Clean scans stay quiet (verbose-only) to keep logs readable.
	if len(matches) > 0 {
		s.logf("/scan %dB cache=%s %.1fms -> %d matches %s", len(buf), cacheStatus, msSince(t0), len(matches), ruleNames(matches))
	} else {
		s.vlogf("/scan %dB cache=%s %.1fms -> 0 matches", len(buf), cacheStatus, msSince(t0))
	}
}

// lookupOrScan resolves a verdict for buf: cache hit, coalesced wait on an
// in-flight identical scan, or a fresh scan whose result is cached. At high
// volume the cache + coalescing collapse a bulk campaign's N identical messages
// into a single scan. Returns the matches and a cache-status label for logs.
func (s *Server) lookupOrScan(key string, buf []byte) ([]Match, string) {
	if m, found := s.cache.Get(key); found {
		s.metrics.cacheHit.Add(1)
		return m, "hit"
	}
	matches, shared := s.flights.Do(key, func() []Match {
		// A leader may have populated the cache between the first lookup and
		// registering this flight.
		if m, found := s.cache.Get(key); found {
			return m
		}
		s.metrics.cacheMiss.Add(1)
		m, scanErr := s.dispatch(buf)
		if scanErr != nil {
			// Fail open: a scan error is "no match" to the plugin so a scanner
			// problem never blocks mail. A failed scan is NOT cached (don't
			// pin a wrong empty verdict for the whole TTL).
			s.metrics.errors.Add(1)
			s.errf("/scan %dB scan error (fail-open): %v", len(buf), scanErr)
			return nil
		}
		s.cache.Put(key, m)
		return m
	})
	if shared {
		s.metrics.cacheCoalesced.Add(1)
		return matches, "coalesced"
	}
	return matches, "miss"
}

// dispatch runs the scanner and never lets a panic reach the caller: on panic
// it logs and returns a non-nil error. Returning an error (not (nil,nil)) is
// deliberate — the caller treats errors as fail-open "no match" but does NOT
// cache them, so a panicking input is rescanned next time instead of being
// pinned as a clean verdict for the whole cache TTL.
func (s *Server) dispatch(buf []byte) (matches []Match, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			s.errf("scan panic: %v", rec)
			matches, err = nil, fmt.Errorf("scan panic: %v", rec)
		}
	}()
	return s.engine.Scan(buf)
}

func (s *Server) acquire() bool {
	select {
	case s.sem <- struct{}{}:
		return true
	default:
	}
	timer := time.NewTimer(s.cfg.BackendTimeout)
	defer timer.Stop()
	select {
	case s.sem <- struct{}{}:
		return true
	case <-timer.C:
		return false
	}
}

// authed validates the shared secret. configured is false when no token is set
// (caller returns 503); ok is the constant-time comparison result. Accepts the
// token as a Bearer Authorization header or X-YARAD-Token.
func (s *Server) authed(r *http.Request) (ok, configured bool) {
	if s.cfg.Token == "" {
		return false, false
	}
	presented := ""
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		presented = strings.TrimSpace(a[len("Bearer "):])
	} else {
		presented = strings.TrimSpace(r.Header.Get("X-YARAD-Token"))
	}
	return hmac.Equal([]byte(presented), []byte(s.cfg.Token)), true
}

func (s *Server) serveMetrics(w http.ResponseWriter) {
	var b strings.Builder
	fm := func(name, help string, v uint64) {
		b.WriteString("# HELP yarad_" + name + " " + help + "\n")
		b.WriteString("# TYPE yarad_" + name + " counter\n")
		b.WriteString("yarad_" + name + " " + strconv.FormatUint(v, 10) + "\n")
	}
	fm("scans_total", "total /scan requests served", s.metrics.scans.Load())
	fm("matches_total", "/scan requests with >=1 rule match", s.metrics.matches.Load())
	fm("errors_total", "scan/read/length errors", s.metrics.errors.Load())
	fm("busy_total", "requests rejected by the concurrency gate", s.metrics.busy.Load())
	fm("cache_hits_total", "verdicts served from cache", s.metrics.cacheHit.Load())
	fm("cache_misses_total", "scans that ran (cache miss)", s.metrics.cacheMiss.Load())
	fm("cache_coalesced_total", "scans coalesced onto an in-flight identical scan", s.metrics.cacheCoalesced.Load())
	b.WriteString("# HELP yarad_rules loaded YARA rule count\n")
	b.WriteString("# TYPE yarad_rules gauge\n")
	b.WriteString("yarad_rules " + strconv.FormatInt(s.engine.RuleCount(), 10) + "\n")

	// OLE/OOXML pre-extraction counters — visibility into the document path.
	ex := s.engine.ExtractMetrics()
	fm("extract_docs_total", "attachments recognised as OLE2/OOXML containers", uint64(ex.Docs))
	fm("extract_macro_docs_total", "documents that yielded >=1 decompressed macro stream", uint64(ex.MacroDocs))
	fm("extract_streams_total", "decompressed macro streams scanned", uint64(ex.Streams))
	fm("extract_failed_total", "container parse attempts that errored", uint64(ex.Failed))
	fm("extract_panicked_total", "parser panics recovered (subset of failed)", uint64(ex.Panicked))
	fm("extract_encrypted_total", "ECMA-376 encrypted OOXML seen (not decrypted)", uint64(ex.Encrypted))
	writeRaw(w, http.StatusOK, "text/plain; version=0.0.4", []byte(b.String()))
}

// --- response helpers ---

func writeText(w http.ResponseWriter, code int, body string) {
	writeRaw(w, code, "text/plain", []byte(body))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"error":"internal"}`)
	}
	writeRaw(w, code, "application/json", b)
}

func writeRaw(w http.ResponseWriter, code int, ctype string, body []byte) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(code)
	_, _ = w.Write(body) // #nosec G705 -- application/json or text/plain API response, not an HTML/XSS sink
}

func sha256key(b []byte) string {
	sum := sha256.Sum256(b)
	return string(sum[:])
}

// ruleNames renders the matched rule identifiers as "[a, b, c]" for the access
// log. Capped so a pathological message matching hundreds of rules can't write a
// multi-kilobyte log line per scan.
func ruleNames(m []Match) string {
	const max = 20
	var b strings.Builder
	b.WriteByte('[')
	for i, x := range m {
		if i == max {
			fmt.Fprintf(&b, ", +%d more", len(m)-max)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(x.Rule)
	}
	b.WriteByte(']')
	return b.String()
}

func msSince(t time.Time) float64 { return float64(time.Since(t).Microseconds()) / 1000 }
