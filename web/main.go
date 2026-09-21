package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/spray/core"
	"github.com/chainreactors/spray/pkg"
	"github.com/chainreactors/utils/httputils"
	"github.com/chainreactors/utils/parsers"
	"github.com/gookit/config/v2"
	"github.com/gookit/config/v2/yaml"
)

// modernUserAgents is loaded from UA.txt next to the binary (or cwd) at init.
// spray's built-in pool is from 2015-2017 and triggers odd behavior on modern sites.
var modernUserAgents []string

func loadUAFile() {
	for _, p := range []string{"UA.txt", filepath.Join(filepath.Dir(mustExe()), "UA.txt")} {
		if data, err := os.ReadFile(p); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, l := range lines {
				l = strings.TrimSpace(l)
				if l != "" {
					modernUserAgents = append(modernUserAgents, l)
				}
			}
			log.Printf("loaded %d user-agents from %s", len(modernUserAgents), p)
			return
		}
	}
	// fallback: a small built-in set
	modernUserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
	}
}

func mustExe() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return exe
}

func init() {
	loadUAFile()
	// Override spray's stale (2015-era) UA pool before any scan starts.
	// spray's --random-agent reads from this pool per request.
	if len(modernUserAgents) > 0 {
		httputils.RandomUA = modernUserAgents
		// pkg.DefaultUserAgent is a package-level var set at pkg init time from
		// the OLD pool (bingbot etc.). Re-sample it from the new pool so that
		// scans without --random-agent also use a modern UA.
		pkg.DefaultUserAgent = httputils.GetRandomUA()
	}

	// spray's RunWithArgs tries to load config.yaml via gookit/config,
	// which needs the yaml driver registered (spray.go's main does this).
	config.WithOptions(func(opt *config.Options) {
		opt.DecoderConfig.TagName = "config"
		opt.ParseDefault = true
	})
	config.AddDriver(yaml.Driver)
}

// event is a single SSE message pushed to the browser.
type event struct {
	Type string      `json:"type"` // started | result | stat | done | error
	Data interface{} `json:"data"`
}

// session holds the state of one scan run.
type session struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	// subscribers receive events over this channel.
	subCh   chan event
	resultC chan event

	startedAt time.Time
	args      []string

	// finished state: once the scan ends we cache the done event so any
	// SSE client connecting late (or reconnecting) gets a proper close.
	finMu  sync.Mutex
	finish event // zero when not yet finished
	doneOnce sync.Once
}

var (
	curMu sync.Mutex
	cur   *session
)

// scanRequest is the JSON body posted by the frontend form.
type scanRequest struct {
	// Input (one of)
	URLs    []string `json:"urls,omitempty"`
	URLFile string   `json:"urlFile,omitempty"`
	CIDRs   []string `json:"cidrs,omitempty"`

	// Dictionary / word / rules
	Dictionaries []string `json:"dictionaries,omitempty"`
	Word         string   `json:"word,omitempty"`
	Rules        []string `json:"rules,omitempty"`
	DefaultDict  bool     `json:"defaultDict,omitempty"`

	// Functions
	Extensions     string `json:"extensions,omitempty"`
	ForceExtension bool   `json:"forceExtension,omitempty"`
	Uppercase      bool   `json:"uppercase,omitempty"`
	Lowercase      bool   `json:"lowercase,omitempty"`

	// Plugins
	Advance bool `json:"advance,omitempty"`
	Finger  bool `json:"finger,omitempty"`
	Bak     bool `json:"bak,omitempty"`
	Common  bool `json:"common,omitempty"`
	Crawl   bool `json:"crawl,omitempty"`
	Active  bool `json:"active,omitempty"`
	Recon   bool `json:"recon,omitempty"`
	Keys    bool `json:"keys,omitempty"`
	Poc     bool `json:"poc,omitempty"`
	Fuzzuli bool `json:"fuzzuli,omitempty"`

	// Output
	Match  string `json:"match,omitempty"`
	Filter string `json:"filter,omitempty"`
	Fuzzy  bool   `json:"fuzzy,omitempty"`
	Quiet  bool   `json:"quiet,omitempty"`

	// Request
	Method     string   `json:"method,omitempty"`
	Headers    []string `json:"headers,omitempty"`
	UserAgent  string   `json:"userAgent,omitempty"`
	Cookie     []string `json:"cookie,omitempty"`
	Timeout    int      `json:"timeout,omitempty"`
	MaxBodyLen int64    `json:"maxBodyLen,omitempty"`

	// Mode
	Mod         string `json:"mod,omitempty"`
	Depth       int    `json:"depth,omitempty"`
	Recursive   string `json:"recursive,omitempty"`
	RateLimit   int    `json:"rateLimit,omitempty"`
	Unique      bool   `json:"unique,omitempty"`
	BlackStatus string `json:"blackStatus,omitempty"`
	WhiteStatus string `json:"whiteStatus,omitempty"`

	// Misc
	Client  string   `json:"client,omitempty"`
	CFPrint string   `json:"cfPrint,omitempty"`
	Pool    int      `json:"pool,omitempty"`
	Thread  int      `json:"thread,omitempty"`
	Proxies []string `json:"proxies,omitempty"`

	// Check-only (no dict/word/rule) → RunWithCheck
	CheckOnly bool `json:"checkOnly,omitempty"`

	// User-Agent rotation: when true, spray picks a random UA from the loaded
	// pool (UA.txt) per request. When false, spray's default UA is used.
	RandomAgent bool `json:"randomAgent,omitempty"`

	// RuleFilter is the hashcat-style filter rule (e.g. ">8" to keep only
	// words longer than 8 chars) applied to dictionary entries.
	RuleFilter string `json:"ruleFilter,omitempty"`

	// Internal-IP bypass: when true, each request gets a random private IPv4
	// in X-Forwarded-For / X-Real-IP / X-Originating-IP etc. headers, to
	// bypass naive SSRF allow-lists. Mirrors OneScan's {{random.local-ip}}.
	RandomLocalIP bool `json:"randomLocalIP,omitempty"`
}

// toArgs converts the GUI request into spray CLI args.
func (r scanRequest) toArgs() []string {
	var args []string

	// input
	for _, u := range r.URLs {
		args = append(args, "-u", u)
	}
	if r.URLFile != "" {
		args = append(args, "-l", r.URLFile)
	}
	for _, c := range r.CIDRs {
		args = append(args, "-i", c)
	}

	// dictionary / word / rules
	for _, d := range r.Dictionaries {
		args = append(args, "-d", d)
	}
	if r.Word != "" {
		args = append(args, "-w", r.Word)
	}
	for _, rl := range r.Rules {
		args = append(args, "-r", rl)
	}
	if r.RuleFilter != "" {
		args = append(args, "--rule-filter", r.RuleFilter)
	}
	if r.DefaultDict {
		args = append(args, "-D")
	}

	// functions
	if r.Extensions != "" {
		args = append(args, "-e", r.Extensions)
	}
	if r.ForceExtension {
		args = append(args, "--force-extension")
	}
	if r.Uppercase {
		args = append(args, "-U")
	}
	if r.Lowercase {
		args = append(args, "-L")
	}

	// plugins
	if r.Advance {
		args = append(args, "-a")
	} else {
		if r.Finger {
			args = append(args, "--finger")
		}
		if r.Bak {
			args = append(args, "--bak")
		}
		if r.Common {
			args = append(args, "--common")
		}
		if r.Crawl {
			args = append(args, "--crawl")
		}
		if r.Active {
			args = append(args, "--active")
		}
		if r.Recon {
			args = append(args, "--recon")
		}
		if r.Keys {
			args = append(args, "--keys")
		}
		if r.Poc {
			args = append(args, "--poc")
		}
		if r.Fuzzuli {
			args = append(args, "--fuzzuli")
		}
	}

	// output
	if r.Match != "" {
		args = append(args, "--match", r.Match)
	}
	if r.Filter != "" {
		args = append(args, "--filter", r.Filter)
	}
	if r.Fuzzy {
		args = append(args, "--fuzzy")
	}
	// quiet + no-color + no-bar: we drive the UI ourselves
	args = append(args, "-q", "--no-color", "--no-bar", "--no-stat")

	// request
	if r.Method != "" {
		args = append(args, "-X", r.Method)
	}
	for _, h := range r.Headers {
		args = append(args, "-H", h)
	}
	// User-Agent: enable spray's random UA rotation only when the user opts in.
	if r.RandomAgent {
		args = append(args, "--random-agent")
	}
	// Internal-IP bypass: inject random private IP into XFF and friends.
	if r.RandomLocalIP {
		args = append(args, "--random-local-ip")
	}
	for _, c := range r.Cookie {
		args = append(args, "--cookie", c)
	}
	// Clamp numeric params to safe ranges (mirrors the frontend constraints).
	timeout := clampInt(r.Timeout, 1, 60, 5)
	args = append(args, "-T", fmt.Sprintf("%d", timeout))
	if r.MaxBodyLen != 0 {
		args = append(args, "--max-length", fmt.Sprintf("%d", r.MaxBodyLen))
	}

	// mode
	if r.Mod != "" {
		args = append(args, "-m", r.Mod)
	}
	depth := clampInt(r.Depth, 0, 10, 0)
	if depth > 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", depth))
	}
	if r.Recursive != "" {
		args = append(args, "--recursive", r.Recursive)
	}
	rateLimit := clampInt(r.RateLimit, 0, 10000, 0)
	if rateLimit > 0 {
		args = append(args, "--rate-limit", fmt.Sprintf("%d", rateLimit))
	}
	if r.Unique {
		args = append(args, "--unique")
	}
	if r.BlackStatus != "" {
		args = append(args, "-B", r.BlackStatus)
	}
	if r.WhiteStatus != "" {
		args = append(args, "-W", r.WhiteStatus)
	}

	// misc
	// When a proxy (e.g. Burp) is set, spray's fast/standard clients (uTLS +
	// HTTP/2) are incompatible with the proxy's MITM and fail with
	// "tls: user canceled" / "malformed HTTP version". Force the req client
	// (imroc/req v3), which works through HTTP proxies over HTTP/1.1.
	client := r.Client
	if len(r.Proxies) > 0 {
		client = "req"
	}
	if client != "" {
		args = append(args, "-C", client)
	}
	if r.CFPrint != "" && len(r.Proxies) == 0 {
		// client TLS fingerprint only meaningful without a proxy
		args = append(args, "--client-fingerprint", r.CFPrint)
	}
	pool := clampInt(r.Pool, 1, 100, 5)
	args = append(args, "-P", fmt.Sprintf("%d", pool))
	thread := clampInt(r.Thread, 1, 1000, 20)
	args = append(args, "-t", fmt.Sprintf("%d", thread))
	for _, p := range r.Proxies {
		args = append(args, "--proxy", p)
	}

	return args
}

// handleScan starts a new scan. Only one scan may run at a time.
func handleScan(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var r scanRequest
	if err := json.NewDecoder(req.Body).Decode(&r); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}

	curMu.Lock()
	if cur != nil {
		// is it still running?
		select {
		case <-cur.done:
			// finished; allow overwrite so a new scan can start
		default:
			curMu.Unlock()
			http.Error(w, "a scan is already running; stop it first", http.StatusConflict)
			return
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &session{
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
		subCh:     make(chan event, 1024),
		resultC:   make(chan event, 1024),
		startedAt: time.Now(),
		args:      r.toArgs(),
	}
	cur = s
	curMu.Unlock()

	// suppress spray's own console output; we render in the browser.
	logs.Log.SetQuiet(true)
	logs.Log.SetColor(false)

	go func() {
		defer s.doneOnce.Do(func() { close(s.done) })
		err := core.RunWithArgs(s.ctx, s.args, core.RunOptions{
			Version: "webgui",
			OnResult: func(res *parsers.SprayResult) {
				if res == nil {
					return
				}
				src := "?"
				if res.Source != 0 {
					src = fmt.Sprintf("%v", res.Source)
				}
				log.Printf("[onresult] url=%s status=%d source=%s", res.UrlString, res.Status, src)
				select {
				case s.resultC <- event{Type: "result", Data: res}:
				case <-s.ctx.Done():
				default:
				}
			},
		})
		if err != nil {
			log.Printf("[scan] RunWithArgs error: %v", err)
			select {
			case s.resultC <- event{Type: "error", Data: map[string]string{"message": err.Error()}}:
			default:
			}
		}
	}()

	// forward results to subscribers, then signal done and clean up session.
	go func() {
		for ev := range s.resultC {
			s.subCh <- ev
		}
		doneEv := event{Type: "done", Data: map[string]int64{"elapsedMs": time.Since(s.startedAt).Milliseconds()}}
		s.subCh <- doneEv
		// cache the terminal event so late SSE clients get a proper close.
		s.finMu.Lock()
		s.finish = doneEv
		s.finMu.Unlock()
		// NOTE: keep cur pointing at s so reconnecting SSE clients can replay.
		// The next handleScan sees s.done closed and overwrites cur.
		// subCh stays open; readers drain to zero and return on ok=false.
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":   true,
		"args": s.args,
	})
}

// handleStop cancels the running scan.
func handleStop(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	curMu.Lock()
	s := cur
	curMu.Unlock()
	if s == nil {
		log.Printf("[stop] no scan running")
		http.Error(w, "no scan running", http.StatusBadRequest)
		return
	}
	log.Printf("[stop] cancelling scan ctx, args=%v", s.args)
	s.cancel()
	// allow a new scan to start immediately: signal done so handleScan's
	// running-check passes. The forward goroutine still sets s.finish for
	// any reconnecting SSE client once RunWithArgs actually returns.
	go func() {
		// small grace period so in-flight results can flush
		time.Sleep(500 * time.Millisecond)
		s.doneOnce.Do(func() { close(s.done) })
	}()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// handleEvents is the SSE endpoint.
func handleEvents(w http.ResponseWriter, req *http.Request) {
	curMu.Lock()
	s := cur
	curMu.Unlock()
	if s == nil {
		http.Error(w, "no scan running", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// signal: started
	fmt.Fprintf(w, "event: started\ndata: %s\n\n", mustJSON(map[string]interface{}{"args": s.args, "time": s.startedAt.Unix()}))
	flusher.Flush()

	// if the scan already finished, replay any buffered results + done, then close.
	s.finMu.Lock()
	finished := s.finish
	s.finMu.Unlock()

	for {
		// If the scan already finished before we connected, replay done now.
		if finished.Type != "" {
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", finished.Type, mustJSON(finished.Data))
			flusher.Flush()
			return
		}

		select {
		case ev, ok := <-s.subCh:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, mustJSON(ev.Data))
			flusher.Flush()
		case <-req.Context().Done():
			return
		case <-s.done:
			// scan finished: drain remaining buffered events.
			drained := false
			for !drained {
				select {
				case ev, ok := <-s.subCh:
					if !ok {
						drained = true
						break
					}
					fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, mustJSON(ev.Data))
					flusher.Flush()
				default:
					drained = true
				}
			}
			// replay the terminal done event so the client closes cleanly.
			s.finMu.Lock()
			fin := s.finish
			s.finMu.Unlock()
			if fin.Type == "" {
				fin = event{Type: "done", Data: map[string]int64{"elapsedMs": time.Since(s.startedAt).Milliseconds()}}
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", fin.Type, mustJSON(fin.Data))
			flusher.Flush()
			return
		}
	}
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// clampInt clamps v into [min,max], returning d when v<=0 (unset).
func clampInt(v, min, max, d int) int {
	if v <= 0 {
		return d
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// handleUpload receives a dictionary file and saves it under uploads/.
// Returns the absolute path the frontend should pass to spray via -d.
func handleUpload(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 32MB cap
	if err := req.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	f, header, err := req.FormFile("file")
	if err != nil {
		http.Error(w, "no file field: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer f.Close()

	// sanitize filename, keep it simple
	name := filepath.Base(header.Filename)
	if name == "" || name == "." || name == "/" {
		name = "upload.txt"
	}
	uploadsDir := resolveUploadsDir()
	if err := os.MkdirAll(uploadsDir, 0o755); err != nil {
		http.Error(w, "mkdir: "+err.Error(), http.StatusInternalServerError)
		return
	}
	dst := filepath.Join(uploadsDir, name)
	out, err := os.Create(dst)
	if err != nil {
		http.Error(w, "create: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := copyFile(out, f); err != nil {
		out.Close()
		http.Error(w, "write: "+err.Error(), http.StatusInternalServerError)
		return
	}
	out.Close()
	abs, _ := filepath.Abs(dst)
	log.Printf("[upload] saved %s (%d bytes) -> %s", name, header.Size, abs)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"path": abs, "name": name})
}

// resolveUploadsDir picks a stable uploads dir next to the binary or cwd.
func resolveUploadsDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "uploads")
	}
	return "uploads"
}

func copyFile(dst io.Writer, src io.Reader) (int64, error) {
	return io.Copy(dst, src)
}

func resolveStaticDir() string {
	// 1. ./static relative to cwd
	if _, err := os.Stat("static"); err == nil {
		return "static"
	}
	// 2. <executable dir>/static
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "static")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// fall back; file server will 404 but server still runs
	return "static"
}

// handleUAs returns the loaded User-Agent pool (from UA.txt).
func handleUAs(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count": len(modernUserAgents),
		"uas":   modernUserAgents,
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/scan", handleScan)
	mux.HandleFunc("/api/stop", handleStop)
	mux.HandleFunc("/api/events", handleEvents)
	mux.HandleFunc("/api/upload", handleUpload)
	mux.HandleFunc("/api/uas", handleUAs)
	mux.Handle("/", http.FileServer(http.Dir(resolveStaticDir())))

	// port: default 888. 8080 is reserved for Burp and hard-blocked.
	addr := os.Getenv("PORT")
	if addr == "" {
		addr = "888"
	}
	if !strings.HasPrefix(addr, ":") {
		addr = ":" + addr
	}
	if addr == ":8080" {
		log.Fatal("port 8080 is reserved for Burp; set PORT=888 or another port")
	}
	log.Printf("spray webgui on http://localhost%s (static: %s)", addr, resolveStaticDir())
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
