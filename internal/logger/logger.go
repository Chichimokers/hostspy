package logger

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxBodyLog = 2 << 20 // 2 MiB per body

// sensitiveHeaders are never written verbatim: a shared log must not leak
// session state.
var sensitiveHeaders = map[string]struct{}{
	"Authorization":       {},
	"Proxy-Authorization": {},
	"Cookie":              {},
	"Set-Cookie":          {},
	"X-Auth-Token":        {},
	"X-Api-Key":           {},
	"X-Csrf-Token":        {},
	"X-Xsrf-Token":        {},
}

// sensitiveParams are query parameters whose values are redacted while keeping
// every other parameter (and the raw order/encoding) intact.
var sensitiveParams = map[string]struct{}{
	"access_token":  {},
	"id_token":      {},
	"refresh_token": {},
	"token":         {},
	"code":          {},
	"ticket":        {},
	"key":           {},
	"api_key":       {},
	"apikey":        {},
	"secret":        {},
	"password":      {},
	"pass":          {},
	"session":       {},
	"sessionid":     {},
	"sig":           {},
	"signature":     {},
}

type Logger struct {
	dir     string
	save    bool
	redact  bool
	mu      sync.Mutex
	counter atomic.Uint64
}

func New(dir string, saveBodies, redact bool) *Logger {
	_ = os.MkdirAll(dir, 0755)
	return &Logger{dir: dir, save: saveBodies, redact: redact}
}

// Redact hides token-like query values according to the logger configuration.
func (l *Logger) Redact(uri string) string {
	return redactQuery(uri, l.redact)
}

func (l *Logger) Printf(format string, args ...any) {
	line := fmt.Sprintf("[%s] ", time.Now().Format("15:04:05.000")) + fmt.Sprintf(format, args...)
	fmt.Println(line)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.append(filepath.Join(l.dir, "hostspy.log"), line+"\n")
}

// Record is one HTTP transaction as seen by the proxy. Request is what the
// client sent, before any change; Upstream is what hostspy actually sent after
// the transport-only rewrites. Body fields hold what was captured for the log
// (possibly decoded), never the bytes that were dropped on the wire.
type Record struct {
	Request                *http.Request
	Upstream               *http.Request
	Status                 int
	ResponseHeader         http.Header
	RequestRemovedHeaders  []string
	ResponseRemovedHeaders []string
	RequestBytes           int64 // -1 when the request body was streamed
	ResponseBytes          int64
	RequestBody            []byte
	ResponseBody           []byte
	RequestTruncated       bool
	ResponseTruncated      bool
	RequestDecoded         bool
	ResponseDecoded        bool
	Duration               time.Duration
}

// Exchange records one HTTP transaction: a one-line summary on the console and
// the full client/upstream/response comparison in the body log.
func (l *Logger) Exchange(rec Record) {
	req := rec.Request
	if req == nil {
		return
	}
	id := l.counter.Add(1)
	host := req.Host
	path := redactQuery(req.URL.RequestURI(), l.redact)
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}

	sum := fmt.Sprintf("%s %s%s -> %d  (%s in, %d B out, %s)",
		method, host, path, rec.Status, formatBytes(rec.RequestBytes), rec.ResponseBytes, rec.Duration.Round(time.Millisecond))
	l.Printf("%s", sum)

	if !l.save {
		return
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s%s\n", method, host, path)
	fmt.Fprintf(&sb, "Upstream: %s\n", upstreamTarget(rec.Upstream, l.redact))
	fmt.Fprintf(&sb, "Status: %d\n", rec.Status)
	fmt.Fprintf(&sb, "Duration: %s\n", rec.Duration.Round(time.Millisecond))
	if l.redact {
		sb.WriteString("Secrets: Authorization/Cookie/Set-Cookie headers and token-like query values are redacted below.\n")
	}

	sb.WriteString("\n--- 1. CLIENT REQUEST (as received) ---\n")
	writeRequest(&sb, req, rec.RequestBody, rec.RequestTruncated, rec.RequestDecoded, l.redact)

	sb.WriteString("\n--- 2. CHANGES MADE FOR TRANSPORT ---\n")
	writeChanges(&sb, req, rec.Upstream, rec.RequestRemovedHeaders, rec.ResponseRemovedHeaders)

	sb.WriteString("\n--- 3. UPSTREAM REQUEST (as sent) ---\n")
	if rec.Upstream != nil {
		writeRequest(&sb, rec.Upstream, rec.RequestBody, rec.RequestTruncated, rec.RequestDecoded, l.redact)
	} else {
		sb.WriteString("(not available)\n")
	}

	sb.WriteString("\n--- 4. UPSTREAM RESPONSE (as received) ---\n")
	fmt.Fprintf(&sb, "Status: %d\n", rec.Status)
	writeHeaders(&sb, rec.ResponseHeader, l.redact)
	sb.WriteString("\nBody:\n")
	sb.WriteString(fmtBody(rec.ResponseBody, rec.ResponseTruncated, rec.ResponseDecoded))

	sb.WriteString("\n--- 5. DELIVERED TO CLIENT ---\n")
	fmt.Fprintf(&sb, "Status: %d\n", rec.Status)
	sb.WriteString("Body: identical bytes to the upstream response above")
	if rec.ResponseHeader != nil {
		if enc := rec.ResponseHeader.Get("Content-Encoding"); enc != "" {
			fmt.Fprintf(&sb, " (Content-Encoding: %s preserved)", enc)
		}
	}
	sb.WriteString(".\n")
	if len(rec.ResponseRemovedHeaders) > 0 {
		fmt.Fprintf(&sb, "Headers removed (hop-by-hop, not part of the message): %s\n",
			strings.Join(rec.ResponseRemovedHeaders, ", "))
	}
	sb.WriteString("\n")

	day := filepath.Join(l.dir, time.Now().Format("2006-01-02"))
	_ = os.MkdirAll(day, 0755)
	name := fmt.Sprintf("%03d_%s_%s_%s.txt", id, time.Now().Format("150405.000"), sanitize(host), sanitize(path))
	l.writeFile(filepath.Join(day, name), sb.String())
}

func formatBytes(total int64) string {
	if total < 0 {
		return "streamed"
	}
	return fmt.Sprintf("%d B", total)
}

func upstreamTarget(u *http.Request, redact bool) string {
	if u == nil || u.URL == nil {
		return "(not available)"
	}
	scheme := u.URL.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + u.URL.Host + redactQuery(u.URL.RequestURI(), redact)
}

func writeRequest(sb *strings.Builder, req *http.Request, body []byte, truncated, decoded, redact bool) {
	path := redactQuery(req.URL.RequestURI(), redact)
	if path == "" {
		path = "/"
	}
	proto := req.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	fmt.Fprintf(sb, "%s %s %s\n", req.Method, path, proto)
	if req.Host != "" {
		fmt.Fprintf(sb, "Host: %s\n", req.Host)
	}
	writeHeaders(sb, req.Header, redact)
	sb.WriteString("\nBody:\n")
	sb.WriteString(fmtBody(body, truncated, decoded))
}

func writeChanges(sb *strings.Builder, client, upstream *http.Request, reqRemoved, respRemoved []string) {
	changed := false
	if client != nil && upstream != nil && client.Host != upstream.Host {
		fmt.Fprintf(sb, "Host: %q -> %q (upstream virtual host)\n", client.Host, upstream.Host)
		changed = true
	}
	if len(reqRemoved) > 0 {
		fmt.Fprintf(sb, "Request headers removed (hop-by-hop): %s\n", strings.Join(reqRemoved, ", "))
		changed = true
	}
	if len(respRemoved) > 0 {
		fmt.Fprintf(sb, "Response headers removed (hop-by-hop): %s\n", strings.Join(respRemoved, ", "))
		changed = true
	}
	if !changed {
		sb.WriteString("(none: the client request was forwarded verbatim)\n")
	}
}

func (l *Logger) WebSocketFrame(host, path, dir string, opcode byte, payload []byte, compressed bool) {
	path = l.Redact(path)
	kind := map[byte]string{0: "cont", 1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong"}[opcode]
	if kind == "" {
		kind = fmt.Sprintf("op%d", opcode)
	}
	switch {
	case compressed && (opcode == 0 || opcode == 1 || opcode == 2):
		l.Printf("WS %s %s%s [%s] %d bytes (permessage-deflate, not decoded)", dir, host, path, kind, len(payload))
	case opcode == 1 || opcode == 0:
		l.Printf("WS %s %s%s [%s] %s", dir, host, path, kind, strings.TrimSpace(string(payload)))
	default:
		l.Printf("WS %s %s%s [%s] %d bytes", dir, host, path, kind, len(payload))
	}
	if !l.save {
		return
	}
	day := filepath.Join(l.dir, time.Now().Format("2006-01-02"))
	_ = os.MkdirAll(day, 0755)
	f := filepath.Join(day, "websocket.log")
	var entry string
	if compressed && (opcode == 0 || opcode == 1 || opcode == 2) {
		entry = fmt.Sprintf("[%s] %s %s%s [%s] permessage-deflate frame, %d bytes (forwarded unchanged)\n\n",
			time.Now().Format("15:04:05.000"), dir, host, path, kind, len(payload))
	} else {
		entry = fmt.Sprintf("[%s] %s %s%s [%s]\n%s\n\n",
			time.Now().Format("15:04:05.000"), dir, host, path, kind, payload)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.append(f, entry)
}

func (l *Logger) writeFile(p, content string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = os.WriteFile(p, []byte(content), 0644)
}

func (l *Logger) append(p, line string) {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}

func writeHeaders(sb *strings.Builder, h http.Header, redact bool) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, secret := sensitiveHeaders[http.CanonicalHeaderKey(k)]; secret && redact {
			for _, v := range h[k] {
				fmt.Fprintf(sb, "%s: %s\n", k, redactHeaderValue(v))
			}
			continue
		}
		for _, v := range h[k] {
			fmt.Fprintf(sb, "%s: %s\n", k, v)
		}
	}
}

// redactHeaderValue keeps the auth scheme (so the log shows "Bearer ...") but
// hides the credential itself.
func redactHeaderValue(v string) string {
	if scheme, _, ok := strings.Cut(v, " "); ok && len(scheme) <= 20 && !strings.ContainsAny(scheme, "=;,") {
		return scheme + " <redacted>"
	}
	return "<redacted>"
}

// redactQuery hides the values of sensitive query parameters while preserving
// the order, the raw encoding and every other parameter byte for byte.
func redactQuery(raw string, redact bool) string {
	if !redact || raw == "" {
		return raw
	}
	prefix, query := "", raw
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		prefix, query = raw[:i+1], raw[i+1:]
	}
	if query == "" {
		return raw
	}
	parts := strings.Split(query, "&")
	changed := false
	for i, part := range parts {
		name, value, ok := strings.Cut(part, "=")
		if !ok || value == "" {
			continue
		}
		decoded, err := url.QueryUnescape(name)
		if err != nil {
			decoded = name
		}
		if _, secret := sensitiveParams[strings.ToLower(decoded)]; !secret {
			continue
		}
		parts[i] = name + "=<redacted>"
		changed = true
	}
	if !changed {
		return raw
	}
	return prefix + strings.Join(parts, "&")
}

func fmtBody(b []byte, truncated, decoded bool) string {
	if len(b) == 0 {
		if truncated {
			return "(not captured)\n"
		}
		return "(empty)\n"
	}
	if len(b) > maxBodyLog {
		b = b[:maxBodyLog]
		truncated = true
	}
	printable := true
	for _, c := range b {
		if c < 0x09 || (c > 0x0d && c < 0x20) {
			printable = false
			break
		}
	}
	var out string
	if printable {
		out = string(b)
		if !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
	} else {
		// A full hex dump of several MiB would make the log useless (and huge).
		const maxHex = 4096
		shown := b
		if len(shown) > maxHex {
			shown = shown[:maxHex]
		}
		out = fmt.Sprintf("(binary, %d bytes captured)\n%x\n", len(b), shown)
		if len(shown) < len(b) {
			out += fmt.Sprintf("... (hex dump limited to the first %d bytes)\n", maxHex)
		}
	}
	if decoded {
		out = "(decoded from Content-Encoding for this log only; the wire bytes were the compressed original)\n" + out
	}
	if truncated {
		out += fmt.Sprintf("... (log capture truncated at %d bytes; the client received every byte)\n", len(b))
	}
	return out
}

func sanitize(s string) string {
	// Replace everything Windows forbids in a file name, plus the separators of
	// the request line. A redacted query contains "<redacted>", so angle
	// brackets must go too or the log file cannot be created.
	r := strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_", "?", "_", "&", "_", "=", "_",
		"*", "_", " ", "_", "<", "_", ">", "_", "|", "_", "\"", "_",
	)
	s = r.Replace(s)
	if len(s) > 80 {
		s = s[:80]
	}
	return strings.Trim(s, "_.")
}
