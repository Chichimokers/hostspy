package logger

import (
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Chichimokers/hostspy/internal/decoder"
)

// TCPSessionRecord describes one proxied TCP connection. Protocol is "tls" for
// a terminated TLS session or "plaintext" for an explicitly configured raw TCP
// passthrough. ClientTLS and UpstreamTLS are human-readable descriptions of the
// negotiated TLS parameters ("none" when the side is not TLS).
type TCPSessionRecord struct {
	ID           uint64
	Protocol     string
	Host         string
	Port         int
	ListenAddr   string
	ClientAddr   string
	UpstreamAddr string
	ClientTLS    string
	UpstreamTLS  string
	LogData      bool
	LogHex       bool
	MaxBytes     int64
	Started      time.Time

	// DecodeData enables the optional decoded sidecar. It is only honoured
	// together with LogData and LogHex: the sidecar is a best-effort
	// interpretation of the same bytes the raw log records.
	DecodeData         bool
	DecodedMaxDepth    int
	DecodedIncludeHex  bool
	DecodedChunkEvents bool
}

// TCPSession writes the decrypted application bytes of one TCP connection to a
// dedicated log file. TCP is a byte stream: every block it writes corresponds
// to one socket read, never to a complete application message.
type TCPSession struct {
	l    *Logger
	rec  TCPSessionRecord
	path string
	file *os.File

	decodedPath string
	decodedFile *os.File
	dec         *decoder.Session

	mu       sync.Mutex
	closed   bool
	sent     int64
	recv     int64
	skippedU int64
	skippedD int64
}

// OpenTCP creates the per-connection log. When LogData is false only the
// console summary is produced and no file is written.
func (l *Logger) OpenTCP(rec TCPSessionRecord) *TCPSession {
	if rec.Started.IsZero() {
		rec.Started = time.Now()
	}
	if rec.Protocol == "" {
		rec.Protocol = "tls"
	}
	if rec.MaxBytes == 0 {
		rec.MaxBytes = 64 << 10
	}
	if rec.MaxBytes < 0 {
		rec.MaxBytes = math.MaxInt64
	}
	s := &TCPSession{l: l, rec: rec}
	if !rec.LogData {
		return s
	}
	day := filepath.Join(l.dir, rec.Started.Format("2006-01-02"))
	if err := os.MkdirAll(day, 0755); err != nil {
		l.Printf("WARN cannot create TCP log directory %s: %v", day, err)
		return s
	}
	name := fmt.Sprintf("tcp_%03d_%s_%s_%d.log",
		rec.ID, rec.Started.Format("150405.000"), sanitize(rec.Host), rec.Port)
	s.path = filepath.Join(day, name)
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		l.Printf("WARN cannot create TCP log %s: %v", s.path, err)
		return s
	}
	s.file = f

	var b strings.Builder
	fmt.Fprintf(&b, "Host: %s\n", rec.Host)
	fmt.Fprintf(&b, "Protocol: %s\n", rec.Protocol)
	fmt.Fprintf(&b, "Listener: %s\n", rec.ListenAddr)
	fmt.Fprintf(&b, "Client: %s\n", rec.ClientAddr)
	fmt.Fprintf(&b, "Upstream: %s\n", rec.UpstreamAddr)
	fmt.Fprintf(&b, "Client TLS: %s\n", rec.ClientTLS)
	fmt.Fprintf(&b, "Upstream TLS: %s\n", rec.UpstreamTLS)
	fmt.Fprintf(&b, "Started: %s\n", rec.Started.Format(time.RFC3339Nano))
	b.WriteString("Note: TCP is a byte stream. Each block is one socket read, not an application message.\n")
	if l.redact {
		b.WriteString("Note: decrypted application bytes are recorded verbatim; HTTP header/query redaction does not apply to this file.\n")
	}
	if rec.MaxBytes > 0 && rec.MaxBytes != math.MaxInt64 {
		fmt.Fprintf(&b, "Log cap: %d bytes per direction.\n", rec.MaxBytes)
	} else {
		b.WriteString("Log cap: unlimited per direction.\n")
	}
	b.WriteString("\n")
	if _, err := f.WriteString(b.String()); err != nil {
		l.Printf("WARN write TCP log header %s: %v", s.path, err)
	}
	l.Printf("%s[%d] log: %s", strings.ToUpper(rec.Protocol), rec.ID, s.path)

	if rec.DecodeData {
		switch {
		case !rec.LogHex:
			l.Printf("WARN %s[%d] decoded sidecar disabled: decodeApplicationData requires logHex=true",
				strings.ToUpper(rec.Protocol), rec.ID)
		default:
			s.openDecoded()
		}
	}
	return s
}

// openDecoded creates the optional .decoded.txt sidecar next to the raw log.
// The raw log is still authoritative: the decoder only sees the bytes that the
// raw log actually recorded.
func (s *TCPSession) openDecoded() {
	base := strings.TrimSuffix(s.path, ".log")
	s.decodedPath = base + ".decoded.txt"
	f, err := os.OpenFile(s.decodedPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		s.l.Printf("WARN cannot create decoded log %s: %v", s.decodedPath, err)
		s.decodedPath = ""
		return
	}
	s.decodedFile = f
	s.dec = decoder.NewSession(f, decoder.Meta{
		Host:         s.rec.Host,
		Protocol:     s.rec.Protocol,
		ListenAddr:   s.rec.ListenAddr,
		ClientAddr:   s.rec.ClientAddr,
		UpstreamAddr: s.rec.UpstreamAddr,
		ClientTLS:    s.rec.ClientTLS,
		UpstreamTLS:  s.rec.UpstreamTLS,
		Started:      s.rec.Started,
	}, decoder.Options{
		MaxDepth:    s.rec.DecodedMaxDepth,
		IncludeHex:  s.rec.DecodedIncludeHex,
		ChunkEvents: s.rec.DecodedChunkEvents,
	})
	s.l.Printf("%s[%d] decoded: %s", strings.ToUpper(s.rec.Protocol), s.rec.ID, s.decodedPath)
}

// Path returns the log file path, or "" when no file is written.
func (s *TCPSession) Path() string { return s.path }

// DecodedPath returns the decoded sidecar path, or "" when it was not created.
func (s *TCPSession) DecodedPath() string { return s.decodedPath }

// Data records one read block. direction is "client->upstream" or
// "upstream->client". Bytes are always forwarded by the caller; this only
// bounds how much is written to disk.
func (s *TCPSession) Data(direction string, data []byte) {
	if len(data) == 0 {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil || s.closed {
		return
	}
	up := strings.HasPrefix(direction, "client")
	logged := &s.recv
	skipped := &s.skippedD
	if up {
		logged = &s.sent
		skipped = &s.skippedU
	}
	remaining := s.rec.MaxBytes - *logged
	if remaining <= 0 {
		*skipped += int64(len(data))
		if s.dec != nil {
			s.dec.Skip(direction, len(data), now)
		}
		return
	}
	chunk := data
	var over int64
	if int64(len(chunk)) > remaining {
		over = int64(len(chunk)) - remaining
		chunk = chunk[:remaining]
	}
	*logged += int64(len(chunk))
	*skipped += over

	fmt.Fprintf(s.file, "[%s] %s %d bytes", now.Format("15:04:05.000"), direction, len(data))
	if over > 0 {
		fmt.Fprintf(s.file, " (only the first %d bytes are logged)", len(chunk))
	}
	s.file.WriteString("\n")
	if preview, ok := textPreview(chunk); ok {
		fmt.Fprintf(s.file, "text: %s\n", preview)
	}
	if s.rec.LogHex {
		writeHex(s.file, chunk)
	}
	s.file.WriteString("\n")

	if s.dec != nil {
		s.dec.Data(direction, chunk, now, over > 0)
	}
}

// Close writes the final summary and closes the files.
func (s *TCPSession) Close(summary string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.dec != nil {
		s.dec.Close(summary)
		s.dec = nil
	}
	if s.decodedFile != nil {
		_ = s.decodedFile.Close()
		s.decodedFile = nil
	}
	if s.file == nil {
		return
	}
	fmt.Fprintf(s.file, "Closed: %s\n", summary)
	if s.skippedU > 0 {
		fmt.Fprintf(s.file, "Not logged (client->upstream cap): %d bytes\n", s.skippedU)
	}
	if s.skippedD > 0 {
		fmt.Fprintf(s.file, "Not logged (upstream->client cap): %d bytes\n", s.skippedD)
	}
	_ = s.file.Close()
}

// writeHex prints offset + hex only. There is deliberately no ASCII column:
// application data may be binary and must not be presented as text.
func writeHex(f *os.File, data []byte) {
	for off := 0; off < len(data); off += 16 {
		end := off + 16
		if end > len(data) {
			end = len(data)
		}
		fmt.Fprintf(f, "%08x  ", off)
		for i := off; i < end; i++ {
			fmt.Fprintf(f, "%02x ", data[i])
		}
		f.WriteString("\n")
	}
}

// textPreview returns a quoted, single-line preview only when the block is
// valid UTF-8 without control characters. Binary data gets no text line.
func textPreview(data []byte) (string, bool) {
	if !utf8.Valid(data) {
		return "", false
	}
	for _, r := range string(data) {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	text := string(data)
	if len(text) > 512 {
		text = strings.ToValidUTF8(text[:512], "") + "..."
	}
	return strconv.Quote(text), true
}

// ListenPort extracts the numeric port from a listen address. It is exported
// only through small helpers so callers do not need to duplicate the parsing.
func ListenPort(addr string) int {
	if addr == "" {
		return 0
	}
	if _, p, err := net.SplitHostPort(addr); err == nil {
		n, _ := strconv.Atoi(p)
		return n
	}
	n, _ := strconv.Atoi(strings.TrimPrefix(addr, ":"))
	return n
}
