package decoder

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tsLayout = "15:04:05.000"

	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA
)

var errIncompleteFrame = errors.New("incomplete WebSocket frame")

// Meta is the per-connection information copied from the raw TCP log header.
type Meta struct {
	Host         string
	Protocol     string
	ListenAddr   string
	ClientAddr   string
	UpstreamAddr string
	ClientTLS    string
	UpstreamTLS  string
	Started      time.Time
}

// Options controls the optional decoded sidecar. It is intentionally separate
// from the raw log options: decoding is best-effort and must never affect the
// proxied connection.
type Options struct {
	MaxDepth           int
	IncludeHex         bool
	ChunkEvents        bool
	MaxFrameBytes      int
	MaxMessageBytes    int
	MaxHTTPHeaderBytes int
}

func (o Options) withDefaults() Options {
	if o.MaxDepth <= 0 {
		o.MaxDepth = 12
	}
	if o.MaxFrameBytes <= 0 {
		o.MaxFrameBytes = 16 << 20
	}
	if o.MaxMessageBytes <= 0 {
		o.MaxMessageBytes = 64 << 20
	}
	if o.MaxHTTPHeaderBytes <= 0 {
		o.MaxHTTPHeaderBytes = 64 << 10
	}
	return o
}

// Session turns the decrypted byte stream of one TCP connection into a
// chronological, human-readable sidecar. The raw .log remains the source of
// truth; this file is an interpretation and may be truncated when the raw log
// cap is reached.
type Session struct {
	mu     sync.Mutex
	w      *bufio.Writer
	meta   Meta
	opts   Options
	client *wsStream
	server *wsStream
	seq    int
	closed bool
	failed bool
}

func NewSession(w io.Writer, meta Meta, opts Options) *Session {
	opts = opts.withDefaults()
	if meta.Started.IsZero() {
		meta.Started = time.Now()
	}
	s := &Session{
		w:    bufio.NewWriterSize(w, 64<<10),
		meta: meta,
		opts: opts,
	}
	s.client = newWSStream(s, "C->S")
	s.server = newWSStream(s, "S->C")
	s.writeHeader()
	_ = s.w.Flush()
	return s
}

func (s *Session) writeHeader() {
	fmt.Fprintf(s.w, "Host: %s\n", s.meta.Host)
	fmt.Fprintf(s.w, "Protocol: %s\n", s.meta.Protocol)
	fmt.Fprintf(s.w, "Listener: %s\n", s.meta.ListenAddr)
	fmt.Fprintf(s.w, "Client: %s\n", s.meta.ClientAddr)
	fmt.Fprintf(s.w, "Upstream: %s\n", s.meta.UpstreamAddr)
	fmt.Fprintf(s.w, "Client TLS: %s\n", s.meta.ClientTLS)
	fmt.Fprintf(s.w, "Upstream TLS: %s\n", s.meta.UpstreamTLS)
	fmt.Fprintf(s.w, "Started: %s\n", s.meta.Started.Format(time.RFC3339Nano))
	fmt.Fprintln(s.w, "Decoder: HTTP upgrade -> WebSocket frames -> generic protobuf fields")
	fmt.Fprintln(s.w, "Note: the raw .log is the source of truth. This file is a best-effort interpretation.")
	fmt.Fprintln(s.w, "Note: protobuf field names are unknown; only field numbers, wire types and values are shown.")
	fmt.Fprintln(s.w, "Note: this file contains personal data (account IDs, BattleTags, session IDs, keys). Treat it as a secret.")
	fmt.Fprintln(s.w)
}

// Data records one socket read. direction is "client->upstream" or
// "upstream->client". truncated means the raw log cap cut this read, so the
// decoder must stop after processing the visible bytes.
func (s *Session) Data(direction string, data []byte, at time.Time, truncated bool) {
	if len(data) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.failed {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	st := s.stream(direction)
	if st == nil {
		return
	}
	s.seq++
	if s.opts.ChunkEvents {
		fmt.Fprintf(s.w, "[%s] %s chunk #%d %d bytes (stream offset %d)\n",
			at.Format(tsLayout), st.label, s.seq, len(data), st.bytesIn)
		if truncated {
			fmt.Fprintln(s.w, "  raw log cap reached in this read; decoding stops after it")
		}
	}
	st.bytesIn += int64(len(data))
	s.guard(func() { st.Data(data, at, truncated) })
	_ = s.w.Flush()
}

// Skip records bytes that the raw logger did not write. Decoding cannot
// continue after a gap in the byte stream.
func (s *Session) Skip(direction string, n int, at time.Time) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.failed {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	st := s.stream(direction)
	if st == nil {
		return
	}
	st.skipped += int64(n)
	if st.disabled {
		return
	}
	st.disabled = true
	st.reason = "raw log cap reached"
	fmt.Fprintf(s.w, "[%s] %s %d bytes not decoded: %s\n", at.Format(tsLayout), st.label, n, st.reason)
	_ = s.w.Flush()
}

func (s *Session) Close(summary string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.client.Close()
	s.server.Close()
	fmt.Fprintf(s.w, "\nClosed: %s\n", summary)
	fmt.Fprintf(s.w, "Decoder summary: C->S %s; S->C %s\n", s.client.summary(), s.server.summary())
	_ = s.w.Flush()
}

func (s *Session) stream(direction string) *wsStream {
	if strings.HasPrefix(direction, "upstream") {
		return s.server
	}
	if strings.HasPrefix(direction, "client") {
		return s.client
	}
	return nil
}

func (s *Session) guard(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			s.failed = true
			fmt.Fprintf(s.w, "\n[decoder panic] %v\n", r)
		}
	}()
	fn()
}

type streamMode int

const (
	modeHandshake streamMode = iota
	modeWebSocket
	modeRaw
)

type wsStream struct {
	s     *Session
	label string
	mode  streamMode

	httpBuf []byte
	buf     []byte

	bytesIn  int64
	frames   int
	messages int
	skipped  int64
	disabled bool
	reason   string
	lastAt   time.Time

	fragOpcode  byte
	fragPayload []byte
	fragFrames  int
}

func newWSStream(s *Session, label string) *wsStream {
	return &wsStream{s: s, label: label, mode: modeHandshake}
}

func (s *wsStream) Data(data []byte, at time.Time, truncated bool) {
	if s.disabled {
		s.skipped += int64(len(data))
		return
	}
	s.lastAt = at
	switch s.mode {
	case modeHandshake:
		s.httpBuf = append(s.httpBuf, data...)
		if len(s.httpBuf) < 4 {
			break
		}
		if !looksHTTP(s.httpBuf) {
			s.note(at, "not an HTTP/WebSocket handshake; switching to raw mode")
			s.mode = modeRaw
			s.raw(s.httpBuf, at)
			s.httpBuf = nil
			break
		}
		idx := bytes.Index(s.httpBuf, []byte("\r\n\r\n"))
		if idx < 0 {
			if len(s.httpBuf) > s.s.opts.MaxHTTPHeaderBytes {
				s.note(at, "HTTP handshake exceeds %d bytes; switching to raw mode", s.s.opts.MaxHTTPHeaderBytes)
				s.mode = modeRaw
				s.raw(s.httpBuf, at)
				s.httpBuf = nil
			}
			break
		}
		if idx+4 > s.s.opts.MaxHTTPHeaderBytes {
			s.note(at, "HTTP handshake header exceeds %d bytes; switching to raw mode", s.s.opts.MaxHTTPHeaderBytes)
			s.mode = modeRaw
			s.raw(s.httpBuf, at)
			s.httpBuf = nil
			break
		}
		head := append([]byte(nil), s.httpBuf[:idx+4]...)
		rest := append([]byte(nil), s.httpBuf[idx+4:]...)
		s.httpBuf = nil
		ws, err := s.handleHTTP(head, at)
		if err != nil {
			s.note(at, "HTTP handshake parse failed: %v; switching to raw mode", err)
			s.mode = modeRaw
			s.raw(head, at)
			if len(rest) > 0 {
				s.raw(rest, at)
			}
			break
		}
		if !ws {
			s.mode = modeRaw
			if len(rest) > 0 {
				s.raw(rest, at)
			}
			break
		}
		s.mode = modeWebSocket
		if len(rest) > 0 {
			s.consume(rest, at)
		}
	case modeWebSocket:
		s.consume(data, at)
	case modeRaw:
		s.raw(data, at)
	}
	if truncated && !s.disabled {
		s.stop(at, "raw log cap reached; the rest of the stream is not in the raw log")
	}
}

func (s *wsStream) consume(data []byte, at time.Time) {
	if len(data) > 0 {
		s.buf = append(s.buf, data...)
	}
	for !s.disabled {
		if len(s.buf) < 2 {
			return
		}
		fh, err := parseFrameHeader(s.buf)
		if errors.Is(err, errIncompleteFrame) {
			if len(s.buf) > s.s.opts.MaxFrameBytes+14 {
				s.stop(at, "buffered data exceeds frame limit (%d bytes)", len(s.buf))
			}
			return
		}
		if err != nil {
			s.stop(at, "invalid WebSocket frame header: %v", err)
			return
		}
		if fh.payloadLen > uint64(s.s.opts.MaxFrameBytes) {
			s.stop(at, "frame payload %d exceeds limit %d", fh.payloadLen, s.s.opts.MaxFrameBytes)
			return
		}
		total := fh.headerLen + int(fh.payloadLen)
		if total < fh.headerLen || total > len(s.buf) {
			return
		}
		payload := append([]byte(nil), s.buf[fh.headerLen:total]...)
		s.buf = s.buf[total:]
		if fh.masked {
			unmask(payload, fh.maskKey)
		}
		s.logFrame(fh, payload, at)
	}
}

func (s *wsStream) logFrame(fh frameHeader, payload []byte, at time.Time) {
	s.frames++
	fmt.Fprintf(s.s.w, "[%s] %s frame #%d fin=%t rsv1=%t rsv2=%t rsv3=%t opcode=%d (%s) masked=%t payload=%d header=%d",
		at.Format(tsLayout), s.label, s.frames, fh.fin, fh.rsv1, fh.rsv2, fh.rsv3,
		fh.opcode, opcodeName(fh.opcode), fh.masked, len(payload), fh.headerLen)
	if fh.masked {
		fmt.Fprintf(s.s.w, " mask=%02x%02x%02x%02x", fh.maskKey[0], fh.maskKey[1], fh.maskKey[2], fh.maskKey[3])
	}
	fmt.Fprintln(s.s.w)
	if s.label == "S->C" && fh.masked {
		fmt.Fprintln(s.s.w, "  note: server-to-client frame is masked (RFC 6455 violation)")
	}
	if s.label == "C->S" && !fh.masked {
		fmt.Fprintln(s.s.w, "  note: client-to-server frame is not masked (RFC 6455 violation)")
	}
	if fh.rsv1 {
		fmt.Fprintln(s.s.w, "  note: RSV1 set; possible permessage-deflate, not decompressed")
	}
	if fh.rsv2 || fh.rsv3 {
		fmt.Fprintln(s.s.w, "  note: RSV2/RSV3 set; no extension negotiated")
	}

	printFrameHex := s.s.opts.IncludeHex && len(payload) > 0
	if printFrameHex {
		writeHexIndent(s.s.w, payload, "  ", 0)
	}

	switch fh.opcode {
	case wsOpContinuation:
		s.handleContinuation(fh, payload, at)
	case wsOpText, wsOpBinary:
		s.handleData(fh, payload, at)
	case wsOpClose:
		s.logClose(payload)
	case wsOpPing, wsOpPong:
		s.logControlPayload(fh.opcode, payload)
	default:
		fmt.Fprintf(s.s.w, "  note: reserved opcode 0x%x; payload not interpreted\n", fh.opcode)
	}
}

func (s *wsStream) handleData(fh frameHeader, payload []byte, at time.Time) {
	if s.fragOpcode != 0 {
		fmt.Fprintln(s.s.w, "  protocol error: new data frame while a fragmented message is open; dropping previous fragment")
		s.resetFrag()
	}
	if fh.fin {
		s.logMessage(fh.opcode, payload, 1, at)
		return
	}
	s.fragOpcode = fh.opcode
	s.fragPayload = append([]byte(nil), payload...)
	s.fragFrames = 1
}

func (s *wsStream) handleContinuation(fh frameHeader, payload []byte, at time.Time) {
	if s.fragOpcode == 0 {
		fmt.Fprintln(s.s.w, "  protocol error: continuation frame without an open fragmented message")
		return
	}
	s.fragPayload = append(s.fragPayload, payload...)
	s.fragFrames++
	if len(s.fragPayload) > s.s.opts.MaxMessageBytes {
		s.stop(at, "fragmented message exceeds limit %d", s.s.opts.MaxMessageBytes)
		return
	}
	if fh.fin {
		op := s.fragOpcode
		data := s.fragPayload
		n := s.fragFrames
		s.resetFrag()
		s.logMessage(op, data, n, at)
	}
}

func (s *wsStream) logMessage(op byte, payload []byte, frames int, at time.Time) {
	s.messages++
	fmt.Fprintf(s.s.w, "[%s] %s message #%d opcode=%d (%s) frames=%d payload=%d\n",
		at.Format(tsLayout), s.label, s.messages, op, opcodeName(op), frames, len(payload))
	if op == wsOpText {
		s.logText(payload)
		return
	}
	s.decodeBinary(payload)
}

func (s *wsStream) logText(payload []byte) {
	if printableUTF8(payload) {
		fmt.Fprintf(s.s.w, "  text: %s\n", quoteBytes(payload, 64<<10))
		return
	}
	fmt.Fprintln(s.s.w, "  text: invalid UTF-8 or control characters")
	if s.s.opts.IncludeHex {
		writeHexIndent(s.s.w, payload, "  ", 0)
	}
}

func (s *wsStream) decodeBinary(payload []byte) {
	if len(payload) == 0 {
		fmt.Fprintln(s.s.w, "  application payload: empty")
		return
	}
	if header, body, ok := splitLengthPrefixed(payload); ok {
		fmt.Fprintf(s.s.w, "  application framing: 2-byte big-endian length prefix (heuristic); header=%d body=%d\n",
			len(header), len(body))
		s.dumpPB("header", header)
		s.dumpPB("body", body)
		return
	}
	s.dumpPB("protobuf", payload)
}

// splitLengthPrefixed recognizes the BGS RPC shape observed on port 1119:
// [uint16 big-endian header length][protobuf header][protobuf body]. It does
// not know any field names; it only separates the two protobuf messages.
func splitLengthPrefixed(p []byte) (header, body []byte, ok bool) {
	if len(p) < 3 {
		return nil, nil, false
	}
	n := int(binary.BigEndian.Uint16(p[:2]))
	if n <= 0 || 2+n > len(p) {
		return nil, nil, false
	}
	h := p[2 : 2+n]
	b := p[2+n:]
	if !validPbMessage(h) {
		return nil, nil, false
	}
	if len(b) > 0 && !validPbMessage(b) {
		return nil, nil, false
	}
	return h, b, true
}

func (s *wsStream) dumpPB(label string, data []byte) {
	fmt.Fprintf(s.s.w, "  %s (%d bytes):\n", label, len(data))
	if len(data) == 0 {
		fmt.Fprintln(s.s.w, "    (empty)")
		return
	}
	err := DumpProtobuf(s.s.w, data, ProtoOptions{
		MaxDepth: s.s.opts.MaxDepth,
		Indent:   2,
	})
	if err != nil {
		fmt.Fprintf(s.s.w, "    protobuf parse failed: %v\n", err)
		if s.s.opts.IncludeHex {
			writeHexIndent(s.s.w, data, "    ", 0)
		}
	}
}

func (s *wsStream) logClose(payload []byte) {
	if len(payload) == 0 {
		fmt.Fprintln(s.s.w, "  close: no status code")
		return
	}
	if len(payload) == 1 {
		fmt.Fprintln(s.s.w, "  close: invalid payload (1 byte)")
		return
	}
	code := int(binary.BigEndian.Uint16(payload[:2]))
	fmt.Fprintf(s.s.w, "  close: code=%d (%s)", code, closeCodeName(code))
	reason := payload[2:]
	if len(reason) > 0 {
		if printableUTF8(reason) {
			fmt.Fprintf(s.s.w, " reason=%s", quoteBytes(reason, 4096))
		} else {
			fmt.Fprint(s.s.w, " reason=<invalid UTF-8>")
		}
	}
	fmt.Fprintln(s.s.w)
}

func (s *wsStream) logControlPayload(op byte, payload []byte) {
	name := "ping"
	if op == wsOpPong {
		name = "pong"
	}
	fmt.Fprintf(s.s.w, "  %s: payload=%d", name, len(payload))
	if len(payload) > 0 && printableUTF8(payload) {
		fmt.Fprintf(s.s.w, " text=%s", quoteBytes(payload, 4096))
	}
	fmt.Fprintln(s.s.w)
}

func (s *wsStream) raw(data []byte, at time.Time) {
	if len(data) == 0 {
		return
	}
	fmt.Fprintf(s.s.w, "[%s] %s raw %d bytes (no WebSocket framing)\n", at.Format(tsLayout), s.label, len(data))
	if s.s.opts.IncludeHex {
		writeHexIndent(s.s.w, data, "  ", 0)
	}
}

func (s *wsStream) handleHTTP(head []byte, at time.Time) (bool, error) {
	hs, err := parseHTTPHandshake(head)
	if err != nil {
		return false, err
	}
	s.logHTTP(hs, at)
	if !hs.websocket {
		s.note(at, "WebSocket upgrade not detected in HTTP %s; switching to raw mode", hs.kind)
		return false, nil
	}
	return true, nil
}

func (s *wsStream) logHTTP(hs httpHandshake, at time.Time) {
	fmt.Fprintf(s.s.w, "[%s] %s HTTP %s (%d bytes)\n", at.Format(tsLayout), s.label, hs.kind, len(hs.raw))
	if hs.kind == "request" {
		fmt.Fprintf(s.s.w, "  method: %s\n", hs.method)
		fmt.Fprintf(s.s.w, "  target: %s\n", hs.target)
		fmt.Fprintf(s.s.w, "  version: %s\n", hs.version)
	} else {
		fmt.Fprintf(s.s.w, "  version: %s\n", hs.version)
		fmt.Fprintf(s.s.w, "  status: %d\n", hs.status)
		fmt.Fprintf(s.s.w, "  reason: %s\n", hs.reason)
	}
	for _, h := range hs.headers {
		fmt.Fprintf(s.s.w, "  header %s: %s\n", h.name, h.value)
	}
	fmt.Fprintf(s.s.w, "  websocket upgrade: %t\n", hs.websocket)
	fmt.Fprintln(s.s.w, "  raw:")
	for _, line := range strings.Split(strings.TrimSuffix(string(hs.raw), "\r\n\r\n"), "\r\n") {
		fmt.Fprintf(s.s.w, "    %s\n", line)
	}
}

func (s *wsStream) note(at time.Time, format string, args ...any) {
	fmt.Fprintf(s.s.w, "[%s] %s note: %s\n", at.Format(tsLayout), s.label, fmt.Sprintf(format, args...))
}

func (s *wsStream) stop(at time.Time, format string, args ...any) {
	if s.disabled {
		return
	}
	s.disabled = true
	s.reason = fmt.Sprintf(format, args...)
	fmt.Fprintf(s.s.w, "[%s] %s decoder stopped: %s\n", at.Format(tsLayout), s.label, s.reason)
}

func (s *wsStream) Close() {
	at := s.lastAt
	if at.IsZero() {
		at = time.Now()
	}
	if s.mode == modeHandshake && len(s.httpBuf) > 0 {
		s.note(at, "stream ended with %d buffered bytes of an incomplete HTTP handshake", len(s.httpBuf))
		if s.s.opts.IncludeHex {
			writeHexIndent(s.s.w, s.httpBuf, "  ", 0)
		}
	}
	if s.mode == modeWebSocket {
		if len(s.buf) > 0 {
			s.note(at, "stream ended with %d buffered bytes of an incomplete WebSocket frame", len(s.buf))
			if s.s.opts.IncludeHex {
				writeHexIndent(s.s.w, s.buf, "  ", 0)
			}
		}
		if s.fragOpcode != 0 {
			s.note(at, "stream ended with an incomplete fragmented message: opcode=%d (%s), frames=%d, payload=%d",
				s.fragOpcode, opcodeName(s.fragOpcode), s.fragFrames, len(s.fragPayload))
			if s.s.opts.IncludeHex {
				writeHexIndent(s.s.w, s.fragPayload, "  ", 0)
			}
		}
	}
	if s.disabled && s.skipped > 0 {
		s.note(at, "decoder stopped earlier (%s); %d further bytes not decoded", s.reason, s.skipped)
	}
}

func (s *wsStream) resetFrag() {
	s.fragOpcode = 0
	s.fragPayload = nil
	s.fragFrames = 0
}

func (s *wsStream) summary() string {
	out := fmt.Sprintf("%d bytes, %d frames, %d messages", s.bytesIn, s.frames, s.messages)
	if s.skipped > 0 {
		out += fmt.Sprintf(", %d bytes skipped", s.skipped)
	}
	if s.disabled {
		out += fmt.Sprintf(" (stopped: %s)", s.reason)
	}
	return out
}

type frameHeader struct {
	fin        bool
	rsv1       bool
	rsv2       bool
	rsv3       bool
	opcode     byte
	masked     bool
	payloadLen uint64
	headerLen  int
	maskKey    [4]byte
}

func parseFrameHeader(b []byte) (frameHeader, error) {
	var fh frameHeader
	if len(b) < 2 {
		return fh, errIncompleteFrame
	}
	fh.fin = b[0]&0x80 != 0
	fh.rsv1 = b[0]&0x40 != 0
	fh.rsv2 = b[0]&0x20 != 0
	fh.rsv3 = b[0]&0x10 != 0
	fh.opcode = b[0] & 0x0f
	fh.masked = b[1]&0x80 != 0
	length := uint64(b[1] & 0x7f)
	n := 2
	switch length {
	case 126:
		if len(b) < 4 {
			return fh, errIncompleteFrame
		}
		length = uint64(binary.BigEndian.Uint16(b[2:4]))
		n = 4
	case 127:
		if len(b) < 10 {
			return fh, errIncompleteFrame
		}
		length = binary.BigEndian.Uint64(b[2:10])
		n = 10
		if length&(1<<63) != 0 {
			return fh, errors.New("payload length has the most significant bit set")
		}
	}
	if fh.opcode >= 0x8 {
		if !fh.fin {
			return fh, errors.New("control frame is fragmented")
		}
		if length > 125 {
			return fh, fmt.Errorf("control frame payload %d exceeds 125", length)
		}
	}
	if fh.masked {
		if len(b) < n+4 {
			return fh, errIncompleteFrame
		}
		copy(fh.maskKey[:], b[n:n+4])
		n += 4
	}
	fh.payloadLen = length
	fh.headerLen = n
	return fh, nil
}

func unmask(payload []byte, key [4]byte) {
	for i := range payload {
		payload[i] ^= key[i%4]
	}
}

func opcodeName(op byte) string {
	switch op {
	case wsOpContinuation:
		return "continuation"
	case wsOpText:
		return "text"
	case wsOpBinary:
		return "binary"
	case wsOpClose:
		return "close"
	case wsOpPing:
		return "ping"
	case wsOpPong:
		return "pong"
	default:
		return "reserved"
	}
}

func closeCodeName(code int) string {
	switch code {
	case 1000:
		return "normal closure"
	case 1001:
		return "going away"
	case 1002:
		return "protocol error"
	case 1003:
		return "unsupported data"
	case 1005:
		return "no status received"
	case 1006:
		return "abnormal closure"
	case 1007:
		return "invalid payload data"
	case 1008:
		return "policy violation"
	case 1009:
		return "message too big"
	case 1010:
		return "mandatory extension"
	case 1011:
		return "internal error"
	case 1015:
		return "TLS handshake"
	default:
		return "unknown"
	}
}

type httpHeader struct {
	name  string
	value string
}

type httpHandshake struct {
	kind      string
	method    string
	target    string
	version   string
	status    int
	reason    string
	headers   []httpHeader
	websocket bool
	raw       []byte
}

func parseHTTPHandshake(head []byte) (httpHandshake, error) {
	hs := httpHandshake{raw: head}
	text := strings.TrimSuffix(string(head), "\r\n\r\n")
	lines := strings.Split(text, "\r\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return hs, errors.New("empty HTTP handshake")
	}
	first := lines[0]
	if strings.HasPrefix(first, "HTTP/") {
		hs.kind = "response"
		parts := strings.SplitN(first, " ", 3)
		if len(parts) < 2 {
			return hs, fmt.Errorf("bad status line %q", first)
		}
		hs.version = parts[0]
		code, err := strconv.Atoi(parts[1])
		if err != nil {
			return hs, fmt.Errorf("bad status code in %q", first)
		}
		hs.status = code
		if len(parts) == 3 {
			hs.reason = parts[2]
		}
	} else {
		hs.kind = "request"
		parts := strings.SplitN(first, " ", 3)
		if len(parts) != 3 {
			return hs, fmt.Errorf("bad request line %q", first)
		}
		hs.method, hs.target, hs.version = parts[0], parts[1], parts[2]
	}
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			return hs, fmt.Errorf("bad header line %q", line)
		}
		hs.headers = append(hs.headers, httpHeader{
			name:  strings.TrimSpace(line[:i]),
			value: strings.TrimSpace(line[i+1:]),
		})
	}
	upgrade := strings.ToLower(hs.header("upgrade"))
	connection := strings.ToLower(hs.header("connection"))
	if hs.kind == "request" {
		hs.websocket = strings.Contains(upgrade, "websocket") && strings.Contains(connection, "upgrade")
	} else {
		hs.websocket = hs.status == 101 && strings.Contains(upgrade, "websocket")
	}
	return hs, nil
}

func (h httpHandshake) header(name string) string {
	for _, x := range h.headers {
		if strings.EqualFold(x.name, name) {
			return x.value
		}
	}
	return ""
}

func looksHTTP(b []byte) bool {
	if len(b) < 4 {
		return true
	}
	prefix := string(b)
	if strings.HasPrefix(prefix, "HTTP/") {
		return true
	}
	for _, method := range []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH ", "TRACE "} {
		if strings.HasPrefix(prefix, method) {
			return true
		}
	}
	return false
}
