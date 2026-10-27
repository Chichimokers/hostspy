package decoder

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

var testTime = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

func httpRequest() []byte {
	return []byte("GET / HTTP/1.1\r\n" +
		"Host: us.actual.battle.net\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Protocol: v1.rpc.battle.net\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n")
}

func httpResponse() []byte {
	return []byte("HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
		"Sec-WebSocket-Protocol: v1.rpc.battle.net\r\n\r\n")
}

func bgsPayload() []byte {
	header := []byte{0x08, 0x01, 0x12, 0x03, 'a', 'b', 'c'}
	body := []byte{0x18, 0x2a, 0x22, 0x05, 'h', 'e', 'l', 'l', 'o'}
	p := make([]byte, 2, 2+len(header)+len(body))
	binary.BigEndian.PutUint16(p, uint16(len(header)))
	p = append(p, header...)
	p = append(p, body...)
	return p
}

// maskedFrame builds a client-to-server WebSocket frame with a fixed mask.
func maskedFrame(fin bool, op byte, payload []byte) []byte {
	var b []byte
	first := op
	if fin {
		first |= 0x80
	}
	b = append(b, first)
	n := len(payload)
	switch {
	case n < 126:
		b = append(b, byte(n)|0x80)
	case n <= 0xffff:
		b = append(b, 126|0x80, byte(n>>8), byte(n))
	default:
		b = append(b, 127|0x80)
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(n))
		b = append(b, l[:]...)
	}
	key := [4]byte{0x11, 0x22, 0x33, 0x44}
	b = append(b, key[:]...)
	body := append([]byte(nil), payload...)
	for i := range body {
		body[i] ^= key[i%4]
	}
	return append(b, body...)
}

func plainFrame(fin bool, op byte, payload []byte) []byte {
	var b []byte
	first := op
	if fin {
		first |= 0x80
	}
	b = append(b, first)
	n := len(payload)
	switch {
	case n < 126:
		b = append(b, byte(n))
	case n <= 0xffff:
		b = append(b, 126, byte(n>>8), byte(n))
	default:
		b = append(b, 127)
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(n))
		b = append(b, l[:]...)
	}
	return append(b, payload...)
}

func decodeSession(t *testing.T, clientBytes, serverBytes []byte, opts Options) string {
	t.Helper()
	var out bytes.Buffer
	s := NewSession(&out, Meta{
		Host:         "us.actual.battle.net",
		Protocol:     "tls",
		ListenAddr:   "127.0.0.1:1119",
		ClientAddr:   "127.0.0.1:50000",
		UpstreamAddr: "1.2.3.4:1119",
		ClientTLS:    "TLS 1.2",
		UpstreamTLS:  "TLS 1.3",
		Started:      testTime,
	}, opts)
	if len(clientBytes) > 0 {
		s.Data("client->upstream", clientBytes, testTime, false)
	}
	if len(serverBytes) > 0 {
		s.Data("upstream->client", serverBytes, testTime, false)
	}
	s.Close("test closed")
	return out.String()
}

func TestSessionHandshakeFrameAndProtobuf(t *testing.T) {
	in := append(httpRequest(), maskedFrame(true, wsOpBinary, bgsPayload())...)
	got := decodeSession(t, in, nil, Options{})

	for _, want := range []string{
		"Host: us.actual.battle.net",
		"HTTP request",
		"method: GET",
		"target: /",
		"header Sec-WebSocket-Protocol: v1.rpc.battle.net",
		"websocket upgrade: true",
		"C->S frame #1 fin=true",
		"opcode=2 (binary) masked=true",
		"C->S message #1 opcode=2 (binary) frames=1",
		"2-byte big-endian length prefix",
		"header (7 bytes):",
		"1: varint 1",
		`2: string(3) "abc"`,
		"body (9 bytes):",
		"3: varint 42",
		`4: string(5) "hello"`,
		"Closed: test closed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}

	frame := strings.Index(got, "frame #1")
	message := strings.Index(got, "message #1")
	field := strings.Index(got, "1: varint 1")
	if frame < 0 || message < 0 || field < 0 || !(frame < message && message < field) {
		t.Errorf("expected frame -> message -> fields order:\n%s", got)
	}
}

func TestSessionServerResponseAndControlFrames(t *testing.T) {
	in := append(httpResponse(), plainFrame(true, wsOpPing, []byte("hi"))...)
	in = append(in, plainFrame(true, wsOpPong, []byte("hi"))...)
	closePayload := []byte{0x03, 0xe8} // 1000
	closePayload = append(closePayload, []byte("bye")...)
	in = append(in, plainFrame(true, wsOpClose, closePayload)...)

	got := decodeSession(t, nil, in, Options{})
	for _, want := range []string{
		"HTTP response",
		"status: 101",
		"websocket upgrade: true",
		"opcode=9 (ping)",
		"ping: payload=2 text=\"hi\"",
		"opcode=10 (pong)",
		"pong: payload=2 text=\"hi\"",
		"close: code=1000 (normal closure) reason=\"bye\"",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestSessionFragmentation(t *testing.T) {
	payload := bgsPayload()
	cut := 4
	first := maskedFrame(false, wsOpBinary, payload[:cut])
	second := maskedFrame(true, wsOpContinuation, payload[cut:])
	in := append(httpRequest(), first...)
	in = append(in, second...)

	got := decodeSession(t, in, nil, Options{})
	if !strings.Contains(got, "message #1 opcode=2 (binary) frames=2 payload=") {
		t.Fatalf("fragmented message was not reassembled:\n%s", got)
	}
	if strings.Count(got, "message #") != 1 {
		t.Fatalf("expected exactly one message:\n%s", got)
	}
	if !strings.Contains(got, "1: varint 1") || !strings.Contains(got, "3: varint 42") {
		t.Fatalf("reassembled payload was not decoded:\n%s", got)
	}
}

func TestSessionSplitReads(t *testing.T) {
	var out bytes.Buffer
	s := NewSession(&out, Meta{Host: "us.actual.battle.net", Started: testTime}, Options{})
	stream := append(httpRequest(), maskedFrame(true, wsOpBinary, bgsPayload())...)
	for i := range stream {
		s.Data("client->upstream", stream[i:i+1], testTime, false)
	}
	s.Close("byte-by-byte")
	got := out.String()
	if !strings.Contains(got, "message #1 opcode=2 (binary) frames=1") {
		t.Fatalf("split frame was not decoded:\n%s", got)
	}
	if !strings.Contains(got, "3: varint 42") {
		t.Fatalf("split payload was not decoded:\n%s", got)
	}
}

func TestSessionRawFallback(t *testing.T) {
	got := decodeSession(t, []byte{0x16, 0x03, 0x01, 0x00, 0x05}, nil, Options{})
	if !strings.Contains(got, "not an HTTP/WebSocket handshake; switching to raw mode") {
		t.Fatalf("expected raw fallback note:\n%s", got)
	}
	if !strings.Contains(got, "raw 5 bytes (no WebSocket framing)") {
		t.Fatalf("expected raw payload line:\n%s", got)
	}
}

func TestSessionCapTruncationStopsDecoding(t *testing.T) {
	frame := maskedFrame(true, wsOpBinary, bgsPayload())
	in := append(httpRequest(), frame[:3]...)
	var out bytes.Buffer
	s := NewSession(&out, Meta{Host: "us.actual.battle.net", Started: testTime}, Options{})
	s.Data("client->upstream", in, testTime, true)
	s.Data("client->upstream", frame[3:], testTime, false)
	s.Close("capped")

	got := out.String()
	if !strings.Contains(got, "raw log cap reached; the rest of the stream is not in the raw log") {
		t.Fatalf("expected a cap stop note:\n%s", got)
	}
	if strings.Contains(got, "message #") {
		t.Fatalf("decoder must not invent messages after a truncated read:\n%s", got)
	}
	if !strings.Contains(got, "Decoder summary: C->S") {
		t.Fatalf("missing summary:\n%s", got)
	}
}

func TestSessionChunkEventsAndHex(t *testing.T) {
	in := append(httpRequest(), maskedFrame(true, wsOpBinary, []byte{0xde, 0xad})...)
	got := decodeSession(t, in, nil, Options{ChunkEvents: true, IncludeHex: true})
	if !strings.Contains(got, "C->S chunk #1") {
		t.Fatalf("expected chunk event:\n%s", got)
	}
	if !strings.Contains(got, "de ad") {
		t.Fatalf("expected frame hex dump:\n%s", got)
	}
}

func TestSessionExtendedPayloadLengths(t *testing.T) {
	client := append(httpRequest(), maskedFrame(true, wsOpBinary, make([]byte, 300))...)
	server := append(httpResponse(), plainFrame(true, wsOpBinary, make([]byte, 70000))...)
	got := decodeSession(t, client, server, Options{})
	for _, want := range []string{
		"C->S message #1 opcode=2 (binary) frames=1 payload=300",
		"C->S frame #1 fin=true",
		"payload=300 header=8",
		"S->C message #1 opcode=2 (binary) frames=1 payload=70000",
		"payload=70000 header=10",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q", want)
		}
	}
}
