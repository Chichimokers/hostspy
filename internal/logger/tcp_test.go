package logger

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestTCPSessionHexCapAndSummary(t *testing.T) {
	dir := t.TempDir()
	l := New(dir, true, true)
	sess := l.OpenTCP(TCPSessionRecord{
		ID:         7,
		Protocol:   "tls",
		Host:       "us.actual.battle.net",
		Port:       1119,
		ClientAddr: "127.0.0.1:50000",
		LogData:    true,
		LogHex:     true,
		MaxBytes:   16,
		Started:    time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC),
	})
	if sess.Path() == "" {
		t.Fatal("expected a log file")
	}

	// First block fits; the second is partially logged, the third fully skipped.
	clientBlock := []byte{0x00, 0x01, 0xfe, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
		0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x11}
	serverBlock := []byte{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
		0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93}
	sess.Data("client->upstream", clientBlock)
	sess.Data("upstream->client", serverBlock)
	sess.Close("eof (FIN/close_notify)")

	b, err := os.ReadFile(sess.Path())
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	text := string(b)
	for _, want := range []string{
		"Host: us.actual.battle.net",
		"Protocol: tls",
		"Log cap: 16 bytes per direction.",
		"client->upstream 20 bytes (only the first 16 bytes are logged)",
		"upstream->client 20 bytes (only the first 16 bytes are logged)",
		"00000000  00 01 fe ff 10 20 30 40 50 60 70 80 90 a0 b0 c0 ",
		"Closed: eof (FIN/close_notify)",
		"Not logged (client->upstream cap): 4 bytes",
		"Not logged (upstream->client cap): 4 bytes",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("log missing %q\n--- log ---\n%s", want, text)
		}
	}
	// Binary blocks must never be presented as text.
	if strings.Contains(text, "text:") {
		t.Errorf("binary data got a text preview\n--- log ---\n%s", text)
	}
}

func TestTCPSessionTextPreviewOnlyForPrintableUTF8(t *testing.T) {
	dir := t.TempDir()
	l := New(dir, true, false)
	sess := l.OpenTCP(TCPSessionRecord{
		ID: 1, Protocol: "plaintext", Host: "example.test", Port: 1234,
		LogData: true, LogHex: false, MaxBytes: 1024,
	})
	sess.Data("client->upstream", []byte("hola mundo\nsegunda linea"))
	sess.Close("test")
	b, _ := os.ReadFile(sess.Path())
	if !strings.Contains(string(b), `text: "hola mundo\nsegunda linea"`) {
		t.Errorf("printable UTF-8 should get a text preview:\n%s", b)
	}

	if _, ok := textPreview([]byte{0xff, 0xfe, 0x00}); ok {
		t.Error("invalid UTF-8 must not get a text preview")
	}
	if _, ok := textPreview([]byte("ok\x00binary")); ok {
		t.Error("control characters must not get a text preview")
	}
}

func TestTCPSessionNoFileWhenDataLoggingDisabled(t *testing.T) {
	dir := t.TempDir()
	l := New(dir, true, true)
	sess := l.OpenTCP(TCPSessionRecord{
		ID: 1, Protocol: "tls", Host: "example.test", Port: 1119,
		LogData: false,
	})
	if sess.Path() != "" {
		t.Fatalf("unexpected log file %q", sess.Path())
	}
	sess.Data("client->upstream", []byte("secret"))
	sess.Close("test")
}

func TestListenPort(t *testing.T) {
	cases := map[string]int{
		":443":         443,
		"127.0.0.1:80": 80,
		"443":          443,
		"":             0,
		"not-a-number": 0,
		"[::1]:1119":   1119,
	}
	for in, want := range cases {
		if got := ListenPort(in); got != want {
			t.Errorf("ListenPort(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestTCPSessionDecodedSidecar(t *testing.T) {
	dir := t.TempDir()
	l := New(dir, true, true)
	sess := l.OpenTCP(TCPSessionRecord{
		ID: 9, Protocol: "tls", Host: "us.actual.battle.net", Port: 1119,
		ClientAddr: "127.0.0.1:50000", UpstreamAddr: "1.2.3.4:1119",
		ClientTLS: "TLS 1.2", UpstreamTLS: "TLS 1.3",
		LogData: true, LogHex: true, MaxBytes: 1 << 20, Started: time.Now(),
		DecodeData: true, DecodedMaxDepth: 8,
		DecodedIncludeHex: true, DecodedChunkEvents: true,
	})
	if sess.DecodedPath() == "" {
		t.Fatal("expected a decoded sidecar")
	}
	wantPath := strings.TrimSuffix(sess.Path(), ".log") + ".decoded.txt"
	if sess.DecodedPath() != wantPath {
		t.Fatalf("DecodedPath() = %q, want %q", sess.DecodedPath(), wantPath)
	}

	in := append(testUpgradeRequest(), testMaskedBinaryFrame(testBGSPayload())...)
	sess.Data("client->upstream", in)
	sess.Close("eof (FIN/close_notify)")

	raw, err := os.ReadFile(sess.Path())
	if err != nil {
		t.Fatalf("read raw log: %v", err)
	}
	if !strings.Contains(string(raw), "client->upstream") {
		t.Fatalf("raw log lost the application bytes:\n%s", raw)
	}

	decoded, err := os.ReadFile(sess.DecodedPath())
	if err != nil {
		t.Fatalf("read decoded log: %v", err)
	}
	text := string(decoded)
	for _, want := range []string{
		"Host: us.actual.battle.net",
		"Decoder: HTTP upgrade -> WebSocket frames -> generic protobuf fields",
		"source of truth",
		"contains personal data",
		"C->S chunk #1",
		"HTTP request",
		"header Sec-WebSocket-Protocol: v1.rpc.battle.net",
		"C->S frame #1 fin=true",
		"opcode=2 (binary) masked=true",
		"C->S message #1 opcode=2 (binary) frames=1",
		"2-byte big-endian length prefix",
		"1: varint 1",
		"3: varint 42",
		`4: string(5) "hello"`,
		"Closed: eof (FIN/close_notify)",
		"Decoder summary: C->S",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("decoded log missing %q\n--- decoded ---\n%s", want, text)
		}
	}
}

func TestTCPSessionDecodedSidecarStopsAtCap(t *testing.T) {
	dir := t.TempDir()
	l := New(dir, true, true)
	req := testUpgradeRequest()
	frame := testMaskedBinaryFrame(testBGSPayload())
	capBytes := int64(len(req) + 5) // HTTP fits; the frame is cut mid-header.
	sess := l.OpenTCP(TCPSessionRecord{
		ID: 10, Protocol: "tls", Host: "us.actual.battle.net", Port: 1119,
		LogData: true, LogHex: true, MaxBytes: capBytes, Started: time.Now(),
		DecodeData: true, DecodedIncludeHex: true,
	})
	in := append(append([]byte(nil), req...), frame...)
	sess.Data("client->upstream", in)
	sess.Data("client->upstream", []byte("more bytes after the cap"))
	sess.Close("cap test")

	raw, _ := os.ReadFile(sess.Path())
	rawText := string(raw)
	if !strings.Contains(rawText, "only the first") {
		t.Fatalf("raw log should show a partial block:\n%s", rawText)
	}
	if !strings.Contains(rawText, "Not logged (client->upstream cap):") {
		t.Fatalf("raw log should count the skipped bytes:\n%s", rawText)
	}

	decoded, err := os.ReadFile(sess.DecodedPath())
	if err != nil {
		t.Fatalf("read decoded log: %v", err)
	}
	text := string(decoded)
	if !strings.Contains(text, "raw log cap reached; the rest of the stream is not in the raw log") {
		t.Fatalf("decoded log should stop at the cap:\n%s", text)
	}
	if !strings.Contains(text, "24 further bytes not decoded") {
		t.Fatalf("decoded log should record the skipped read:\n%s", text)
	}
	if strings.Contains(text, "message #") {
		t.Fatalf("decoded log must not invent a message after truncation:\n%s", text)
	}
}

func TestTCPSessionDecodedRequiresHex(t *testing.T) {
	dir := t.TempDir()
	l := New(dir, true, true)
	sess := l.OpenTCP(TCPSessionRecord{
		ID: 11, Protocol: "tls", Host: "example.test", Port: 1119,
		LogData: true, LogHex: false, MaxBytes: 1024, Started: time.Now(),
		DecodeData: true,
	})
	if sess.DecodedPath() != "" {
		t.Fatalf("decoded sidecar should require logHex, got %q", sess.DecodedPath())
	}
	sess.Data("client->upstream", []byte("plain text"))
	sess.Close("test")
}

func testUpgradeRequest() []byte {
	return []byte("GET / HTTP/1.1\r\n" +
		"Host: us.actual.battle.net\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Protocol: v1.rpc.battle.net\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n")
}

func testBGSPayload() []byte {
	header := []byte{0x08, 0x01}
	body := []byte{0x18, 0x2a, 0x22, 0x05, 'h', 'e', 'l', 'l', 'o'}
	return append(append([]byte{0x00, byte(len(header))}, header...), body...)
}

func testMaskedBinaryFrame(payload []byte) []byte {
	key := [4]byte{1, 2, 3, 4}
	b := []byte{0x82, 0x80 | byte(len(payload))}
	b = append(b, key[:]...)
	for i, v := range payload {
		b = append(b, v^key[i%4])
	}
	return b
}
