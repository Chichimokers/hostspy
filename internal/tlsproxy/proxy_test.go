package tlsproxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Chichimokers/hostspy/internal/logger"
)

const testProto = "sc2-proto"

// testCertificate returns a self-signed certificate valid for the given names,
// plus a pool that trusts it. The same certificate is used for the proxy and for
// the test upstream; tests that must fail verification simply pass no pool.
func testCertificate(t *testing.T, dnsNames ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

type fixedDialer struct {
	addr string
	mu   sync.Mutex
	n    int
	last string
}

func (d *fixedDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.n++
	d.last = addr
	d.mu.Unlock()
	var nd net.Dialer
	return nd.DialContext(ctx, network, d.addr)
}

func (d *fixedDialer) calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.n
}

func (d *fixedDialer) lastAddr() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.last
}

type upstreamObservation struct {
	sni   string
	alpn  string
	proto uint16
	data  []byte
	err   error
}

// startTLSUpstream runs a TLS echo server. It records the negotiated SNI/ALPN
// and every application byte, which proves the proxy opened an independent,
// validated TLS session to the real upstream.
func startTLSUpstream(t *testing.T, cert tls.Certificate) (addr string, observations <-chan upstreamObservation) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{testProto},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ch := make(chan upstreamObservation, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- upstreamObservation{err: err}
			return
		}
		defer conn.Close()
		if err := conn.(*tls.Conn).Handshake(); err != nil {
			ch <- upstreamObservation{err: err}
			return
		}
		state := conn.(*tls.Conn).ConnectionState()
		var received bytes.Buffer
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				received.Write(buf[:n])
				if _, werr := conn.Write(buf[:n]); werr != nil {
					ch <- upstreamObservation{sni: state.ServerName, alpn: state.NegotiatedProtocol,
						proto: state.Version, data: received.Bytes(), err: werr}
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					ch <- upstreamObservation{sni: state.ServerName, alpn: state.NegotiatedProtocol,
						proto: state.Version, data: received.Bytes(), err: err}
					return
				}
				ch <- upstreamObservation{sni: state.ServerName, alpn: state.NegotiatedProtocol,
					proto: state.Version, data: received.Bytes()}
				return
			}
		}
	}()
	return ln.Addr().String(), ch
}

func startProxy(t *testing.T, opts Options) (*Server, string) {
	t.Helper()
	srv, err := New(opts)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if err := srv.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = srv.Serve() }()
	return srv, srv.Addr().String()
}

func tcpLogFiles(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*", "tcp_*.log"))
	if err != nil {
		t.Fatalf("glob logs: %v", err)
	}
	return matches
}

func waitForTCPLog(t *testing.T, dir string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		files := tcpLogFiles(t, dir)
		if len(files) == 1 {
			// The summary line is written last; wait until it is present so the
			// assertions do not race the writer.
			if b, err := os.ReadFile(files[0]); err == nil && bytes.Contains(b, []byte("\nClosed: ")) {
				// Close writes the summary before closing the file; give the
				// writer a moment so TempDir cleanup does not race it on Windows.
				time.Sleep(50 * time.Millisecond)
				return files[0]
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	files := tcpLogFiles(t, dir)
	t.Fatalf("no completed TCP log in %s; candidate files: %v", dir, files)
	return ""
}

func TestSNIRoutingIndependentTLSAndExactPayload(t *testing.T) {
	cert, pool := testCertificate(t, "logon.test", "upstream.test")
	upstreamAddr, observations := startTLSUpstream(t, cert)

	logDir := t.TempDir()
	dialer := &fixedDialer{addr: upstreamAddr}
	_, proxyAddr := startProxy(t, Options{
		ListenPort: 1119,
		ServerTLS:  &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		Dialer:     dialer,
		Routes:     map[string]string{"logon.test": "tls://upstream.test:1119"},
		Log:        logger.New(logDir, true, true),
		// The upstream certificate is private to this test.
		UpstreamTLSConfig:  &tls.Config{RootCAs: pool},
		LogApplicationData: true,
		LogHex:             true,
		MaxLoggedBytes:     1 << 20,

		DecodeApplicationData: true,
		DecodedChunkEvents:    true,
	})

	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte((i*37 + 0x80) % 256)
	}
	payload[0], payload[1], payload[2] = 0x00, 0xff, 0x16 // deliberately invalid UTF-8

	client, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		ServerName: "logon.test",
		RootCAs:    pool,
		NextProtos: []string{testProto},
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer client.Close()
	if got := client.ConnectionState().NegotiatedProtocol; got != testProto {
		t.Fatalf("client ALPN = %q, want %q", got, testProto)
	}

	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("client close_write: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	echoed, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("echoed payload differs: got %d bytes, want %d", len(echoed), len(payload))
	}

	select {
	case obs := <-observations:
		if obs.err != nil {
			t.Fatalf("upstream: %v", obs.err)
		}
		if obs.sni != "upstream.test" {
			t.Errorf("upstream SNI = %q, want upstream.test", obs.sni)
		}
		if obs.alpn != testProto {
			t.Errorf("upstream ALPN = %q, want %q (client ALPN must be mirrored)", obs.alpn, testProto)
		}
		if obs.proto < tls.VersionTLS12 {
			t.Errorf("upstream TLS version = 0x%04x, want TLS >= 1.2", obs.proto)
		}
		if !bytes.Equal(obs.data, payload) {
			t.Errorf("upstream received %d bytes, want %d", len(obs.data), len(payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never observed the proxied connection")
	}

	logPath := waitForTCPLog(t, logDir)
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read TCP log: %v", err)
	}
	logText := string(b)
	for _, want := range []string{
		"Host: logon.test",
		"Protocol: tls",
		"Upstream: upstream.test:1119",
		"Client TLS: TLS 1.",
		"Upstream TLS: TLS 1.",
		"alpn=" + testProto,
		"client->upstream " + "1024 bytes",
		"upstream->client " + "1024 bytes",
	} {
		if !strings.Contains(logText, want) {
			t.Errorf("TCP log missing %q\n--- log ---\n%s", want, logText)
		}
	}
	// The payload is binary: the log must contain an offset-based hex dump and
	// must not pretend it is text.
	firstLine := hex.EncodeToString(payload[:16])
	if !strings.Contains(logText, "00000000  ") || !strings.Contains(logText, formatHexLine(payload[:16])) {
		t.Errorf("TCP log missing hex dump; first line should contain %q\n--- log ---\n%s", firstLine, logText)
	}
	if strings.Contains(logText, "text:") {
		t.Errorf("binary payload must not get a text preview\n--- log ---\n%s", logText)
	}

	decodedPath := strings.TrimSuffix(logPath, ".log") + ".decoded.txt"
	decoded, err := os.ReadFile(decodedPath)
	if err != nil {
		t.Fatalf("read decoded log %s: %v", decodedPath, err)
	}
	decodedText := string(decoded)
	for _, want := range []string{
		"Decoder: HTTP upgrade -> WebSocket frames -> generic protobuf fields",
		"not an HTTP/WebSocket handshake; switching to raw mode",
		"C->S chunk #1",
		"raw 1024 bytes (no WebSocket framing)",
	} {
		if !strings.Contains(decodedText, want) {
			t.Errorf("decoded log missing %q\n--- decoded ---\n%s", want, decodedText)
		}
	}

	if calls := dialer.calls(); calls != 1 {
		t.Errorf("upstream dial calls = %d, want 1", calls)
	}
}

func TestDecodeOptionsRequireLogging(t *testing.T) {
	cert, _ := testCertificate(t, "logon.test")
	base := func() Options {
		return Options{
			ListenPort: 1119,
			ServerTLS:  &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
			Dialer:     &fixedDialer{},
			Log:        logger.New(t.TempDir(), true, true),
		}
	}

	noApp := base()
	noApp.DecodeApplicationData = true
	noApp.LogHex = true
	if _, err := New(noApp); err == nil || !strings.Contains(err.Error(), "logApplicationData") {
		t.Fatalf("decode without logApplicationData: err = %v", err)
	}

	noHex := base()
	noHex.DecodeApplicationData = true
	noHex.LogApplicationData = true
	if _, err := New(noHex); err == nil || !strings.Contains(err.Error(), "logHex") {
		t.Fatalf("decode without logHex: err = %v", err)
	}

	enabled := base()
	enabled.DecodeApplicationData = true
	enabled.LogApplicationData = true
	enabled.LogHex = true
	enabled.MaxLoggedBytes = -1
	srv, err := New(enabled)
	if err != nil {
		t.Fatalf("valid decode options: %v", err)
	}
	if srv.opts.MaxLoggedBytes != math.MaxInt64 {
		t.Errorf("negative cap = %d, want unlimited (%d)", srv.opts.MaxLoggedBytes, int64(math.MaxInt64))
	}

	zero := base()
	zero.MaxLoggedBytes = 0
	srv, err = New(zero)
	if err != nil {
		t.Fatalf("zero cap: %v", err)
	}
	if srv.opts.MaxLoggedBytes != 64<<10 {
		t.Errorf("zero cap = %d, want %d", srv.opts.MaxLoggedBytes, 64<<10)
	}
}

func formatHexLine(data []byte) string {
	var b strings.Builder
	for _, c := range data {
		b.WriteString(hex.EncodeToString([]byte{c}))
		b.WriteString(" ")
	}
	return b.String()
}

func TestNonTLSConnectionRejectedByDefault(t *testing.T) {
	cert, _ := testCertificate(t, "logon.test")
	logDir := t.TempDir()
	dialer := &fixedDialer{addr: "127.0.0.1:1"}
	_, proxyAddr := startProxy(t, Options{
		ListenPort: 1119,
		ServerTLS:  &tls.Config{Certificates: []tls.Certificate{cert}},
		Dialer:     dialer,
		Log:        logger.New(logDir, true, true),
		Routes:     map[string]string{"logon.test": "tls://upstream.test:1119"},
	})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.Copy(io.Discard, conn)

	if calls := dialer.calls(); calls != 0 {
		t.Errorf("non-TLS traffic must not reach any upstream, dial calls = %d", calls)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(filepath.Join(logDir, "hostspy.log"))
		if err == nil && bytes.Contains(b, []byte("non-TLS data")) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("log does not explain the rejected non-TLS connection")
}

func TestPlaintextPassthroughWhenExplicitlyConfigured(t *testing.T) {
	cert, _ := testCertificate(t, "logon.test")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen plaintext upstream: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				// Give Windows a moment to flush the echoed bytes before the
				// socket closes; an immediate close after EOF can turn into RST.
				time.Sleep(50 * time.Millisecond)
				return
			}
		}
	}()

	logDir := t.TempDir()
	dialer := &fixedDialer{addr: ln.Addr().String()}
	_, proxyAddr := startProxy(t, Options{
		ListenPort:         1119,
		ServerTLS:          &tls.Config{Certificates: []tls.Certificate{cert}},
		Dialer:             dialer,
		Log:                logger.New(logDir, true, true),
		PlaintextUpstream:  "tcp://plain.test:1119",
		LogApplicationData: true,
	})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	payload := []byte("plaintext\x00payload")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if cw, ok := conn.(*net.TCPConn); ok {
		_ = cw.CloseWrite()
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	echoed, err := io.ReadAll(conn)
	if err != nil && describeErr(err) != "reset (RST)" {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("echo = %q, want %q", echoed, payload)
	}

	logPath := waitForTCPLog(t, logDir)
	b, _ := os.ReadFile(logPath)
	if !strings.Contains(string(b), "Protocol: plaintext") {
		t.Errorf("plaintext log does not identify the protocol:\n%s", b)
	}
}

func TestUpstreamHandshakeFailureIsReportedSeparately(t *testing.T) {
	cert, pool := testCertificate(t, "logon.test", "upstream.test")
	upstreamAddr, _ := startTLSUpstream(t, cert)
	logDir := t.TempDir()
	_, proxyAddr := startProxy(t, Options{
		ListenPort: 1119,
		ServerTLS:  &tls.Config{Certificates: []tls.Certificate{cert}},
		Dialer:     &fixedDialer{addr: upstreamAddr},
		Routes:     map[string]string{"logon.test": "tls://upstream.test:1119"},
		Log:        logger.New(logDir, true, true),
		// Deliberately no RootCAs: the upstream certificate is untrusted.
	})

	client, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		ServerName: "logon.test",
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("client handshake should succeed before the upstream is attempted: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("data")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := client.Read(make([]byte, 16)); err == nil && n > 0 {
		t.Fatalf("client received %d bytes although the upstream handshake failed", n)
	}

	b, err := os.ReadFile(filepath.Join(logDir, "hostspy.log"))
	if err != nil {
		t.Fatalf("read hostspy.log: %v", err)
	}
	text := string(b)
	if !strings.Contains(text, "UPSTREAM HANDSHAKE FAILED") {
		t.Errorf("log does not identify the failed upstream TLS session:\n%s", text)
	}
	if strings.Contains(text, "CLIENT HANDSHAKE FAILED") {
		t.Errorf("log wrongly reports a client-side failure:\n%s", text)
	}
}

func TestNoSNIWithoutDefaultUpstreamIsRejected(t *testing.T) {
	cert, _ := testCertificate(t, "logon.test")
	logDir := t.TempDir()
	dialer := &fixedDialer{addr: "127.0.0.1:1"}
	_, proxyAddr := startProxy(t, Options{
		ListenPort: 1119,
		ServerTLS:  &tls.Config{Certificates: []tls.Certificate{cert}},
		Dialer:     dialer,
		Log:        logger.New(logDir, true, true),
		Routes:     map[string]string{"logon.test": "tls://upstream.test:1119"},
	})

	// InsecureSkipVerify is required to omit SNI while still accepting the
	// certificate; the proxy cannot know the destination and must close.
	client, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test only
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		// Some Go versions fail the handshake when the server rejects early;
		// that is also an acceptable outcome.
		return
	}
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := client.Read(make([]byte, 16)); err == nil && n > 0 {
		t.Fatalf("no-SNI client received %d bytes", n)
	}
	if calls := dialer.calls(); calls != 0 {
		t.Errorf("no-SNI client must not cause an upstream dial, calls = %d", calls)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(filepath.Join(logDir, "hostspy.log"))
		if bytes.Contains(b, []byte("no SNI")) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("log does not explain the missing SNI")
}

func TestNoSNIUsesDefaultUpstream(t *testing.T) {
	cert, pool := testCertificate(t, "upstream.test")
	upstreamAddr, observations := startTLSUpstream(t, cert)
	logDir := t.TempDir()
	_, proxyAddr := startProxy(t, Options{
		ListenPort:      1119,
		ServerTLS:       &tls.Config{Certificates: []tls.Certificate{cert}},
		Dialer:          &fixedDialer{addr: upstreamAddr},
		DefaultUpstream: "tls://upstream.test:1119",
		UpstreamTLSConfig: &tls.Config{
			RootCAs: pool,
		},
		Log:                logger.New(logDir, true, true),
		LogApplicationData: true,
	})

	// StarCraft II does not send SNI on port 1119. With defaultUpstream set,
	// the proxy must use it explicitly instead of guessing from the port.
	client, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test only
		NextProtos:         []string{testProto},
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer client.Close()
	payload := []byte{0x00, 0x01, 0xff, 's', 'c', '2'}
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = client.CloseWrite()
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	echoed, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("echo = %x, want %x", echoed, payload)
	}

	select {
	case obs := <-observations:
		if obs.err != nil {
			t.Fatalf("upstream: %v", obs.err)
		}
		if obs.sni != "upstream.test" {
			t.Errorf("upstream SNI = %q, want upstream.test", obs.sni)
		}
		if obs.alpn != testProto {
			t.Errorf("upstream ALPN = %q, want %q", obs.alpn, testProto)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never observed the connection")
	}

	logPath := waitForTCPLog(t, logDir)
	b, _ := os.ReadFile(logPath)
	if !strings.Contains(string(b), "Host: upstream.test") {
		t.Errorf("log must name the explicit default destination:\n%s", b)
	}
}

func TestUpstreamRoutesDefaultToSNIAndListenerPort(t *testing.T) {
	cert, _ := testCertificate(t, "logon.test")
	srv, err := New(Options{
		ListenPort: 1119,
		ServerTLS:  &tls.Config{Certificates: []tls.Certificate{cert}},
		Dialer:     &fixedDialer{},
		Log:        logger.New(t.TempDir(), true, true),
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	up, err := srv.upstreamFor("US.Actual.Battle.Net.")
	if err != nil {
		t.Fatalf("upstreamFor: %v", err)
	}
	if up.Addr != "us.actual.battle.net:1119" {
		t.Errorf("upstream = %q, want us.actual.battle.net:1119", up.Addr)
	}
	if up.ServerName != "us.actual.battle.net" {
		t.Errorf("server name = %q, want us.actual.battle.net", up.ServerName)
	}
	if !up.UseTLS {
		t.Error("default upstream must use TLS")
	}

	// An explicit route wins, and the SNI must never be replaced by loopback.
	srv.opts.Routes = map[string]string{
		"us.actual.battle.net": "tls://logon.example:7019",
	}
	up, err = srv.upstreamFor("us.actual.battle.net")
	if err != nil {
		t.Fatalf("upstreamFor route: %v", err)
	}
	if up.Addr != "logon.example:7019" {
		t.Errorf("routed upstream = %q, want logon.example:7019", up.Addr)
	}

	srv.opts.Routes = map[string]string{"us.actual.battle.net": "logon.example:not-a-port"}
	if _, err := srv.upstreamFor("us.actual.battle.net"); err == nil {
		t.Error("expected an invalid port error")
	}
}

func TestPassthroughPreservesUpstreamCertificate(t *testing.T) {
	proxyCert, _ := testCertificate(t, "proxy.test")
	upstreamCert, _ := testCertificate(t, "pinned.test")

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{upstreamCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			received <- "accept: " + err.Error()
			return
		}
		defer conn.Close()
		tc := conn.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			received <- "handshake: " + err.Error()
			return
		}
		var got []byte
		buf := make([]byte, 256)
		for !bytes.Contains(got, []byte("\r\n\r\n")) {
			n, err := tc.Read(buf)
			got = append(got, buf[:n]...)
			if err != nil {
				received <- string(got)
				return
			}
		}
		received <- string(got)
		_, _ = tc.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n\r\n"))
		_, _ = io.Copy(io.Discard, tc)
	}()

	logDir := t.TempDir()
	dialer := &fixedDialer{addr: ln.Addr().String()}
	_, proxyAddr := startProxy(t, Options{
		ListenPort:         1119,
		ServerTLS:          &tls.Config{Certificates: []tls.Certificate{proxyCert}, MinVersion: tls.VersionTLS12},
		Dialer:             dialer,
		DefaultUpstream:    "eu.pinned.test:1119",
		PassthroughHosts:   []string{"*.pinned.test"},
		Log:                logger.New(logDir, true, true),
		LogApplicationData: true,
		LogHex:             true,
		HalfCloseTimeout:   200 * time.Millisecond,
	})

	rawConn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	// No ServerName: the real client (SC2/BGS) sends no SNI on 1119.
	client := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	defer client.Close()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	state := client.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificate")
	}
	if cn := state.PeerCertificates[0].Subject.CommonName; cn != "pinned.test" {
		t.Fatalf("client saw certificate %q; TLS was terminated instead of passed through", cn)
	}

	request := "GET / HTTP/1.1\r\nHost: pinned.test:1119\r\n\r\n"
	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	var response []byte
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	for !bytes.Contains(response, []byte("\r\n\r\n")) {
		buf := make([]byte, 128)
		n, err := client.Read(buf)
		response = append(response, buf[:n]...)
		if err != nil {
			t.Fatalf("read response: %v (got %q)", err, response)
		}
	}
	if !strings.HasPrefix(string(response), "HTTP/1.1 101") {
		t.Fatalf("response = %q", response)
	}

	select {
	case got := <-received:
		if got != request {
			t.Fatalf("upstream received %q, want %q", got, request)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream never received the request")
	}
	if got := dialer.lastAddr(); got != "eu.pinned.test:1119" {
		t.Errorf("dial address = %q, want eu.pinned.test:1119 (from defaultUpstream)", got)
	}
	b, err := os.ReadFile(filepath.Join(logDir, "hostspy.log"))
	if err != nil {
		t.Fatalf("read hostspy log: %v", err)
	}
	if !strings.Contains(string(b), "PASSTHROUGH") {
		t.Errorf("hostspy log does not record the passthrough\n%s", b)
	}
	if files := tcpLogFiles(t, logDir); len(files) != 0 {
		t.Errorf("passthrough must not create decrypted TCP logs, got %v", files)
	}
}

// startStalledTLSUpstream completes a TLS handshake, waits for the proxy to
// half-close, then keeps the socket open for a while. It simulates a server
// that never sends a response after the client sent FIN.
func startStalledTLSUpstream(t *testing.T, cert tls.Certificate) (string, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	readEOF := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(readEOF)
			return
		}
		defer conn.Close()
		tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		if err := tc.Handshake(); err != nil {
			close(readEOF)
			return
		}
		_, _ = io.Copy(io.Discard, tc)
		close(readEOF)
		time.Sleep(1500 * time.Millisecond)
	}()
	return ln.Addr().String(), readEOF
}

func TestHalfCloseGraceClosesTheRemainingDirection(t *testing.T) {
	cert, pool := testCertificate(t, "logon.test")
	upstreamAddr, readEOF := startStalledTLSUpstream(t, cert)

	logDir := t.TempDir()
	_, proxyAddr := startProxy(t, Options{
		ListenPort:         1119,
		ServerTLS:          &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		Dialer:             &fixedDialer{addr: upstreamAddr},
		DefaultUpstream:    "logon.test:1119",
		UpstreamTLSConfig:  &tls.Config{RootCAs: pool},
		HalfCloseTimeout:   200 * time.Millisecond,
		Log:                logger.New(logDir, true, true),
		LogApplicationData: true,
		LogHex:             true,
	})

	client, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		ServerName: "logon.test", RootCAs: pool, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("close_write: %v", err)
	}
	select {
	case <-readEOF:
	case <-time.After(3 * time.Second):
		t.Fatal("proxy never propagated the half-close upstream")
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	_, err = client.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected the proxy to close the client socket")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("client stayed open for %s; half-close grace did not close it", elapsed)
	}

	logPath := waitForTCPLog(t, logDir)
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read TCP log: %v", err)
	}
	if !strings.Contains(string(b), "half-close grace expired") {
		t.Errorf("log does not record the grace expiry\n--- log ---\n%s", b)
	}
}

func TestCloseBeforeAnyApplicationDataIsImmediate(t *testing.T) {
	cert, pool := testCertificate(t, "logon.test")
	upstreamAddr, readEOF := startStalledTLSUpstream(t, cert)

	logDir := t.TempDir()
	_, proxyAddr := startProxy(t, Options{
		ListenPort:        1119,
		ServerTLS:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		Dialer:            &fixedDialer{addr: upstreamAddr},
		DefaultUpstream:   "logon.test:1119",
		UpstreamTLSConfig: &tls.Config{RootCAs: pool},
		// Much longer than the test timeout: the zero-byte path must not wait.
		HalfCloseTimeout:   10 * time.Second,
		Log:                logger.New(logDir, true, true),
		LogApplicationData: true,
		LogHex:             true,
	})

	client, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		ServerName: "logon.test", RootCAs: pool, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer client.Close()
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("close_write: %v", err)
	}
	select {
	case <-readEOF:
	case <-time.After(3 * time.Second):
		t.Fatal("proxy never propagated the half-close upstream")
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	_, err = client.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected the proxy to close the client socket")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("client stayed open for %s; zero-byte half-close must close immediately", elapsed)
	}

	logPath := waitForTCPLog(t, logDir)
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read TCP log: %v", err)
	}
	if !strings.Contains(string(b), "half-close before any application data") {
		t.Errorf("log does not record the zero-byte half-close\n--- log ---\n%s", b)
	}
}
