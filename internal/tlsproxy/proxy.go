// Package tlsproxy implements a transparent TCP proxy with independent TLS
// termination on both sides. It is used for ports such as StarCraft II's 1119
// logon port, where the protocol is binary TLS rather than HTTP.
//
// The incoming hostname is recovered from the TLS SNI extension: the hosts file
// only redirects the name to 127.0.0.1, so the original destination is not
// otherwise available. The upstream is the SNI host on the same port by
// default, unless tcpTls.upstreams maps it explicitly.
package tlsproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Chichimokers/hostspy/internal/logger"
)

const (
	dirClientToUpstream = "client->upstream"
	dirUpstreamToClient = "upstream->client"
)

// Dialer is implemented by dnsres.Resolver. It must resolve names through
// public DNS so the local hosts file cannot redirect the upstream back to us.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Options configures one TLS interception listener.
type Options struct {
	// ListenPort is the local TCP port. It is also the default upstream port
	// when no route specifies one.
	ListenPort int

	// ServerTLS terminates the client connection. Its NextProtos are replaced
	// per connection with the client's own ALPN list, so binary protocols keep
	// their negotiation instead of being offered HTTP/2.
	ServerTLS *tls.Config

	// Dialer resolves and connects to the real upstream. Required.
	Dialer Dialer

	// Routes maps a lower-case hostname to an upstream. The value may be
	// "host:port", "host", or a URL. https/tls (and a missing scheme) mean the
	// upstream is wrapped in TLS; http/tcp mean plaintext.
	Routes map[string]string

	// DefaultUpstream is used only when a TLS client sends no SNI. Without it,
	// such connections are diagnosed and closed rather than guessed.
	DefaultUpstream string

	// PlaintextUpstream enables raw TCP passthrough when the first bytes are
	// not TLS. Empty means non-TLS traffic is diagnosed and closed.
	PlaintextUpstream string

	// PassthroughHosts lists host patterns (for example
	// "*.actual.battle.net") whose TLS sessions are tunneled instead of
	// terminated. Some clients pin the upstream public key inside the TLS
	// stack (StarCraft II uses libcurl's CURLOPT_PINNEDPUBLICKEY with the BGS
	// key list), so a locally generated certificate is rejected after the
	// handshake and the client never sends a request. Tunneling preserves the
	// real certificate and key, at the cost of not being able to decrypt the
	// connection. Patterns use path.Match syntax; a pattern is matched against
	// the SNI name, the configured upstream name and the upstream host.
	PassthroughHosts []string

	// HalfCloseTimeout bounds how long one direction may stay open after the
	// other side sent FIN. Without it, a client that half-closes can leave its
	// socket in FIN_WAIT_2 for as long as the peer keeps its side open.
	HalfCloseTimeout time.Duration

	InsecureUpstream bool
	// UpstreamTLSConfig is the base config for the outbound TLS session. It is
	// mainly useful in tests (custom RootCAs); production callers can leave it
	// nil to use the system roots.
	UpstreamTLSConfig *tls.Config

	Log                *logger.Logger
	LogApplicationData bool
	LogHex             bool
	MaxLoggedBytes     int64

	// DecodeApplicationData enables the decoded sidecar. It requires
	// LogApplicationData and LogHex because the sidecar must mirror the bytes
	// that the raw log records.
	DecodeApplicationData bool
	DecodedMaxDepth       int
	DecodedIncludeHex     bool
	DecodedChunkEvents    bool

	HandshakeTimeout time.Duration
	ConnectTimeout   time.Duration
	MaxConns         int
}

// Server is one listening port.
type Server struct {
	opts Options
	log  *logger.Logger

	listener net.Listener

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}

	sem    chan struct{}
	nextID atomic.Uint64
}

// New validates the options and prepares a server. It does not bind yet.
func New(opts Options) (*Server, error) {
	if opts.ListenPort <= 0 || opts.ListenPort > 65535 {
		return nil, fmt.Errorf("invalid listen port %d", opts.ListenPort)
	}
	if opts.ServerTLS == nil {
		return nil, errors.New("server TLS config is required")
	}
	if opts.Dialer == nil {
		return nil, errors.New("upstream dialer is required")
	}
	if opts.Log == nil {
		return nil, errors.New("logger is required")
	}
	if len(opts.ServerTLS.Certificates) == 0 && opts.ServerTLS.GetCertificate == nil {
		return nil, errors.New("server TLS config has no certificate")
	}
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = 10 * time.Second
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = 15 * time.Second
	}
	if opts.HalfCloseTimeout <= 0 {
		opts.HalfCloseTimeout = 5 * time.Second
	}
	for i, pattern := range opts.PassthroughHosts {
		pattern = normalizeHost(pattern)
		if pattern == "" {
			continue
		}
		if _, err := path.Match(pattern, "probe.example"); err != nil {
			return nil, fmt.Errorf("tcpTls.passthroughHosts pattern %q: %w", pattern, err)
		}
		opts.PassthroughHosts[i] = pattern
	}
	if opts.MaxLoggedBytes == 0 {
		opts.MaxLoggedBytes = 64 << 10
	}
	if opts.MaxLoggedBytes < 0 {
		opts.MaxLoggedBytes = math.MaxInt64
	}
	if opts.DecodeApplicationData && !opts.LogApplicationData {
		return nil, errors.New("decodeApplicationData requires logApplicationData=true")
	}
	if opts.DecodeApplicationData && !opts.LogHex {
		return nil, errors.New("decodeApplicationData requires logHex=true")
	}
	if opts.MaxConns <= 0 {
		opts.MaxConns = 512
	}

	// Never advertise HTTP protocols on a binary port. The per-connection
	// config below mirrors the client's ALPN list instead.
	serverTLS := opts.ServerTLS.Clone()
	serverTLS.NextProtos = nil
	if serverTLS.MinVersion == 0 {
		serverTLS.MinVersion = tls.VersionTLS12
	}
	opts.ServerTLS = serverTLS

	routes := make(map[string]string, len(opts.Routes))
	for host, raw := range opts.Routes {
		host = normalizeHost(host)
		if host == "" || strings.TrimSpace(raw) == "" {
			continue
		}
		routes[host] = raw
	}
	opts.Routes = routes

	return &Server{
		opts:  opts,
		log:   opts.Log,
		conns: make(map[net.Conn]struct{}),
		sem:   make(chan struct{}, opts.MaxConns),
	}, nil
}

// Listen binds the configured address (for example "127.0.0.1:1119").
func (s *Server) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = ln
	return nil
}

// Addr returns the bound address, or nil before Listen.
func (s *Server) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Serve accepts connections until Close is called.
func (s *Server) Serve() error {
	if s.listener == nil {
		return errors.New("tlsproxy: Serve called before Listen")
	}
	for {
		raw, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || s.isClosed() {
				return nil
			}
			return err
		}
		if !s.acquire() {
			s.log.Printf("TCP connect %s: rejected, %d concurrent connections already active",
				raw.RemoteAddr(), s.opts.MaxConns)
			_ = raw.Close()
			continue
		}
		if !s.track(raw) {
			s.release()
			_ = raw.Close()
			continue
		}
		go func(c net.Conn) {
			defer s.untrack(c)
			defer s.release()
			defer c.Close()
			s.handle(c)
		}(raw)
	}
}

// Close stops accepting and closes every active connection.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.listener
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	return nil
}

func (s *Server) acquire() bool {
	select {
	case s.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) release() { <-s.sem }

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Server) handle(raw net.Conn) {
	id := s.nextID.Add(1)
	remote, local := raw.RemoteAddr().String(), raw.LocalAddr().String()
	started := time.Now()
	handedOff := false
	defer func() {
		if !handedOff {
			s.log.Printf("TCP[%d] CLOSE %s after %s (session not established)",
				id, remote, time.Since(started).Round(time.Millisecond))
		}
	}()
	s.log.Printf("TCP[%d] ACCEPT %s -> %s", id, remote, local)

	// Large enough for a full TLS record (16 KiB + header): the ClientHello is
	// inspected before deciding whether to terminate or tunnel the session.
	br := bufio.NewReaderSize(raw, 32<<10)
	_ = raw.SetReadDeadline(time.Now().Add(s.opts.HandshakeTimeout))
	head, err := br.Peek(1)
	if err != nil {
		_ = raw.SetReadDeadline(time.Time{})
		s.log.Printf("TCP[%d] %s before protocol detection from %s: %v",
			id, describeErr(err), remote, err)
		return
	}
	if head[0] != 0x16 {
		_ = raw.SetReadDeadline(time.Time{})
		handedOff = s.handlePlain(id, raw, br, remote, local, head[0])
		return
	}
	// A TLS record starts with 0x16 and a 0x03 major version. Peek the third
	// byte so an SSLv2-style hello is not mistaken for modern TLS.
	three, peekErr := br.Peek(3)
	_ = raw.SetReadDeadline(time.Time{})
	if peekErr != nil || len(three) < 3 || three[0] != 0x16 || three[1] != 0x03 {
		s.log.Printf("TCP[%d] unsupported TLS framing from %s (%x); closing", id, remote, three)
		return
	}

	// The client may pin the upstream public key. Decide before terminating:
	// once crypto/tls answers the ClientHello, a pinning client has already
	// seen the wrong certificate and will close without sending a request.
	_ = raw.SetReadDeadline(time.Now().Add(s.opts.HandshakeTimeout))
	sniHint, parseErr := peekClientHelloSNI(br)
	_ = raw.SetReadDeadline(time.Time{})
	if parseErr != nil {
		s.log.Printf("TCP[%d] cannot inspect ClientHello from %s for SNI: %v (terminating TLS as usual)",
			id, remote, parseErr)
	} else if up, err := s.upstreamFor(sniHint); err == nil && up.UseTLS && s.shouldPassthrough(up, sniHint) {
		if s.handlePassthrough(id, raw, br, up, sniHint, remote, local) {
			handedOff = true
		}
		return
	}

	client := &bufferedConn{Conn: raw, r: br}
	var sni string
	var clientProtos []string
	tlsClient := tls.Server(client, s.clientTLSConfig(&sni, &clientProtos))

	ctx, cancel := context.WithTimeout(context.Background(), s.opts.HandshakeTimeout)
	_ = raw.SetDeadline(time.Now().Add(s.opts.HandshakeTimeout))
	err = tlsClient.HandshakeContext(ctx)
	cancel()
	_ = raw.SetDeadline(time.Time{})
	if err != nil {
		s.log.Printf("TLS[%d] CLIENT HANDSHAKE FAILED from %s (SNI %s): %v",
			id, remote, displayHost(sni), err)
		return
	}
	state := tlsClient.ConnectionState()
	if state.ServerName != "" {
		sni = state.ServerName
	}
	clientTLS := tlsDescription(state)
	s.log.Printf("TLS[%d] client handshake ok: SNI=%s %s", id, displayHost(sni), clientTLS)

	up, err := s.upstreamFor(sni)
	if err != nil {
		s.log.Printf("TLS[%d] cannot select upstream for %s: %v", id, displayHost(sni), err)
		return
	}

	rawUp, err := s.dial(up.Addr)
	if err != nil {
		s.log.Printf("TLS[%d] UPSTREAM DIAL FAILED %s (%s): %s", id, up.Addr, up.Reason, describeErr(err))
		return
	}
	defer rawUp.Close()

	var upstream net.Conn = rawUp
	upstreamTLS := "none (plaintext)"
	if up.UseTLS {
		cfg := s.upstreamTLSConfig(up.ServerName, clientProtos)
		tlsUp := tls.Client(rawUp, cfg)

		ctx2, cancel2 := context.WithTimeout(context.Background(), s.opts.ConnectTimeout)
		_ = rawUp.SetDeadline(time.Now().Add(s.opts.ConnectTimeout))
		err = tlsUp.HandshakeContext(ctx2)
		cancel2()
		_ = rawUp.SetDeadline(time.Time{})
		if err != nil {
			s.log.Printf("TLS[%d] UPSTREAM HANDSHAKE FAILED for %s (server name %q): %v",
				id, up.Addr, up.ServerName, err)
			return
		}
		stateUp := tlsUp.ConnectionState()
		upstreamTLS = tlsDescription(stateUp)
		upstream = tlsUp
		s.log.Printf("TLS[%d] upstream handshake ok: %s %s", id, up.Addr, upstreamTLS)
	} else {
		s.log.Printf("TLS[%d] upstream %s opened without TLS (explicit route)", id, up.Addr)
	}

	logHost := sni
	if logHost == "" {
		logHost = up.ServerName
		if logHost == "" {
			logHost = hostOnly(up.Addr)
		}
	}
	s.relay(id, logHost, "tls", tlsClient, upstream, clientTLS, upstreamTLS, up.Addr, remote, local)
	handedOff = true
}

func (s *Server) handlePlain(id uint64, raw net.Conn, br *bufio.Reader, remote, local string, first byte) bool {
	if strings.TrimSpace(s.opts.PlaintextUpstream) == "" {
		s.log.Printf("TCP[%d] non-TLS data from %s (first byte 0x%02x); no tcpTls.plaintextUpstream configured, closing",
			id, remote, first)
		return false
	}
	up, err := s.parseUpstream(s.opts.PlaintextUpstream, s.opts.ListenPort, "")
	if err != nil {
		s.log.Printf("TCP[%d] invalid tcpTls.plaintextUpstream: %v", id, err)
		return false
	}
	rawUp, err := s.dial(up.Addr)
	if err != nil {
		s.log.Printf("TCP[%d] PLAINTEXT UPSTREAM DIAL FAILED %s: %s", id, up.Addr, describeErr(err))
		return false
	}
	defer rawUp.Close()
	s.log.Printf("TCP[%d] non-TLS connection from %s routed to explicit plaintext upstream %s",
		id, remote, up.Addr)

	client := &bufferedConn{Conn: raw, r: br}
	s.relay(id, hostOnly(up.Addr), "plaintext", client, rawUp, "none", "none", up.Addr, remote, local)
	return true
}

// handlePassthrough opens the real endpoint and tunnels the bytes without
// terminating TLS. It returns false when the upstream could not be reached.
func (s *Server) handlePassthrough(id uint64, raw net.Conn, br *bufio.Reader, up upstream, sni, remote, local string) bool {
	rawUp, err := s.dial(up.Addr)
	if err != nil {
		s.log.Printf("TLS[%d] PASSTHROUGH UPSTREAM DIAL FAILED %s (%s): %s", id, up.Addr, up.Reason, describeErr(err))
		return false
	}
	defer rawUp.Close()

	host := sni
	if host == "" {
		host = hostOnly(up.Addr)
	}
	client := &bufferedConn{Conn: raw, r: br}
	s.relayPassthrough(id, host, client, rawUp, up.Addr, remote, local)
	return true
}

// shouldPassthrough reports whether the selected destination is configured to
// keep its native TLS session. SNI is optional: clients that pin often dial an
// IP with no SNI and rely on tcpTls.defaultUpstream.
func (s *Server) shouldPassthrough(up upstream, sni string) bool {
	if len(s.opts.PassthroughHosts) == 0 {
		return false
	}
	names := []string{sni, up.ServerName, hostOnly(up.Addr)}
	for _, pattern := range s.opts.PassthroughHosts {
		for _, name := range names {
			name = normalizeHost(name)
			if name == "" {
				continue
			}
			if ok, _ := path.Match(pattern, name); ok {
				return true
			}
		}
	}
	return false
}

// clientTLSConfig mirrors the client's ALPN list for this connection. Without
// it, a binary TLS client that offers its own protocol could fail negotiation
// against the HTTP-oriented list used by port 443.
func (s *Server) clientTLSConfig(sni *string, protos *[]string) *tls.Config {
	base := s.opts.ServerTLS.Clone()
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		*sni = hello.ServerName
		*protos = append([]string(nil), hello.SupportedProtos...)
		if len(hello.SupportedProtos) == 0 {
			return nil, nil
		}
		cfg := base.Clone()
		cfg.GetConfigForClient = nil
		cfg.NextProtos = append([]string(nil), hello.SupportedProtos...)
		return cfg, nil
	}
	return base
}

// upstreamFor chooses the real destination. Without an explicit route the SNI
// host and the local listener port are used, never 127.0.0.1 and never a guess
// based on the port alone.
func (s *Server) upstreamFor(sni string) (upstream, error) {
	virtualHost := normalizeHost(sni)
	if virtualHost == "" {
		if strings.TrimSpace(s.opts.DefaultUpstream) == "" {
			return upstream{}, fmt.Errorf("the client sent no SNI and tcpTls.defaultUpstream is not configured (set it to \"your-server:%d\")", s.opts.ListenPort)
		}
		up, err := s.parseUpstream(s.opts.DefaultUpstream, s.opts.ListenPort, "")
		if err != nil {
			return upstream{}, fmt.Errorf("tcpTls.defaultUpstream: %w", err)
		}
		up.Reason = "tcpTls.defaultUpstream (no SNI)"
		return up, nil
	}
	if raw, ok := s.opts.Routes[virtualHost]; ok {
		up, err := s.parseUpstream(raw, s.opts.ListenPort, virtualHost)
		if err != nil {
			return upstream{}, fmt.Errorf("tcpTls.upstreams[%s]: %w", virtualHost, err)
		}
		up.Reason = "tcpTls.upstreams"
		return up, nil
	}
	return upstream{
		Addr:       net.JoinHostPort(virtualHost, strconv.Itoa(s.opts.ListenPort)),
		ServerName: virtualHost,
		UseTLS:     true,
		Reason:     "SNI + listener port",
	}, nil
}

type upstream struct {
	Addr       string
	ServerName string
	UseTLS     bool
	Reason     string
}

func (s *Server) parseUpstream(raw string, defaultPort int, sni string) (upstream, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return upstream{}, errors.New("empty upstream")
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return upstream{}, err
		}
		host := u.Hostname()
		if host == "" {
			return upstream{}, fmt.Errorf("no host in %q", raw)
		}
		port := u.Port()
		if port == "" {
			port = strconv.Itoa(defaultPort)
		}
		if err := validatePort(port); err != nil {
			return upstream{}, fmt.Errorf("%q: %w", raw, err)
		}
		scheme := strings.ToLower(u.Scheme)
		useTLS := scheme != "http" && scheme != "tcp"
		serverName := host
		if net.ParseIP(host) != nil && sni != "" {
			serverName = sni
		}
		return upstream{
			Addr:       net.JoinHostPort(host, port),
			ServerName: serverName,
			UseTLS:     useTLS,
		}, nil
	}

	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		host = strings.Trim(raw, "[]")
		port = strconv.Itoa(defaultPort)
	}
	if host == "" {
		return upstream{}, fmt.Errorf("no host in %q", raw)
	}
	if err := validatePort(port); err != nil {
		return upstream{}, fmt.Errorf("%q: %w", raw, err)
	}
	serverName := host
	if net.ParseIP(host) != nil && sni != "" {
		serverName = sni
	}
	return upstream{
		Addr:       net.JoinHostPort(host, port),
		ServerName: serverName,
		UseTLS:     true,
	}, nil
}

func (s *Server) upstreamTLSConfig(serverName string, protos []string) *tls.Config {
	cfg := &tls.Config{}
	if s.opts.UpstreamTLSConfig != nil {
		cfg = s.opts.UpstreamTLSConfig.Clone()
	}
	cfg.ServerName = serverName
	cfg.InsecureSkipVerify = s.opts.InsecureUpstream
	cfg.MinVersion = tls.VersionTLS12
	if len(protos) > 0 {
		cfg.NextProtos = append([]string(nil), protos...)
	}
	return cfg
}

func (s *Server) dial(addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.opts.ConnectTimeout)
	defer cancel()
	return s.opts.Dialer.DialContext(ctx, "tcp", addr)
}

func (s *Server) relay(id uint64, host, protocol string, client, upstream net.Conn,
	clientTLS, upstreamTLS, upstreamAddr, remote, local string) {

	started := time.Now()
	port := s.opts.ListenPort
	sess := s.log.OpenTCP(logger.TCPSessionRecord{
		ID:           id,
		Protocol:     protocol,
		Host:         host,
		Port:         port,
		ListenAddr:   local,
		ClientAddr:   remote,
		UpstreamAddr: upstreamAddr,
		ClientTLS:    clientTLS,
		UpstreamTLS:  upstreamTLS,
		LogData:      s.opts.LogApplicationData,
		LogHex:       s.opts.LogHex,
		MaxBytes:     s.opts.MaxLoggedBytes,
		Started:      started,

		DecodeData:         s.opts.DecodeApplicationData,
		DecodedMaxDepth:    s.opts.DecodedMaxDepth,
		DecodedIncludeHex:  s.opts.DecodedIncludeHex,
		DecodedChunkEvents: s.opts.DecodedChunkEvents,
	})

	kind := strings.ToUpper(protocol)
	s.log.Printf("%s[%d] OPEN %s:%d -> %s | client %s | upstream %s",
		kind, id, host, port, upstreamAddr, clientTLS, upstreamTLS)

	st := &stream{
		srv:      s,
		id:       id,
		sess:     sess,
		client:   client,
		upstream: upstream,
	}
	st.run()

	if st.upBytes.Load() == 0 && st.downBytes.Load() == 0 {
		s.log.Printf("%s[%d] no application data: the client closed after the TLS handshake without sending a request (certificate pinning, a rejected certificate, or a wrong region)",
			kind, id)
	}
	summary := fmt.Sprintf("%d B client->upstream (%s); %d B upstream->client (%s); %s",
		st.upBytes.Load(), st.reasonUp(),
		st.downBytes.Load(), st.reasonDown(),
		time.Since(started).Round(time.Millisecond))
	s.log.Printf("%s[%d] CLOSE %s:%d: %s", kind, id, host, port, summary)
	sess.Close(summary)
}

// relayPassthrough copies the still-encrypted stream in both directions. No
// application data is logged or decoded because the proxy never sees plaintext.
func (s *Server) relayPassthrough(id uint64, host string, client, upstream net.Conn,
	upstreamAddr, remote, local string) {

	started := time.Now()
	sess := s.log.OpenTCP(logger.TCPSessionRecord{
		ID:           id,
		Protocol:     "tls-passthrough",
		Host:         host,
		Port:         s.opts.ListenPort,
		ListenAddr:   local,
		ClientAddr:   remote,
		UpstreamAddr: upstreamAddr,
		ClientTLS:    "not terminated (passthrough)",
		UpstreamTLS:  "not terminated (passthrough)",
		Started:      started,
	})
	s.log.Printf("TLS[%d] PASSTHROUGH %s:%d -> %s | TLS is tunneled end to end (not decrypted)",
		id, host, s.opts.ListenPort, upstreamAddr)

	st := &stream{
		srv:      s,
		id:       id,
		sess:     sess,
		client:   client,
		upstream: upstream,
	}
	st.run()

	summary := fmt.Sprintf("%d B client->upstream (%s); %d B upstream->client (%s); %s; encrypted, not decoded",
		st.upBytes.Load(), st.reasonUp(),
		st.downBytes.Load(), st.reasonDown(),
		time.Since(started).Round(time.Millisecond))
	s.log.Printf("TLS[%d] CLOSE %s:%d (passthrough): %s", id, host, s.opts.ListenPort, summary)
	sess.Close(summary)
}

type stream struct {
	srv      *Server
	id       uint64
	sess     *logger.TCPSession
	client   net.Conn
	upstream net.Conn

	upBytes   atomic.Int64
	downBytes atomic.Int64
	aborted   atomic.Bool
	closeOnce sync.Once

	mu         sync.Mutex
	upReason   string
	downReason string
}

func (s *stream) run() {
	var wg sync.WaitGroup
	allDone := make(chan struct{})
	firstDone := make(chan struct{})
	var firstOnce sync.Once
	finish := func() { firstOnce.Do(func() { close(firstDone) }) }

	wg.Add(2)
	go func() {
		defer wg.Done()
		defer finish()
		s.pump(s.client, s.upstream, true, dirClientToUpstream)
	}()
	go func() {
		defer wg.Done()
		defer finish()
		s.pump(s.upstream, s.client, false, dirUpstreamToClient)
	}()
	go func() {
		wg.Wait()
		close(allDone)
	}()

	// Wait for one direction to finish. A half-close only makes sense while
	// the other side may still have data to deliver; it must not keep the
	// socket in FIN_WAIT_2 forever.
	<-firstDone

	if s.aborted.Load() {
		<-allDone
		return
	}
	if s.upBytes.Load() == 0 && s.downBytes.Load() == 0 {
		// No request, no response. There is nothing left to drain: the client
		// gave up right after the handshake (for example a pinning rejection).
		s.setReason(true, "half-close before any application data")
		s.setReason(false, "half-close before any application data")
		s.srv.log.Printf("TCP[%d] closing before any application data; not waiting for the other side", s.id)
		s.closeBoth()
		<-allDone
		return
	}

	grace := s.srv.opts.HalfCloseTimeout
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-allDone:
	case <-timer.C:
		s.setReason(true, "half-close grace expired")
		s.setReason(false, "half-close grace expired")
		s.srv.log.Printf("TCP[%d] half-close grace expired after %s; closing both sides",
			s.id, grace.Round(time.Millisecond))
		s.closeBoth()
		<-allDone
	}
}

func (s *stream) pump(src, dst net.Conn, upstreamDirection bool, direction string) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			wn, werr := dst.Write(buf[:n])
			if wn > 0 {
				if upstreamDirection {
					s.upBytes.Add(int64(wn))
				} else {
					s.downBytes.Add(int64(wn))
				}
				s.sess.Data(direction, buf[:wn])
			}
			if werr != nil {
				s.setReason(upstreamDirection, "write "+describeErr(werr))
				s.srv.log.Printf("TCP[%d] %s write failed: %v", s.id, direction, werr)
				s.abort()
				return
			}
			if wn != n {
				s.setReason(upstreamDirection, "short write")
				s.srv.log.Printf("TCP[%d] %s short write: %d of %d bytes", s.id, direction, wn, n)
				s.abort()
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				s.setReason(upstreamDirection, "eof (FIN/close_notify)")
				s.halfClose(dst, direction)
				return
			}
			if s.aborted.Load() || errors.Is(err, net.ErrClosed) {
				s.setReason(upstreamDirection, "closed")
				return
			}
			reason := describeErr(err)
			s.setReason(upstreamDirection, reason)
			s.srv.log.Printf("TCP[%d] %s read failed: %v", s.id, direction, err)
			s.abort()
			return
		}
	}
}

func (s *stream) halfClose(dst net.Conn, direction string) {
	cw, ok := dst.(interface{ CloseWrite() error })
	if !ok {
		return
	}
	if err := cw.CloseWrite(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.srv.log.Printf("TCP[%d] %s half-close: %v", s.id, direction, err)
	}
}

func (s *stream) abort() {
	s.aborted.Store(true)
	s.closeBoth()
}

func (s *stream) closeBoth() {
	s.closeOnce.Do(func() {
		_ = s.client.Close()
		_ = s.upstream.Close()
	})
}

func (s *stream) setReason(upstreamDirection bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if upstreamDirection {
		if s.upReason == "" {
			s.upReason = reason
		}
		return
	}
	if s.downReason == "" {
		s.downReason = reason
	}
}

func (s *stream) reasonUp() string   { return s.reason(true) }
func (s *stream) reasonDown() string { return s.reason(false) }

func (s *stream) reason(upstreamDirection bool) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if upstreamDirection {
		if s.upReason == "" {
			return "unknown"
		}
		return s.upReason
	}
	if s.downReason == "" {
		return "unknown"
	}
	return s.downReason
}

// peekClientHelloSNI parses the first TLS record without consuming it and
// returns the SNI host name. A nil error with an empty name means the
// ClientHello is well formed but carries no SNI. Because Peek leaves the bytes
// in the reader, the same ClientHello can later be forwarded verbatim to a
// passthrough upstream or handed to crypto/tls.
func peekClientHelloSNI(br *bufio.Reader) (string, error) {
	hdr, err := br.Peek(5)
	if err != nil {
		return "", err
	}
	if hdr[0] != 0x16 || hdr[1] != 0x03 {
		return "", errors.New("not a TLS handshake record")
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen < 4 || recLen > 1<<14 {
		return "", fmt.Errorf("invalid TLS record length %d", recLen)
	}
	rec, err := br.Peek(5 + recLen)
	if err != nil {
		return "", err
	}
	body := rec[5:]
	if body[0] != 0x01 {
		return "", fmt.Errorf("first handshake message is type %d, not ClientHello", body[0])
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if hsLen > len(body)-4 {
		return "", errors.New("ClientHello spans multiple TLS records")
	}
	h := body[4 : 4+hsLen]

	// legacy_version (2) + random (32) + session_id + cipher_suites +
	// compression_methods + extensions.
	p := 34
	if p >= len(h) {
		return "", errors.New("truncated ClientHello")
	}
	sidLen := int(h[p])
	p++
	if p+sidLen+2 > len(h) {
		return "", errors.New("truncated ClientHello session id")
	}
	p += sidLen
	csLen := int(h[p])<<8 | int(h[p+1])
	p += 2
	if p+csLen+1 > len(h) {
		return "", errors.New("truncated ClientHello cipher suites")
	}
	p += csLen
	compLen := int(h[p])
	p++
	if p+compLen > len(h) {
		return "", errors.New("truncated ClientHello compression methods")
	}
	p += compLen
	if p+2 > len(h) {
		return "", nil // TLS 1.0-style hello without extensions: no SNI
	}
	extLen := int(h[p])<<8 | int(h[p+1])
	p += 2
	end := p + extLen
	if end > len(h) {
		end = len(h)
	}
	for p+4 <= end {
		extType := int(h[p])<<8 | int(h[p+1])
		extSize := int(h[p+2])<<8 | int(h[p+3])
		p += 4
		if p+extSize > end {
			return "", errors.New("truncated ClientHello extension")
		}
		if extType == 0 { // server_name
			data := h[p : p+extSize]
			if len(data) < 2 {
				return "", errors.New("truncated server_name extension")
			}
			listLen := int(data[0])<<8 | int(data[1])
			q := 2
			limit := 2 + listLen
			if limit > len(data) {
				limit = len(data)
			}
			for q+3 <= limit {
				nameType := data[q]
				nameLen := int(data[q+1])<<8 | int(data[q+2])
				q += 3
				if q+nameLen > limit {
					return "", errors.New("truncated server_name entry")
				}
				if nameType == 0 {
					return normalizeHost(string(data[q : q+nameLen])), nil
				}
				q += nameLen
			}
		}
		p += extSize
	}
	return "", nil
}

// bufferedConn preserves bytes consumed while sniffing the first record.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func validatePort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q", port)
	}
	return nil
}

// hostOnly strips the port from "host:port" for display in the session record.
func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func displayHost(host string) string {
	if host == "" {
		return "(none)"
	}
	return host
}

func tlsDescription(st tls.ConnectionState) string {
	alpn := st.NegotiatedProtocol
	if alpn == "" {
		alpn = "-"
	}
	return fmt.Sprintf("%s, %s, alpn=%s", tlsVersion(st.Version), tls.CipherSuiteName(st.CipherSuite), alpn)
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS version 0x%04x", v)
	}
}

// describeErr turns a connection error into the diagnostic vocabulary used in
// the logs: EOF/FIN, reset/RST, timeout, local close, or the raw error.
func describeErr(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, io.EOF):
		return "eof (FIN/close_notify)"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected eof"
	case errors.Is(err, net.ErrClosed):
		return "closed locally"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset (RST)"
	case errors.Is(err, syscall.ECONNABORTED):
		return "aborted"
	}
	// On Windows, syscall.ECONNRESET/ECONNABORTED are Winsock error codes and
	// do not always compare equal through errors.Is. Check the errno directly.
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch uintptr(errno) {
		case 10053: // WSAECONNABORTED
			return "aborted"
		case 10054: // WSAECONNRESET
			return "reset (RST)"
		case 10060: // WSAETIMEDOUT
			return "timeout"
		}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "reset by peer"), strings.Contains(msg, "forcibly closed"):
		return "reset (RST)"
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"):
		return "timeout"
	case strings.Contains(msg, "broken pipe"):
		return "broken pipe"
	case strings.Contains(msg, "closed"):
		return "closed locally"
	}
	return "error: " + err.Error()
}
