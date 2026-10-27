package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Chichimokers/hostspy/internal/dnsres"
	"github.com/Chichimokers/hostspy/internal/logger"
)

const (
	// maxCapture is how many bytes of each body are kept in memory for the log.
	// Bodies are always forwarded in full; this only bounds log memory.
	maxCapture = 2 << 20
	// maxBuffer is the largest request body buffered in memory so the request
	// can be replayed on transport retries. Bigger bodies are streamed as-is.
	maxBuffer = 32 << 20
)

// hopByHopHeaders are the connection-specific headers defined by RFC 9110/9112.
// They describe the client<->proxy connection, not the request, so they must
// not travel to the upstream (Go's HTTP/2 transport even rejects Connection).
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

type Options struct {
	// Routes maps an inbound host to an upstream base URL. Missing hosts fall
	// back to https://<host>.
	Routes           map[string]string
	Log              *logger.Logger
	InsecureUpstream bool
	// Resolver resolves upstream names through public DNS so the local hosts
	// file (which points those names at us) never causes a forwarding loop.
	Resolver *dnsres.Resolver
	// Overrides serve a fixed local body for matching requests instead of
	// contacting the upstream. They are meant for controlled experiments, for
	// example replacing a certificate pinning database with one that trusts a
	// local CA.
	Overrides []Override
}

// Override is a canned response for one host and path.
type Override struct {
	Host        string
	Path        string
	PathPrefix  bool
	Status      int
	ContentType string
	Headers     map[string]string
	Body        []byte
	// Source is the file the body came from, for the startup and request logs.
	Source string
}

type Server struct {
	routes    map[string]*url.URL
	overrides []Override
	log       *logger.Logger
	client    *http.Client
	resolver  *dnsres.Resolver
	insecure  bool
}

func New(opts Options) *Server {
	routes := make(map[string]*url.URL, len(opts.Routes))
	for host, raw := range opts.Routes {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		routes[strings.ToLower(host)] = u
	}
	resolver := opts.Resolver
	if resolver == nil {
		resolver = dnsres.New(nil)
	}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: opts.InsecureUpstream},
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
		// Forward the client's Accept-Encoding untouched and hand the body back
		// exactly as it arrived. Decoding a response for the log is done on a
		// copy, never on the bytes sent to the client.
		DisableCompression: true,
		DialContext:        resolver.DialContext,
	}
	return &Server{
		routes:    routes,
		overrides: opts.Overrides,
		log:       opts.Log,
		resolver:  resolver,
		insecure:  opts.InsecureUpstream,
		client: &http.Client{
			Transport: tr,
			// Do not follow redirects: the client must see the real response.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// matchOverride returns the first override that matches the request's host and
// path. Host comparison ignores the port and is case-insensitive.
func (s *Server) matchOverride(r *http.Request) (Override, bool) {
	if len(s.overrides) == 0 {
		return Override{}, false
	}
	host := hostOnly(r.Host)
	p := r.URL.Path
	if p == "" {
		p = "/"
	}
	for _, ov := range s.overrides {
		if hostOnly(ov.Host) != host {
			continue
		}
		if ov.PathPrefix {
			if !strings.HasPrefix(p, ov.Path) {
				continue
			}
		} else if p != ov.Path {
			continue
		}
		return ov, true
	}
	return Override{}, false
}

// serveOverride writes the canned body. It never contacts the upstream, so it
// works even when the real host is unreachable.
func (s *Server) serveOverride(w http.ResponseWriter, r *http.Request, ov Override) {
	for k, v := range ov.Headers {
		w.Header().Set(k, v)
	}
	if ov.ContentType != "" {
		w.Header().Set("Content-Type", ov.ContentType)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(ov.Body)))
	status := ov.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(ov.Body)
	}
	s.log.Printf("OVERRIDE %s %s%s -> %d (%d B from %s)",
		r.Method, r.Host, s.log.Redact(r.URL.RequestURI()), status, len(ov.Body), ov.Source)
}

func hostOnly(h string) string {
	if h == "" {
		return h
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(h)
}

func (s *Server) upstreamFor(host string) *url.URL {
	h := hostOnly(host)
	if u, ok := s.routes[h]; ok {
		return u
	}
	return &url.URL{Scheme: "https", Host: h}
}

func defaultPort(scheme string) string {
	if scheme == "http" {
		return "80"
	}
	return "443"
}

// sameAuthority reports whether the client's Host names exactly the same
// upstream authority, so it can be forwarded byte for byte. A port that is only
// the local listening port (for example :8443 while testing) is not forwarded:
// the upstream must see the port it would have seen without the proxy.
func sameAuthority(clientHost string, up *url.URL) bool {
	if up == nil {
		return false
	}
	wantHost, wantPort := hostOnly(up.Host), up.Port()
	if wantPort == "" {
		wantPort = defaultPort(up.Scheme)
	}
	gotHost := clientHost
	gotPort := ""
	if h, p, err := net.SplitHostPort(clientHost); err == nil {
		gotHost, gotPort = h, p
	}
	if gotPort == "" {
		gotPort = wantPort
	}
	return strings.EqualFold(gotHost, wantHost) && gotPort == wantPort
}

// removeHopByHop deletes the connection-specific headers of h, including the
// ones named by its Connection header, and returns the names it removed so the
// log can show exactly what changed.
func removeHopByHop(h http.Header) []string {
	removed := make([]string, 0, 4)
	seen := make(map[string]struct{}, 8)
	del := func(name string) {
		name = http.CanonicalHeaderKey(name)
		if name == "" {
			return
		}
		if _, ok := h[name]; !ok {
			return
		}
		h.Del(name)
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		removed = append(removed, name)
	}
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			del(strings.TrimSpace(name))
		}
	}
	for _, name := range hopByHopHeaders {
		del(name)
	}
	return removed
}

// suppressDefaultUserAgent stops net/http from inventing a User-Agent when the
// client did not send one: an empty value is written as nothing.
func suppressDefaultUserAgent(h http.Header) {
	if _, ok := h["User-Agent"]; !ok {
		h["User-Agent"] = []string{""}
	}
}

type requestBody struct {
	reader    io.ReadCloser
	getBody   func() (io.ReadCloser, error)
	captured  []byte
	truncated bool
	length    int64 // -1 when the body is streamed instead of buffered
}

func capBytes(b []byte) ([]byte, bool) {
	if len(b) <= maxCapture {
		return b, false
	}
	return b[:maxCapture], true
}

// captureRequestBody reads the body so it can be forwarded byte-for-byte and
// replayed on retries. Nothing is ever truncated on the wire: bodies above
// maxBuffer are streamed with the prefix already read in front of the rest.
func captureRequestBody(r *http.Request) (*requestBody, error) {
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return &requestBody{reader: http.NoBody, length: 0}, nil
	}
	head, err := io.ReadAll(io.LimitReader(r.Body, maxBuffer+1))
	if err != nil {
		_ = r.Body.Close()
		return nil, err
	}
	if len(head) <= maxBuffer {
		_ = r.Body.Close()
		data := head
		captured, truncated := capBytes(data)
		return &requestBody{
			reader:    io.NopCloser(bytes.NewReader(data)),
			getBody:   func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil },
			captured:  captured,
			truncated: truncated,
			length:    int64(len(data)),
		}, nil
	}
	// Too large to buffer: forward the prefix already read followed by the live
	// body. Retries are disabled for this request, but no byte is lost.
	rest := struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(head), r.Body), r.Body}
	return &requestBody{
		reader:    rest,
		captured:  head[:maxCapture],
		truncated: true,
		length:    -1,
	}, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if ov, ok := s.matchOverride(r); ok {
		s.serveOverride(w, r, ov)
		return
	}
	up := s.upstreamFor(r.Host)
	if up.Host == "" {
		http.Error(w, "hostspy: cannot determine upstream", http.StatusBadGateway)
		return
	}
	reqURI := s.log.Redact(r.URL.RequestURI())

	if isWebSocket(r) {
		s.handleWebSocket(w, r, up)
		return
	}

	body, err := captureRequestBody(r)
	if err != nil {
		s.log.Printf("ERROR reading request body %s %s%s: %v", r.Method, r.Host, reqURI, err)
		http.Error(w, "hostspy: cannot read request body", http.StatusBadRequest)
		return
	}

	out := r.Clone(r.Context())
	out.URL.Scheme = up.Scheme
	out.URL.Host = up.Host
	if out.URL.Path == "" {
		out.URL.Path = "/"
	}
	out.RequestURI = ""
	// Host must name the upstream virtual host. When it is the same authority
	// the client used, keep it byte for byte (including any explicit port).
	if !sameAuthority(r.Host, up) {
		out.Host = up.Host
	}
	out.Close = false
	out.TransferEncoding = nil
	out.Trailer = nil
	out.Body = body.reader
	out.GetBody = body.getBody
	out.ContentLength = body.length
	out.Header.Del("Content-Length")
	requestRemoved := removeHopByHop(out.Header)
	suppressDefaultUserAgent(out.Header)

	start := time.Now()
	var resp *http.Response
	for attempt := 0; attempt < 3; attempt++ {
		attemptReq := out.Clone(out.Context())
		if attempt == 0 {
			attemptReq.Body = out.Body
		} else {
			if out.GetBody == nil {
				break
			}
			replay, replayErr := out.GetBody()
			if replayErr != nil {
				break
			}
			attemptReq.Body = replay
		}
		resp, err = s.client.Do(attemptReq)
		if err == nil {
			break
		}
		if !retryable(err) || attempt == 2 {
			break
		}
		s.log.Printf("RETRY %s %s%s: %v", r.Method, r.Host, reqURI, err)
		time.Sleep(150 * time.Millisecond)
	}
	if err != nil {
		if isCanceled(err) {
			s.log.Printf("ABORT %s %s%s: client disconnected", r.Method, r.Host, reqURI)
		} else {
			s.log.Printf("ERROR %s %s%s: %v", r.Method, r.Host, reqURI, err)
		}
		http.Error(w, "hostspy: upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Keep the headers exactly as they arrived for the log, then drop only the
	// connection-specific ones before delivering them.
	upstreamHeader := resp.Header.Clone()
	responseRemoved := removeHopByHop(resp.Header)

	noBody := resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusResetContent ||
		resp.StatusCode == http.StatusNotModified ||
		(resp.StatusCode >= 100 && resp.StatusCode < 200)
	if !noBody && resp.ContentLength >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	for k, vv := range resp.Header {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	capture := &cappedBuffer{limit: maxCapture}
	var responseBytes int64
	if r.Method != http.MethodHead && !noBody {
		n, copyErr := io.Copy(io.MultiWriter(w, capture), resp.Body)
		responseBytes = n
		if copyErr != nil && !isCanceled(copyErr) {
			s.log.Printf("ERROR streaming %s %s%s: %v", r.Method, r.Host, reqURI, copyErr)
		}
	}

	reqLog, reqDecoded := decodeForLog(body.captured, r.Header.Get("Content-Encoding"), body.truncated)
	respLog, respDecoded := decodeForLog(capture.Bytes(), upstreamHeader.Get("Content-Encoding"), capture.Truncated())
	s.log.Exchange(logger.Record{
		Request:                r,
		Upstream:               out,
		Status:                 resp.StatusCode,
		ResponseHeader:         upstreamHeader,
		RequestRemovedHeaders:  requestRemoved,
		ResponseRemovedHeaders: responseRemoved,
		RequestBytes:           body.length,
		ResponseBytes:          responseBytes,
		RequestBody:            reqLog,
		ResponseBody:           respLog,
		RequestTruncated:       body.truncated,
		ResponseTruncated:      capture.Truncated(),
		RequestDecoded:         reqDecoded,
		ResponseDecoded:        respDecoded,
		Duration:               time.Since(start),
	})
}

// cappedBuffer keeps the first limit bytes written to it and silently drops
// the rest, so a response can be streamed to the client and captured at once.
type cappedBuffer struct {
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if remaining := c.limit - c.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			c.buf.Write(p[:remaining])
			c.overflow = true
		} else {
			c.buf.Write(p)
		}
	} else if len(p) > 0 {
		c.overflow = true
	}
	return len(p), nil
}

func (c *cappedBuffer) Bytes() []byte { return c.buf.Bytes() }

func (c *cappedBuffer) Truncated() bool { return c.overflow }

// decodeForLog returns a readable copy of body for the log. The bytes sent over
// the wire are never touched: this only affects what is written to disk.
func decodeForLog(body []byte, encoding string, truncated bool) ([]byte, bool) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	if len(body) == 0 || enc == "" || enc == "identity" {
		return body, false
	}
	var reader io.Reader
	switch enc {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return compressedMarker(enc, len(body), truncated), false
		}
		defer zr.Close()
		reader = zr
	case "deflate":
		zr, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			return compressedMarker(enc, len(body), truncated), false
		}
		defer zr.Close()
		reader = zr
	default:
		// br, zstd... would need an extra dependency; show that it is compressed.
		return compressedMarker(enc, len(body), truncated), false
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, maxCapture+1))
	if err != nil && len(decoded) == 0 {
		return compressedMarker(enc, len(body), truncated), false
	}
	if len(decoded) > maxCapture {
		decoded = decoded[:maxCapture]
	}
	return decoded, true
}

func compressedMarker(enc string, size int, truncated bool) []byte {
	note := fmt.Sprintf("(body is %s-compressed: %d bytes captured", enc, size)
	if truncated {
		note += ", log truncated"
	}
	note += "; forwarded unchanged)"
	return []byte(note)
}

func isWebSocket(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// retryable reports whether err is a transient transport failure worth retrying.
func retryable(err error) bool {
	if err == nil || isCanceled(err) {
		return false
	}
	msg := err.Error()
	for _, s := range []string{
		"GOAWAY",
		"server closed idle connection",
		"unexpected EOF",
		"connection reset by peer",
		"use of closed network connection",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// isCanceled reports whether the error means the client hung up.
func isCanceled(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "context canceled") || strings.Contains(msg, "context deadline exceeded")
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request, up *url.URL) {
	reqURI := s.log.Redact(r.URL.RequestURI())
	addr := up.Host
	if up.Port() == "" {
		if up.Scheme == "https" {
			addr = net.JoinHostPort(up.Hostname(), "443")
		} else {
			addr = net.JoinHostPort(up.Hostname(), "80")
		}
	}

	var upConn net.Conn
	var err error
	rawConn, err := s.resolver.DialContext(r.Context(), "tcp", addr)
	if err != nil {
		s.log.Printf("ERROR ws dial %s%s: %v", addr, reqURI, err)
		http.Error(w, "hostspy: ws upstream dial error", http.StatusBadGateway)
		return
	}
	if up.Scheme == "https" {
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName:         up.Hostname(),
			InsecureSkipVerify: s.insecure,
		})
		if err = tlsConn.HandshakeContext(r.Context()); err != nil {
			_ = rawConn.Close()
			s.log.Printf("ERROR ws tls %s%s: %v", addr, reqURI, err)
			http.Error(w, "hostspy: ws upstream tls error", http.StatusBadGateway)
			return
		}
		upConn = tlsConn
	} else {
		upConn = rawConn
	}
	if err != nil {
		s.log.Printf("ERROR ws dial %s%s: %v", addr, reqURI, err)
		http.Error(w, "hostspy: ws upstream dial error", http.StatusBadGateway)
		return
	}
	defer upConn.Close()

	upReq := r.Clone(r.Context())
	upReq.URL.Scheme = up.Scheme
	upReq.URL.Host = up.Host
	if !sameAuthority(r.Host, up) {
		upReq.Host = up.Host
	}
	upReq.RequestURI = ""
	upReq.Close = false
	suppressDefaultUserAgent(upReq.Header)
	// Sec-WebSocket-* are end-to-end here: the handshake is relayed verbatim and
	// frames are copied byte for byte, so permessage-deflate keeps working.
	if err = upReq.Write(upConn); err != nil {
		s.log.Printf("ERROR ws write upstream: %v", err)
		http.Error(w, "hostspy: ws upstream write error", http.StatusBadGateway)
		return
	}

	upReader := bufio.NewReaderSize(upConn, 32*1024)
	resp, err := http.ReadResponse(upReader, upReq)
	if err != nil {
		s.log.Printf("ERROR ws handshake %s%s: %v", r.Host, reqURI, err)
		http.Error(w, "hostspy: ws upstream handshake error", http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hostspy: hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		s.log.Printf("WS HANDSHAKE %s%s -> upstream %d (not upgrading)", r.Host, reqURI, resp.StatusCode)
		upstreamHeader := resp.Header.Clone()
		// Stream the body to the client while keeping a copy for the log: the
		// client still gets every byte, even when the error page is large.
		capture := &cappedBuffer{limit: maxCapture}
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.TeeReader(resp.Body, capture), resp.Body}
		_ = resp.Write(clientConn)
		s.log.Exchange(logger.Record{
			Request:           r,
			Upstream:          upReq,
			Status:            resp.StatusCode,
			ResponseHeader:    upstreamHeader,
			RequestBytes:      r.ContentLength,
			ResponseBytes:     resp.ContentLength,
			ResponseBody:      capture.Bytes(),
			ResponseTruncated: capture.Truncated(),
		})
		return
	}

	if err = resp.Write(clientConn); err != nil {
		return
	}

	s.log.Printf("WS OPEN  %s%s -> %s", r.Host, reqURI, addr)

	done := make(chan struct{}, 2)
	go func() {
		s.pumpWS(upConn, clientBuf.Reader, r.Host, reqURI, ">>")
		done <- struct{}{}
	}()
	go func() {
		s.pumpWS(clientConn, upReader, r.Host, reqURI, "<<")
		done <- struct{}{}
	}()
	<-done
	s.log.Printf("WS CLOSE %s%s", r.Host, reqURI)
}

// pumpWS forwards WebSocket frames byte for byte while decoding them for the log.
func (s *Server) pumpWS(dst io.Writer, src io.Reader, host, uri, dir string) {
	br := bufio.NewReaderSize(src, 32*1024)
	compressedMessage := false
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return
		}
		b0, b1 := hdr[0], hdr[1]
		opcode := b0 & 0x0f
		fin := b0&0x80 != 0
		rsv1 := b0&0x40 != 0
		if rsv1 && (opcode == 0x1 || opcode == 0x2) {
			compressedMessage = true
		}
		masked := b1&0x80 != 0
		length := int64(b1 & 0x7f)

		var ext []byte
		switch length {
		case 126:
			var e [2]byte
			if _, err := io.ReadFull(br, e[:]); err != nil {
				return
			}
			ext = append(ext, e[:]...)
			length = int64(binary.BigEndian.Uint16(e[:]))
		case 127:
			var e [8]byte
			if _, err := io.ReadFull(br, e[:]); err != nil {
				return
			}
			ext = append(ext, e[:]...)
			length = int64(binary.BigEndian.Uint64(e[:]))
		}

		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(br, mask[:]); err != nil {
				return
			}
		}

		if length < 0 || length > 64<<20 {
			return
		}

		payload := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(br, payload); err != nil {
				return
			}
		}

		// Forward the exact original bytes, RSV1 and fragmentation included.
		if _, err := dst.Write(hdr[:2]); err != nil {
			return
		}
		if ext != nil {
			if _, err := dst.Write(ext); err != nil {
				return
			}
		}
		if masked {
			if _, err := dst.Write(mask[:]); err != nil {
				return
			}
		}
		if length > 0 {
			if _, err := dst.Write(payload); err != nil {
				return
			}
		}

		data := payload
		if masked && length > 0 {
			data = make([]byte, length)
			for i := range payload {
				data[i] = payload[i] ^ mask[i%4]
			}
		}
		s.log.WebSocketFrame(host, uri, dir, opcode, data, compressedMessage)
		if fin {
			compressedMessage = false
		}

		if opcode == 0x8 {
			return
		}
	}
}
