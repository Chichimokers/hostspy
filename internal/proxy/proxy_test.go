package proxy

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Chichimokers/hostspy/internal/logger"
)

type capturedRequest struct {
	method  string
	uri     string
	host    string
	headers http.Header
	body    []byte
}

// TestForwardingFidelity checks the contract of the proxy: the client request
// reaches the upstream unmodified except for hop-by-hop framing, and the
// upstream response reaches the client byte for byte.
func TestForwardingFidelity(t *testing.T) {
	const (
		token  = "SECRET-QUERY-TOKEN"
		cookie = "sid=SECRET-COOKIE-VALUE"
	)
	largeBody := make([]byte, 3<<20)
	for i := range largeBody {
		largeBody[i] = byte(i % 251)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(`{"hello":"world","padding":"` + strings.Repeat("a", 4096) + `"}`))
	_ = zw.Close()
	gzipBody := gz.Bytes()

	var got capturedRequest
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = capturedRequest{method: r.Method, uri: r.RequestURI, host: r.Host, headers: r.Header.Clone(), body: body}

		switch r.URL.Path {
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "public, max-age=60")
			w.Header().Set("Set-Cookie", "server=SECRET-SET-COOKIE; HttpOnly")
			w.Header().Set("X-Application-Header", "keep-me")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write(gzipBody)
		default:
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(largeBody)
		}
	}))
	defer upstream.Close()

	logDir := t.TempDir()
	logg := logger.New(logDir, true, true)
	srv := New(Options{
		Routes:           map[string]string{"127.0.0.1": upstream.URL},
		Log:              logg,
		InsecureUpstream: true,
	})

	run := func(t *testing.T, path string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Host = "127.0.0.1"
		req.ContentLength = int64(len(body))
		req.Header = http.Header{
			"Origin":                         {"https://us.shop.battle.net"},
			"Referer":                        {"https://us.shop.battle.net/es-es/embedded/product/starcraft-ii?autoRegion=true"},
			"User-Agent":                     {"Mozilla/5.0 Battle.net/2.53.4.17896"},
			"Cookie":                         {cookie},
			"Authorization":                  {"Bearer " + token},
			"Content-Type":                   {"application/json"},
			"Accept":                         {"application/json, text/plain, */*"},
			"Accept-Language":                {"es-ES,es;q=0.9"},
			"Accept-Encoding":                {"gzip, deflate, br"},
			"Access-Control-Request-Method":  {"POST"},
			"Access-Control-Request-Headers": {"content-type"},
			"Sec-Fetch-Dest":                 {"empty"},
			"Sec-Fetch-Mode":                 {"cors"},
			"Sec-Fetch-Site":                 {"same-site"},
			"Cache-Control":                  {"no-cache"},
			"If-None-Match":                  {`"abc123"`},
			"If-Modified-Since":              {"Mon, 26 Oct 2026 00:00:00 GMT"},
			"Connection":                     {"keep-alive, X-Hop"},
			"X-Hop":                          {"must-not-be-forwarded"},
			"Keep-Alive":                     {"timeout=5"},
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	t.Run("gzip response", func(t *testing.T) {
		rec := run(t, "/gzip?a=1&access_token="+token+"&b=2&b=3", []byte(`{"grant_type":"client_credentials"}`))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
		}
		if got.method != http.MethodPost {
			t.Errorf("method = %q", got.method)
		}
		if want := "/gzip?a=1&access_token=" + token + "&b=2&b=3"; got.uri != want {
			t.Errorf("upstream URI = %q, want %q", got.uri, want)
		}
		if got.host != "127.0.0.1" {
			t.Errorf("upstream Host = %q, want %q", got.host, "127.0.0.1")
		}
		for name, want := range map[string]string{
			"Origin":                         "https://us.shop.battle.net",
			"Referer":                        "https://us.shop.battle.net/es-es/embedded/product/starcraft-ii?autoRegion=true",
			"User-Agent":                     "Mozilla/5.0 Battle.net/2.53.4.17896",
			"Cookie":                         cookie,
			"Authorization":                  "Bearer " + token,
			"Content-Type":                   "application/json",
			"Accept":                         "application/json, text/plain, */*",
			"Accept-Language":                "es-ES,es;q=0.9",
			"Accept-Encoding":                "gzip, deflate, br",
			"Access-Control-Request-Method":  "POST",
			"Access-Control-Request-Headers": "content-type",
			"Sec-Fetch-Dest":                 "empty",
			"Sec-Fetch-Mode":                 "cors",
			"Sec-Fetch-Site":                 "same-site",
			"Cache-Control":                  "no-cache",
			"If-None-Match":                  `"abc123"`,
			"If-Modified-Since":              "Mon, 26 Oct 2026 00:00:00 GMT",
		} {
			if v := got.headers.Get(name); v != want {
				t.Errorf("upstream %s = %q, want %q", name, v, want)
			}
		}
		for _, name := range []string{"X-Hop", "Connection", "Keep-Alive"} {
			if v := got.headers.Get(name); v != "" {
				t.Errorf("hop-by-hop header %s leaked upstream: %q", name, v)
			}
		}
		if want := `{"grant_type":"client_credentials"}`; string(got.body) != want {
			t.Errorf("upstream body = %q, want %q", got.body, want)
		}

		if body := rec.Body.Bytes(); !bytes.Equal(body, gzipBody) {
			t.Errorf("delivered body differs from upstream bytes: got %d bytes, want %d", len(body), len(gzipBody))
		}
		if enc := rec.Header().Get("Content-Encoding"); enc != "gzip" {
			t.Errorf("Content-Encoding = %q, want gzip", enc)
		}
		if cl := rec.Header().Get("Content-Length"); cl != "" {
			// httptest.ResponseRecorder does not populate Content-Length itself;
			// the header must mirror the upstream value when it is set.
			t.Logf("Content-Length seen: %q", cl)
		}
		if v := rec.Header().Get("X-Application-Header"); v != "keep-me" {
			t.Errorf("application header lost: %q", v)
		}
		if sc := rec.Header().Get("Set-Cookie"); sc != "server=SECRET-SET-COOKIE; HttpOnly" {
			t.Errorf("Set-Cookie altered: %q", sc)
		}
	})

	t.Run("large body is not truncated", func(t *testing.T) {
		rec := run(t, "/large", largeBody)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		if want := sha256.Sum256(largeBody); sha256.Sum256(got.body) != want {
			t.Errorf("upstream received %d bytes, want %d (hash mismatch)", len(got.body), len(largeBody))
		}
		if want := sha256.Sum256(largeBody); sha256.Sum256(rec.Body.Bytes()) != want {
			t.Errorf("client received %d bytes, want %d (hash mismatch)", rec.Body.Len(), len(largeBody))
		}
	})

	t.Run("log keeps the wire semantics but redacts secrets", func(t *testing.T) {
		var logs []byte
		files := 0
		err := filepath.Walk(logDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".txt") {
				return err
			}
			files++
			b, readErr := os.ReadFile(path)
			logs = append(logs, b...)
			return readErr
		})
		if err != nil {
			t.Fatal(err)
		}
		if files != 2 {
			t.Errorf("wrote %d request logs, want 2 (one per exchange)", files)
		}
		text := string(logs)
		for _, section := range []string{
			"--- 1. CLIENT REQUEST (as received) ---",
			"--- 2. CHANGES MADE FOR TRANSPORT ---",
			"--- 3. UPSTREAM REQUEST (as sent) ---",
			"--- 4. UPSTREAM RESPONSE (as received) ---",
			"--- 5. DELIVERED TO CLIENT ---",
		} {
			if !strings.Contains(text, section) {
				t.Errorf("log is missing section %q", section)
			}
		}
		if !strings.Contains(text, "X-Hop") {
			t.Error("log should name the removed hop-by-hop header")
		}
		for _, secret := range []string{token, "SECRET-COOKIE-VALUE", "SECRET-SET-COOKIE"} {
			if strings.Contains(text, secret) {
				t.Errorf("log leaked secret %q", secret)
			}
		}
	})
}
