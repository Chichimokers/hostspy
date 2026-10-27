package proxy

import (
	"io"
	"net/http/httptest"
	"testing"

	"github.com/Chichimokers/hostspy/internal/logger"
)

func TestOverrideMatchesHostAndPath(t *testing.T) {
	s := New(Options{
		Log: logger.New(t.TempDir(), false, false),
		Overrides: []Override{{
			Host:        "nydus.battle.net",
			Path:        "/Bnet/zxx/client/bgs-key-fingerprint",
			Status:      200,
			ContentType: "text/plain",
			Body:        []byte("canned"),
			Source:      "test.bkp",
		}},
	})

	cases := []struct {
		name string
		host string
		path string
		want bool
	}{
		{"exact", "nydus.battle.net", "/Bnet/zxx/client/bgs-key-fingerprint", true},
		{"case and port", "NYDUS.battle.net:80", "/Bnet/zxx/client/bgs-key-fingerprint", true},
		{"other path", "nydus.battle.net", "/Bnet/zxx/client/other", false},
		{"other host", "keys.actual.battle.net", "/Bnet/zxx/client/bgs-key-fingerprint", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tc.host+tc.path, nil)
			req.Host = tc.host
			_, ok := s.matchOverride(req)
			if ok != tc.want {
				t.Errorf("matchOverride(%q, %q) = %v, want %v", tc.host, tc.path, ok, tc.want)
			}
		})
	}
}

func TestOverrideServesBodyWithoutUpstream(t *testing.T) {
	s := New(Options{
		Log: logger.New(t.TempDir(), false, false),
		Overrides: []Override{{
			Host:        "keys.actual.battle.net",
			Path:        "/pki/prod/fingerprints.bkp",
			Status:      200,
			ContentType: "text/plain",
			Body:        []byte(`{"pins":["ours"]}`),
			Source:      "test.bkp",
		}},
	})

	req := httptest.NewRequest("GET", "https://keys.actual.battle.net/pki/prod/fingerprints.bkp", nil)
	req.Host = "keys.actual.battle.net"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		t.Errorf("status = %d, want 200", res.StatusCode)
	}
	if got := string(body); got != `{"pins":["ours"]}` {
		t.Errorf("body = %q", got)
	}
	if got := res.Header.Get("Content-Type"); got != "text/plain" {
		t.Errorf("content-type = %q, want text/plain", got)
	}
}
