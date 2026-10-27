package dnsres

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSplitResolvable(t *testing.T) {
	in := []string{
		"eu.actual.battle.net",
		"EU.Actual.Battle.Net.",
		"*.googleusercontent.com",
		"",
		"  keys.actual.battle.net  ",
		"*.battle.net",
		"eu.actual.battle.net",
	}
	resolvable, wildcards := SplitResolvable(in)

	wantResolvable := []string{"eu.actual.battle.net", "keys.actual.battle.net"}
	if strings.Join(resolvable, ",") != strings.Join(wantResolvable, ",") {
		t.Fatalf("resolvable = %v, want %v", resolvable, wantResolvable)
	}
	wantWildcards := []string{"*.googleusercontent.com", "*.battle.net"}
	if strings.Join(wildcards, ",") != strings.Join(wantWildcards, ",") {
		t.Fatalf("wildcards = %v, want %v", wildcards, wantWildcards)
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"Example.COM.":       "example.com",
		"  example.com  ":    "example.com",
		"a.b.c":              "a.b.c",
		"":                   "",
		"\tUPPER.example.\n": "upper.example",
	}
	for in, want := range cases {
		if got := normalize(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLookupIPUsesCache(t *testing.T) {
	r := New([]string{"192.0.2.1"}) // TEST-NET-1: never answers.
	r.store("example.com", []net.IP{net.ParseIP("203.0.113.7")})

	ips, err := r.LookupIP(context.Background(), "EXAMPLE.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "203.0.113.7" {
		t.Fatalf("ips = %v, want [203.0.113.7]", ips)
	}
}

func TestLookupIPResolvesLiteralIP(t *testing.T) {
	r := New(nil)
	ips, err := r.LookupIP(context.Background(), "10.1.2.3")
	if err != nil || len(ips) != 1 || ips[0].String() != "10.1.2.3" {
		t.Fatalf("ips = %v, err = %v", ips, err)
	}
}

// A blocked resolver must not hold the caller for longer than its deadline:
// the startup budget is what used to expire before a working resolver was
// tried.
func TestLookupIPHonoursDeadline(t *testing.T) {
	r := New([]string{"192.0.2.1", "192.0.2.2"})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := r.LookupIP(ctx, "definitely-not-a-real-host.invalid"); err == nil {
		t.Fatal("expected an error for an unresolvable host")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("lookup took %v, deadline was 200ms", elapsed)
	}
}

func TestStatsRecordAnswersAndFailures(t *testing.T) {
	r := New(nil)
	errTransport := errors.New("i/o timeout")
	r.noteResult("public DNS 1.1.1.1", errTransport)
	r.noteResult("public DNS 1.1.1.1", errTransport)
	r.noteResult("system DNS 192.168.43.1", nil)

	stats := r.Stats()
	if len(stats) != 2 {
		t.Fatalf("len(stats) = %d, want 2", len(stats))
	}
	if stats[0].Name != "system DNS 192.168.43.1" || stats[0].Answered != 1 {
		t.Fatalf("first stat = %+v, want the answering resolver first", stats[0])
	}
	if stats[1].Name != "public DNS 1.1.1.1" || stats[1].Failed != 2 {
		t.Fatalf("second stat = %+v, want the failing resolver", stats[1])
	}
}

// A source that never answers must be dropped from later lookups instead of
// costing a socket and a timeout for every host in the batch.
func TestCircuitBreakerSkipsDeadSource(t *testing.T) {
	r := New([]string{"192.0.2.1"})
	dead := "public DNS 192.0.2.1"
	errTransport := errors.New("i/o timeout")

	if r.skipDead(dead) {
		t.Fatal("a fresh source must not be considered dead")
	}
	for i := 0; i < 3; i++ {
		r.noteResult(dead, errTransport)
	}
	if !r.skipDead(dead) {
		t.Fatal("three consecutive failures must trip the breaker")
	}

	// An empty answer (NXDOMAIN) proves the resolver is alive and resets it.
	r.noteResult(dead, nil)
	for i := 0; i < 2; i++ {
		r.noteResult(dead, errTransport)
	}
	if r.skipDead(dead) {
		t.Fatal("an answered query must reset the breaker's failure count")
	}
	for i := 0; i < 3; i++ {
		r.noteResult(dead, errTransport)
	}
	if !r.skipDead(dead) {
		t.Fatal("three consecutive failures must trip the breaker again")
	}

	sources := r.lookupSources()
	for _, s := range sources {
		if s.name == dead {
			t.Fatalf("%s should have been filtered out, got %v", dead, sources)
		}
	}
}
