package dnsres

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Resolver resolves upstream hostnames through explicit DNS servers so that the
// local hosts file (which we rewrite to point at 127.0.0.1) never affects
// outbound requests.
//
// Go's net.Resolver always consults the hosts file before DNS, even with a
// custom Dial hook, so the wire protocol is implemented here directly.
//
// Configured servers (dnsServers) are tried first-class, but they are not
// trusted to exist: a VPN or a captive portal often blocks public resolvers
// (1.1.1.1, 8.8.8.8, 9.9.9.9). The DNS servers actually configured on the
// operating system are queried in parallel as a fallback, read from the
// registry on Windows so the (possibly poisoned) hosts file is never involved.
type Resolver struct {
	servers []string
	ttl     time.Duration
	timeout time.Duration

	mu       sync.Mutex
	cache    map[string]entry
	snapshot map[string][]net.IP

	sysMu      sync.Mutex
	sysServers []string
	sysExpires time.Time

	statsMu sync.Mutex
	stats   map[string]*SourceStat
	health  map[string]*sourceHealth
}

type entry struct {
	ips     []net.IP
	expires time.Time
}

// SourceStat reports how often one DNS source answered and how often it failed,
// so the startup summary can make a blocked public resolver visible instead of
// silent. "Answered" includes empty answers (NXDOMAIN): the resolver did reply.
type SourceStat struct {
	Name     string
	Answered int
	Failed   int
}

// sourceHealth is a small circuit breaker: a resolver that fails three times in
// a row is skipped for a while. With a VPN up, half the adapters in the
// registry carry resolvers that cannot be reached at all; letting them hold a
// socket for every host only adds contention.
type sourceHealth struct {
	fails int
	until time.Time
}

func New(servers []string) *Resolver {
	if len(servers) == 0 {
		servers = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	}
	return &Resolver{
		servers:  servers,
		ttl:      5 * time.Minute,
		timeout:  2 * time.Second,
		cache:    map[string]entry{},
		snapshot: map[string][]net.IP{},
		stats:    map[string]*SourceStat{},
		health:   map[string]*sourceHealth{},
	}
}

// SystemServers returns the DNS servers configured on the operating system,
// bypassing the hosts file. The result is cached for a short time so a network
// change (VPN connect/disconnect) is picked up without a restart.
func (r *Resolver) SystemServers() []string {
	r.sysMu.Lock()
	defer r.sysMu.Unlock()
	if time.Now().Before(r.sysExpires) {
		return append([]string(nil), r.sysServers...)
	}
	servers := platformDNSServers()
	if len(servers) > 0 {
		r.sysServers = servers
		r.sysExpires = time.Now().Add(2 * time.Minute)
	}
	return append([]string(nil), servers...)
}

// Snapshot records the current system resolution of the given hosts. It is a
// last-resort cache only: because it goes through net.LookupIP it is affected
// by the hosts file, so it must be called before that file is rewritten.
func (r *Resolver) Snapshot(hosts []string) {
	for _, h := range hosts {
		h = normalize(h)
		if h == "" {
			continue
		}
		ips, err := net.LookupIP(h)
		if err != nil || len(ips) == 0 {
			continue
		}
		usable := make([]net.IP, 0, len(ips))
		for _, ip := range ips {
			if !ip.IsLoopback() {
				usable = append(usable, ip)
			}
		}
		if len(usable) == 0 {
			continue
		}
		r.mu.Lock()
		r.snapshot[h] = usable
		r.mu.Unlock()
	}
}

// SplitResolvable separates hosts that can be resolved from wildcard patterns.
// A hosts file has no wildcard support, so patterns such as
// "*.googleusercontent.com" can neither be resolved nor be written usefully.
func SplitResolvable(hosts []string) (resolvable, wildcards []string) {
	seen := map[string]bool{}
	for _, h := range hosts {
		h = normalize(h)
		if h == "" {
			continue
		}
		if strings.Contains(h, "*") || strings.Contains(h, "?") {
			if !seen[h] {
				seen[h] = true
				wildcards = append(wildcards, h)
			}
			continue
		}
		if seen[h] {
			continue
		}
		seen[h] = true
		resolvable = append(resolvable, h)
	}
	return resolvable, wildcards
}

// ResolveBatch resolves every host concurrently within a global budget and
// primes the cache with the real addresses, so request handling never has to
// wait on DNS. Hosts without a usable public address are returned as skipped.
func (r *Resolver) ResolveBatch(parent context.Context, hosts []string, budget time.Duration) (ok []string, skipped []string) {
	const workers = 8

	resolvable, _ := SplitResolvable(hosts)
	if budget <= 0 {
		budget = 3 * time.Second
	}
	// Guarantee every host at least one full attempt. With N workers the batch
	// needs ceil(hosts/workers) waves and an unresponsive resolver costs one
	// query timeout per host, so a 3s budget used to expire while the working
	// resolver was still being reached: all hosts were then reported as
	// "skipped" even though DNS was fine.
	if waves := (len(resolvable) + workers - 1) / workers; waves > 0 {
		if min := time.Duration(waves) * r.timeout; budget < min {
			budget = min
		}
	}

	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()

	type result struct {
		host string
		ips  []net.IP
	}

	results := make(chan result, len(resolvable))
	sem := make(chan struct{}, workers)
	for _, h := range resolvable {
		h := h
		go func() {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results <- result{host: h}
				return
			}
			defer func() { <-sem }()
			ips, _ := r.LookupIP(ctx, h)
			results <- result{host: h, ips: ips}
		}()
	}

	for i := 0; i < len(resolvable); i++ {
		res := <-results
		usable := make([]net.IP, 0, len(res.ips))
		for _, ip := range res.ips {
			if !ip.IsLoopback() {
				usable = append(usable, ip)
			}
		}
		if len(usable) == 0 {
			skipped = append(skipped, res.host)
			continue
		}
		// Keep startup results for longer: public DNS may be blocked later.
		r.mu.Lock()
		r.cache[normalize(res.host)] = entry{ips: usable, expires: time.Now().Add(30 * time.Minute)}
		r.mu.Unlock()
		ok = append(ok, res.host)
	}
	return
}

// Stats returns a per-source breakdown, ordered by number of successful
// lookups. It lets the caller print which resolver actually worked.
func (r *Resolver) Stats() []SourceStat {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	out := make([]SourceStat, 0, len(r.stats))
	for _, st := range r.stats {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Answered != out[j].Answered {
			return out[i].Answered > out[j].Answered
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// noteResult records one attempt. A transport error also feeds the circuit
// breaker; an empty answer means the resolver is alive and should stay in use.
func (r *Resolver) noteResult(name string, err error) {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	st := r.stats[name]
	if st == nil {
		st = &SourceStat{Name: name}
		r.stats[name] = st
	}
	h := r.health[name]
	if h == nil {
		h = &sourceHealth{}
		r.health[name] = h
	}
	if err == nil {
		st.Answered++
		h.fails = 0
		return
	}
	st.Failed++
	h.fails++
	if h.fails >= 3 {
		h.until = time.Now().Add(60 * time.Second)
	}
}

// skipDead reports whether a source failed repeatedly and is cooling down.
func (r *Resolver) skipDead(name string) bool {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	h := r.health[name]
	return h != nil && h.fails >= 3 && time.Now().Before(h.until)
}

func normalize(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

type lookupSource struct {
	name string
	fn   func(context.Context, string) ([]net.IP, error)
}

// lookupSources builds the list of resolvers to race for every lookup. The
// configured public resolvers and the operating system's own resolvers are
// queried in parallel: whichever answers first wins. Sequential fallback would
// be useless here, because three blocked public resolvers already exceed the
// startup budget before the working resolver is even tried.
func (r *Resolver) lookupSources() []lookupSource {
	var all []lookupSource
	seen := map[string]bool{}
	add := func(prefix string, servers []string) {
		for _, s := range servers {
			s = strings.TrimSpace(s)
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			server := s
			all = append(all, lookupSource{
				name: prefix + server,
				fn: func(ctx context.Context, host string) ([]net.IP, error) {
					return r.queryHost(ctx, server, host)
				},
			})
		}
	}
	add("public DNS ", r.servers)
	add("system DNS ", r.SystemServers())

	live := make([]lookupSource, 0, len(all))
	for _, s := range all {
		if !r.skipDead(s.name) {
			live = append(live, s)
		}
	}
	// If everything is cooling down, still try: a stale breaker must never
	// leave the caller without any resolver.
	if len(live) == 0 {
		return all
	}
	return live
}

func (r *Resolver) queryHost(ctx context.Context, server, host string) ([]net.IP, error) {
	ips, err := r.query(ctx, server, host, 1) // A
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		ips, err = r.query(ctx, server, host, 28) // AAAA
		if err != nil {
			return nil, err
		}
	}
	return ips, nil
}

func (r *Resolver) fromCache(host string) ([]net.IP, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.cache[host]; ok && time.Now().Before(e.expires) {
		return append([]net.IP(nil), e.ips...), true
	}
	return nil, false
}

func (r *Resolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	host = normalize(host)
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if ips, ok := r.fromCache(host); ok {
		return ips, nil
	}

	sources := r.lookupSources()

	// Cancel the losing queries as soon as one resolver answers. Without this,
	// every lookup leaves len(sources)-1 sockets blocked until their own
	// timeout, which on a slow link congests DNS enough to fail the whole batch.
	lookupCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		source lookupSource
		ips    []net.IP
		err    error
	}

	ch := make(chan result, len(sources))
	for _, s := range sources {
		s := s
		go func() {
			ips, err := s.fn(lookupCtx, host)
			ch <- result{source: s, ips: ips, err: err}
		}()
	}

	var problems []string
	remaining := len(sources)
	for remaining > 0 {
		select {
		case <-ctx.Done():
			problems = append(problems, ctx.Err().Error())
			remaining = 0
		case res := <-ch:
			remaining--
			if len(res.ips) > 0 {
				usable := make([]net.IP, 0, len(res.ips))
				for _, ip := range res.ips {
					if !ip.IsLoopback() {
						usable = append(usable, ip)
					}
				}
				if len(usable) > 0 {
					r.noteResult(res.source.name, nil)
					cancel()
					r.store(host, usable)
					return usable, nil
				}
			}
			r.noteResult(res.source.name, res.err)
			if res.err != nil {
				problems = append(problems, res.source.name+": "+res.err.Error())
			}
		}
	}

	// Last resort: a value captured before the hosts file was rewritten.
	r.mu.Lock()
	snap := append([]net.IP(nil), r.snapshot[host]...)
	r.mu.Unlock()
	if len(snap) > 0 {
		r.store(host, snap)
		return snap, nil
	}

	if len(sources) == 0 {
		return nil, fmt.Errorf("dns lookup %s failed: no dns servers configured and none found on this system", host)
	}
	if len(problems) == 0 {
		return nil, fmt.Errorf("dns lookup %s failed: no records returned by any resolver", host)
	}
	return nil, fmt.Errorf("dns lookup %s failed: %s", host, strings.Join(problems, "; "))
}

func (r *Resolver) store(host string, ips []net.IP) {
	r.mu.Lock()
	r.cache[host] = entry{ips: ips, expires: time.Now().Add(r.ttl)}
	r.mu.Unlock()
}

// DialContext resolves host through the configured resolvers and connects to
// the resulting IP. TLS SNI / Host headers keep using the original hostname.
func (r *Resolver) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second}

	if ip := net.ParseIP(host); ip != nil {
		return dialer.DialContext(ctx, network, addr)
	}

	ips, err := r.LookupIP(ctx, host)
	if err != nil {
		return nil, err
	}

	var lastErr error
	var loopbackOnly bool
	for _, ip := range ips {
		if ip.IsLoopback() {
			loopbackOnly = true
			continue
		}
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		if loopbackOnly {
			return nil, fmt.Errorf("refusing to forward %s to loopback (hosts recursion)", host)
		}
		return nil, fmt.Errorf("no usable address for %s", host)
	}
	return nil, lastErr
}

// ---- minimal DNS client (UDP with TCP fallback on truncation) ----

func (r *Resolver) query(ctx context.Context, server, host string, qtype uint16) ([]net.IP, error) {
	msg, id, err := buildQuery(host, qtype)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(r.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	resp, err := exchangeUDP(ctx, server, msg, deadline)
	if err != nil {
		return nil, err
	}
	if len(resp) < 12 || binary.BigEndian.Uint16(resp[0:2]) != id {
		return nil, errors.New("invalid dns response")
	}
	// Truncated: retry over TCP.
	if resp[2]&0x02 != 0 {
		resp, err = exchangeTCP(ctx, server, msg, deadline)
		if err != nil {
			return nil, err
		}
	}
	rcode := resp[3] & 0x0f
	if rcode != 0 {
		if rcode == 3 {
			return nil, nil // NXDOMAIN
		}
		return nil, fmt.Errorf("dns rcode %d", rcode)
	}
	return parseAnswers(resp, qtype)
}

func buildQuery(host string, qtype uint16) ([]byte, uint16, error) {
	id := uint16(rand.Intn(65536))
	buf := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCOUNT

	for _, label := range strings.Split(normalize(host), ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			return nil, 0, errors.New("dns label too long")
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0) // root
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], 1) // IN
	buf = append(buf, tail[:]...)
	return buf, id, nil
}

func exchangeUDP(ctx context.Context, server string, msg []byte, deadline time.Time) ([]byte, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(server, "53"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	// Abort a blocked Read when the caller cancels (another resolver won).
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stop:
		}
	}()

	if _, err = conn.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return buf[:n], nil
}

func exchangeTCP(ctx context.Context, server string, msg []byte, deadline time.Time) ([]byte, error) {
	dialer := &net.Dialer{Timeout: time.Until(deadline)}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(server, "53"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stop:
		}
	}()

	framed := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(framed[0:2], uint16(len(msg)))
	copy(framed[2:], msg)
	if _, err = conn.Write(framed); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err = io.ReadFull(conn, l[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err = io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func parseAnswers(msg []byte, qtype uint16) ([]net.IP, error) {
	if len(msg) < 12 {
		return nil, errors.New("short dns message")
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))

	off := 12
	var err error
	for i := 0; i < qd; i++ {
		if off, err = skipName(msg, off); err != nil {
			return nil, err
		}
		off += 4
		if off > len(msg) {
			return nil, errors.New("truncated question")
		}
	}

	var ips []net.IP
	for i := 0; i < an; i++ {
		if off, err = skipName(msg, off); err != nil {
			return nil, err
		}
		if off+10 > len(msg) {
			return nil, errors.New("truncated rr")
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return nil, errors.New("truncated rdata")
		}
		if typ == qtype {
			switch typ {
			case 1:
				if rdlen == 4 {
					ips = append(ips, net.IPv4(msg[off], msg[off+1], msg[off+2], msg[off+3]))
				}
			case 28:
				if rdlen == 16 {
					ip := make(net.IP, 16)
					copy(ip, msg[off:off+16])
					ips = append(ips, ip)
				}
			}
		}
		off += rdlen
	}
	return ips, nil
}

func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, errors.New("truncated name")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return 0, errors.New("truncated pointer")
			}
			return off + 2, nil
		case l&0xC0 != 0:
			return 0, errors.New("bad label length")
		default:
			off += 1 + l
		}
	}
}
