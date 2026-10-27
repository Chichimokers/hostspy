package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Chichimokers/hostspy/internal/ca"
	"github.com/Chichimokers/hostspy/internal/dnsres"
	"github.com/Chichimokers/hostspy/internal/hosts"
	"github.com/Chichimokers/hostspy/internal/logger"
	"github.com/Chichimokers/hostspy/internal/proxy"
	"github.com/Chichimokers/hostspy/internal/tlsproxy"
)

type Config struct {
	ListenHTTPS                string             `json:"listenHTTPS"`
	ListenHTTP                 string             `json:"listenHTTP"`
	ListenIP                   string             `json:"listenIP"`
	LogDir                     string             `json:"logDir"`
	SaveBodies                 bool               `json:"saveBodies"`
	RedactLogs                 bool               `json:"redactLogs"`
	RestoreHostsOnExit         bool               `json:"restoreHostsOnExit"`
	UpstreamInsecureSkipVerify bool               `json:"upstreamInsecureSkipVerify"`
	DNSServers                 []string           `json:"dnsServers"`
	ResolveTimeoutMS           int                `json:"resolveTimeoutMs"`
	CertificateDomains         []string           `json:"certificateDomains"`
	InterceptHosts             []string           `json:"interceptHosts"`
	Upstreams                  map[string]string  `json:"upstreams"`
	InterceptPorts             []int              `json:"interceptPorts"`
	TCPTLS                     TCPTLSConfig       `json:"tcpTls"`
	ResponseOverrides          []ResponseOverride `json:"responseOverrides"`
}

// ResponseOverride serves a local file instead of the real upstream response.
// It exists for controlled experiments (for example, replacing a certificate
// pinning database). bodyFile is resolved relative to the config file.
type ResponseOverride struct {
	Host        string            `json:"host"`
	Path        string            `json:"path"`
	PathPrefix  bool              `json:"pathPrefix"`
	Status      int               `json:"status"`
	ContentType string            `json:"contentType"`
	BodyFile    string            `json:"bodyFile"`
	Headers     map[string]string `json:"headers"`
}

// TCPTLSConfig controls the additional TCP ports that are terminated with TLS
// (for example StarCraft II's 1119 logon port). It is independent of the HTTP
// and HTTPS interceptors; when interceptPorts is empty nothing changes.
type TCPTLSConfig struct {
	LogApplicationData         bool              `json:"logApplicationData"`
	LogHex                     bool              `json:"logHex"`
	MaxLoggedBytesPerDirection int64             `json:"maxLoggedBytesPerDirection"`
	HandshakeTimeoutMS         int               `json:"handshakeTimeoutMs"`
	ConnectTimeoutMS           int               `json:"connectTimeoutMs"`
	Upstreams                  map[string]string `json:"upstreams"`
	DefaultUpstream            string            `json:"defaultUpstream"`
	PlaintextUpstream          string            `json:"plaintextUpstream"`
	PassthroughHosts           []string          `json:"passthroughHosts"`
	HalfCloseTimeoutMS         int               `json:"halfCloseTimeoutMs"`

	// DecodeApplicationData writes a best-effort .decoded.txt sidecar next to
	// each raw TCP log: HTTP upgrade, WebSocket frames and generic protobuf
	// fields. It requires logApplicationData and logHex.
	DecodeApplicationData bool `json:"decodeApplicationData"`
	DecodedMaxDepth       int  `json:"decodedMaxDepth"`
	DecodedIncludeHex     bool `json:"decodedIncludeHex"`
	DecodedChunkEvents    bool `json:"decodedChunkEvents"`
}

func defaults() Config {
	return Config{
		ListenHTTPS:        ":443",
		ListenHTTP:         ":80",
		ListenIP:           "",
		LogDir:             "./logs",
		SaveBodies:         true,
		RedactLogs:         true,
		RestoreHostsOnExit: true,
		DNSServers:         []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"},
	}
}

func main() {
	var (
		cfgPath     = flag.String("config", "config.json", "path to config file")
		installCert = flag.Bool("install-cert", false, "install the generated certificate into LocalMachine\\Root and exit")
		restore     = flag.Bool("restore", false, "remove the hostspy block from the hosts file and exit")
		noHosts     = flag.Bool("no-hosts", false, "do not modify the hosts file")
		regenCert   = flag.Bool("regen-cert", false, "force regeneration of the certificate")
		dnsCheck    = flag.Bool("dns-check", false, "resolve interceptHosts through every DNS source, print a report and exit (does not touch the hosts file)")
	)
	flag.Parse()

	if *restore {
		if err := hosts.Restore(); err != nil {
			fmt.Println("[HOSTSPY] restore failed:", err)
			os.Exit(1)
		}
		fmt.Println("[HOSTSPY] hosts restored")
		return
	}

	cfg := defaults()
	absCfg, _ := filepath.Abs(*cfgPath)
	if b, err := os.ReadFile(absCfg); err == nil {
		if err := json.Unmarshal(b, &cfg); err != nil {
			log.Fatalf("invalid config %s: %v", absCfg, err)
		}
	} else {
		log.Fatalf("config not found: %s", absCfg)
	}
	// Work relative to the config file so logs/certs land next to it.
	baseDir := filepath.Dir(absCfg)
	if !filepath.IsAbs(cfg.LogDir) {
		cfg.LogDir = filepath.Join(baseDir, cfg.LogDir)
	}

	if *dnsCheck {
		dnsReport(cfg)
		return
	}

	all := append([]string{}, cfg.CertificateDomains...)
	all = append(all, cfg.InterceptHosts...)

	certPath, keyPath, err := ca.Ensure(filepath.Join(baseDir, "certs"), all, *regenCert)
	if err != nil {
		log.Fatalf("certificate generation failed: %v", err)
	}
	pair, err := ca.Load(certPath, keyPath)
	if err != nil {
		log.Fatalf("certificate load failed: %v", err)
	}

	if *installCert {
		if err := installCertificate(certPath); err != nil {
			log.Fatalf("certificate install failed: %v", err)
		}
		fmt.Println("[HOSTSPY] certificate installed in LocalMachine\\Root:", certPath)
		return
	}

	logg := logger.New(cfg.LogDir, cfg.SaveBodies, cfg.RedactLogs)

	fmt.Println("[HOSTSPY] ==============================")
	fmt.Println("[HOSTSPY] certificate:", certPath)
	if pair.Leaf != nil {
		fmt.Printf("[HOSTSPY] valid until: %s\n", pair.Leaf.NotAfter.Format(time.RFC3339))
		fmt.Printf("[HOSTSPY] names: %s\n", strings.Join(pair.Leaf.DNSNames, ", "))
	}

	if !*noHosts {
		if _, err := hosts.Backup(); err != nil {
			log.Fatalf("hosts backup failed (run as Administrator?): %v", err)
		}
		// A previous run may have been killed before restoring the file. Its
		// block points real domains at 127.0.0.1 and would poison resolution.
		if removed, err := hosts.RemoveStale(); err != nil {
			fmt.Fprintf(os.Stderr, "[HOSTSPY] warning: cannot clean a stale hosts block: %v\n", err)
		} else if removed {
			fmt.Println("[HOSTSPY] removed a stale hosts block from a previous run (it redirected real domains to 127.0.0.1)")
		}
	}

	// Resolve the real addresses before the hosts file points them at us, so the
	// cache is warm and request handling never blocks on DNS.
	resolver := dnsres.New(cfg.DNSServers)

	intercept := cfg.InterceptHosts
	if !*noHosts {
		resolvable, wildcards := dnsres.SplitResolvable(cfg.InterceptHosts)
		if len(wildcards) > 0 {
			fmt.Printf("[HOSTSPY] ignoring %d wildcard entries (the hosts file has no wildcard support): %s\n",
				len(wildcards), strings.Join(wildcards, ", "))
		}
		via := strings.Join(cfg.DNSServers, ", ")
		if sys := resolver.SystemServers(); len(sys) > 0 {
			via += " and the system resolvers " + strings.Join(sys, ", ")
		} else {
			via += " (no system DNS servers detected)"
		}
		fmt.Printf("[HOSTSPY] resolving %d hosts via %s ...\n", len(resolvable), via)
		var skipped []string
		budget := time.Duration(cfg.ResolveTimeoutMS) * time.Millisecond
		if budget <= 0 {
			budget = 3 * time.Second
		}
		intercept, skipped = resolver.ResolveBatch(context.Background(), resolvable, budget)
		for _, st := range resolver.Stats() {
			fmt.Printf("[HOSTSPY] dns %-22s %3d answered, %3d failed\n", st.Name, st.Answered, st.Failed)
		}
		if len(skipped) > 0 {
			fmt.Printf("[HOSTSPY] skipped %d hosts without a public address: %s\n",
				len(skipped), strings.Join(skipped, ", "))
		}
		fmt.Printf("[HOSTSPY] resolved %d/%d hosts\n", len(intercept), len(resolvable))
		if len(intercept) == 0 {
			fmt.Println("[HOSTSPY] WARNING: nothing resolved, so nothing can be intercepted.")
			fmt.Println("[HOSTSPY]          the hosts file will be left untouched. If a VPN blocks public DNS,")
			fmt.Println("[HOSTSPY]          point dnsServers at a resolver the VPN allows, or fix the VPN's DNS.")
		}
	}

	overrides, err := loadResponseOverrides(baseDir, cfg.ResponseOverrides)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	handler := proxy.New(proxy.Options{
		Routes:           cfg.Upstreams,
		Log:              logg,
		InsecureUpstream: cfg.UpstreamInsecureSkipVerify,
		Resolver:         resolver,
		Overrides:        overrides,
	})
	for _, ov := range overrides {
		kind := "exact"
		if ov.PathPrefix {
			kind = "prefix"
		}
		fmt.Printf("[HOSTSPY] override %s %s (%s) -> %d, %d B from %s\n",
			ov.Host, ov.Path, kind, ov.Status, len(ov.Body), ov.Source)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{*pair},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	// One self-signed certificate is used for HTTP/HTTPS and for the additional
	// TLS ports. If a client asks for a name the certificate does not cover, the
	// warning is explicit: the client may reject the session.
	var certWarned sync.Map
	tlsConf.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName != "" && pair.Leaf != nil {
			if err := pair.Leaf.VerifyHostname(hello.ServerName); err != nil {
				if _, loaded := certWarned.LoadOrStore(strings.ToLower(hello.ServerName), true); !loaded {
					logg.Printf("WARN certificate does not cover %q: %v (the client may reject this TLS session)",
						hello.ServerName, err)
				}
			}
		}
		return pair, nil
	}

	ports, err := interceptPorts(cfg)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	var tcpServers []*tlsproxy.Server
	if len(ports) > 0 {
		baseRoutes := make(map[string]string, len(cfg.Upstreams)+len(cfg.TCPTLS.Upstreams))
		for host, raw := range cfg.Upstreams {
			baseRoutes[host] = raw
		}
		for host, raw := range cfg.TCPTLS.Upstreams {
			baseRoutes[host] = raw
		}
		tcpTLSBase := tlsConf.Clone()
		tcpTLSBase.NextProtos = nil
		for _, port := range ports {
			addr := net.JoinHostPort(cfg.ListenIP, strconv.Itoa(port))
			srv, err := tlsproxy.New(tlsproxy.Options{
				ListenPort:         port,
				ServerTLS:          tcpTLSBase,
				Dialer:             resolver,
				Routes:             baseRoutes,
				DefaultUpstream:    cfg.TCPTLS.DefaultUpstream,
				PlaintextUpstream:  cfg.TCPTLS.PlaintextUpstream,
				PassthroughHosts:   cfg.TCPTLS.PassthroughHosts,
				HalfCloseTimeout:   milliseconds(cfg.TCPTLS.HalfCloseTimeoutMS, 5*time.Second),
				InsecureUpstream:   cfg.UpstreamInsecureSkipVerify,
				Log:                logg,
				LogApplicationData: cfg.TCPTLS.LogApplicationData,
				LogHex:             cfg.TCPTLS.LogHex,
				MaxLoggedBytes:     cfg.TCPTLS.MaxLoggedBytesPerDirection,
				HandshakeTimeout:   milliseconds(cfg.TCPTLS.HandshakeTimeoutMS, 10*time.Second),
				ConnectTimeout:     milliseconds(cfg.TCPTLS.ConnectTimeoutMS, 15*time.Second),

				DecodeApplicationData: cfg.TCPTLS.DecodeApplicationData,
				DecodedMaxDepth:       cfg.TCPTLS.DecodedMaxDepth,
				DecodedIncludeHex:     cfg.TCPTLS.DecodedIncludeHex,
				DecodedChunkEvents:    cfg.TCPTLS.DecodedChunkEvents,
			})
			if err != nil {
				log.Fatalf("tcp tls port %d: %v", port, err)
			}
			// Bind before touching the hosts file: a busy port must not leave the
			// machine redirected to a listener that does not exist.
			if err := srv.Listen(addr); err != nil {
				for _, prev := range tcpServers {
					_ = prev.Close()
				}
				if runtime.GOOS == "windows" {
					fmt.Fprintf(os.Stderr, "[HOSTSPY] hint: Windows may have this port in an excluded range (Hyper-V/WSL/NAT).\n")
					fmt.Fprintf(os.Stderr, "[HOSTSPY] check: netsh interface ipv4 show excludedportrange protocol=tcp\n")
					fmt.Fprintf(os.Stderr, "[HOSTSPY] workaround (Administrator): net stop winnat, start hostspy, then net start winnat when done.\n")
				}
				log.Fatalf("tcp tls listen %s: %v", addr, err)
			}
			tcpServers = append(tcpServers, srv)
		}
	}

	if !*noHosts {
		if len(intercept) == 0 {
			fmt.Println("[HOSTSPY] hosts unchanged (no domains resolved)")
		} else {
			if err := hosts.Apply(intercept, "127.0.0.1"); err != nil {
				log.Fatalf("hosts update failed (run as Administrator?): %v", err)
			}
			fmt.Printf("[HOSTSPY] hosts -> 127.0.0.1 for %d domains\n", len(intercept))
		}
	}

	upstreamDNS := strings.Join(cfg.DNSServers, ", ")
	if sys := resolver.SystemServers(); len(sys) > 0 {
		upstreamDNS += " + system: " + strings.Join(sys, ", ")
	}
	fmt.Printf("[HOSTSPY] upstream DNS: %s (bypasses the hosts file)\n", upstreamDNS)

	httpsSrv := &http.Server{
		Addr:      cfg.ListenIP + cfg.ListenHTTPS,
		Handler:   handler,
		TLSConfig: tlsConf,
		ErrorLog:  log.New(&logWriter{logg}, "", 0),
	}

	httpSrv := &http.Server{
		Addr:     cfg.ListenIP + cfg.ListenHTTP,
		Handler:  handler,
		ErrorLog: log.New(&logWriter{logg}, "", 0),
	}

	errCh := make(chan error, 2+len(tcpServers))

	go func() {
		fmt.Printf("[HOSTSPY] HTTPS listening on %s\n", httpsSrv.Addr)
		if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("https: %w", err)
		}
	}()

	if cfg.ListenHTTP != "" {
		go func() {
			fmt.Printf("[HOSTSPY] HTTP  listening on %s\n", httpSrv.Addr)
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("http: %w", err)
			}
		}()
	}

	for _, srv := range tcpServers {
		mode := "application logging off"
		if cfg.TCPTLS.LogApplicationData {
			mode = "decrypted application data logged"
			if cfg.TCPTLS.DecodeApplicationData {
				mode += " + decoded sidecar"
			}
		}
		if len(cfg.TCPTLS.PassthroughHosts) > 0 {
			mode += "; passthrough (not decrypted): " + strings.Join(cfg.TCPTLS.PassthroughHosts, ", ")
		}
		fmt.Printf("[HOSTSPY] TCP/TLS listening on %s (SNI -> host:port, %s)\n", srv.Addr(), mode)
		go func(s *tlsproxy.Server) {
			if err := s.Serve(); err != nil {
				select {
				case errCh <- fmt.Errorf("tcp tls %s: %w", s.Addr(), err):
				default:
				}
			}
		}(srv)
	}

	fmt.Printf("[HOSTSPY] logs in %s\n", cfg.LogDir)
	fmt.Println("[HOSTSPY] launch the game now. Ctrl+C to stop.")
	fmt.Println("[HOSTSPY] ==============================")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		fmt.Println("[HOSTSPY] server error:", err)
	case <-stop:
		fmt.Println("\n[HOSTSPY] shutting down...")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, srv := range tcpServers {
		_ = srv.Close()
	}
	_ = httpsSrv.Shutdown(ctx)
	_ = httpSrv.Shutdown(ctx)

	if cfg.RestoreHostsOnExit && !*noHosts {
		if err := hosts.Restore(); err != nil {
			fmt.Println("[HOSTSPY] hosts restore failed:", err)
		} else {
			fmt.Println("[HOSTSPY] hosts restored")
		}
	}
}

// interceptPorts validates and de-duplicates the additional TCP/TLS ports. A
// port already served by the HTTP or HTTPS listener is a configuration error:
// two listeners cannot bind the same address and silently skipping one would
// make the hosts redirection point at the wrong service.
func interceptPorts(cfg Config) ([]int, error) {
	if len(cfg.InterceptPorts) == 0 {
		return nil, nil
	}
	occupied := make(map[int]string, 2)
	if p := logger.ListenPort(cfg.ListenHTTPS); p > 0 {
		occupied[p] = "listenHTTPS"
	}
	if p := logger.ListenPort(cfg.ListenHTTP); p > 0 {
		occupied[p] = "listenHTTP"
	}

	seen := make(map[int]struct{}, len(cfg.InterceptPorts))
	ports := make([]int, 0, len(cfg.InterceptPorts))
	for _, port := range cfg.InterceptPorts {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("interceptPorts contains invalid port %d (must be 1-65535)", port)
		}
		if _, dup := seen[port]; dup {
			continue
		}
		if listener, taken := occupied[port]; taken {
			return nil, fmt.Errorf("interceptPorts contains %d, which is already used by %s", port, listener)
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	return ports, nil
}

// milliseconds converts an optional config timeout into a duration. A zero or
// negative value means "use the built-in default".
func milliseconds(ms int, fallback time.Duration) time.Duration {
	if ms <= 0 {
		return fallback
	}
	return time.Duration(ms) * time.Millisecond
}

// loadResponseOverrides reads the canned bodies once at startup. A missing or
// unreadable file is a hard error: silently serving nothing would hide a typo
// while the client keeps failing for an unrelated reason.
func loadResponseOverrides(baseDir string, cfgs []ResponseOverride) ([]proxy.Override, error) {
	out := make([]proxy.Override, 0, len(cfgs))
	for i, c := range cfgs {
		host := strings.TrimSpace(c.Host)
		if host == "" {
			return nil, fmt.Errorf("responseOverrides[%d]: host is required", i)
		}
		p := strings.TrimSpace(c.Path)
		if p == "" {
			return nil, fmt.Errorf("responseOverrides[%d]: path is required", i)
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		file := strings.TrimSpace(c.BodyFile)
		if file == "" {
			return nil, fmt.Errorf("responseOverrides[%d]: bodyFile is required", i)
		}
		if !filepath.IsAbs(file) {
			file = filepath.Join(baseDir, file)
		}
		body, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("responseOverrides[%d]: %w", i, err)
		}
		status := c.Status
		if status == 0 {
			status = http.StatusOK
		}
		out = append(out, proxy.Override{
			Host:        host,
			Path:        p,
			PathPrefix:  c.PathPrefix,
			Status:      status,
			ContentType: c.ContentType,
			Headers:     c.Headers,
			Body:        body,
			Source:      file,
		})
	}
	return out, nil
}

type logWriter struct{ l *logger.Logger }

func (w *logWriter) Write(p []byte) (int, error) {
	w.l.Printf("SERVER %s", strings.TrimRight(string(p), "\r\n"))
	return len(p), nil
}

func installCertificate(certPath string) error {
	if _, err := os.Stat(certPath); err != nil {
		return err
	}
	out, err := exec.Command("certutil", "-addstore", "-f", "Root", certPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// dnsReport prints which resolver actually answers for the intercepted hosts,
// without touching the hosts file. A VPN that blocks public DNS used to surface
// only as "resolved 0 hosts"; this makes the cause explicit.
func dnsReport(cfg Config) {
	resolver := dnsres.New(cfg.DNSServers)
	resolvable, wildcards := dnsres.SplitResolvable(cfg.InterceptHosts)

	fmt.Println("[HOSTSPY] ==============================")
	fmt.Println("[HOSTSPY] DNS CHECK (the hosts file is not touched)")
	fmt.Printf("[HOSTSPY] configured dnsServers: %s\n", strings.Join(cfg.DNSServers, ", "))
	if sys := resolver.SystemServers(); len(sys) > 0 {
		fmt.Printf("[HOSTSPY] system resolvers:     %s\n", strings.Join(sys, ", "))
	} else {
		fmt.Println("[HOSTSPY] system resolvers:     none detected")
	}

	ctx := context.Background()
	probes := []string{"eu.actual.battle.net", "us.actual.battle.net", "keys.actual.battle.net", "oauth.battle.net"}
	fmt.Println("[HOSTSPY] --- probes")
	for _, h := range probes {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, err := resolver.LookupIP(pctx, h)
		cancel()
		if err != nil {
			fmt.Printf("[HOSTSPY]   %-24s FAILED: %v\n", h, err)
			continue
		}
		parts := make([]string, 0, len(ips))
		for _, ip := range ips {
			parts = append(parts, ip.String())
		}
		fmt.Printf("[HOSTSPY]   %-24s %s\n", h, strings.Join(parts, ", "))
	}

	budget := time.Duration(cfg.ResolveTimeoutMS) * time.Millisecond
	if budget <= 0 {
		budget = 3 * time.Second
	}
	// A fresh resolver keeps the probe results from flattering the batch stats.
	batch := dnsres.New(cfg.DNSServers)
	ok, skipped := batch.ResolveBatch(ctx, resolvable, budget)
	fmt.Printf("[HOSTSPY] --- batch: %d ok, %d skipped, %d total (%d wildcard patterns ignored)\n",
		len(ok), len(skipped), len(resolvable), len(wildcards))
	for _, st := range batch.Stats() {
		fmt.Printf("[HOSTSPY]   %-24s %3d answered, %3d failed\n", st.Name, st.Answered, st.Failed)
	}
	if len(skipped) > 0 {
		fmt.Printf("[HOSTSPY]   skipped: %s\n", strings.Join(skipped, ", "))
	}
	switch {
	case len(ok) == 0:
		fmt.Println("[HOSTSPY] RESULT: nothing resolves. Fix the network/VPN DNS before running HostSpy.")
	case len(skipped) > 0:
		fmt.Println("[HOSTSPY] RESULT: partial. Interception would only cover the resolved hosts.")
	default:
		fmt.Println("[HOSTSPY] RESULT: every host resolves. Good to start.")
	}
	fmt.Println("[HOSTSPY] ==============================")
}
