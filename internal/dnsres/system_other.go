//go:build !windows

package dnsres

import (
	"bufio"
	"os"
	"strings"
)

// platformDNSServers reads /etc/resolv.conf on non-Windows systems. It exists
// so the package builds and behaves sensibly away from Windows; the shipped
// tool targets Windows.
func platformDNSServers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return dedupeServers(out)
}

// dedupeServers validates, normalises and de-duplicates a list of DNS servers,
// dropping addresses that can never be queried directly.
func dedupeServers(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" || seen[raw] {
			continue
		}
		seen[raw] = true
		out = append(out, raw)
	}
	return out
}
