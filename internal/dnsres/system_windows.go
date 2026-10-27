//go:build windows

package dnsres

import (
	"net"
	"strings"
	"syscall"
	"unsafe"
)

// Windows DNS discovery.
//
// The nameservers configured on the adapters live in the registry. Reading them
// there is deliberate: net.LookupIP would consult the hosts file first, and
// HostSpy rewrites that file to point the intercepted domains at 127.0.0.1.
// Querying these servers directly bypasses both the hosts file and the cache.
//
// Per-interface values are preferred over the global ones: with a VPN up, the
// global list can be stale or empty while the tunnel adapter carries the only
// resolver that actually answers.

var (
	modAdvapi32          = syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKeyExW    = modAdvapi32.NewProc("RegOpenKeyExW")
	procRegEnumKeyExW    = modAdvapi32.NewProc("RegEnumKeyExW")
	procRegQueryValueExW = modAdvapi32.NewProc("RegQueryValueExW")
	procRegCloseKey      = modAdvapi32.NewProc("RegCloseKey")
)

const (
	hkeyLocalMachine = 0x80000002
	keyRead          = 0x20019
	regSZ            = 1
	regExpandSZ      = 2
	regMultiSZ       = 7
	errNoMoreItems   = 259
	maxDNSServers    = 6
)

var (
	dnsInterfaceRoots = []string{
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`,
		`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces`,
	}
	dnsGlobalRoots = []string{
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`,
	}
)

// platformDNSServers returns the DNS servers configured on this machine.
func platformDNSServers() []string {
	var raw []string
	for _, root := range dnsInterfaceRoots {
		for _, sub := range enumSubkeys(root) {
			raw = append(raw, queryServerValues(root+`\`+sub)...)
		}
	}
	for _, root := range dnsGlobalRoots {
		raw = append(raw, queryServerValues(root)...)
	}
	return dedupeServers(raw)
}

func openKey(path string) (syscall.Handle, bool) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, false
	}
	var h syscall.Handle
	ret, _, _ := procRegOpenKeyExW.Call(
		uintptr(hkeyLocalMachine),
		uintptr(unsafe.Pointer(p)),
		0,
		keyRead,
		uintptr(unsafe.Pointer(&h)),
	)
	if ret != 0 {
		return 0, false
	}
	return h, true
}

func enumSubkeys(root string) []string {
	h, ok := openKey(root)
	if !ok {
		return nil
	}
	defer procRegCloseKey.Call(uintptr(h))

	var out []string
	buf := make([]uint16, 256)
	for i := 0; ; i++ {
		n := uint32(len(buf))
		ret, _, _ := procRegEnumKeyExW.Call(
			uintptr(h),
			uintptr(i),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&n)),
			0, 0, 0, 0,
		)
		if ret == errNoMoreItems || ret != 0 {
			break
		}
		out = append(out, syscall.UTF16ToString(buf[:n]))
	}
	return out
}

func queryServerValues(keyPath string) []string {
	h, ok := openKey(keyPath)
	if !ok {
		return nil
	}
	defer procRegCloseKey.Call(uintptr(h))

	var out []string
	for _, name := range []string{"NameServer", "DhcpNameServer"} {
		np, err := syscall.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		var typ, size uint32
		buf := make([]uint16, 2048)
		size = uint32(len(buf) * 2)
		ret, _, _ := procRegQueryValueExW.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(np)),
			0,
			uintptr(unsafe.Pointer(&typ)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
		)
		if ret != 0 || size == 0 {
			continue
		}
		switch typ {
		case regSZ, regExpandSZ:
			s := syscall.UTF16ToString(buf)
			out = append(out, strings.FieldsFunc(s, func(r rune) bool {
				return r == ' ' || r == ',' || r == ';' || r == '\t'
			})...)
		case regMultiSZ:
			cur := make([]uint16, 0, 64)
			for _, u := range buf {
				if u == 0 {
					if len(cur) > 0 {
						out = append(out, syscall.UTF16ToString(cur))
						cur = cur[:0]
					}
					continue
				}
				cur = append(cur, u)
			}
		}
	}
	return out
}

// dedupeServers validates, normalises and de-duplicates a list of DNS servers,
// dropping addresses that can never be queried directly.
func dedupeServers(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		raw = strings.TrimPrefix(raw, "[")
		raw = strings.TrimSuffix(raw, "]")
		// IPv6 zone identifiers (fe80::1%12) cannot be used without the zone.
		if i := strings.IndexByte(raw, '%'); i >= 0 {
			raw = raw[:i]
		}
		ip := net.ParseIP(raw)
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			continue
		}
		s := ip.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= maxDNSServers {
			break
		}
	}
	return out
}
