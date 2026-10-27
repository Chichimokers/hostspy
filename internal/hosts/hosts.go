package hosts

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

const (
	markerStart = "# HOSTSPY-START"
	markerEnd   = "# HOSTSPY-END"
)

func Path() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	return "/etc/hosts"
}

func Backup() (string, error) {
	path := Path()
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	backup := path + ".hostspy.bak"
	if err := os.WriteFile(backup, b, 0644); err != nil {
		return "", err
	}
	return backup, nil
}

// RemoveStale deletes a leftover HOSTSPY block, for example after a run that
// was killed before it could restore the file. Such a block points real domains
// at 127.0.0.1, which poisons every lookup performed through the local resolver
// and leaves the game broken while HostSpy is not running. Call it before
// resolving upstream addresses.
func RemoveStale() (bool, error) {
	path := Path()
	content, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	s := string(content)
	if !strings.Contains(s, markerStart) {
		return false, nil
	}
	if err := RemoveBlock(&s); err != nil {
		return false, err
	}
	if err := os.WriteFile(path, []byte(s), 0644); err != nil {
		return false, err
	}
	FlushDNS()
	return true, nil
}

func Apply(domains []string, ip string) error {
	path := Path()
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	s := string(content)
	if strings.Contains(s, markerStart) {
		// Replace an existing block instead of failing.
		if err := RemoveBlock(&s); err != nil {
			return err
		}
	}

	var sb strings.Builder
	sb.WriteString(s)
	if !strings.HasSuffix(s, "\n") {
		sb.WriteString("\n")
	}
	sb.WriteString(markerStart + "\n")
	seen := map[string]bool{}
	for _, d := range domains {
		d = strings.TrimSpace(d)
		// The hosts file has no wildcard support: writing "*.example.com"
		// does nothing useful and only confuses readers of the file.
		if d == "" || strings.ContainsAny(d, "*?") {
			continue
		}
		key := strings.ToLower(d)
		if seen[key] {
			continue
		}
		seen[key] = true
		sb.WriteString(fmt.Sprintf("%s %s\n", ip, d))
	}
	sb.WriteString(markerEnd + "\n")

	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		return err
	}
	FlushDNS()
	return nil
}

func Restore() error {
	path := Path()
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	s := string(content)
	if !strings.Contains(s, markerStart) {
		return errors.New("no hostspy block found in hosts")
	}
	if err := RemoveBlock(&s); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(s), 0644); err != nil {
		return err
	}
	FlushDNS()
	return nil
}

func RemoveBlock(s *string) error {
	start := strings.Index(*s, markerStart)
	if start == -1 {
		return errors.New("no start marker")
	}
	end := strings.Index(*s, markerEnd)
	if end == -1 || end < start {
		// Unterminated block (interrupted write or manual edit): drop
		// everything from the marker to the end of the file so the
		// poisoned entries cannot survive.
		*s = strings.TrimRight((*s)[:start], " \t\r\n") + "\n"
		return nil
	}
	end += len(markerEnd)
	if end < len(*s) && (*s)[end] == '\n' {
		end++
	}
	*s = (*s)[:start] + (*s)[end:]
	return nil
}

// FlushDNS clears the Windows resolver cache so the hosts change takes effect
// immediately for processes that already queried those names.
func FlushDNS() {
	if runtime.GOOS != "windows" {
		return
	}
	_ = exec.Command("ipconfig", "/flushdns").Run()
}
