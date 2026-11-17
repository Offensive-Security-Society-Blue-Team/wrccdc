//go:build !windows

package common

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// hardenFilePerms re-applies owner-only permissions (advisory on unix where
// WriteFile already honored the mode).
func hardenFilePerms(path string) { _ = os.Chmod(path, 0o600) }

type passwdEntry struct {
	Name  string
	UID   int
	Home  string
	Shell string
}

func readPasswd() ([]passwdEntry, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []passwdEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		out = append(out, passwdEntry{Name: parts[0], UID: uid, Home: parts[5], Shell: parts[6]})
	}
	return out, sc.Err()
}

func rotateImpl(cfg RotateConfig) *RotateReport {
	rep := &RotateReport{OS: "linux"}

	if !IsPrivileged() && !cfg.DryRun {
		rep.Creds = append(rep.Creds, Credential{
			Scope: "local", User: "-", Status: "error: must run as root to change passwords",
		})
		return rep
	}

	self := ""
	if u, err := user.Current(); err == nil {
		self = u.Username
	}

	entries, err := readPasswd()
	if err != nil {
		rep.Creds = append(rep.Creds, Credential{Scope: "local", User: "-",
			Status: "error: read /etc/passwd: " + err.Error()})
		return rep
	}

	for _, e := range entries {
		reason := skipReasonUnix(e, cfg, self)
		if reason != "" {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("%s (%s)", e.Name, reason))
			continue
		}
		pw := Generate(GenOptions{Length: cfg.Length, Symbols: cfg.Symbols})
		cred := Credential{Scope: "local", User: e.Name, Password: pw}
		if cfg.DryRun {
			cred.Status = "dry-run"
			rep.Creds = append(rep.Creds, cred)
			continue
		}
		// Feed "user:password" on stdin so the secret never appears in argv.
		res := RunStdin(e.Name+":"+pw+"\n", "chpasswd")
		if res.OK() {
			cred.Status = "changed"
		} else {
			cred.Password = "" // do not record a password we failed to set
			cred.Status = "error: chpasswd: " + firstLine(res.Stderr)
		}
		rep.Creds = append(rep.Creds, cred)
	}
	return rep
}

// skipReasonUnix returns "" if the account should be rotated, else the reason
// to skip it.
func skipReasonUnix(e passwdEntry, cfg RotateConfig, self string) string {
	if e.UID == 0 {
		if cfg.IncludeRoot && (cfg.IncludeSelf || e.Name != self) {
			return "" // rotate root
		}
		if e.Name == self && !cfg.IncludeSelf {
			return "current user (use --include-self to override)"
		}
		return "root (use --include-root to rotate)"
	}
	if !cfg.IncludeSelf && e.Name == self {
		return "current user (use --include-self to override)"
	}
	if IsServiceAccount(e.Name, cfg.Deny) {
		return "service/system account"
	}
	if !IsLoginShell(e.Shell) {
		return "non-login shell (" + e.Shell + ")"
	}
	if e.UID < cfg.MinUID || e.UID > cfg.MaxUID {
		return fmt.Sprintf("uid %d outside human range %d-%d", e.UID, cfg.MinUID, cfg.MaxUID)
	}
	return ""
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if s == "" {
		return "unknown error"
	}
	return s
}
