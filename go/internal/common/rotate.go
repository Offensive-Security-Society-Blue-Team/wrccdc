package common

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RotateConfig controls a password-rotation run across local and (on Windows
// domain controllers) domain accounts.
type RotateConfig struct {
	MinUID        int      // Linux: lowest UID treated as a human account (default 1000)
	MaxUID        int      // Linux: highest UID treated as a human account (default 60000)
	IncludeRoot   bool     // Linux root / Windows built-in Administrator
	IncludeSelf   bool     // rotate the account the tool is running as (default false: avoid self-lockout)
	IncludeDomain bool     // Windows: also rotate AD users when a DC / AD module is present
	Deny          []string // extra account names to leave alone (case-insensitive)
	Length        int
	Symbols       bool
	OutFile       string // credential record destination
	DryRun        bool
}

// Credential is one rotated account.
type Credential struct {
	Scope    string // "local" or "domain"
	User     string
	Password string
	Status   string // "changed", "dry-run", "skipped: <reason>", "error: <msg>"
}

// RotateReport summarizes a run.
type RotateReport struct {
	Host    string
	OS      string
	When    time.Time
	Creds   []Credential
	Skipped []string // "name (reason)" for accounts deliberately left alone
}

func (r *RotateReport) Changed() int {
	n := 0
	for _, c := range r.Creds {
		if c.Status == "changed" || c.Status == "dry-run" {
			n++
		}
	}
	return n
}

// serviceAccountDeny is a baseline of names that are service/system accounts on
// Linux or Windows which must never be rotated even if they happen to carry a
// login shell (git, gitea, postgres, etc. sometimes do). krbtgt is included so
// a careless run never touches the Kerberos service account.
var serviceAccountDeny = []string{
	// unix system / service
	"root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
	"news", "uucp", "proxy", "backup", "list", "irc", "gnats", "nobody",
	"systemd-network", "systemd-resolve", "systemd-timesync", "messagebus",
	"syslog", "_apt", "tss", "uuidd", "tcpdump", "landscape", "pollinate",
	"sshd", "systemd-coredump", "lxd", "dnsmasq", "ntp", "chrony",
	"mysql", "postgres", "redis", "mongodb", "mongod", "nginx", "www-data",
	"apache", "httpd", "named", "bind", "git", "gitea", "forgejo", "nobody4",
	"ftp", "vmail", "dovecot", "dovenull", "postfix", "clamav", "amavis",
	"haproxy", "memcache", "rabbitmq", "elasticsearch", "grafana", "prometheus",
	"docker", "containerd", "nixbld", "snapd",
	// windows built-in / service
	"krbtgt", "guest", "defaultaccount", "wdagutilityaccount",
	"sshd_server", "healthmailbox",
}

// IsServiceAccount reports whether name matches the baseline service/system
// deny list or the caller-supplied extra deny list.
func IsServiceAccount(name string, extra []string) bool {
	ln := strings.ToLower(strings.TrimSpace(name))
	for _, d := range serviceAccountDeny {
		if ln == d {
			return true
		}
	}
	for _, d := range extra {
		if ln == strings.ToLower(strings.TrimSpace(d)) {
			return true
		}
	}
	// Heuristic: nixbld1..N build users and gMSA-style service prefixes.
	if strings.HasPrefix(ln, "nixbld") || strings.HasPrefix(ln, "svc-") ||
		strings.HasPrefix(ln, "svc_") || strings.HasPrefix(ln, "_") {
		return true
	}
	return false
}

// nologinShells are shells that mark an account as non-interactive (service or
// system). An account with one of these is never rotated.
var nologinShells = map[string]bool{
	"/usr/sbin/nologin": true,
	"/sbin/nologin":     true,
	"/usr/bin/nologin":  true,
	"/bin/false":        true,
	"/usr/bin/false":    true,
	"":                  true,
}

// IsLoginShell reports whether shell permits interactive login.
func IsLoginShell(shell string) bool {
	return !nologinShells[strings.TrimSpace(shell)]
}

// RotateAllPasswords dispatches to the platform implementation.
func RotateAllPasswords(cfg RotateConfig) *RotateReport {
	if cfg.MinUID == 0 {
		cfg.MinUID = 1000
	}
	if cfg.MaxUID == 0 {
		cfg.MaxUID = 60000
	}
	if cfg.Length == 0 {
		cfg.Length = 20
	}
	rep := rotateImpl(cfg)
	rep.When = time.Now()
	host, _ := os.Hostname()
	rep.Host = host
	return rep
}

// WriteCredFile writes rotated credentials to a 0600 file as CSV plus a grouped
// summary. The directory is created if needed. Returns the absolute path.
func WriteCredFile(path string, rep *RotateReport) (string, error) {
	if path == "" {
		return "", nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# WRCCDC password rotation record\n")
	fmt.Fprintf(&b, "# host=%s os=%s time=%s\n", rep.Host, rep.OS, rep.When.Format(time.RFC3339))
	fmt.Fprintf(&b, "# KEEP THIS FILE SECRET. Record it off-box, then delete.\n")
	fmt.Fprintf(&b, "scope,username,password,status\n")

	creds := append([]Credential(nil), rep.Creds...)
	sort.Slice(creds, func(i, j int) bool {
		if creds[i].Scope != creds[j].Scope {
			return creds[i].Scope < creds[j].Scope
		}
		return creds[i].User < creds[j].User
	})
	for _, c := range creds {
		// CSV-escape minimally (no commas/newlines expected in our charset).
		fmt.Fprintf(&b, "%s,%s,%s,%s\n", c.Scope, c.User, c.Password, c.Status)
	}
	if len(rep.Skipped) > 0 {
		b.WriteString("\n# skipped (left intentionally alone):\n")
		for _, s := range rep.Skipped {
			fmt.Fprintf(&b, "# - %s\n", s)
		}
	}

	// 0600: owner read/write only.
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return "", err
	}
	abs, _ := filepath.Abs(path)
	// Best-effort tighten on Windows via icacls (chmod bits are advisory there).
	hardenFilePerms(abs)
	return abs, nil
}
