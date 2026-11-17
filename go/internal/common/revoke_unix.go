//go:build !windows

package common

import (
	"os"
	"os/user"
	"regexp"
	"strings"
)

func revokeImpl(cfg RevokeConfig) *RevokeReport {
	rep := &RevokeReport{OS: "linux"}
	if !IsPrivileged() {
		rep.fail("must run as root to revoke sessions")
		return rep
	}

	self := ""
	if u, err := user.Current(); err == nil {
		self = u.Username
	}
	mySession := currentSessionID()

	// 1) Terminate individual login sessions (precise; safe for root because we
	//    only kill the specific login, not every root process).
	if Have("loginctl") {
		terminateLoginctlSessions(cfg, self, mySession, rep)
	} else {
		terminateTTYSessions(cfg, self, rep)
	}

	// 2) Backstop: kill stray processes owned by human users (catches detached
	//    red-team processes not attached to a login session). Root and the
	//    current user are never swept wholesale.
	entries, err := readPasswd()
	if err == nil {
		seen := map[string]bool{}
		for _, e := range entries {
			if e.UID < cfg.minUID() || e.UID > 60000 {
				continue // skip system/service and nologin ranges
			}
			if seen[e.Name] {
				continue
			}
			seen[e.Name] = true
			if !cfg.IncludeSelf && e.Name == self {
				rep.act("kept current user %q processes", e.Name)
				continue
			}
			if IsServiceAccount(e.Name, cfg.Deny) {
				continue
			}
			res := Run("pkill", "-KILL", "-u", e.Name)
			// pkill exits 1 when no processes matched; that is success for us.
			if res.ExitCode == 0 {
				rep.act("killed processes for user %q", e.Name)
			} else if res.ExitCode == 1 {
				rep.act("no live processes for user %q", e.Name)
			} else {
				rep.fail("pkill -u %s: %s", e.Name, firstLine(res.Stderr))
			}
		}
	} else {
		rep.fail("read /etc/passwd: %v", err)
	}

	return rep
}

func (c RevokeConfig) minUID() int { return 1000 }

// currentSessionID returns the systemd login session id of this process, or "".
// It prefers XDG_SESSION_ID, then derives the id from our own cgroup, which
// stays correct even under sudo where the env var is often unset.
func currentSessionID() string {
	if id := strings.TrimSpace(os.Getenv("XDG_SESSION_ID")); id != "" {
		return id
	}
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		if m := sessionScopeRe.FindStringSubmatch(string(data)); m != nil {
			return m[1]
		}
	}
	return ""
}

var sessionScopeRe = regexp.MustCompile(`session-(\w+)\.scope`)

func terminateLoginctlSessions(cfg RevokeConfig, self, mySession string, rep *RevokeReport) {
	res := Run("loginctl", "list-sessions", "--no-legend")
	if !res.OK() {
		rep.fail("loginctl list-sessions: %s", firstLine(res.Stderr))
		return
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		sess := fields[0]
		userName := fields[2]
		if sess == mySession {
			rep.act("kept own login session %s (%s)", sess, userName)
			continue
		}
		if !cfg.IncludeSelf && userName == self && mySession == "" {
			// We could not identify our own session id; be conservative and
			// skip our own username to avoid self-termination.
			rep.act("kept session %s for current user %q (own session id unknown)", sess, userName)
			continue
		}
		if IsServiceAccount(userName, cfg.Deny) {
			continue
		}
		r := Run("loginctl", "terminate-session", sess)
		if r.OK() {
			rep.act("terminated login session %s (%s)", sess, userName)
		} else {
			rep.fail("terminate-session %s: %s", sess, firstLine(r.Stderr))
		}
	}
}

// terminateTTYSessions is the non-systemd fallback (e.g. Alpine/OpenRC). It
// reads `who` and kills processes bound to each tty except our own.
func terminateTTYSessions(cfg RevokeConfig, self string, rep *RevokeReport) {
	myTTY := ""
	if res := Run("tty"); res.OK() {
		myTTY = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(res.Stdout), "/dev/"))
	}
	res := Run("who")
	if !res.OK() {
		rep.fail("who: %s", firstLine(res.Stderr))
		return
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		userName, tty := fields[0], fields[1]
		if tty == myTTY {
			rep.act("kept own tty %s (%s)", tty, userName)
			continue
		}
		if !cfg.IncludeSelf && userName == self && myTTY == "" {
			rep.act("kept %s session for current user (own tty unknown)", tty)
			continue
		}
		if IsServiceAccount(userName, cfg.Deny) {
			continue
		}
		r := Run("pkill", "-KILL", "-t", tty)
		if r.ExitCode == 0 || r.ExitCode == 1 {
			rep.act("terminated tty %s (%s)", tty, userName)
		} else {
			rep.fail("pkill -t %s: %s", tty, firstLine(r.Stderr))
		}
	}
}
