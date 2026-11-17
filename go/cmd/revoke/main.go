// Command revoke kicks active intruders out of a host. It runs a three-stage
// sequence: revoke all sessions, rotate local (and domain, on a DC) passwords
// for human accounts, then revoke sessions again so any session re-established
// with now-stale credentials is dropped. Service and system accounts are never
// touched. It is OS-aware and preserves the operator's own session by default.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"wrccdc/internal/common"
)

func main() {
	info := common.Detect()
	defaultOut := filepath.Join(common.SecretDir(info), info.Hostname+"-revoke_passwords.txt")

	var (
		out         = flag.String("out", defaultOut, "credential record output file (0600)")
		includeSelf = flag.Bool("include-self", false, "also terminate the operator's own sessions (can kill this tool)")
		includeRoot = flag.Bool("include-root", true, "also rotate root / built-in Administrator during the password stage")
		domain      = flag.Bool("domain", true, "on a DC, also rotate Active Directory users")
		length      = flag.Int("length", 20, "generated password length")
		noSymbols   = flag.Bool("no-symbols", false, "use alphanumeric-only passwords")
		deny        = flag.String("deny", "", "comma-separated extra account names to leave alone")
		noRotate    = flag.Bool("no-rotate", false, "only revoke sessions, do not rotate passwords")
	)
	flag.Parse()

	if !common.IsPrivileged() {
		common.Fatal("must run as root/Administrator")
	}

	common.Info("host=%s os=%s — stage 1: revoking sessions", info.Hostname, info.OS)
	rc := common.RevokeConfig{IncludeSelf: *includeSelf, Deny: common.SplitCSV(*deny)}
	printRevoke(common.RevokeSessions(rc))

	if !*noRotate {
		common.Info("stage 2: rotating passwords (local%s)", domainNote(*domain))
		cfg := common.RotateConfig{
			IncludeRoot:   *includeRoot,
			IncludeSelf:   *includeSelf,
			IncludeDomain: *domain,
			Deny:          common.SplitCSV(*deny),
			Length:        *length,
			Symbols:       !*noSymbols,
			OutFile:       *out,
		}
		rep := common.RotateAllPasswords(cfg)
		rep.OS = info.OS
		for _, c := range rep.Creds {
			if c.Status == "changed" {
				common.Good("%s %-20s changed", c.Scope, c.User)
			} else {
				common.Err("%s %-20s %s", c.Scope, c.User, c.Status)
			}
		}
		if path, err := common.WriteCredFile(*out, rep); err == nil && path != "" {
			common.Good("credentials written to %s (0600)", path)
		} else if err != nil {
			common.Err("writing credential file: %v", err)
		}
	} else {
		common.Info("stage 2 skipped (--no-rotate)")
	}

	common.Info("stage 3: revoking sessions again to drop any reconnects")
	printRevoke(common.RevokeSessions(rc))

	fmt.Fprintln(os.Stderr, "\nDone. Verify no unexpected sessions remain and that the credential record is stored off-box.")
}

func printRevoke(rep *common.RevokeReport) {
	for _, a := range rep.Actions {
		common.Good("%s", a)
	}
	for _, e := range rep.Errors {
		common.Warn("%s", e)
	}
}

func domainNote(d bool) string {
	if d {
		return " + domain if DC"
	}
	return ""
}
