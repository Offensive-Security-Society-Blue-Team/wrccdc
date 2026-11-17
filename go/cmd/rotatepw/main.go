// Command rotatepw rotates passwords for every human/local account (and, on a
// Windows domain controller, domain accounts) while deliberately leaving
// service and system accounts untouched. It replaces user-passwords.sh,
// root_pass.sh, passwords.ps1, localusers.ps1 and changePasswords.bat with one
// OS-aware binary.
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
	defaultOut := filepath.Join(common.SecretDir(info), info.Hostname+"-new_passwords.txt")

	var (
		out         = flag.String("out", defaultOut, "credential record output file (0600)")
		length      = flag.Int("length", 20, "generated password length")
		noSymbols   = flag.Bool("no-symbols", false, "use alphanumeric-only passwords")
		includeRoot = flag.Bool("include-root", true, "also rotate root / built-in Administrator")
		includeSelf = flag.Bool("include-self", false, "also rotate the account running this tool")
		domain      = flag.Bool("domain", true, "on a DC, also rotate Active Directory users (skips SPN/service accounts)")
		minUID      = flag.Int("min-uid", 1000, "Linux: lowest UID treated as a human account")
		maxUID      = flag.Int("max-uid", 60000, "Linux: highest UID treated as a human account")
		deny        = flag.String("deny", "", "comma-separated extra account names to leave alone")
		dryRun      = flag.Bool("dry-run", false, "show what would change without changing anything")
	)
	flag.Parse()

	cfg := common.RotateConfig{
		MinUID:        *minUID,
		MaxUID:        *maxUID,
		IncludeRoot:   *includeRoot,
		IncludeSelf:   *includeSelf,
		IncludeDomain: *domain,
		Deny:          common.SplitCSV(*deny),
		Length:        *length,
		Symbols:       !*noSymbols,
		OutFile:       *out,
		DryRun:        *dryRun,
	}

	common.Info("host=%s os=%s distro=%s (dry-run=%v)", info.Hostname, info.OS, info.Distro, cfg.DryRun)
	rep := common.RotateAllPasswords(cfg)
	rep.OS = info.OS

	for _, c := range rep.Creds {
		switch {
		case c.Status == "changed":
			common.Good("%s %-20s changed", c.Scope, c.User)
		case c.Status == "dry-run":
			common.Info("%s %-20s would change", c.Scope, c.User)
		default:
			common.Err("%s %-20s %s", c.Scope, c.User, c.Status)
		}
	}
	for _, s := range rep.Skipped {
		common.Info("skip: %s", s)
	}

	if !cfg.DryRun {
		path, err := common.WriteCredFile(*out, rep)
		if err != nil {
			common.Err("writing credential file: %v", err)
		} else if path != "" {
			common.Good("credentials written to %s (0600) — record off-box then delete", path)
		}
	}

	fmt.Fprintf(os.Stderr, "\nSummary: %d accounts changed, %d skipped, %d errors\n",
		rep.Changed(), len(rep.Skipped), errorCount(rep))
	if errorCount(rep) > 0 {
		os.Exit(1)
	}
}

func errorCount(rep *common.RotateReport) int {
	n := 0
	for _, c := range rep.Creds {
		if c.Status != "changed" && c.Status != "dry-run" {
			n++
		}
	}
	return n
}
