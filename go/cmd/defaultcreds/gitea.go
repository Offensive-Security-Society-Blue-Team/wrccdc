package main

import (
	"os"
	"strings"

	"wrccdc/internal/common"
)

type giteaCfg struct {
	bin   string
	conf  string
	admin string
	runAs string
	gen   common.GenOptions
	dry   bool
	info  common.OSInfo
}

func (g giteaCfg) run(rep *common.RotateReport) {
	const scope = "gitea"
	if g.bin == "" {
		rep.Creds = append(rep.Creds, common.Credential{Scope: scope, User: "-",
			Status: "skipped: gitea binary not found (pass --gitea-bin)"})
		return
	}
	if g.admin == "" {
		rep.Creds = append(rep.Creds, common.Credential{Scope: scope, User: "-",
			Status: "skipped: no admin username given (pass --gitea-admin <user>)"})
		return
	}

	pw := common.Generate(g.gen)
	cred := common.Credential{Scope: scope, User: g.admin, Password: pw}
	if g.dry {
		cred.Status = "dry-run"
		rep.Creds = append(rep.Creds, cred)
		return
	}

	// Gitea changed the subcommand across versions: newer is
	// `admin user change-password`, older is `admin change-password`.
	variants := [][]string{
		{"admin", "user", "change-password", "--username", g.admin, "--password", pw},
		{"admin", "change-password", "--username", g.admin, "--password", pw},
	}

	var last common.Result
	for _, base := range variants {
		args := base
		if g.conf != "" {
			args = append(args, "--config", g.conf)
		}
		last = g.exec(args)
		if last.OK() {
			cred.Status = "changed"
			rep.Creds = append(rep.Creds, cred)
			return
		}
		// If the failure is clearly not an "unknown command", stop trying.
		if !looksLikeUnknownCmd(last) {
			break
		}
	}
	cred.Password = ""
	cred.Status = "error: " + firstLine(last.Stderr)
	rep.Creds = append(rep.Creds, cred)
}

// exec runs gitea as its service user on Linux (so files stay correctly owned),
// falling back to a direct run. On Windows it runs directly.
func (g giteaCfg) exec(args []string) common.Result {
	env := g.workEnv()
	if !g.info.IsWindows() && g.runAs != "" && common.Have("sudo") {
		sudoArgs := append([]string{"-u", g.runAs, "-H", g.bin}, args...)
		return common.RunFull(g.workDir(), env, "sudo", sudoArgs...)
	}
	return common.RunFull(g.workDir(), env, g.bin, args...)
}

func (g giteaCfg) workDir() string {
	for _, d := range []string{"/var/lib/gitea", "/var/lib/forgejo"} {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return d
		}
	}
	return ""
}

func (g giteaCfg) workEnv() []string {
	if wd := g.workDir(); wd != "" {
		return []string{"GITEA_WORK_DIR=" + wd}
	}
	return nil
}

func looksLikeUnknownCmd(r common.Result) bool {
	s := strings.ToLower(r.Stderr + r.Stdout)
	return strings.Contains(s, "unknown command") ||
		strings.Contains(s, "flag provided but not defined") ||
		strings.Contains(s, "command not found") ||
		strings.Contains(s, "no help topic")
}
