// Command defaultcreds rotates the well-known default credentials of common
// competition services — MySQL/MariaDB, WordPress, and Gitea — so an attacker
// who memorized the stock passwords is locked out. It detects installed
// tooling at runtime and is OS-aware (locating mysql.exe / gitea.exe on Windows
// and the equivalents on Linux). Every service is best-effort: when a tool or
// config is missing it reports that clearly instead of failing the whole run.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"wrccdc/internal/common"
)

func main() {
	info := common.Detect()
	defaultOut := filepath.Join(common.SecretDir(info), info.Hostname+"-default_creds.txt")

	var (
		services = flag.String("services", "mysql,wordpress,gitea", "comma-separated services to rotate")
		out      = flag.String("out", defaultOut, "credential record output file (0600)")
		length   = flag.Int("length", 24, "generated password length")
		dryRun   = flag.Bool("dry-run", false, "show what would happen without changing anything")

		// MySQL / MariaDB
		mysqlBin  = flag.String("mysql-bin", "", "path to mysql client (auto-detected if empty)")
		mysqlUser = flag.String("mysql-user", "root", "mysql admin user to authenticate as")
		mysqlPass = flag.String("mysql-pass", "", "current password for --mysql-user (empty tries socket/auth)")
		mysqlHost = flag.String("mysql-host", "127.0.0.1", "mysql host")
		mysqlAll  = flag.Bool("mysql-all", false, "rotate every non-system mysql account, not just root")

		// WordPress
		wpPath  = flag.String("wp-path", "", "path to the WordPress install (contains wp-config.php)")
		wpAdmin = flag.String("wp-admin", "admin", "WordPress admin login to reset")

		// Gitea
		giteaBin   = flag.String("gitea-bin", "", "path to gitea binary (auto-detected if empty)")
		giteaConf  = flag.String("gitea-config", "", "path to gitea app.ini (auto-detected if empty)")
		giteaUser  = flag.String("gitea-admin", "", "gitea admin username to reset (required to rotate gitea)")
		giteaRunAs = flag.String("gitea-runas", defaultGiteaUser(info), "OS user the gitea service runs as (Linux)")
	)
	flag.Parse()

	// Symbols off: these passwords flow through SQL and config files where
	// punctuation is most likely to cause trouble; 24 alphanumerics stay strong.
	gen := common.GenOptions{Length: *length, Symbols: false}

	want := map[string]bool{}
	for _, s := range common.SplitCSV(*services) {
		want[strings.ToLower(s)] = true
	}

	rep := &common.RotateReport{OS: info.OS, Host: info.Hostname}
	common.Info("host=%s os=%s — rotating default service credentials (dry-run=%v)", info.Hostname, info.OS, *dryRun)

	if want["mysql"] || want["mariadb"] {
		mysqlCfg{
			bin: resolveMysql(*mysqlBin), user: *mysqlUser, pass: *mysqlPass,
			host: *mysqlHost, all: *mysqlAll, gen: gen, dry: *dryRun,
		}.run(rep)
	}
	if want["wordpress"] || want["wp"] {
		wpCfg{path: *wpPath, admin: *wpAdmin, gen: gen, dry: *dryRun, info: info}.run(rep)
	}
	if want["gitea"] || want["forgejo"] {
		giteaCfg{
			bin: resolveGitea(*giteaBin), conf: resolveGiteaConf(*giteaConf),
			admin: *giteaUser, runAs: *giteaRunAs, gen: gen, dry: *dryRun, info: info,
		}.run(rep)
	}

	for _, c := range rep.Creds {
		switch {
		case c.Status == "changed" || c.Status == "dry-run":
			common.Good("%s %-24s %s", c.Scope, c.User, c.Status)
		default:
			common.Err("%s %-24s %s", c.Scope, c.User, c.Status)
		}
	}

	if !*dryRun {
		if path, err := common.WriteCredFile(*out, rep); err == nil && path != "" {
			common.Good("credentials written to %s (0600) — record off-box then delete", path)
		} else if err != nil {
			common.Err("writing credential file: %v", err)
		}
	}
	fmt.Fprintf(os.Stderr, "\nDone. Review statuses above; services not installed are reported, not errors.\n")
}
