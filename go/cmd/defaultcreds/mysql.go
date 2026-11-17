package main

import (
	"strings"

	"wrccdc/internal/common"
)

type mysqlCfg struct {
	bin  string
	user string
	pass string
	host string
	all  bool
	gen  common.GenOptions
	dry  bool
}

// systemMysqlUsers are internal accounts that must not be rotated: breaking
// them can wedge the server or distro maintenance tooling.
var systemMysqlUsers = map[string]bool{
	"mysql.sys": true, "mysql.session": true, "mysql.infoschema": true,
	"debian-sys-maint": true, "mariadb.sys": true,
}

func (m mysqlCfg) run(rep *common.RotateReport) {
	const scope = "mysql"
	if m.bin == "" {
		rep.Creds = append(rep.Creds, common.Credential{Scope: scope, User: "-",
			Status: "skipped: mysql client not found (install or pass --mysql-bin)"})
		return
	}

	// Verify we can authenticate before making changes.
	if res := m.query("SELECT 1"); !res.OK() {
		rep.Creds = append(rep.Creds, common.Credential{Scope: scope, User: m.user,
			Status: "skipped: cannot authenticate (" + firstLine(res.Stderr) + ")"})
		return
	}

	targets := []string{}
	if m.all {
		res := m.query("SELECT CONCAT(user,'\t',host) FROM mysql.user")
		if res.OK() {
			for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
				parts := strings.Split(strings.TrimSpace(line), "\t")
				if len(parts) != 2 || parts[0] == "" {
					continue
				}
				if systemMysqlUsers[strings.ToLower(parts[0])] {
					continue
				}
				targets = append(targets, quoteUser(parts[0], parts[1]))
			}
		}
	} else {
		// Just the default superuser across the hosts it commonly exists on.
		for _, h := range []string{"localhost", "127.0.0.1", "%"} {
			if m.userHostExists(m.user, h) {
				targets = append(targets, quoteUser(m.user, h))
			}
		}
		if len(targets) == 0 {
			targets = append(targets, quoteUser(m.user, "localhost"))
		}
	}

	for _, t := range targets {
		pw := common.Generate(m.gen)
		cred := common.Credential{Scope: scope, User: t, Password: pw}
		if m.dry {
			cred.Status = "dry-run"
			rep.Creds = append(rep.Creds, cred)
			continue
		}
		// Try MySQL 8 / modern MariaDB syntax first, then legacy SET PASSWORD.
		alter := "ALTER USER " + t + " IDENTIFIED BY '" + pw + "'"
		res := m.query(alter)
		if !res.OK() {
			legacy := "SET PASSWORD FOR " + t + " = PASSWORD('" + pw + "')"
			res = m.query(legacy)
		}
		if res.OK() {
			m.query("FLUSH PRIVILEGES")
			cred.Status = "changed"
		} else {
			cred.Password = ""
			cred.Status = "error: " + firstLine(res.Stderr)
		}
		rep.Creds = append(rep.Creds, cred)
	}
}

func (m mysqlCfg) baseArgs() []string {
	return []string{"-u", m.user, "-h", m.host, "--protocol=TCP", "-N", "-B"}
}

// query runs SQL. The current password is passed via MYSQL_PWD so it never
// appears on the process argument list.
func (m mysqlCfg) query(sql string) common.Result {
	args := append(m.baseArgs(), "-e", sql)
	var env []string
	if m.pass != "" {
		env = []string{"MYSQL_PWD=" + m.pass}
	}
	return common.RunEnv(env, m.bin, args...)
}

func (m mysqlCfg) userHostExists(user, host string) bool {
	res := m.query("SELECT 1 FROM mysql.user WHERE user='" + escQuote(user) + "' AND host='" + escQuote(host) + "'")
	return res.OK() && strings.TrimSpace(res.Stdout) != ""
}

func quoteUser(user, host string) string {
	return "'" + escQuote(user) + "'@'" + escQuote(host) + "'"
}

func escQuote(s string) string { return strings.ReplaceAll(s, "'", "''") }

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	if s == "" {
		return "unknown error"
	}
	return s
}
