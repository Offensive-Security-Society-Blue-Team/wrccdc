package main

import (
	"crypto/md5"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"wrccdc/internal/common"
)

type wpCfg struct {
	path  string
	admin string
	gen   common.GenOptions
	dry   bool
	info  common.OSInfo
}

func (w wpCfg) run(rep *common.RotateReport) {
	const scope = "wordpress"
	dir := w.path
	if dir == "" {
		dir = findWordpress(w.info)
	}
	if dir == "" {
		rep.Creds = append(rep.Creds, common.Credential{Scope: scope, User: "-",
			Status: "skipped: no wp-config.php found (pass --wp-path)"})
		return
	}

	pw := common.Generate(w.gen)
	cred := common.Credential{Scope: scope, User: w.admin + " @ " + dir, Password: pw}
	if w.dry {
		cred.Status = "dry-run"
		rep.Creds = append(rep.Creds, cred)
		return
	}

	// Preferred path: wp-cli handles hashing and cache correctly.
	if common.Have("wp") {
		args := []string{"user", "update", w.admin,
			"--user_pass=" + pw, "--path=" + dir}
		if runtime.GOOS != "windows" {
			args = append(args, "--allow-root")
		}
		res := common.Run("wp", args...)
		if res.OK() {
			cred.Status = "changed (wp-cli)"
			rep.Creds = append(rep.Creds, cred)
			return
		}
		// fall through to DB method on wp-cli failure
	}

	// Fallback: update the users table directly. WordPress accepts a legacy
	// 32-char MD5 in user_pass and transparently upgrades it on next login.
	status := w.updateViaDB(dir, pw)
	if strings.HasPrefix(status, "changed") {
		cred.Status = status
	} else {
		cred.Password = ""
		cred.Status = status
	}
	rep.Creds = append(rep.Creds, cred)
}

func (w wpCfg) updateViaDB(dir, pw string) string {
	cfgPath := filepath.Join(dir, "wp-config.php")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return "error: read wp-config.php: " + err.Error()
	}
	text := string(data)
	name := wpDefine(text, "DB_NAME")
	user := wpDefine(text, "DB_USER")
	pass := wpDefine(text, "DB_PASSWORD")
	host := wpDefine(text, "DB_HOST")
	prefix := wpPrefix(text)
	if name == "" || user == "" {
		return "error: could not parse DB credentials from wp-config.php"
	}
	if host == "" {
		host = "localhost"
	}

	mysqlBin := resolveMysql("")
	if mysqlBin == "" {
		return "error: wp-cli absent and mysql client not found for DB fallback"
	}

	hash := fmt.Sprintf("%x", md5.Sum([]byte(pw)))
	sql := fmt.Sprintf("UPDATE %susers SET user_pass='%s' WHERE user_login='%s'",
		prefix, hash, escQuote(w.admin))

	args := []string{"-u", user}
	// localhost -> use the local socket; a TCP host -> connect over TCP.
	if host != "localhost" {
		hp := strings.SplitN(host, ":", 2)
		args = append(args, "-h", hp[0], "--protocol=TCP")
		if len(hp) == 2 {
			args = append(args, "-P", hp[1])
		}
	}
	args = append(args, name, "-e", sql)

	var env []string
	if pass != "" {
		env = []string{"MYSQL_PWD=" + pass}
	}
	res := common.RunEnv(env, mysqlBin, args...)
	if res.OK() {
		return "changed (db md5)"
	}
	return "error: db update: " + firstLine(res.Stderr)
}

func wpDefine(text, key string) string {
	re := regexp.MustCompile(fmt.Sprintf(`(?i)define\(\s*['"]%s['"]\s*,\s*['"]([^'"]*)['"]`, regexp.QuoteMeta(key)))
	if m := re.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return ""
}

func wpPrefix(text string) string {
	re := regexp.MustCompile(`(?m)^\s*\$table_prefix\s*=\s*['"]([^'"]+)['"]`)
	if m := re.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return "wp_"
}

func findWordpress(info common.OSInfo) string {
	var roots []string
	if info.IsWindows() {
		roots = []string{`C:\inetpub\wwwroot`, `C:\xampp\htdocs`, `C:\wamp64\www`, `C:\wamp\www`}
	} else {
		roots = []string{"/var/www/html", "/var/www", "/usr/share/nginx/html", "/srv/www", "/srv/http", "/srv"}
	}
	for _, r := range roots {
		if hasWPConfig(r) {
			return r
		}
		// one level of subdirectories (e.g. /var/www/html/blog)
		entries, err := os.ReadDir(r)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				sub := filepath.Join(r, e.Name())
				if hasWPConfig(sub) {
					return sub
				}
			}
		}
	}
	return ""
}

func hasWPConfig(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "wp-config.php"))
	return err == nil
}
