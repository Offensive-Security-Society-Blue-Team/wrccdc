package main

import (
	"os"
	"path/filepath"
	"runtime"

	"wrccdc/internal/common"
)

// findBin returns name if it is on PATH, otherwise the first existing path in
// candidates, otherwise "".
func findBin(name string, candidates []string) string {
	if common.Have(name) {
		return name
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if matches, _ := filepath.Glob(c); len(matches) > 0 {
			return matches[0]
		}
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func resolveMysql(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	name := "mysql"
	cands := []string{}
	if runtime.GOOS == "windows" {
		name = "mysql.exe"
		cands = []string{
			`C:\Program Files\MySQL\MySQL Server *\bin\mysql.exe`,
			`C:\Program Files\MariaDB *\bin\mysql.exe`,
			`C:\xampp\mysql\bin\mysql.exe`,
			`C:\wamp64\bin\mysql\mysql*\bin\mysql.exe`,
			`C:\wamp\bin\mysql\mysql*\bin\mysql.exe`,
		}
	} else {
		cands = []string{"/usr/bin/mysql", "/usr/local/bin/mysql", "/usr/bin/mariadb"}
	}
	if b := findBin(name, cands); b != "" {
		return b
	}
	// Try mariadb client name as a last resort on unix.
	if runtime.GOOS != "windows" && common.Have("mariadb") {
		return "mariadb"
	}
	return ""
}

func resolveGitea(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	name := "gitea"
	cands := []string{}
	if runtime.GOOS == "windows" {
		name = "gitea.exe"
		cands = []string{`C:\gitea\gitea.exe`, `C:\Program Files\Gitea\gitea.exe`}
	} else {
		cands = []string{"/usr/local/bin/gitea", "/usr/bin/gitea", "/usr/local/bin/forgejo", "/usr/bin/forgejo"}
	}
	return findBin(name, cands)
}

func resolveGiteaConf(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	cands := []string{}
	if runtime.GOOS == "windows" {
		cands = []string{`C:\gitea\custom\conf\app.ini`, `C:\Program Files\Gitea\custom\conf\app.ini`}
	} else {
		cands = []string{
			"/etc/gitea/app.ini",
			"/var/lib/gitea/custom/conf/app.ini",
			"/etc/forgejo/app.ini",
			"/var/lib/forgejo/custom/conf/app.ini",
		}
	}
	for _, c := range cands {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func defaultGiteaUser(info common.OSInfo) string {
	if info.IsWindows() {
		return ""
	}
	return "git"
}
