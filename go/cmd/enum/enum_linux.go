//go:build linux

package main

import (
	"os"
	"strings"

	"wrccdc/internal/common"
)

func enumerate(info common.OSInfo) []section {
	specs := []cmdSpec{
		{Title: "Kernel", Prog: "uname", Args: []string{"-a"}},
	}

	// Services: prefer systemd, fall back to OpenRC, then SysV.
	switch {
	case common.Have("systemctl"):
		specs = append(specs, cmdSpec{"Running services (systemd)", "systemctl",
			[]string{"list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"}})
	case common.Have("rc-status"):
		specs = append(specs, cmdSpec{"Running services (OpenRC)", "rc-status", []string{"-a"}})
	case common.Have("service"):
		specs = append(specs, cmdSpec{"Services (SysV)", "service", []string{"--status-all"}})
	}

	// Listening ports + connections.
	if common.Have("ss") {
		specs = append(specs,
			cmdSpec{"Listening ports (ss)", "ss", []string{"-tulpn"}},
			cmdSpec{"Established connections (ss)", "ss", []string{"-tunp", "state", "established"}})
	} else if common.Have("netstat") {
		specs = append(specs,
			cmdSpec{"Listening ports (netstat)", "netstat", []string{"-tulnp"}},
			cmdSpec{"Connections (netstat)", "netstat", []string{"-antup"}})
	}

	specs = append(specs,
		cmdSpec{"All processes", "ps", []string{"aux"}},
		cmdSpec{"Logged-in users (w)", "w", nil},
		cmdSpec{"Recent logins (last)", "last", []string{"-n", "40"}},
		cmdSpec{"Open network files (lsof -i)", "lsof", []string{"-i", "-n", "-P"}},
		cmdSpec{"Interfaces (ip addr)", "ip", []string{"addr"}},
		cmdSpec{"Routes (ip route)", "ip", []string{"route"}},
		cmdSpec{"Mounts", "mount", nil},
		cmdSpec{"Disk usage", "df", []string{"-h"}},
	)

	// Package inventory per distro.
	switch info.PkgManager() {
	case "apk":
		specs = append(specs, cmdSpec{"Installed packages (apk)", "apk", []string{"info", "-v"}})
	case "dpkg":
		specs = append(specs, cmdSpec{"Installed packages (dpkg)", "dpkg", []string{"-l"}})
	case "rpm":
		specs = append(specs, cmdSpec{"Installed packages (rpm)", "rpm", []string{"-qa"}})
	case "nix":
		specs = append(specs, cmdSpec{"Nix store (live paths)", "nix-store", []string{"--gc", "--print-live"}})
	default:
		if common.Have("dpkg") {
			specs = append(specs, cmdSpec{"Installed packages (dpkg)", "dpkg", []string{"-l"}})
		} else if common.Have("rpm") {
			specs = append(specs, cmdSpec{"Installed packages (rpm)", "rpm", []string{"-qa"}})
		} else if common.Have("apk") {
			specs = append(specs, cmdSpec{"Installed packages (apk)", "apk", []string{"info", "-v"}})
		}
	}

	var out []section
	for _, s := range specs {
		out = append(out, s.run())
	}

	// File-based sections read directly in Go (more reliable than shelling cat).
	out = append(out,
		fileSection("Crontab (system)", "/etc/crontab"),
		globSection("Cron jobs (/etc/cron.d)", "/etc/cron.d"),
		fileSection("Sudoers", "/etc/sudoers"),
		fileSection("Network interfaces (debian)", "/etc/network/interfaces"),
		globSection("Netplan", "/etc/netplan"),
		fileSection("SSH server config", "/etc/ssh/sshd_config"),
		fstabSection(),
		worldWritableSection(),
	)
	return out
}

func fileSection(title, path string) section {
	data, err := os.ReadFile(path)
	if err != nil {
		return section{title, "(" + path + ": " + err.Error() + ")"}
	}
	return section{title, strings.TrimRight(string(data), "\n")}
}

func globSection(title, dir string) section {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return section{title, "(" + dir + ": " + err.Error() + ")"}
	}
	var b strings.Builder
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := dir + "/" + e.Name()
		b.WriteString("### " + p + "\n")
		if data, err := os.ReadFile(p); err == nil {
			b.Write(data)
		}
		b.WriteString("\n")
	}
	if b.Len() == 0 {
		return section{title, "(empty)"}
	}
	return section{title, b.String()}
}

func fstabSection() section { return fileSection("fstab", "/etc/fstab") }

func worldWritableSection() section {
	// Bounded search: only common writable locations to avoid a full-disk walk.
	res := common.Run("find", "/etc", "/var/www", "/srv", "/home", "-xdev",
		"-type", "f", "-perm", "-0002", "-ls")
	body := strings.TrimRight(res.Stdout, "\n")
	if body == "" {
		body = "(none found in /etc /var/www /srv /home)"
	}
	return section{"World-writable files (common paths)", body}
}
