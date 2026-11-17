package common

import (
	"os"
	"runtime"
	"strings"
)

// OSInfo describes the host the binary is executing on.
type OSInfo struct {
	OS       string // runtime.GOOS: "linux", "windows", ...
	Distro   string // e.g. "debian", "ubuntu", "alpine", "nixos", "rhel", "windows"
	Version  string // distro / windows version string if known
	Hostname string
}

func (o OSInfo) IsWindows() bool { return o.OS == "windows" }
func (o OSInfo) IsLinux() bool   { return o.OS == "linux" }

// Detect inspects the running system. It never fails; unknown fields are left
// empty so callers can degrade gracefully.
func Detect() OSInfo {
	host, _ := os.Hostname()
	info := OSInfo{OS: runtime.GOOS, Hostname: host}

	switch runtime.GOOS {
	case "windows":
		info.Distro = "windows"
		info.Version = os.Getenv("OS") // "Windows_NT"; refined elsewhere if needed
	case "linux":
		id, ver := parseOSRelease()
		info.Distro = id
		info.Version = ver
		if info.Distro == "" {
			info.Distro = fallbackDistro()
		}
	default:
		info.Distro = runtime.GOOS
	}
	return info
}

// parseOSRelease reads /etc/os-release (freedesktop standard). Returns ID and
// VERSION_ID. On non-Linux the file is absent and empties are returned.
func parseOSRelease() (id, ver string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = strings.ToLower(v)
		case "VERSION_ID":
			ver = v
		}
	}
	return id, ver
}

// fallbackDistro guesses the distro family when /etc/os-release is missing.
func fallbackDistro() string {
	checks := map[string]string{
		"/etc/alpine-release": "alpine",
		"/etc/debian_version": "debian",
		"/etc/redhat-release": "rhel",
		"/etc/nixos":          "nixos",
	}
	for path, name := range checks {
		if _, err := os.Stat(path); err == nil {
			return name
		}
	}
	return "linux"
}

// PkgManager returns the primary package query command family for the distro.
func (o OSInfo) PkgManager() string {
	switch o.Distro {
	case "alpine":
		return "apk"
	case "debian", "ubuntu", "kali", "raspbian":
		return "dpkg"
	case "rhel", "centos", "fedora", "rocky", "almalinux":
		return "rpm"
	case "nixos":
		return "nix"
	default:
		// best effort probe order handled by caller
		return ""
	}
}
