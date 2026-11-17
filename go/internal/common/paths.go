package common

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// SplitCSV splits a comma-separated flag value into trimmed, non-empty parts.
func SplitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// SecretDir returns a directory suitable for dropping sensitive output
// (credential records, snapshots) with restrictive permissions. It prefers a
// root/admin-owned location and falls back to the temp dir.
func SecretDir(info OSInfo) string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return ensure(filepath.Join(pd, "wrccdc"))
		}
		if sd := os.Getenv("SystemDrive"); sd != "" {
			return ensure(filepath.Join(sd+`\`, "wrccdc"))
		}
		return ensure(`C:\wrccdc`)
	}
	// Linux / unix.
	if IsPrivileged() {
		return ensure("/root/wrccdc")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return ensure(filepath.Join(home, "wrccdc"))
	}
	return ensure(filepath.Join(os.TempDir(), "wrccdc"))
}

func ensure(dir string) string {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return os.TempDir()
	}
	return dir
}
