//go:build windows

package common

// IsPrivileged reports whether the process holds administrative rights on
// Windows. "net session" requires elevation, so a zero exit code is a reliable,
// dependency-free signal that we are running elevated.
func IsPrivileged() bool {
	return Run("net", "session").OK()
}
