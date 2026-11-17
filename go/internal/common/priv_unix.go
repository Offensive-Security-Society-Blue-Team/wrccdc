//go:build !windows

package common

import "os"

// IsPrivileged reports whether the process has administrative rights. On unix
// that means an effective UID of 0 (root).
func IsPrivileged() bool {
	return os.Geteuid() == 0
}
