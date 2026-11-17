//go:build windows

package main

import (
	"os"
	"path/filepath"

	"wrccdc/internal/common"
)

// defaultPaths returns the folders most worth protecting on a Windows server:
// IIS/web content, DNS zone files, SSH config, and common third-party web
// roots. Only paths that exist are archived.
func defaultPaths(info common.OSInfo) []string {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	sysDrive := os.Getenv("SystemDrive")
	if sysDrive == "" {
		sysDrive = "C:"
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return []string{
		filepath.Join(sysDrive+`\`, "inetpub", "wwwroot"), // IIS web root
		filepath.Join(sysDrive+`\`, "inetpub"),            // IIS config/logs
		filepath.Join(sysRoot, "System32", "dns"),         // DNS zone files
		filepath.Join(programData, "ssh"),                 // OpenSSH config + host keys
		filepath.Join(sysDrive+`\`, "xampp", "htdocs"),    // XAMPP web root
		filepath.Join(sysDrive+`\`, "wamp", "www"),        // WAMP web root
		filepath.Join(sysDrive+`\`, "Apache24", "htdocs"), // standalone Apache
	}
}
