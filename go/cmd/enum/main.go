// Command enum performs OS-aware defensive enumeration of a host and writes a
// consolidated report. It replaces the per-distro *-enum.sh scripts and the
// Windows systeminfo.ps1 with a single binary that detects the platform at
// runtime.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"wrccdc/internal/common"
)

type section struct {
	Title string
	Body  string
}

// cmdSpec is one enumeration command. It runs only when prog is on PATH (or
// when prog is empty, meaning the body is produced in Go).
type cmdSpec struct {
	Title string
	Prog  string
	Args  []string
}

func (c cmdSpec) run() section {
	if c.Prog == "" {
		return section{c.Title, ""}
	}
	if !common.Have(c.Prog) {
		return section{c.Title, "(" + c.Prog + " not installed)"}
	}
	res := common.Run(c.Prog, c.Args...)
	body := strings.TrimRight(res.Stdout, "\n")
	if body == "" {
		body = strings.TrimRight(res.Stderr, "\n")
	}
	if body == "" {
		body = "(no output)"
	}
	return section{c.Title, body}
}

func main() {
	info := common.Detect()
	defaultOut := filepath.Join(os.TempDir(), info.Hostname+"-enum.txt")

	out := flag.String("out", defaultOut, "output report file")
	flag.Parse()

	common.Info("host=%s os=%s distro=%s version=%s", info.Hostname, info.OS, info.Distro, info.Version)
	if !common.IsPrivileged() {
		common.Warn("not running as root/Administrator: some sections will be incomplete")
	}

	var sections []section
	sections = append(sections, section{"Host", fmt.Sprintf(
		"hostname: %s\nos: %s\ndistro: %s\nversion: %s\ncollected: %s",
		info.Hostname, info.OS, info.Distro, info.Version, time.Now().Format(time.RFC3339))})

	sections = append(sections, enumerate(info)...)

	var b strings.Builder
	for _, s := range sections {
		b.WriteString("==================================================\n")
		b.WriteString(s.Title)
		b.WriteString("\n--------------------------------------------------\n")
		b.WriteString(s.Body)
		b.WriteString("\n\n")
	}

	if err := os.WriteFile(*out, []byte(b.String()), 0o600); err != nil {
		common.Fatal("write report: %v", err)
	}
	common.Good("enumeration written to %s", *out)
}
