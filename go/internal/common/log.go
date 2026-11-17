package common

import (
	"fmt"
	"os"
	"time"
)

// Simple leveled logger writing to stderr with timestamps. No colors so output
// stays clean when redirected to a file or captured over SSH/WinRM.

func ts() string { return time.Now().Format("15:04:05") }

func Info(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[%s] [*] %s\n", ts(), fmt.Sprintf(format, a...))
}

func Good(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[%s] [+] %s\n", ts(), fmt.Sprintf(format, a...))
}

func Warn(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[%s] [!] %s\n", ts(), fmt.Sprintf(format, a...))
}

func Err(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[%s] [-] %s\n", ts(), fmt.Sprintf(format, a...))
}

func Fatal(format string, a ...any) {
	Err(format, a...)
	os.Exit(1)
}
