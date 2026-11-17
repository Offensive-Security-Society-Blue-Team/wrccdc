package common

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Result holds the outcome of an external command.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

func (r Result) OK() bool { return r.Err == nil && r.ExitCode == 0 }

// Run executes name with args, no shell involved, with a default 2 minute
// timeout. Arguments are passed verbatim, so values (passwords, user names)
// are never subject to shell parsing.
func Run(name string, args ...string) Result {
	return RunTimeout(2*time.Minute, name, args...)
}

// RunTimeout is Run with an explicit timeout.
func RunTimeout(d time.Duration, name string, args ...string) Result {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return RunCtx(ctx, name, args...)
}

// RunCtx executes a command bound to ctx.
func RunCtx(ctx context.Context, name string, args ...string) Result {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	res := Result{Stdout: out.String(), Stderr: errb.String()}
	if err != nil {
		res.Err = err
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		} else {
			res.ExitCode = -1
		}
	}
	return res
}

// RunFull executes a command with an optional working directory and extra
// environment entries ("KEY=value"), appended to the current environment.
func RunFull(dir string, extraEnv []string, name string, args ...string) Result {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	res := Result{Stdout: out.String(), Stderr: errb.String()}
	if err != nil {
		res.Err = err
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		} else {
			res.ExitCode = -1
		}
	}
	return res
}

// RunEnv executes a command with extra environment entries appended.
func RunEnv(extraEnv []string, name string, args ...string) Result {
	return RunFull("", extraEnv, name, args...)
}

// RunStdin executes a command feeding stdin from the given string. Used for
// chpasswd and similar tools that read "user:password" pairs on stdin, which
// keeps secrets off the process argument list.
func RunStdin(stdin, name string, args ...string) Result {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	res := Result{Stdout: out.String(), Stderr: errb.String()}
	if err != nil {
		res.Err = err
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		} else {
			res.ExitCode = -1
		}
	}
	return res
}

// Have reports whether an executable is found on PATH.
func Have(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Powershell runs a PowerShell script block and returns the result. On
// non-Windows hosts (or where pwsh exists) it still works if PowerShell is
// installed, but it is intended for Windows. The script is passed via
// -EncodedCommand-free -Command to keep it readable; callers must build the
// script with values already quoted/escaped for PowerShell.
func Powershell(script string) Result {
	shell := "powershell"
	if !Have(shell) && Have("pwsh") {
		shell = "pwsh"
	}
	return RunTimeout(10*time.Minute, shell,
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", script)
}

// PSQuote single-quotes a string for safe embedding in a PowerShell command,
// doubling embedded single quotes per PowerShell literal-string rules.
func PSQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
