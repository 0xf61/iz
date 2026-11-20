package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
)

// runRecord runs the command inside a PTY. Output is mirrored to the user's
// terminal (colors and all) while being collected into a buffer. The child's
// exit code is returned unchanged so the shell's $status stays correct.
func runRecord(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: iz -- <cmd> [args...]")
		return 2
	}
	if args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: iz -- <cmd> [args...]")
		return 2
	}

	// Never record iz itself (wrapper chains would feed on themselves).
	if filepath.Base(args[0]) == "iz" {
		return passthrough(args)
	}

	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer db.Close()

	// Use PTY only when both stdin and stdout are terminals; otherwise run in
	// pipe mode so piped commands (e.g. `cat urls | httpx` or `cmd | grep`)
	// receive EOF cleanly and don't get ANSI/CRLF injected into pipelines.
	if !isTTY() {
		return runPipeRecord(db, args)
	}

	cmd := exec.Command(args[0], args[1:]...)
	// CLICOLOR/CLICOLOR_FORCE: keep BSD ls (macOS) colored even when a fish
	// alias is bypassed; GNU ls is colored automatically inside a PTY.
	cmd.Env = append(os.Environ(), "CLICOLOR=1", "CLICOLOR_FORCE=1")
	start := time.Now()

	// Start with the current terminal size: fast tools (fastfetch!) would
	// otherwise render against the default 80x24 before the resize poller runs.
	var ptmx *os.File
	if ws, err := pty.GetsizeFull(os.Stdin); err == nil {
		ptmx, err = pty.StartWithSize(cmd, ws)
	} else {
		ptmx, err = pty.Start(cmd) // child sees isatty(stdout) = true → colors
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer ptmx.Close()

	// Put stdin into raw mode so interactive tools (ssh, sudo, fzf) receive
	// keystrokes directly, passwords are not echoed by the outer TTY, and
	// Ctrl-C is delivered to the child PTY instead of killing iz mid-scan.
	var oldTermState *term.State
	if s, err := term.MakeRaw(int(os.Stdin.Fd())); err == nil {
		oldTermState = s
	}
	restoreTerm := func() {
		if oldTermState != nil {
			_ = term.Restore(int(os.Stdin.Fd()), oldTermState)
			oldTermState = nil
		}
	}
	defer restoreTerm()

	// Forward terminal resizes and external SIGINT/SIGTERM to the child PTY.
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	go func() {
		for range winch {
			pty.InheritSize(os.Stdin, ptmx) //nolint
		}
	}()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		for sig := range sigCh {
			if cmd.Process != nil {
				if s, ok := sig.(syscall.Signal); ok {
					_ = syscall.Kill(-cmd.Process.Pid, s)
				} else {
					_ = cmd.Process.Signal(sig)
				}
			}
		}
	}()

	// stdin → PTY
	go func() { io.Copy(ptmx, os.Stdin) }() //nolint

	// PTY → screen + buffer
	var buf bytes.Buffer
	io.Copy(io.MultiWriter(os.Stdout, &buf), ptmx) //nolint
	cmd.Wait()                                     //nolint
	restoreTerm()

	raw := tidyRaw(buf.Bytes())
	z := gz(raw)
	r := Run{
		Ts:       float64(start.UnixNano()) / 1e9,
		Hostname: hostname(),
		Tool:     filepath.Base(args[0]),
		Cmd:      joinArgs(args),
		Cwd:      cwd(),
		Dur:      ni(int64(time.Since(start) / time.Millisecond)),
		Size:     ni(int64(len(z))),
	}
	if cmd.ProcessState != nil {
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				r.ExitCode = ni(int64(128 + int(ws.Signal())))
			} else {
				r.ExitCode = ni(int64(ws.ExitStatus()))
			}
		}
	}
	exit := 0
	if r.ExitCode.Valid {
		exit = int(r.ExitCode.Int64)
	}

	id, dbErr := insertRun(db, r, z, truncFTS(stripANSI(raw)))
	if dbErr != nil {
		fmt.Fprintf(os.Stderr, "[iz] RECORD FAILED: %v\n", dbErr)
		return exit
	}
	fmt.Fprintf(os.Stderr, "[iz] #%d saved · exit=%d · %.1fs · %s\n",
		id, exit, time.Since(start).Seconds(), humanBytes(int64(r.Size.Int64)))
	return exit
}

// runPipeRecord runs the command without a PTY when stdin or stdout is piped,
// mirroring stdout/stderr cleanly while recording the combined output.
func runPipeRecord(db *sql.DB, args []string) int {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	start := time.Now()

	var mu sync.Mutex
	var buf bytes.Buffer
	syncWrite := func(w io.Writer, p []byte) (int, error) {
		mu.Lock()
		buf.Write(p)
		mu.Unlock()
		return w.Write(p)
	}
	cmd.Stdout = writerFunc(func(p []byte) (int, error) { return syncWrite(os.Stdout, p) })
	cmd.Stderr = writerFunc(func(p []byte) (int, error) { return syncWrite(os.Stderr, p) })

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		for sig := range sigCh {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}()

	exit := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				exit = 128 + int(ws.Signal())
			} else {
				exit = ee.ExitCode()
			}
		} else {
			fmt.Fprintln(os.Stderr, "iz:", err)
			return 2
		}
	}

	raw := tidyRaw(buf.Bytes())
	z := gz(raw)
	r := Run{
		Ts:       float64(start.UnixNano()) / 1e9,
		Hostname: hostname(),
		Tool:     filepath.Base(args[0]),
		Cmd:      joinArgs(args),
		Cwd:      cwd(),
		ExitCode: ni(int64(exit)),
		Dur:      ni(int64(time.Since(start) / time.Millisecond)),
		Size:     ni(int64(len(z))),
	}
	id, dbErr := insertRun(db, r, z, truncFTS(stripANSI(raw)))
	if dbErr != nil {
		fmt.Fprintf(os.Stderr, "[iz] RECORD FAILED: %v\n", dbErr)
		return exit
	}
	fmt.Fprintf(os.Stderr, "[iz] #%d saved · exit=%d · %.1fs · %s\n",
		id, exit, time.Since(start).Seconds(), humanBytes(int64(r.Size.Int64)))
	return exit
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// passthrough runs the command directly, no PTY or recording.
func passthrough(args []string) int {
	c := exec.Command(args[0], args[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	return 0
}

// joinArgs renders args as a single shell-syntax command line.
func joinArgs(a []string) string {
	parts := make([]string, len(a))
	for i, s := range a {
		if s == "" || strings.ContainsAny(s, " \t\n\"'`$;&|<>(){}*?[]#~\\") {
			parts[i] = "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		} else {
			parts[i] = s
		}
	}
	return strings.Join(parts, " ")
}

func cwd() string {
	d, err := os.Getwd()
	if err != nil {
		return "."
	}
	return d
}

func humanBytes(n int64) string {
	f := float64(n)
	for _, u := range []string{"B", "KB", "MB"} {
		if f < 1024 {
			return fmt.Sprintf("%.0f%s", f, u)
		}
		f /= 1024
	}
	return fmt.Sprintf("%.0fGB", f)
}
