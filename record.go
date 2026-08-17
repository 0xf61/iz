package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty"
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

	// Forward terminal resizes to the PTY.
	go func() {
		for {
			ws, err := pty.GetsizeFull(os.Stdin)
			if err != nil {
				return
			}
			pty.Setsize(ptmx, ws) //nolint
			time.Sleep(200 * time.Millisecond)
		}
	}()
	// stdin → PTY
	go func() { io.Copy(ptmx, os.Stdin) }() //nolint

	// PTY → screen + buffer
	var buf bytes.Buffer
	io.Copy(io.MultiWriter(os.Stdout, &buf), ptmx) //nolint
	cmd.Wait()                                     //nolint

	raw := tidyRaw(buf.Bytes())
	r := Run{
		Ts:       float64(start.UnixNano()) / 1e9,
		Hostname: hostname(),
		Tool:     filepath.Base(args[0]),
		Cmd:      joinArgs(args),
		Cwd:      cwd(),
		Dur:      ni(int64(time.Since(start) / time.Millisecond)),
		Size:     ni(int64(len(gz(raw)))),
	}
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
		r.ExitCode = ni(int64(ws.ExitStatus()))
	}
	exit := 0
	if r.ExitCode.Valid {
		exit = int(r.ExitCode.Int64)
	}

	id, dbErr := insertRun(db, r, gz(raw), stripANSI(raw))
	if dbErr != nil {
		fmt.Fprintf(os.Stderr, "[iz] RECORD FAILED: %v\n", dbErr)
		return exit
	}
	fmt.Fprintf(os.Stderr, "[iz] #%d saved · exit=%d · %.1fs · %s\n",
		id, exit, time.Since(start).Seconds(), humanBytes(int64(r.Size.Int64)))
	return exit
}

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
