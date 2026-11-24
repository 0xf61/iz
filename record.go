package main

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// runRecord runs the command and records its output. Output is mirrored to
// the user's terminal (colors and all) while being collected into a bounded
// buffer. The child's exit code is returned unchanged so the shell's $status
// stays correct; a command that cannot be started returns 127 (not found) or
// 126 (not executable) and records nothing.
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
	if _, err := exec.LookPath(args[0]); err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return startFailure(err)
	}

	// A broken database must never break the wrapped tool: run it unrecorded.
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "[iz] not recording:", err)
		return passthrough(args)
	}
	defer db.Close()

	// PTY only when stdin and stdout are terminals and we are the terminal's
	// foreground job. Otherwise pipe mode: piped commands (`cat urls | httpx`,
	// `cmd | grep`) get EOF cleanly and no ANSI/CRLF injected into pipelines,
	// and a background job (`iz -- x &`) is not stopped by SIGTTOU when it
	// would switch the terminal to raw mode.
	if isTTY() && foreground() {
		return runPTYRecord(db, args)
	}
	return runPipeRecord(db, args)
}

// runPTYRecord runs the command inside a PTY so it sees a terminal (colors,
// progress bars, interactive prompts).
func runPTYRecord(db *sql.DB, args []string) int {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = ptyEnv(args[0])
	// `cmd 2>file`: keep the redirect (pty.Start only fills nil streams), so
	// stderr goes to the file instead of being merged into the PTY output.
	if !term.IsTerminal(int(os.Stderr.Fd())) {
		cmd.Stderr = os.Stderr
	}
	start := time.Now()

	// Signals are caught from before the child starts until iz returns, so
	// none kills iz while the terminal is raw or the run unsaved; they reach
	// the child (its whole process group: it leads its own session) only
	// while it runs.
	sigs := forwardSignals(true, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer sigs.release()

	// Start with the current terminal size: fast tools (fastfetch!) would
	// otherwise render against the default 80x24 before the resize poller runs.
	var ptmx *os.File
	var err error
	if ws, sizeErr := pty.GetsizeFull(os.Stdin); sizeErr == nil {
		ptmx, err = pty.StartWithSize(cmd, ws)
	} else {
		ptmx, err = pty.Start(cmd) // child sees isatty(stdout) = true → colors
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return startFailure(err)
	}
	defer ptmx.Close()
	sigs.to(cmd.Process)

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

	// Forward terminal resizes to the child PTY.
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	resized := make(chan struct{})
	go func() {
		defer close(resized)
		for range winch {
			pty.InheritSize(os.Stdin, ptmx) //nolint
		}
	}()

	stopStdin, stdinDone := forwardStdin(ptmx)

	// PTY → buffer + screen (buffer first: it never fails, the screen may)
	capture := newCapture()
	drained := make(chan struct{})
	go func() {
		io.Copy(io.MultiWriter(capture, os.Stdout), ptmx) //nolint
		close(drained)
	}()
	waitErr := cmd.Wait()
	sigs.stop() // the child is reaped: its pid (group) may be reused
	// The child is gone. Stop reading stdin, so typeahead stays with the
	// shell, and give the remaining output a moment to drain: a daemonized
	// grandchild still holding the PTY slave would otherwise block us forever.
	// Nothing here waits unbounded: the stdin forwarder may be stuck writing
	// to a full PTY nobody reads, so it is only waited for briefly, after the
	// PTY is closed (which fails its next write).
	stopStdin()
	signal.Stop(winch) // no more sends after Stop: safe to close
	close(winch)
	<-resized
	select {
	case <-drained:
	case <-time.After(drainTimeout):
	}
	ptmx.Close()
	select {
	case <-stdinDone:
	case <-time.After(drainTimeout):
	}
	restoreTerm()

	return saveRun(db, args, start, capture.Bytes(), exitStatus(waitErr, cmd.ProcessState))
}

// ptyEnv is the environment of a PTY child (nil: iz's own). CLICOLOR and
// CLICOLOR_FORCE keep BSD ls (macOS) colored even when a fish alias is
// bypassed; GNU ls is colored automatically inside a PTY. Only for ls
// itself: inherited by anything else (`sh -c 'ls | xargs …'`), they would
// force ANSI codes into the child's own pipes.
func ptyEnv(name string) []string {
	if filepath.Base(name) != "ls" {
		return nil
	}
	return append(os.Environ(), "CLICOLOR=1", "CLICOLOR_FORCE=1")
}

// drainTimeout bounds how long output is still collected after the child
// exits (only a lingering grandchild can make it matter).
const drainTimeout = 500 * time.Millisecond

// runPipeRecord runs the command without a PTY when stdin or stdout is piped
// (or iz runs in the background), mirroring stdout/stderr cleanly while
// recording the combined output.
func runPipeRecord(db *sql.DB, args []string) int {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	start := time.Now()

	// The capture comes first: it never fails, while a write to a closed
	// stdout (`iz -- cmd | head`) stops the copy, and the chunk is kept.
	capture := newCapture()
	cmd.Stdout = io.MultiWriter(capture, os.Stdout)
	cmd.Stderr = io.MultiWriter(capture, os.Stderr)
	// Output goes through pipes; a daemonized grandchild keeping them open
	// must not make Wait block after the child itself has exited.
	cmd.WaitDelay = drainTimeout

	// Signals iz must survive without acting on them, caught (not ignored)
	// so the child still starts with default dispositions:
	//   - SIGPIPE: a closed downstream pipe must not kill iz before the run
	//     is saved (Go dies on EPIPE to fd 1/2 unless SIGPIPE is handled);
	//   - SIGINT/SIGQUIT in the foreground: the child shares our process group
	//     and gets the terminal's signal itself; relaying it would deliver
	//     Ctrl-C twice (many scanners treat a second one as "abort now").
	// Without a controlling terminal, iz relays SIGINT/SIGQUIT instead.
	swallow := []os.Signal{syscall.SIGPIPE}
	relay := []os.Signal{syscall.SIGTERM, syscall.SIGHUP}
	if foreground() {
		swallow = append(swallow, syscall.SIGINT, syscall.SIGQUIT)
	} else {
		relay = append(relay, syscall.SIGINT, syscall.SIGQUIT)
	}
	quiet := make(chan os.Signal, 1)
	signal.Notify(quiet, swallow...)
	defer signal.Stop(quiet)
	sigs := forwardSignals(false, relay...)
	defer sigs.release()

	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return startFailure(err)
	}
	sigs.to(cmd.Process)

	waitErr := cmd.Wait()
	sigs.stop()
	return saveRun(db, args, start, capture.Bytes(), exitStatus(waitErr, cmd.ProcessState))
}

// saveRun stores a finished run and reports it on stderr; it returns exit.
func saveRun(db *sql.DB, args []string, start time.Time, out []byte, exit int) int {
	raw := tidyRaw(out)
	tool := filepath.Base(args[0])
	cmdStr := joinArgs(args)
	host := hostname()
	workDir := cwd()
	now := time.Now()
	dur := now.Sub(start)

	inPipe := !term.IsTerminal(int(os.Stdin.Fd()))
	outPipe := !term.IsTerminal(int(os.Stdout.Fd()))
	shellCmd := os.Getenv("IZ_SHELL_CMD")
	pidKey := os.Getenv("IZ_PIPELINE_ID")

	if (inPipe || outPipe) && (pidKey != "" || strings.Contains(shellCmd, "|")) {
		stagePos := 3
		switch {
		case !inPipe && outPipe:
			stagePos = 0
		case inPipe && outPipe:
			stagePos = 1
		case inPipe && !outPipe:
			stagePos = 2
		}
		st := PipelineStage{
			PGID:     unix.Getpgrp(),
			PidKey:   pidKey,
			StagePos: stagePos,
			Ts:       unixTime(start),
			EndTs:    unixTime(now),
			Tool:     tool,
			Cmd:      cmdStr,
			ShellCmd: shellCmd,
			Cwd:      workDir,
			Hostname: host,
			ExitCode: exit,
			Raw:      raw,
		}
		id, finalSize, finalExit, finalDur, err := recordPipelineStage(db, st)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[iz] RECORD FAILED: %v\n", err)
			return exit
		}
		if outPipe && shellCmd != "" && hasDownstreamWrappedTool(shellCmd, tool, queryNames(db, "tools")) {
			return exit
		}
		fmt.Fprintf(os.Stderr, "[iz] #%d saved · exit=%d · %.1fs · %s\n",
			id, finalExit, finalDur.Seconds(), humanBytes(finalSize))
		return exit
	}

	z := gz(raw)
	r := Run{
		Ts:       unixTime(start),
		Hostname: host,
		Tool:     tool,
		Cmd:      cmdStr,
		Cwd:      workDir,
		ExitCode: ni(int64(exit)),
		Dur:      ni(int64(dur / time.Millisecond)),
		Size:     ni(int64(len(z))),
	}
	id, err := insertRun(db, r, z, truncFTS(stripANSI(raw)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[iz] RECORD FAILED: %v\n", err)
		return exit
	}
	fmt.Fprintf(os.Stderr, "[iz] #%d saved · exit=%d · %.1fs · %s\n",
		id, exit, dur.Seconds(), humanBytes(r.Size.Int64))
	return exit
}

// exitStatus maps a finished child to a shell-style exit code: its status,
// or 128+N when it was killed by signal N.
func exitStatus(waitErr error, ps *os.ProcessState) int {
	if ps == nil {
		if waitErr != nil {
			return 1
		}
		return 0
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ps.ExitCode()
}

// startFailure is the shell's exit code for a command that could not start.
func startFailure(err error) int {
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
		return 127
	}
	return 126
}

// sigForwarder relays caught signals to a child process.
type sigForwarder struct {
	ch      chan os.Signal
	p       atomic.Pointer[os.Process]
	done    chan struct{}
	release func() // restores the signals' default action (idempotent)
}

// forwardSignals catches sigs at once: from then on they no longer take
// their default (fatal) action, but are relayed to the child named by to —
// to its whole process group when group is set — until stop; signals caught
// before to or after stop are dropped. release ends the catching.
func forwardSignals(group bool, sigs ...os.Signal) *sigForwarder {
	f := &sigForwarder{ch: make(chan os.Signal, 4), done: make(chan struct{})}
	signal.Notify(f.ch, sigs...)
	go func() {
		defer close(f.done)
		for sig := range f.ch {
			p := f.p.Load()
			switch s, ok := sig.(syscall.Signal); {
			case p == nil:
			case ok && group:
				_ = syscall.Kill(-p.Pid, s)
			default:
				_ = p.Signal(sig)
			}
		}
	}()
	f.release = sync.OnceFunc(func() {
		f.stop()
		signal.Stop(f.ch)
		close(f.ch)
		<-f.done
	})
	return f
}

// to starts relaying to the started child p.
func (f *sigForwarder) to(p *os.Process) { f.p.Store(p) }

// stop ends the relaying, e.g. once the child is reaped (and its pid free
// for reuse); signals are still caught until release.
func (f *sigForwarder) stop() { f.p.Store(nil) }

// foreground reports whether iz runs in the foreground process group of its
// controlling terminal (false without one).
func foreground() bool {
	for _, fd := range []int{0, 1, 2} {
		if term.IsTerminal(fd) {
			pg, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
			return err == nil && pg == unix.Getpgrp()
		}
	}
	return false
}

// forwardStdin copies stdin to dst until stop is called; done is closed once
// the copier has exited. It waits for input with select(2) (poll(2) does not
// support ttys on macOS) and reads only what is already there, so keystrokes
// typed after the command exits stay in the terminal for the shell instead
// of being eaten by a read left blocking on stdin. stop never blocks: the
// copier may be stuck writing to dst.
func forwardStdin(dst io.Writer) (stop func(), done <-chan struct{}) {
	in := int(os.Stdin.Fd())
	exited := make(chan struct{})
	r, w, err := os.Pipe()
	if err != nil || in >= unix.FD_SETSIZE || int(r.Fd()) >= unix.FD_SETSIZE {
		if err == nil {
			r.Close()
			w.Close()
		}
		go io.Copy(dst, os.Stdin) //nolint — best effort
		close(exited)
		return func() {}, exited
	}
	cancel := int(r.Fd())
	go func() {
		defer close(exited)
		defer r.Close() // only once select(2) no longer watches it
		buf := make([]byte, 32<<10)
		for {
			var set unix.FdSet
			set.Set(in)
			set.Set(cancel)
			if _, err := unix.Select(max(in, cancel)+1, &set, nil, nil, nil); err != nil {
				if err == unix.EINTR {
					continue
				}
				return
			}
			if set.IsSet(cancel) {
				return
			}
			n, err := unix.Read(in, buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if n == 0 || err != nil && err != unix.EINTR && err != unix.EAGAIN {
				return // EOF or a real error
			}
		}
	}()
	return func() { w.Close() }, exited
}

// Captured output is bounded so a tool running for hours (tshark, responder)
// cannot exhaust memory: the first captureHead bytes and the last captureTail
// bytes are kept, with a marker in between saying how much was dropped.
const (
	maxCapture  = 32 << 20
	captureTail = 4 << 20
	captureHead = maxCapture - 2*captureTail // tail buffer peaks at 2×captureTail
)

// capture is a concurrency-safe, bounded io.Writer.
type capture struct {
	mu         sync.Mutex
	head, tail []byte
	total      int64
}

func newCapture() *capture { return &capture{} }

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	c.total += int64(n)
	if room := captureHead - len(c.head); room > 0 {
		k := min(room, len(p))
		c.head, p = append(c.head, p[:k]...), p[k:]
	}
	if len(p) > 0 {
		c.tail = append(c.tail, p...)
		if len(c.tail) > 2*captureTail { // amortized: trim back to captureTail
			c.tail = append(c.tail[:0:0], c.tail[len(c.tail)-captureTail:]...)
		}
	}
	return n, nil
}

// Bytes returns the captured output; when some was dropped, a marker line
// replaces the gap: the head ends and the tail starts at a full line (so no
// UTF-8 sequence or escape is cut), and colors are reset before the marker.
func (c *capture) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	head, tail := c.head, c.tail[max(0, len(c.tail)-captureTail):]
	dropped := c.total - int64(len(head)) - int64(len(tail))
	if dropped == 0 {
		return append(append([]byte{}, head...), tail...)
	}
	if i := bytes.LastIndexByte(head, '\n'); i >= 0 {
		head = head[:i+1]
	} else { // one huge line: at least end on a whole character
		head = head[:len(head)-partialRune(head)]
	}
	if i := bytes.IndexByte(tail, '\n'); i >= 0 {
		tail = tail[i+1:]
	} else { // one huge line: at least start on a whole character
		for k := 0; k < utf8.UTFMax-1 && len(tail) > 0 && !utf8.RuneStart(tail[0]); k++ {
			tail = tail[1:]
		}
	}
	dropped = c.total - int64(len(head)) - int64(len(tail))
	out := append([]byte{}, head...)
	if len(head) > 0 && head[len(head)-1] != '\n' {
		out = append(out, '\n')
	}
	out = fmt.Appendf(out, "\x1b[0m[iz] output truncated: %s not recorded\n", humanBytes(dropped))
	return append(out, tail...)
}

// partialRune is the length of an incomplete UTF-8 sequence ending b.
func partialRune(b []byte) int {
	for k := 1; k <= min(utf8.UTFMax, len(b)); k++ {
		if utf8.RuneStart(b[len(b)-k]) {
			if utf8.FullRune(b[len(b)-k:]) {
				return 0
			}
			return k
		}
	}
	return 0
}

// passthrough runs the command directly, no PTY or recording.
func passthrough(args []string) int {
	c := exec.Command(args[0], args[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return startFailure(err)
	}
	return exitStatus(c.Wait(), c.ProcessState)
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
