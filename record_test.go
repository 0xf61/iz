package main

import (
	"bytes"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

func TestJoinArgs(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"nmap", "-sV", "10.0.0.1"}, "nmap -sV 10.0.0.1"},
		{[]string{"echo", "hello world"}, `echo 'hello world'`},
		{[]string{"sh", "-c", "printf \"hi\"\n"}, "sh -c 'printf \"hi\"\n'"},
		{[]string{"grep", "it's"}, `grep 'it'\''s'`},
		{[]string{"echo", ""}, `echo ''`},
	}
	for _, c := range cases {
		if got := joinArgs(c.in); got != c.want {
			t.Errorf("joinArgs(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{500, "500B"}, {2048, "2KB"}, {5 * 1024 * 1024, "5MB"}, {3 * 1024 * 1024 * 1024, "3GB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.in); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsToolName(t *testing.T) {
	for _, ok := range []string{"nmap", "nuclei", "nxc", "ferox-buster", "ffuf2", "evil-winrm"} {
		if !isToolName(ok) || !wrappable(ok) {
			t.Errorf("isToolName/wrappable(%q) should be true", ok)
		}
	}
	// a leading '-' reads as an option: `iz a --help` must not add "--help"
	for _, bad := range []string{"", "rm -rf", "a;b", "$(x)", "x y", "-x", "--help"} {
		if isToolName(bad) {
			t.Errorf("isToolName(%q) should be false", bad)
		}
	}
	// shell builtins/keywords (bash, zsh, fish) and iz itself are never wrapped
	for _, bad := range []string{"iz", "cd", "if", "function", "end", "string", "status", "time", "bind", "bindkey", "zle", "commandline"} {
		if wrappable(bad) {
			t.Errorf("wrappable(%q) should be false", bad)
		}
	}
}

func countRuns(t *testing.T, path string) int {
	t.Helper()
	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM runs`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// lastRun returns the newest run and its stored output.
func lastRun(t *testing.T, path string) (Run, string) {
	t.Helper()
	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var id int64
	if err := db.QueryRow(`SELECT max(id) FROM runs`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	raw, r, err := getMeta(db, id)
	if err != nil {
		t.Fatal(err)
	}
	return r, string(ungz(raw))
}

// A command that cannot start exits like the shell would (127) and records
// nothing — it used to report exit=0 and save an empty run.
func TestRunRecordMissingBinary(t *testing.T) {
	path := testDB(t)
	t.Setenv("IZ", path)
	if code := runRecord([]string{"--", "iz-no-such-binary-4242"}); code != 127 {
		t.Errorf("missing binary exit=%d, want 127", code)
	}
	if n := countRuns(t, path); n != 0 {
		t.Errorf("missing binary recorded %d run(s), want 0", n)
	}
}

// Without a terminal (go test), runs go through pipe mode: the exit code is
// passed through and stdout+stderr are recorded.
func TestRunRecordPipeMode(t *testing.T) {
	path := testDB(t)
	t.Setenv("IZ", path)
	if code := runRecord([]string{"sh", "-c", "echo out-line; echo err-line >&2; exit 3"}); code != 3 {
		t.Fatalf("exit=%d, want 3", code)
	}
	r, out := lastRun(t, path)
	if !r.ExitCode.Valid || r.ExitCode.Int64 != 3 || r.Tool != "sh" {
		t.Errorf("run = %+v", r)
	}
	if !strings.Contains(out, "out-line") || !strings.Contains(out, "err-line") {
		t.Errorf("output = %q", out)
	}
}

// Pipe mode relays SIGTERM to the child once it has started (the forwarder
// reads cmd.Process: -race catches a goroutine started before Start), and the
// run is saved with the shell's 128+N status.
func TestRunRecordPipeModeForwardsSignal(t *testing.T) {
	path := testDB(t)
	t.Setenv("IZ", path)
	// Keep SIGTERM caught by the test too: if it ever arrived before iz
	// registers its forwarder, the test fails instead of killing the binary.
	guard := make(chan os.Signal, 1)
	signal.Notify(guard, syscall.SIGTERM)
	t.Cleanup(func() { signal.Stop(guard) })

	start := time.Now()
	code := runRecord([]string{"sh", "-c", "sleep 0.5; kill -TERM $PPID; exec sleep 10"})
	if code != 128+int(syscall.SIGTERM) {
		t.Errorf("exit=%d, want %d", code, 128+int(syscall.SIGTERM))
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("child not signaled (took %s)", d)
	}
	if r, _ := lastRun(t, path); r.ExitCode.Int64 != 128+int64(syscall.SIGTERM) {
		t.Errorf("recorded exit=%d", r.ExitCode.Int64)
	}
}

// The capture buffer keeps head and tail of huge outputs within maxCapture.
func TestCaptureBounded(t *testing.T) {
	c := newCapture()
	chunk := bytes.Repeat([]byte("0123456789abcde\n"), 1<<16) // 1 MiB of lines
	c.Write([]byte("FIRST LINE\n"))                           //nolint
	for range maxCapture/len(chunk) + 8 {
		c.Write(chunk) //nolint
	}
	c.Write([]byte("LAST LINE\n")) //nolint

	out := c.Bytes()
	if len(out) > maxCapture+128 {
		t.Errorf("captured %d bytes, cap is %d", len(out), maxCapture)
	}
	if !bytes.HasPrefix(out, []byte("FIRST LINE\n")) || !bytes.HasSuffix(out, []byte("LAST LINE\n")) {
		t.Error("head or tail of the output lost")
	}
	if !bytes.Contains(out, []byte("[iz] output truncated:")) {
		t.Error("missing truncation marker")
	}
	// the tail resumes at a full line
	_, after, _ := bytes.Cut(out, []byte("not recorded\n"))
	if !bytes.HasPrefix(after, []byte("0123456789abcde\n")) {
		t.Errorf("tail starts mid-line: %q", after[:min(32, len(after))])
	}

	// the head ends on a full line, colors are reset before the marker
	if !bytes.Contains(out, []byte("0123456789abcde\n\x1b[0m[iz] output truncated:")) {
		t.Error("head not cut at a line end before the marker")
	}

	small := newCapture()
	small.Write([]byte("hello")) //nolint
	if string(small.Bytes()) != "hello" {
		t.Errorf("small capture = %q", small.Bytes())
	}
}

func TestPartialRune(t *testing.T) {
	for in, want := range map[string]int{
		"":                 0,
		"abc":              0,
		"aş":               0,
		"aş"[:2]:           1,
		"a€"[:3]:           2,
		"a\xff":            0, // invalid, not incomplete
		"a😀"[:4]:           3,
		"\x80\x80\x80\x80": 0,
	} {
		if got := partialRune([]byte(in)); got != want {
			t.Errorf("partialRune(%q) = %d, want %d", in, got, want)
		}
	}
}

// Once stopped (the child is reaped), the forwarder relays nothing — its pid
// may already belong to another process — but still catches the signal.
func TestForwardSignalsStop(t *testing.T) {
	guard := make(chan os.Signal, 1) // the test binary never takes SIGUSR1's default action
	signal.Notify(guard, syscall.SIGUSR1)
	t.Cleanup(func() { signal.Stop(guard) })

	f := forwardSignals(false, syscall.SIGUSR1)
	defer f.release()
	child := exec.Command("sleep", "10")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill() //nolint
	exited := make(chan struct{})
	go func() { child.Wait(); close(exited) }() //nolint

	f.to(child.Process)
	f.stop()
	syscall.Kill(os.Getpid(), syscall.SIGUSR1) //nolint
	select {
	case <-exited:
		t.Fatal("signal relayed after stop")
	case <-time.After(200 * time.Millisecond):
	}

	f.to(child.Process)
	syscall.Kill(os.Getpid(), syscall.SIGUSR1) //nolint
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("signal not relayed while forwarding")
	}
	if ws, ok := child.ProcessState.Sys().(syscall.WaitStatus); !ok || ws.Signal() != syscall.SIGUSR1 {
		t.Errorf("child state = %v", child.ProcessState)
	}
	f.release()
	f.release() // idempotent (deferred again above)
}

// Runs get millisecond timestamps.
func TestRunRecordMillisTimestamp(t *testing.T) {
	path := testDB(t)
	t.Setenv("IZ", path)
	if code := runRecord([]string{"true"}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if r, _ := lastRun(t, path); r.Ts != math.Round(r.Ts*1e3)/1e3 {
		t.Errorf("ts = %v, not millisecond precision", r.Ts)
	}
}

// One huge line with nothing but multi-byte characters: the kept tail
// starts on a whole character too.
func TestCaptureTailRuneBoundary(t *testing.T) {
	c := newCapture()
	c.Write(bytes.Repeat([]byte("a"), captureHead))     //nolint
	c.Write(bytes.Repeat([]byte("é"), 3*captureTail/2)) //nolint
	c.Write([]byte("z"))                                // the kept tail is odd-sized: it would start mid-"é"
	out := c.Bytes()
	if !utf8.Valid(out) {
		t.Error("captured output is not valid UTF-8")
	}
	if _, after, _ := bytes.Cut(out, []byte("not recorded\n")); !bytes.HasPrefix(after, []byte("é")) || !bytes.HasSuffix(after, []byte("éz")) {
		t.Errorf("tail = %q…", after[:min(8, len(after))])
	}
}

// Only ls gets the forced-color environment.
func TestPTYEnv(t *testing.T) {
	if env := ptyEnv("sh"); env != nil {
		t.Errorf("ptyEnv(sh) = %d vars, want nil (inherit)", len(env))
	}
	if env := ptyEnv("/bin/ls"); !slices.Contains(env, "CLICOLOR_FORCE=1") {
		t.Error("ptyEnv(ls) lacks CLICOLOR_FORCE=1")
	}
}

func TestRecordPipelineBothOutputs(t *testing.T) {
	path := testDB(t)
	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	id1, _, _, _, err := recordPipelineStage(db, PipelineStage{
		PGID: 1234, PidKey: "p-1", StagePos: 0, Ts: 100.0, EndTs: 106.0,
		Tool: "subfinder", Cmd: "subfinder -d de2.in", ShellCmd: "subfinder -d de2.in | httpx -silent",
		Cwd: "/tmp", Hostname: "h", ExitCode: 0, Raw: []byte("a.de2.in\nb.de2.in\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	id2, _, exit, dur, err := recordPipelineStage(db, PipelineStage{
		PGID: 1234, PidKey: "p-1", StagePos: 2, Ts: 100.0, EndTs: 110.0,
		Tool: "httpx", Cmd: "httpx -silent", ShellCmd: "subfinder -d de2.in | httpx -silent",
		Cwd: "/tmp", Hostname: "h", ExitCode: 0, Raw: []byte("https://a.de2.in\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("expected same run id, got %d and %d", id1, id2)
	}
	if n := countRuns(t, path); n != 1 {
		t.Fatalf("runs count = %d, want 1", n)
	}
	if exit != 0 || dur != 10*time.Second {
		t.Errorf("exit=%d dur=%v, want 0 and 10s", exit, dur)
	}
	r, out := lastRun(t, path)
	if r.Cmd != "subfinder -d de2.in | httpx -silent" || r.Tool != "subfinder" {
		t.Errorf("run = %+v", r)
	}
	if !strings.Contains(out, "[1/2] subfinder -d de2.in") || !strings.Contains(out, "[2/2] httpx -silent") {
		t.Errorf("expected both stage sections in output:\n%s", out)
	}
	if !strings.Contains(out, "b.de2.in") || !strings.Contains(out, "https://a.de2.in") {
		t.Errorf("missing stage outputs:\n%s", out)
	}
}

func TestRecordPipelineEmptyDownstream(t *testing.T) {
	path := testDB(t)
	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, _, _, _, err = recordPipelineStage(db, PipelineStage{
		PGID: 5678, PidKey: "p-2", StagePos: 0, Ts: 200.0, EndTs: 206.0,
		Tool: "subfinder", Cmd: "subfinder -d de2.in", ShellCmd: "subfinder -d de2.in | httpx -silent",
		Cwd: "/tmp", Hostname: "h", ExitCode: 0, Raw: []byte("a.de2.in\nb.de2.in\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, err = recordPipelineStage(db, PipelineStage{
		PGID: 5678, PidKey: "p-2", StagePos: 2, Ts: 200.0, EndTs: 210.0,
		Tool: "httpx", Cmd: "httpx -silent", ShellCmd: "subfinder -d de2.in | httpx -silent",
		Cwd: "/tmp", Hostname: "h", ExitCode: 0, Raw: nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := countRuns(t, path); n != 1 {
		t.Fatalf("runs count = %d, want 1", n)
	}
	r, out := lastRun(t, path)
	if r.Cmd != "subfinder -d de2.in | httpx -silent" {
		t.Errorf("cmd = %q", r.Cmd)
	}
	if out != "a.de2.in\nb.de2.in\n" {
		t.Errorf("expected upstream output directly without empty downstream noise, got %q", out)
	}
}

func TestPipelineHelpers(t *testing.T) {
	tools := []string{"subfinder", "httpx"}
	if !hasDownstreamWrappedTool("subfinder -d de2.in | httpx -silent", "subfinder", tools) {
		t.Error("expected subfinder to see downstream httpx")
	}
	if hasDownstreamWrappedTool("subfinder -d de2.in | httpx -silent", "httpx", tools) {
		t.Error("httpx should not see downstream wrapped tool")
	}
	if hasDownstreamWrappedTool("subfinder -d de2.in | grep api", "subfinder", tools) {
		t.Error("grep is unwrapped, should return false")
	}
	got := extractPipelineCmd("cd /tmp && subfinder -d de2.in | httpx -silent", []PipelineStage{{Tool: "subfinder"}, {Tool: "httpx"}})
	if got != "subfinder -d de2.in | httpx -silent" {
		t.Errorf("extractPipelineCmd = %q", got)
	}
}
