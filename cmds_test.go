package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

// covers the non-TUI subcommands end to end against a temp database
func TestSubcommands(t *testing.T) {
	path := testDB(t)
	t.Setenv("IZ", path)

	// add / list / del round trip
	db, _ := openDBAt(path)
	var initCount int
	db.QueryRow(`SELECT count(*) FROM tools`).Scan(&initCount) //nolint
	db.Close()

	if code := toolsCmd("add", []string{"mycustomtool", "nuclei"}); code != 0 {
		t.Fatalf("add exit=%d", code)
	}
	for _, rejected := range [][]string{{"iz"}, {"if"}, {"if", "-x"}} { // nothing added: a failure
		if code := toolsCmd("add", rejected); code != 1 {
			t.Fatalf("add %q exit=%d, want 1", rejected, code)
		}
	}
	db, _ = openDBAt(path)
	var n int
	db.QueryRow(`SELECT count(*) FROM tools`).Scan(&n) //nolint
	if n != initCount+1 {                              // nuclei is already in default tools, mycustomtool added, iz rejected
		t.Errorf("tools = %d, want %d", n, initCount+1)
	}
	db.Close()

	if code := toolsCmd("del", []string{"mycustomtool"}); code != 0 {
		t.Fatalf("del exit=%d", code)
	}
	db, _ = openDBAt(path)
	var left int
	db.QueryRow(`SELECT count(*) FROM tools`).Scan(&left) //nolint
	if left != initCount {
		t.Errorf("tools after del = %d, want %d", left, initCount)
	}
	db.Close()

	// previously blacklisted names import fine now
	dir := t.TempDir()
	f := filepath.Join(dir, "nmap.xml")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := importCmd([]string{"nmap", f}); code != 0 {
		t.Errorf("import after del exit=%d, want 0", code)
	}
}

// delRuns accepts whole fzf lines; only the leading id matters
func TestDelRuns(t *testing.T) {
	path := testDB(t)
	t.Setenv("IZ", path)
	id := mustInsert(t, path, sampleRun("nmap", "nmap -sV", "80/tcp open"), "80/tcp open")

	if code := delRuns([]string{"garbage", "  "}); code != 130 {
		t.Errorf("delRuns without any id exit=%d, want 130", code)
	}
	if code := delRuns([]string{strconv.FormatInt(id, 10) + " rest of line"}); code != 0 {
		t.Fatalf("delRuns exit=%d", code)
	}
	db, _ := openDBAt(path)
	defer db.Close()
	if runs, _ := queryRuns(db, ""); len(runs) != 0 {
		t.Errorf("run still present after delete")
	}
}

// showCmd separates ids from query terms and skips filter tokens
func TestShowCmdArgs(t *testing.T) {
	path := testDB(t)
	t.Setenv("IZ", path)
	id := mustInsert(t, path, sampleRun("nmap", "nmap -sV", "80/tcp open"), "80/tcp open")

	if code := showCmd(nil); code != 2 {
		t.Errorf("no args exit=%d, want 2", code)
	}
	// the TUI passes whole fzf lines ({+}), then "--" and the query ({q})
	line := strconv.FormatInt(id, 10) + " \x1b[90m2026\x1b[0m nmap -sV"
	if code := showCmd([]string{line, "--", "80/tcp", "host:kali"}); code != 0 {
		t.Errorf("show exit=%d", code)
	}
	if code := showCmd([]string{"99999"}); code != 1 {
		t.Errorf("missing run exit=%d, want 1", code)
	}
}

// showArgs: a numeric query is not mistaken for a run id
func TestShowCmdNumericQuery(t *testing.T) {
	path := testDB(t)
	a := mustInsert(t, path, sampleRun("nmap", "nmap a", "443 open"), "443 open")
	b := mustInsert(t, path, sampleRun("nmap", "nmap b", "80 open"), "80 open")
	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sa, sb := strconv.FormatInt(a, 10), strconv.FormatInt(b, 10)

	cases := []struct {
		args  []string
		ids   []int64
		terms []string
	}{
		{[]string{sa, "443 open"}, []int64{a}, []string{"443", "open"}},
		{[]string{sa, sb}, []int64{a, b}, nil},                 // both exist: two runs
		{[]string{sa, "99999"}, []int64{a}, []string{"99999"}}, // no such run: query
		{[]string{sa, "--", sb}, []int64{a}, []string{sb}},     // after --: query
		{[]string{sa + " \x1b[90m01-02\x1b[0m nmap", sb + " x", "--", "open"}, []int64{a, b}, []string{"open"}},
		{[]string{"open"}, nil, []string{"open"}},
	}
	for _, c := range cases {
		ids, terms := showArgs(db, c.args)
		if !slices.Equal(ids, c.ids) || !slices.Equal(terms, c.terms) {
			t.Errorf("showArgs(%q) = %v %q, want %v %q", c.args, ids, terms, c.ids, c.terms)
		}
	}
}

// linesCmd is the TUI reload source: it must honor filters and free text
func TestLinesCmd(t *testing.T) {
	path := testDB(t)
	t.Setenv("IZ", path)
	mustInsert(t, path, sampleRun("nmap", "scan a", "vmware-detect here"), "vmware-detect here")
	mustInsert(t, path, sampleRun("nxc", "scan b", "signing:False"), "signing:False")

	if code := linesCmd(nil); code != 0 {
		t.Fatalf("lines exit=%d", code)
	}
	if code := linesCmd([]string{"vmware-detect"}); code != 0 {
		t.Fatalf("lines filter exit=%d", code)
	}
}

// size: filter composes with free-text search and other filters
func TestSizeFilterComposition(t *testing.T) {
	path := testDB(t)
	small := sampleRun("nmap", "small", "needle here")
	small.Size = ni(1024)
	big := sampleRun("nmap", "big", "needle there")
	big.Size = ni(3 << 20)
	other := sampleRun("nxc", "other", "needle elsewhere")
	other.Size = ni(3 << 20)
	mustInsert(t, path, small, "needle here")
	mustInsert(t, path, big, "needle there")
	mustInsert(t, path, other, "needle elsewhere")

	db, _ := openDBAt(path)
	defer db.Close()

	cases := []struct {
		q    string
		want int
	}{
		{"needle", 3},
		{"needle size:>1mb", 2},
		{"needle size:>1mb cmd:nmap", 1},
		{"needle size:<2kb", 1},
		{"needle cmd:nxc size:>1mb", 1},
	}
	for _, c := range cases {
		runs, err := queryRuns(db, c.q)
		if err != nil {
			t.Fatalf("%s: %v", c.q, err)
		}
		if len(runs) != c.want {
			t.Errorf("%-30q → %d runs, want %d", c.q, len(runs), c.want)
		}
	}
}

func TestResolveEditor(t *testing.T) {
	t.Setenv("EDITOR", "my-custom-editor")
	if ed := resolveEditor(); ed != "my-custom-editor" {
		t.Errorf("resolveEditor() = %q, want 'my-custom-editor'", ed)
	}

	for _, blank := range []string{"", "   "} {
		t.Setenv("EDITOR", blank)
		ed := resolveEditor()
		if ed != "nvim" && ed != "vim" && ed != "vi" && ed != "nano" {
			t.Errorf("EDITOR=%q: resolveEditor() = %q, want one of nvim/vim/vi/nano", blank, ed)
		}
	}
}

// captureStdout returns what fn prints to stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() { b, _ := io.ReadAll(r); done <- b }()
	defer func() { os.Stdout = old }()
	fn()
	w.Close()
	return string(<-done)
}

func TestRecallCmdArgsAndErrors(t *testing.T) {
	path := testDB(t)
	t.Setenv("IZ", path)
	mustInsert(t, path, sampleRun("nmap", "nmap -sV host", "22/tcp open ssh"), "22/tcp open ssh")
	db, _ := openDBAt(path)
	if _, err := insertMemory(db, Memory{Namespace: "pentest", Title: "nmap tips", Content: "use nmap -sV"}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	for _, args := range [][]string{{}, {"-l", "abc", "x"}, {"-l", "0", "x"}, {"x", "-l"}, {"--json"}} {
		if code := recallCmd(args); code != 2 {
			t.Errorf("recall %q exit=%d, want 2", args, code)
		}
	}

	var res struct {
		Notes []Memory `json:"memories"`
		Runs  []struct {
			Tool string `json:"tool"`
		} `json:"runs"`
	}
	recall := func(args ...string) {
		t.Helper()
		out := captureStdout(t, func() {
			if code := recallCmd(append([]string{"--json"}, args...)); code != 0 {
				t.Errorf("recall %q exit=%d", args, code)
			}
		})
		res.Notes, res.Runs = nil, nil
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("recall %q: %v\n%s", args, err, out)
		}
	}
	recall("cmd:nmap") // a runs-only filter limits the search to runs
	if len(res.Runs) != 1 || len(res.Notes) != 0 {
		t.Errorf("cmd:nmap → %d notes, %d runs; want runs only", len(res.Notes), len(res.Runs))
	}
	recall("-n", "nmap", "cmd:nmap") // explicit -n wins over the filter
	if len(res.Runs) != 0 {
		t.Errorf("-n with cmd: returned runs: %+v", res.Runs)
	}
	recall("nmap") // both sides
	if len(res.Runs) != 1 || len(res.Notes) != 1 {
		t.Errorf("nmap → %d notes, %d runs; want 1 and 1", len(res.Notes), len(res.Runs))
	}

	// a database that cannot be opened is an error, not an empty result
	t.Setenv("IZ", t.TempDir()) // a directory
	if code := recallCmd([]string{"nmap"}); code == 0 {
		t.Error("recall on a broken database exited 0")
	}
}

// Commands without options still answer --help and reject unknown options.
func TestHelpAndUnknownOptions(t *testing.T) {
	t.Setenv("IZ", testDB(t))
	called := false
	fn := func(string) int { called = true; return 0 }
	for args, want := range map[string]int{"--help": 0, "-h": 0, "-x": 2, "--nope": 2} {
		if code := oneArg("iz e <id>", []string{args}, fn); code != want {
			t.Errorf("oneArg %q exit=%d, want %d", args, code, want)
		}
		if code := importCmd([]string{args}); code != want {
			t.Errorf("iz i %q exit=%d, want %d", args, code, want)
		}
	}
	if called {
		t.Error("oneArg ran the command for an option")
	}
	if code := primeCmd([]string{"--unknown"}); code != 2 {
		t.Errorf("iz prime --unknown exit=%d, want 2", code)
	}
}

func TestAIGuideCmd(t *testing.T) {
	if code := aiGuideCmd(); code != 0 {
		t.Errorf("aiGuideCmd() = %d, want 0", code)
	}
}
