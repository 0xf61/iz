package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "iz.db")
	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	return path
}

// insert a run directly (bypasses PTY) and return its id
func mustInsert(t *testing.T, path string, r Run, text string) int64 {
	t.Helper()
	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id, err := insertRun(db, r, gz([]byte(text)), []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func sampleRun(tool, cmd, text string) Run {
	return Run{Ts: 1700000000, Hostname: "kali", Tool: tool, Cmd: cmd, Cwd: "/tmp",
		ExitCode: ni(0), Dur: ni(100), Size: ni(64)}
}

func TestInsertAndSearchOutputText(t *testing.T) {
	path := testDB(t)
	mustInsert(t, path, sampleRun("certipy", "certipy find", "ESC2 vuln found"), "ESC2 vuln found")
	mustInsert(t, path, sampleRun("nxc", "nxc smb 10.0.0.0/24", "signing:False"), "signing:False")

	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	runs, err := queryRuns(db, "ESC2")
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Tool != "certipy" {
		t.Errorf("expected 1 certipy run matching ESC2, got %+v", runs)
	}
}

func TestQueryFilters(t *testing.T) {
	path := testDB(t)
	mustInsert(t, path, sampleRun("nxc", "cmd a", "output a"), "output a")

	db, _ := openDBAt(path)
	defer db.Close()

	runs, err := queryRuns(db, "tool:nxc")
	if err != nil || len(runs) != 1 {
		t.Errorf("tool:nxc → %v, %v", runs, err)
	}
	runs, err = queryRuns(db, "cmd:nmap")
	if err != nil || len(runs) != 0 {
		t.Errorf("tool:nmap → %v, %v", runs, err)
	}
	runs, err = queryRuns(db, "host:kali")
	if err != nil || len(runs) != 1 {
		t.Errorf("host:kali → %v, %v", runs, err)
	}
	runs, err = queryRuns(db, "host:other")
	if err != nil || len(runs) != 0 {
		t.Errorf("host:other → %v, %v", runs, err)
	}
}

func TestQueryColonTermFallsBackToLike(t *testing.T) {
	// "signing:False" is invalid FTS5 syntax (column filter); must fall back to LIKE.
	path := testDB(t)
	mustInsert(t, path, sampleRun("nxc", "cmd", "SMB 10.0.0.5 signing:False"), "SMB 10.0.0.5 signing:False")

	db, _ := openDBAt(path)
	defer db.Close()

	runs, err := queryRuns(db, "signing:False")
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Errorf("expected LIKE fallback to find 1 run, got %d", len(runs))
	}
}

func TestCmdAliasAndSizeFilter(t *testing.T) {
	path := testDB(t)
	small := sampleRun("nmap", "small scan", "x")
	small.Size = ni(1024)
	big := sampleRun("nmap", "big scan", "y")
	big.Size = ni(5 << 20) // 5MB
	mustInsert(t, path, small, "x")
	mustInsert(t, path, big, "y")

	db, _ := openDBAt(path)
	defer db.Close()

	// cmd: and legacy tool: both filter on the tool column
	for _, q := range []string{"cmd:nmap", "tool:nmap"} {
		runs, err := queryRuns(db, q)
		if err != nil || len(runs) != 2 {
			t.Errorf("%s → %d runs, %v", q, len(runs), err)
		}
	}
	runs, err := queryRuns(db, "size:>1mb")
	if err != nil || len(runs) != 1 || runs[0].Cmd != "big scan" {
		t.Errorf("size:>1mb → %+v, %v", runs, err)
	}
	runs, err = queryRuns(db, "size:<=4kb")
	if err != nil || len(runs) != 1 || runs[0].Cmd != "small scan" {
		t.Errorf("size:<=4kb → %+v, %v", runs, err)
	}
}

func TestParseSize(t *testing.T) {
	cases := []struct {
		in   string
		op   string
		want int64
	}{
		{">1mb", ">", 1 << 20}, {"<500kb", "<", 500 << 10}, {">=2gb", ">=", 2 << 30},
		{">1024", ">", 1024}, {"1mb", ">", 1 << 20}, {">bogus", "", 0},
	}
	for _, c := range cases {
		op, n, ok := parseSize(c.in)
		if c.want == 0 {
			if ok {
				t.Errorf("parseSize(%q) should fail", c.in)
			}
			continue
		}
		if !ok || op != c.op || n != c.want {
			t.Errorf("parseSize(%q) = %q,%d,%v want %q,%d", c.in, op, n, ok, c.op, c.want)
		}
	}
}

func TestHighlight(t *testing.T) {
	in := []byte("ESC8 vuln found\nall good\n")
	got := highlight(in, []string{"esc8"})
	if !strings.Contains(string(got), "\x1b[7mESC8\x1b[27m") {
		t.Errorf("highlight = %q", got)
	}
	if string(highlight(in, nil)) != string(in) {
		t.Error("no terms must leave output untouched")
	}
}

func TestCaseSensitivity(t *testing.T) {
	path := testDB(t)
	lower := sampleRun("toolA", "cmd a", "esc8 found here")
	mixed := sampleRun("toolB", "cmd b", "ESC8 FOUND here")
	mustInsert(t, path, lower, "esc8 found here")
	mustInsert(t, path, mixed, "ESC8 FOUND here")
	db, _ := openDBAt(path)
	defer db.Close()

	if runs, _ := queryRuns(db, "esc8"); len(runs) != 2 {
		t.Errorf("lowercase esc8 should match both, got %d", len(runs))
	}
	if runs, _ := queryRuns(db, "ESC8"); len(runs) != 1 {
		t.Errorf("mixed-case ESC8 should match only the exact one, got %d", len(runs))
	}
}

func TestFirstMatchLine(t *testing.T) {
	in := []byte("line0 top\nline1 filler\nline2 has vmware-detect here\nline3 tail\n")
	if n := firstMatchLine(in, []string{"vmware-detect"}); n != 2 {
		t.Errorf("firstMatchLine = %d, want 2", n)
	}
	if n := firstMatchLine(in, []string{"nonexistent"}); n != -1 {
		t.Errorf("no match should be -1, got %d", n)
	}
	if n := firstMatchLine(in, []string{"line0"}); n != 0 {
		t.Errorf("match on first line = %d, want 0 (no jump needed)", n)
	}
	if n := firstMatchLine(in, []string{"x"}); n != -1 {
		t.Errorf("terms shorter than 2 chars must be ignored, got %d", n)
	}
}

func TestDeleteRuns(t *testing.T) {
	path := testDB(t)
	id := mustInsert(t, path, sampleRun("nmap", "nmap -sV", "80/tcp open"), "80/tcp open")

	db, _ := openDBAt(path)
	defer db.Close()

	if n := deleteRuns(db, []int64{id}); n != 1 {
		t.Errorf("deleteRuns → %d, want 1", n)
	}
	if n := deleteRuns(db, []int64{id}); n != 0 {
		t.Errorf("double delete → %d, want 0", n)
	}
	if runs, _ := queryRuns(db, ""); len(runs) != 0 {
		t.Errorf("expected empty result after delete, got %d", len(runs))
	}
}

func TestImportSetsDirFromFileLocation(t *testing.T) {
	// importing atbanksube/kapsam.nuclei must stamp the file's directory,
	// not the caller's cwd
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "atbanksube"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "atbanksube", "kapsam.nuclei")
	if err := os.WriteFile(file, []byte("[nuclei] findings here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := testDB(t)
	t.Setenv("IZ", path)

	if code := importCmd([]string{"nuclei", file}); code != 0 {
		t.Fatalf("importCmd exit=%d", code)
	}
	db, _ := openDBAt(path)
	defer db.Close()
	runs, err := queryRuns(db, "tool:nuclei")
	if err != nil || len(runs) != 1 {
		t.Fatalf("expected 1 run, got %d (%v)", len(runs), err)
	}
	want := filepath.Join(dir, "atbanksube")
	if runs[0].Cwd != want {
		t.Errorf("Cwd = %q, want %q", runs[0].Cwd, want)
	}
}

func TestGetMeta(t *testing.T) {
	path := testDB(t)
	id := mustInsert(t, path, sampleRun("nmap", "nmap -sV", "80/tcp open"), "80/tcp open")

	db, _ := openDBAt(path)
	defer db.Close()

	raw, r, err := getMeta(db, id)
	if err != nil {
		t.Fatal(err)
	}
	if r.Cmd != "nmap -sV" || r.Hostname != "kali" {
		t.Errorf("getMeta → %+v", r)
	}
	if string(ungz(raw)) != "80/tcp open" {
		t.Errorf("raw mismatch: %q", ungz(raw))
	}
}

func TestMergeDedup(t *testing.T) {
	mainPath := testDB(t)
	otherPath := testDB(t)

	mustInsert(t, otherPath, sampleRun("nmap", "nmap -sV", "80/tcp open"), "80/tcp open")
	mustInsert(t, otherPath, sampleRun("nmap", "nmap -p 443", "443/tcp open"), "443/tcp open")

	// merge other → main
	t.Setenv("IZ", mainPath)
	if code := mergeCmd(otherPath); code != 0 {
		t.Fatalf("mergeCmd exit=%d", code)
	}
	// merging again must skip all as duplicates
	if code := mergeCmd(otherPath); code != 0 {
		t.Fatalf("second mergeCmd exit=%d", code)
	}

	db, _ := openDBAt(mainPath)
	defer db.Close()
	runs, err := queryRuns(db, "tool:nmap")
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Errorf("expected 2 runs after merge (dedup), got %d", len(runs))
	}
}

func TestRunLineSearchableFields(t *testing.T) {
	r := Run{ID: 7, Ts: 1700000000, Hostname: "kali", Tool: "nmap",
		Cmd: "nmap -sV", Cwd: "/home/user/eng", ExitCode: ni(0), Size: ni(4096),
		Snippet: "80/tcp open"}
	line := r.line()

	// visible: id, date, tool, dir name, command
	for _, want := range []string{"nmap", "eng", "nmap -sV"} {
		if !strings.Contains(line, want) {
			t.Errorf("line missing %q: %q", want, line)
		}
	}
	// host stays a filter token in the dim run; exit/size are preview-only
	for _, want := range []string{"host:kali"} {
		if !strings.Contains(line, want) {
			t.Errorf("line missing filter token %q: %q", want, line)
		}
	}
	// the output snippet must not leak into the visible list line
	if strings.Contains(line, "80/tcp open") {
		t.Errorf("line should not contain the output snippet: %q", line)
	}
}
