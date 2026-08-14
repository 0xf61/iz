package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// covers the non-TUI subcommands end to end against a temp database
func TestSubcommands(t *testing.T) {
	path := testDB(t)
	t.Setenv("IZ", path)

	// add / list / del-blacklist round trip
	if code := toolsCmd("add", []string{"nmap", "nuclei"}); code != 0 {
		t.Fatalf("add exit=%d", code)
	}
	if code := toolsCmd("add", []string{"iz"}); code != 0 {
		t.Fatalf("add iz exit=%d", code)
	}
	db, _ := openDBAt(path)
	var n int
	db.QueryRow(`SELECT count(*) FROM tools`).Scan(&n) //nolint
	if n != 2 {                                        // iz must be rejected
		t.Errorf("tools = %d, want 2", n)
	}
	db.Close()

	if code := toolsCmd("del", []string{"nmap", "vim"}); code != 0 {
		t.Fatalf("del exit=%d", code)
	}
	db, _ = openDBAt(path)
	var blocked int
	db.QueryRow(`SELECT count(*) FROM blacklist`).Scan(&blocked) //nolint
	if blocked != 2 {                                            // nmap + vim both land there
		t.Errorf("blacklist = %d, want 2", blocked)
	}
	var left int
	db.QueryRow(`SELECT count(*) FROM tools`).Scan(&left) //nolint
	if left != 1 {
		t.Errorf("tools after del = %d, want 1", left)
	}
	db.Close()

	// blacklisted tool cannot be imported
	dir := t.TempDir()
	f := filepath.Join(dir, "nmap.xml")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := importCmd([]string{"nmap", f}); code != 1 {
		t.Errorf("import of blacklisted tool exit=%d, want 1", code)
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
	// ids mixed with query terms and filter tokens (fzf passes whole lines)
	if code := showCmd([]string{strconv.FormatInt(id, 10) + " 2026 nmap exit=0", "80/tcp", "host:kali"}); code != 0 {
		t.Errorf("show exit=%d", code)
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
