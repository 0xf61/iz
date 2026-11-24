package main

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
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

func TestQueryColonTermUsesQuotedFTS(t *testing.T) {
	// "signing:False" is invalid FTS5 syntax (column filter); the quoted form
	// ("signing:False" as a phrase) must still find it.
	path := testDB(t)
	mustInsert(t, path, sampleRun("nxc", "cmd", "SMB 10.0.0.5 signing:False"), "SMB 10.0.0.5 signing:False")

	db, _ := openDBAt(path)
	defer db.Close()

	runs, err := queryRuns(db, "signing:False")
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Errorf("expected quoted FTS query to find 1 run, got %d", len(runs))
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
	// ANSI sequences must never be matched/corrupted when searching numbers like "31"
	ansiIn := []byte("\x1b[31mport 31 open\x1b[0m\n")
	ansiGot := string(highlight(ansiIn, []string{"31"}))
	if !strings.HasPrefix(ansiGot, "\x1b[31m") || !strings.Contains(ansiGot, "port \x1b[7m31\x1b[27m open") {
		t.Errorf("highlight corrupted ANSI escape or missed match: %q", ansiGot)
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

	if n, err := deleteRuns(db, []int64{id}); n != 1 || err != nil {
		t.Errorf("deleteRuns → %d (%v), want 1", n, err)
	}
	if n, err := deleteRuns(db, []int64{id}); n != 0 || err != nil {
		t.Errorf("double delete → %d (%v), want 0", n, err)
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
	r := Run{ID: 7, Ts: 1700000000, Hostname: "kali.local", Tool: "nmap",
		Cmd: "nmap -sV", Cwd: "/home/user/eng", ExitCode: ni(1), Size: ni(4096),
		Snippet: "80/tcp open"}
	line := r.line(10, "macbook")

	// visible: id (red on non-zero exit), date, dir name, tool, command args, @host when remote
	for _, want := range []string{"\x1b[31m7\x1b[0m", "nmap", "eng", "-sV", "@kali"} {
		if !strings.Contains(line, want) {
			t.Errorf("line missing %q: %q", want, line)
		}
	}
	// local host is omitted for compactness
	localLine := r.line(10, "kali.local")
	if strings.Contains(localLine, "@kali") {
		t.Errorf("local host should be omitted: %q", localLine)
	}
	// the output snippet must not leak into the visible list line
	if strings.Contains(line, "80/tcp open") {
		t.Errorf("line should not contain the output snippet: %q", line)
	}
}

// FTS syntax around words: a prefix star, parens and boolean operators keep
// working, and smart case still applies to the bare word ("ESC*" used to
// require the literal "ESC*" in the output and found nothing).
func TestSearchRunsPrefixAndGroups(t *testing.T) {
	path := testDB(t)
	mustInsert(t, path, sampleRun("t1", "a", "ESCALATION possible"), "ESCALATION possible")
	mustInsert(t, path, sampleRun("t2", "b", "escape hatch"), "escape hatch")
	mustInsert(t, path, sampleRun("t3", "c", "SSH Admin login"), "SSH Admin login")
	db, _ := openDBAt(path)
	defer db.Close()

	cases := []struct {
		q    string
		want int
	}{
		{"ESC*", 1},            // uppercase: case-sensitive prefix
		{"esc*", 2},            // lowercase: any case
		{"(SSH AND Admin)", 1}, // grouping
		{"ssh OR escape", 2},   // pure OR
		{"hatch possible", 2},  // AND finds nothing → OR fallback
		{"nomatch", 0},
	}
	for _, c := range cases {
		runs, err := queryRuns(db, c.q)
		if err != nil {
			t.Fatalf("%q: %v", c.q, err)
		}
		if len(runs) != c.want {
			t.Errorf("queryRuns(%q) = %d runs, want %d", c.q, len(runs), c.want)
		}
	}
}

// Highlighting looks for the words of the query: quotes, parens and the
// prefix star are stripped, operators and filters are not highlighted, and
// case folding covers Turkish (İ/I/ı) with byte offsets kept intact.
func TestHighlightQuotedAndTurkish(t *testing.T) {
	in := []byte("error: \"443/tcp\" open, ESCALATION\n")
	got := string(highlight(in, strings.Fields(`"443/tcp" OR (ESC* host:kali`)))
	if !strings.Contains(got, "\x1b[7m443/tcp\x1b[27m") || !strings.Contains(got, "\x1b[7mESC\x1b[27mALATION") {
		t.Errorf("quoted/prefix terms not highlighted: %q", got)
	}
	if strings.Contains(got, "err\x1b[7mor") || strings.Contains(got, "kali") {
		t.Errorf("operator or filter highlighted: %q", got)
	}

	tr := []byte("İSTANBUL ofisi, IŞIK açık\n")
	got = string(highlight(tr, []string{"istanbul", "ışık"}))
	if want := "\x1b[7mİSTANBUL\x1b[27m ofisi, \x1b[7mIŞIK\x1b[27m açık\n"; got != want {
		t.Errorf("turkish highlight = %q, want %q", got, want)
	}
	if n := firstMatchLine([]byte("satır\nŞİRKET ağı\n"), []string{"şirket"}); n != 1 {
		t.Errorf("firstMatchLine(şirket) = %d, want 1", n)
	}
	if l := matchLine("a\nİzmir sunucusu\n", needles([]string{"izmir"})); l != "İzmir sunucusu" {
		t.Errorf("matchLine(izmir) = %q", l)
	}
}

// Pre-v4 NUL-delimited tombstone keys are converted, not dropped, so the
// deletes they record still apply; truncated 1-byte keys are removed.
func TestMigrationConvertsLegacyTombstones(t *testing.T) {
	path := testDB(t)
	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := []string{"m\x00abc123", "r\x00kali\x001700000000\x00nmap\x00nmap -sV", "m", "m\x00dup", "m:dup"}
	for _, k := range legacy {
		if _, err := db.Exec(`INSERT INTO tombstones(key, ts) VALUES(?, 0)`, k); err != nil {
			t.Fatal(err)
		}
	}
	db.Exec(`PRAGMA user_version=3`) //nolint
	db.Close()

	db, err = openDBAt(path) // migrates
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var keys []string
	rows, err := db.Query(`SELECT key FROM tombstones ORDER BY key`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var k string
		rows.Scan(&k) //nolint
		keys = append(keys, k)
	}
	rows.Close()
	want := []string{"m:abc123", "m:dup", runKey("kali", 1700000000, "nmap", "nmap -sV")}
	if strings.Join(keys, "|") != strings.Join(want, "|") {
		t.Errorf("tombstones after migration = %q, want %q", keys, want)
	}
}

// dir: matches whole path components and LIKE wildcards in filters are literal.
func TestDirCondAndLikeEscaping(t *testing.T) {
	path := testDB(t)
	for _, c := range []struct{ host, cwd string }{
		{"kali", "/Users/x/eng"}, {"kali", "/tmp/us"}, {"kali", "/opt/a_b"},
		{"kali", "/opt/axb"}, {"kali", "/opt/50%"}, {"k_li", "/opt/5000"},
	} {
		r := sampleRun("ls", "ls "+c.cwd, "")
		r.Hostname, r.Cwd = c.host, c.cwd
		mustInsert(t, path, r, "")
	}
	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for q, want := range map[string]int{
		"dir:/":          6,
		"dir:us":         1, // not /Users
		"dir:/Users":     1,
		"dir:/Users/":    1,
		"dir:x/eng":      1,
		"dir:a_b":        1, // not axb
		"dir:50%":        1, // not 5000
		"dir:/opt":       4,
		"host:k_li":      1, // not kali
		"host:k%":        0,
		"dir:/opt/a_b/c": 0,
	} {
		runs, err := queryRuns(db, q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if len(runs) != want {
			t.Errorf("%-16q → %d runs, want %d", q, len(runs), want)
		}
	}
}

// $IZ paths with URI metacharacters open the file they name, pragmas intact.
func TestOpenDBAtSpecialChars(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a #1?x%20", "iz.db")
	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var mode string
	var timeout int
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Errorf("journal_mode = %q (%v), want wal", mode, err)
	}
	if err := db.QueryRow(`PRAGMA busy_timeout`).Scan(&timeout); err != nil || timeout != 5000 {
		t.Errorf("busy_timeout = %d (%v), want 5000", timeout, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("database not at its path: %v", err)
	}
}

func TestParseSizeRejectsNonFinite(t *testing.T) {
	for _, in := range []string{">inf", ">nan", "<-1kb", ">+Inf", ">1e300gb", ">9223372036854775807"} {
		if op, n, ok := parseSize(in); ok {
			t.Errorf("parseSize(%q) = %q,%d, want rejected", in, op, n)
		}
	}
}

// A failing delete is reported and leaves the runs in place.
func TestDeleteRunsError(t *testing.T) {
	path := testDB(t)
	id := mustInsert(t, path, sampleRun("nmap", "nmap -sV", "x"), "x")
	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE tombstones`); err != nil {
		t.Fatal(err)
	}
	if n, err := deleteRuns(db, []int64{id}); err == nil || n != 0 {
		t.Errorf("deleteRuns = %d, %v; want an error", n, err)
	}
	if runs, _ := queryRuns(db, ""); len(runs) != 1 {
		t.Errorf("runs after a failed delete = %d, want 1", len(runs))
	}
	t.Setenv("IZ", path)
	if code := delRuns([]string{strconv.FormatInt(id, 10)}); code != 1 {
		t.Errorf("delRuns exit=%d, want 1", code)
	}
}

func TestDefaultToolsSeeded(t *testing.T) {
	db, err := openDBAt(testDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got := queryNames(db, "tools"); !slices.Equal(got, slices.Sorted(slices.Values(defaultTools))) {
		t.Errorf("tools = %q", got)
	}
}

// Local table setup and chmod run only when migrating behind PRAGMA user_version.
func TestOpenDBAtSchemaVersionGate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "iz.db")
	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	var ver int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&ver); err != nil || ver != localSchemaVersion {
		t.Fatalf("user_version = %d (%v), want %d", ver, err, localSchemaVersion)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("initial db perm = %04o, want 0600", perm)
	}

	// Drop pipeline_stages and relax permissions while keeping user_version current:
	// reopening must skip both ensureLocalTables and chmod.
	if _, err := db.Exec(`DROP TABLE pipeline_stages`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	db, err = openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	var tbl int
	db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='pipeline_stages'`).Scan(&tbl) //nolint
	if tbl != 0 {
		t.Errorf("pipeline_stages recreated despite current user_version=%d", localSchemaVersion)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("chmod ran despite current user_version: perm=%04o err=%v", fi.Mode().Perm(), err)
	}

	// Downgrade user_version to 5: reopening must migrate, recreate pipeline_stages, and chmod 0600.
	if _, err := db.Exec(`PRAGMA user_version=5`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db, err = openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='pipeline_stages'`).Scan(&tbl) //nolint
	if tbl != 1 {
		t.Errorf("pipeline_stages not created on v5->v%d migration", localSchemaVersion)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("perm after migration = %04o (%v), want 0600", fi.Mode().Perm(), err)
	}
}

func TestGetRunCmd(t *testing.T) {
	path := testDB(t)
	id := mustInsert(t, path, sampleRun("nmap", "nmap -sV 10.0.0.1", "80/tcp open"), "80/tcp open")
	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	got, err := getRunCmd(db, id)
	if err != nil || got != "nmap -sV 10.0.0.1" {
		t.Errorf("getRunCmd(%d) = %q, %v; want nmap -sV 10.0.0.1", id, got, err)
	}
	if _, err := getRunCmd(db, id+999); err == nil {
		t.Error("expected error for missing run id")
	}
}
