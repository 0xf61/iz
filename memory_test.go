package main

import (
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
)

func TestMemoryCRUD(t *testing.T) {
	dir := t.TempDir()
	db, err := openDBAt(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// 1. Insert memory
	m := Memory{
		Namespace: "machines",
		Title:     "kali",
		Content:   "Kali box IP 10.42.13.37",
		Author:    "alice",
		Tags:      "kali,vpn",
		Hostname:  "macbook",
	}

	id, err := insertMemory(db, m)
	if err != nil {
		t.Fatalf("insertMemory: %v", err)
	}
	if id <= 0 {
		t.Fatalf("expected positive id, got %d", id)
	}

	// 2. Query memory via FTS
	results, err := queryMemories(db, "kali", 10)
	if err != nil {
		t.Fatalf("queryMemories: %v", err)
	}
	if len(results) != 1 || results[0].Title != "kali" || !strings.Contains(results[0].Content, "10.42.13.37") {
		t.Fatalf("expected 1 'kali' with 10.42.13.37, got %+v", results)
	}

	// 3. Query with namespace, tag, and host filters
	for _, q := range []string{"ns:machines 10.42.13.37", "tag:vpn", "host:macbook kali", "author:alice"} {
		res, err := queryMemories(db, q, 10)
		if err != nil || len(res) != 1 {
			t.Fatalf("queryMemories(%q) → %d results, err=%v", q, len(res), err)
		}
	}

	// 4. Update memory (title, tags, content) and verify FTS reflects changes
	err = updateMemory(db, Memory{
		ID:        id,
		Namespace: "machines",
		Title:     "kali-box",
		Content:   "Kali box IP 10.42.13.37 (ssh 2222)",
		Tags:      "kali,ssh",
		Mtime:     m.Ts + 50,
	})
	if err != nil {
		t.Fatalf("updateMemory: %v", err)
	}
	if res, _ := queryMemories(db, "ns:machines 2222", 10); len(res) != 1 || res[0].Title != "kali-box" {
		t.Fatalf("expected updated note via FTS, got %+v", res)
	}

	// 5. Delete memory
	if err := deleteMemory(db, id); err != nil {
		t.Fatalf("deleteMemory: %v", err)
	}
	if delResults, _ := queryMemories(db, "kali", 10); len(delResults) != 0 {
		t.Fatalf("expected 0 results after delete, got %d", len(delResults))
	}
}

func TestNoteDocAndCLISubcommands(t *testing.T) {
	path := testDB(t)
	t.Setenv("IZ", path)

	if code := noteCmd([]string{"machines:kali", "-t", "kali,vpn", "Kali IP 10.42.13.37"}); code != 0 {
		t.Fatalf("noteCmd add exit=%d", code)
	}
	if code := noteCmd([]string{"list", "machines"}); code != 0 {
		t.Fatalf("noteCmd list exit=%d", code)
	}
	if code := noteCmd([]string{"show", "1"}); code != 0 {
		t.Fatalf("noteCmd show exit=%d", code)
	}
	if code := recallCmd([]string{"--json", "kali"}); code != 0 {
		t.Fatalf("recallCmd --json exit=%d", code)
	}
	if code := recallCmd([]string{"10.42.13.37"}); code != 0 {
		t.Fatalf("recallCmd text exit=%d", code)
	}

	// Verify parseNoteDoc with tags
	ns, title, tags, body, ok := parseNoteDoc("# machines:kali [kali,vpn]\n" + noteHint + "\n10.42.13.37\n")
	if !ok || ns != "machines" || title != "kali" || tags != "kali,vpn" || !strings.Contains(body, "10.42.13.37") {
		t.Errorf("parseNoteDoc = %q %q %q %q (%v)", ns, title, tags, body, ok)
	}
}

func TestNoteUpsertAppendAndTargets(t *testing.T) {
	path := testDB(t)
	t.Setenv("IZ", path)

	// Upsert by namespace:title must update in place without creating duplicates
	if code := noteCmd([]string{"machines:kali", "-t", "vpn", "10.42.13.37"}); code != 0 {
		t.Fatalf("initial noteCmd exit=%d", code)
	}
	if code := noteCmd([]string{"-t", "vpn,ssh", "machines:kali", "10.10.138.15"}); code != 0 {
		t.Fatalf("upsert noteCmd exit=%d", code)
	}
	if code := noteCmd([]string{"-a", "machines:kali", "port 2222"}); code != 0 {
		t.Fatalf("append noteCmd exit=%d", code)
	}

	db, _ := openDBAt(path)
	defer db.Close()
	res, err := queryMemories(db, "ns:machines", 10)
	if err != nil || len(res) != 1 {
		t.Fatalf("expected 1 deduplicated note, got %d (%v)", len(res), err)
	}
	if !strings.Contains(res[0].Content, "10.10.138.15") || !strings.Contains(res[0].Content, "port 2222") {
		t.Errorf("unexpected content after upsert+append: %q", res[0].Content)
	}

	// tag:pi must not match tag "vpn,api"
	if code := noteCmd([]string{"machines:router", "-t", "vpn,api", "router note"}); code != 0 {
		t.Fatalf("router note exit=%d", code)
	}
	if piRes, _ := queryMemories(db, "tag:pi", 10); len(piRes) != 0 {
		t.Errorf("tag:pi matched unrelated tag: %+v", piRes)
	}
	if apiRes, _ := queryMemories(db, "tag:api", 10); len(apiRes) != 1 {
		t.Errorf("tag:api expected 1 match, got %d", len(apiRes))
	}

	// show and del by namespace:title
	if code := noteCmd([]string{"show", "machines:kali"}); code != 0 {
		t.Errorf("show by ns:title exit=%d", code)
	}
	if code := noteCmd([]string{"del", "machines:kali"}); code != 0 {
		t.Errorf("del by ns:title exit=%d", code)
	}
	if after, _ := queryMemories(db, "ns:machines", 10); len(after) != 1 {
		t.Errorf("expected 1 note left after delete, got %d", len(after))
	}
}

func TestImportMarkdownCodeBlocksAndInlineSection(t *testing.T) {
	dir := t.TempDir()
	md := "# Setup\nSee (bkz. §LINT). Inline §Finans should not split.\n\n```bash\n# comment inside code block\necho hi\n```\n\n## Second Section\nBody 2\n"
	file := filepath.Join(dir, "guide.md")
	if err := os.WriteFile(file, []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}

	path := testDB(t)
	t.Setenv("IZ", path)
	if code := importNotes(file); code != 0 {
		t.Fatalf("importNotes exit=%d", code)
	}

	db, _ := openDBAt(path)
	defer db.Close()
	res, err := queryMemories(db, "ns:guide", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 sections (Setup + Second Section), got %d: %+v", len(res), res)
	}
}

// noteByTarget loads a note by "ns:title" (fails the test when missing).
func noteByTarget(t *testing.T, path, target string) Memory {
	t.Helper()
	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id, err := resolveMemoryID(db, target)
	if err != nil {
		t.Fatal(err)
	}
	m, err := getMemory(db, id)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Flags after the content used to be saved as content ("foo -a").
func TestNoteCmdTrailingFlags(t *testing.T) {
	path := testDB(t)
	t.Setenv("IZ", path)

	steps := []struct {
		args []string
		code int
	}{
		{[]string{"x:y", "first"}, 0},
		{[]string{"x:y", "second", "-a"}, 0},                    // trailing append
		{[]string{"x:y", "third", "--append", "-t", "a, b"}, 0}, // trailing tags + append
		{[]string{"x:y", "-t"}, 2},                              // -t without a value
		{[]string{"x:z", "--", "-a", "-t", "x"}, 0},             // after --: content
	}
	for _, s := range steps {
		if code := noteCmd(s.args); code != s.code {
			t.Fatalf("noteCmd(%q) exit=%d, want %d", s.args, code, s.code)
		}
	}
	m := noteByTarget(t, path, "x:y")
	if m.Content != "first\nsecond\nthird" || m.Tags != "a,b" {
		t.Errorf("x:y = %q tags %q", m.Content, m.Tags)
	}
	if m := noteByTarget(t, path, "x:z"); m.Content != "-a -t x" || m.Tags != "" {
		t.Errorf("x:z = %q tags %q", m.Content, m.Tags)
	}
}

// Concurrent writers (separate connections, like separate iz processes) all
// succeed: read-then-write transactions take the write lock at BEGIN instead
// of failing with SQLITE_BUSY on upgrade.
func TestConcurrentUpsertMemory(t *testing.T) {
	path := testDB(t)
	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			db, err := openDBAt(path)
			if err != nil {
				errs <- err
				return
			}
			defer db.Close()
			m := Memory{Namespace: "race", Title: "same", Content: fmt.Sprintf("line %d", i)}
			if _, _, err := upsertMemory(db, m, true); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent upsert: %v", err)
	}
	m := noteByTarget(t, path, "race:same")
	if got := len(strings.Split(m.Content, "\n")); got != n {
		t.Errorf("appended lines = %d, want %d: %q", got, n, m.Content)
	}
	db, _ := openDBAt(path)
	defer db.Close()
	var rows int
	db.QueryRow(`SELECT count(*) FROM memories`).Scan(&rows) //nolint
	if rows != 1 {
		t.Errorf("notes = %d, want 1", rows)
	}
}

// Namespaces from subdirectories ("projeler/aktif") and titles with colons
// stay addressable, and an editor round trip keeps them unchanged.
func TestImportSubdirNamespaceAddressable(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "projeler")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "aktif.md"), []byte("# Faz 1: Setup\nkurulum\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := testDB(t)
	t.Setenv("IZ", path)
	if code := importNotes(dir); code != 0 {
		t.Fatalf("import exit=%d", code)
	}

	const target = "projeler/aktif:Faz 1: Setup"
	m := noteByTarget(t, path, target)
	if m.Namespace != "projeler/aktif" || m.Title != "Faz 1: Setup" {
		t.Fatalf("imported as %q:%q", m.Namespace, m.Title)
	}
	for _, args := range [][]string{{"show", target}, {target, "-a", "yeni satır"}} {
		if code := noteCmd(args); code != 0 {
			t.Errorf("noteCmd(%q) exit=%d", args, code)
		}
	}
	if m := noteByTarget(t, path, target); m.Content != "kurulum\nyeni satır" {
		t.Errorf("content after append = %q", m.Content)
	}
	// $EDITOR round trip: the header must parse back to the same note
	ns, title, _, body, ok := parseNoteDoc(noteDoc(m))
	if !ok || ns != m.Namespace || title != m.Title || body != m.Content {
		t.Errorf("noteDoc round trip = %q %q %q", ns, title, body)
	}
	if ns, title := parseTarget("machines/kali"); ns != "machines" || title != "kali" {
		t.Errorf("parseTarget(machines/kali) = %q %q", ns, title)
	}
	if ns, title := parseTarget(":bare [x]"); ns != "notes" || title != "bare [x]" {
		t.Errorf("parseTarget(:bare [x]) = %q %q", ns, title)
	}
}

// Repeated headings become numbered notes; fences of either kind (nested
// too) never split; "§" splits only at marker lines; re-import updates.
func TestImportDuplicateHeadingsAndFences(t *testing.T) {
	md := strings.Join([]string{
		"## Tekrar", "bir",
		"## Tekrar", "iki",
		"~~~", "```", "## not a heading", "```", "## still code", "~~~",
		"§1.2 is a reference, not a marker",
		"## Son", "son",
	}, "\n")
	dir := t.TempDir()
	file := filepath.Join(dir, "doc.md")
	if err := os.WriteFile(file, []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}
	path := testDB(t)
	t.Setenv("IZ", path)
	for range 2 { // the second import must update, not duplicate
		if code := importNotes(file); code != 0 {
			t.Fatalf("import exit=%d", code)
		}
	}
	db, _ := openDBAt(path)
	defer db.Close()
	res, err := queryMemories(db, "ns:doc", 20)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, m := range res {
		got[m.Title] = m.Content
	}
	if len(got) != 3 || got["Tekrar"] != "bir" || got["Son"] != "son" {
		t.Fatalf("sections = %q", got)
	}
	if two := got["Tekrar (2)"]; !strings.HasPrefix(two, "iki\n~~~") ||
		!strings.Contains(two, "## not a heading") || !strings.Contains(two, "## still code") ||
		!strings.HasSuffix(two, "§1.2 is a reference, not a marker") {
		t.Errorf("Tekrar (2) = %q", two)
	}

	// marker documents: a heading after "§" titles the section, plain text
	// stays in the body
	secs := splitMarkdown("§ İlk not\ngövde\n§\n## Başlık\ngövde 2\n", "def")
	want := []mdSection{{"İlk not", "İlk not\ngövde"}, {"Başlık", "gövde 2"}}
	if !slices.Equal(secs, want) {
		t.Errorf("splitMarkdown(§) = %q, want %q", secs, want)
	}
}

// Inline triple backticks do not open a code block (a backtick fence has no
// backticks in its info string), and generated duplicate titles are unique.
func TestImportInlineBackticksAndDuplicateTitles(t *testing.T) {
	md := strings.Join([]string{
		"## Run", "```nmap -sV``` first",
		"## Foo", "one",
		"## Foo (2)", "two",
		"## Foo", "three",
		"```bash", "## inside code", "```",
	}, "\n")
	file := filepath.Join(t.TempDir(), "doc.md")
	if err := os.WriteFile(file, []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}
	path := testDB(t)
	t.Setenv("IZ", path)
	if code := importNotes(file); code != 0 {
		t.Fatalf("import exit=%d", code)
	}
	db, _ := openDBAt(path)
	defer db.Close()
	res, err := queryMemories(db, "ns:doc", 20)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, m := range res {
		got[m.Title] = m.Content
	}
	want := map[string]string{
		"Run":     "```nmap -sV``` first",
		"Foo":     "one",
		"Foo (2)": "two",
		"Foo (3)": "three\n```bash\n## inside code\n```",
	}
	if !maps.Equal(got, want) {
		t.Errorf("sections = %q, want %q", got, want)
	}

	var f codeFence
	for line, inside := range map[string]bool{"```inline``` text": false, "``` go": true} {
		f = codeFence{}
		if got := f.inside(line); got != inside {
			t.Errorf("inside(%q) = %v, want %v", line, got, inside)
		}
	}
}

// Flags still follow a single quoted content argument, but from a second
// content word on the rest is content: command lines keep their own flags.
func TestNoteCmdMidContentFlags(t *testing.T) {
	path := testDB(t)
	t.Setenv("IZ", path)
	for _, c := range []struct {
		args                  []string
		target, content, tags string
	}{
		{[]string{"tools:ffuf", "ffuf", "-u", "URL", "-t", "50"}, "tools:ffuf", "ffuf -u URL -t 50", ""},
		{[]string{"tools:ffuf2", "ffuf", "-t", "50", "-u", "URL"}, "tools:ffuf2", "ffuf -t 50 -u URL", ""},
		{[]string{"tools:hydra", "hydra", "-t", "4", "ssh://x"}, "tools:hydra", "hydra -t 4 ssh://x", ""},
		{[]string{"tools:ls", "ls", "-a", "/tmp"}, "tools:ls", "ls -a /tmp", ""},
		{[]string{"-t", "ad", "tools:nxc", "nxc", "smb", "-u", "a", "-a"}, "tools:nxc", "nxc smb -u a -a", "ad"},
		{[]string{"x:q", "quoted content", "-t", "k"}, "x:q", "quoted content", "k"},
		{[]string{"tools:sqlmap", "-t", "web", "--", "sqlmap", "-a"}, "tools:sqlmap", "sqlmap -a", "web"},
	} {
		if code := noteCmd(c.args); code != 0 {
			t.Fatalf("noteCmd(%q) exit=%d", c.args, code)
		}
		if m := noteByTarget(t, path, c.target); m.Content != c.content || m.Tags != c.tags {
			t.Errorf("noteCmd(%q): content %q tags %q, want %q / %q", c.args, m.Content, m.Tags, c.content, c.tags)
		}
	}
}

// An empty ATX heading ("##   ") is text, not a heading that would title
// (and so drop) the paragraphs after it.
func TestSplitMarkdownEmptyHeading(t *testing.T) {
	if h, ok := headingText("##   ", 2); ok {
		t.Errorf("headingText(empty) = %q, true", h)
	}
	got := splitMarkdown("## A\nx\n##   \ny\n", "doc")
	want := []mdSection{{"A", "x\n##   \ny"}}
	if !slices.Equal(got, want) {
		t.Errorf("splitMarkdown = %q, want %q", got, want)
	}
}

// iz n list <ns> lists that namespace and its sub-namespaces, not every
// namespace sharing its prefix.
func TestListNotesNamespace(t *testing.T) {
	path := testDB(t)
	t.Setenv("IZ", path)
	for _, target := range []string{"pentest:a", "pentest/web:b", "pentest2:c"} {
		if code := noteCmd([]string{target, "body"}); code != 0 {
			t.Fatalf("noteCmd(%s) exit=%d", target, code)
		}
	}
	out := captureStdout(t, func() { listNotes("pentest") })
	if !strings.Contains(out, "pentest:a") || !strings.Contains(out, "pentest/web:b") || strings.Contains(out, "pentest2") {
		t.Errorf("iz n list pentest:\n%s", out)
	}
}

// New notes and runs carry millisecond timestamps (≤13 significant digits,
// lossless through a remote's JSON floats).
func TestUnixTimeMillis(t *testing.T) {
	ts := unixTime(time.Unix(1795348751, 204460123))
	if got := strconv.FormatFloat(ts, 'f', -1, 64); got != "1795348751.204" {
		t.Errorf("unixTime = %s, want 1795348751.204", got)
	}
	if n := now(); n != math.Round(n*1e3)/1e3 {
		t.Errorf("now() = %v, not millisecond precision", n)
	}
}

func TestFzfExit(t *testing.T) {
	if code := fzfExit(exec.Command("iz-no-such-fzf-4242").Run()); code != 2 {
		t.Errorf("fzf missing: exit=%d, want 2", code)
	}
	if code := fzfExit(exec.Command("sh", "-c", "exit 130").Run()); code != 0 {
		t.Errorf("fzf aborted (esc): exit=%d, want 0", code)
	}
}

// captureStderr returns what fn prints to stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(r); done <- b }()
	defer func() {
		os.Stderr = old
		_ = w.Close()
		_ = r.Close()
	}()
	fn()
	_ = w.Close()
	os.Stderr = old
	return string(<-done)
}

// Re-saving an identical note (including unnormalized tags like "a, b" vs "a,b")
// must keep mtime unchanged, and re-importing unchanged markdown must not count
// them as newly imported or updated.
func TestUpsertUnchangedPreservesMtimeAndImportCount(t *testing.T) {
	path := testDB(t)
	t.Setenv("IZ", path)

	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	origID, status, err := upsertMemory(db, Memory{
		Namespace: "ns",
		Title:     "same",
		Content:   "body text",
		Tags:      "a,b",
		TagsSet:   true,
		Ts:        1000,
		Mtime:     1000,
	}, false)
	if err != nil || status != "saved" {
		t.Fatalf("initial upsert = (%d, %q, %v)", origID, status, err)
	}

	// Re-save with unnormalized equivalent tags ("a, b" and " a , , b ") and
	// without -t: status must be "unchanged" and mtime must stay 1000.
	for _, m := range []Memory{
		{Namespace: "ns", Title: "same", Content: "body text", Tags: "a, b", TagsSet: true},
		{Namespace: "ns", Title: "same", Content: "body text", Tags: " a , , b ", TagsSet: true},
		{Namespace: "ns", Title: "same", Content: "body text"},
	} {
		id, st, err := upsertMemory(db, m, false)
		if err != nil || id != origID || st != "unchanged" {
			t.Fatalf("upsertMemory(%+v) = (%d, %q, %v), want (%d, unchanged, nil)", m, id, st, err, origID)
		}
		got, err := getMemory(db, origID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Mtime != 1000 || got.Tags != "a,b" {
			t.Errorf("after unchanged upsert: mtime=%v tags=%q, want 1000 / a,b", got.Mtime, got.Tags)
		}
	}
	db.Close()

	// CLI noteCmd with unnormalized equivalent tags reports "unchanged" and keeps mtime.
	stderr := captureStderr(t, func() {
		if code := noteCmd([]string{"ns:same", "-t", "a, b", "body text"}); code != 0 {
			t.Fatalf("noteCmd exit=%d", code)
		}
	})
	if !strings.Contains(stderr, "[iz] unchanged") {
		t.Errorf("stderr = %q, want '[iz] unchanged'", stderr)
	}
	if m := noteByTarget(t, path, "ns:same"); m.Mtime != 1000 {
		t.Errorf("noteCmd unchanged bumped mtime to %v", m.Mtime)
	}

	// Changing tags actually updates and advances mtime.
	if code := noteCmd([]string{"ns:same", "-t", "a,c", "body text"}); code != 0 {
		t.Fatalf("noteCmd tag change exit=%d", code)
	}
	if m := noteByTarget(t, path, "ns:same"); m.Mtime <= 1000 || m.Tags != "a,c" {
		t.Errorf("after tag change: mtime=%v tags=%q", m.Mtime, m.Tags)
	}

	// importNotes must not count unchanged notes as newly imported or updated.
	mdFile := filepath.Join(t.TempDir(), "guide.md")
	if err := os.WriteFile(mdFile, []byte("# One\nfirst\n\n## Two\nsecond\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out1 := captureStderr(t, func() {
		if code := importNotes(mdFile); code != 0 {
			t.Fatalf("first importNotes exit=%d", code)
		}
	})
	if !strings.Contains(out1, "imported 2 new, updated 0 notes") {
		t.Errorf("first import stderr = %q", out1)
	}

	// Pin imported notes' mtime so any unintended update is detectable.
	db, err = openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE memories SET mtime = 1000 WHERE namespace = 'guide'`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	out2 := captureStderr(t, func() {
		if code := importNotes(mdFile); code != 0 {
			t.Fatalf("second importNotes exit=%d", code)
		}
	})
	if !strings.Contains(out2, "imported 0 new, updated 0 notes") {
		t.Errorf("re-import unchanged stderr = %q, want 0 new / 0 updated", out2)
	}
	for _, target := range []string{"guide:One", "guide:Two"} {
		if m := noteByTarget(t, path, target); m.Mtime != 1000 {
			t.Errorf("re-import unchanged bumped %s mtime to %v", target, m.Mtime)
		}
	}

	// Modifying one section updates only that section.
	if err := os.WriteFile(mdFile, []byte("# One\nfirst\n\n## Two\nsecond edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out3 := captureStderr(t, func() {
		if code := importNotes(mdFile); code != 0 {
			t.Fatalf("third importNotes exit=%d", code)
		}
	})
	if !strings.Contains(out3, "imported 0 new, updated 1 notes") {
		t.Errorf("re-import 1 changed stderr = %q, want 0 new / 1 updated", out3)
	}
	if m := noteByTarget(t, path, "guide:One"); m.Mtime != 1000 {
		t.Errorf("unchanged section guide:One mtime bumped to %v", m.Mtime)
	}
	if m := noteByTarget(t, path, "guide:Two"); m.Mtime <= 1000 || m.Content != "second edited" {
		t.Errorf("updated section guide:Two = mtime %v content %q", m.Mtime, m.Content)
	}
}

// On title collision / update failure, editNoteCmd preserves the user's edited
// text in a temp file and prints its path on stderr.
func TestEditNoteCmdPreservesTempFileOnUpdateFailure(t *testing.T) {
	path := testDB(t)
	t.Setenv("IZ", path)
	if code := noteCmd([]string{"ns:first", "original first"}); code != 0 {
		t.Fatalf("seed first exit=%d", code)
	}
	if code := noteCmd([]string{"ns:second", "original second"}); code != 0 {
		t.Fatalf("seed second exit=%d", code)
	}

	// Fake $EDITOR that renames ns:first to collide with ns:second.
	const editedDoc = "# ns:second\n\nmy edited content that must not be lost\n"
	editorPath := filepath.Join(t.TempDir(), "fake-editor.sh")
	script := "#!/bin/sh\nprintf '%s' " + joinArgs([]string{editedDoc}) + " > \"$1\"\n"
	if err := os.WriteFile(editorPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", editorPath)

	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Fatalf("pty.Open: %v", err)
	}
	defer ptmx.Close()
	defer tty.Close()

	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = tty, tty
	defer func() {
		os.Stdin, os.Stdout = oldIn, oldOut
	}()

	var code int
	stderr := captureStderr(t, func() {
		code = editNoteCmd("ns:first")
	})
	if code != 1 {
		t.Fatalf("editNoteCmd exit=%d, want 1 (stderr: %q)", code, stderr)
	}
	if !strings.Contains(stderr, "update failed") {
		t.Fatalf("stderr missing update failed: %q", stderr)
	}
	const prefix = "(saved edit to "
	_, after, ok := strings.Cut(stderr, prefix)
	if !ok {
		t.Fatalf("stderr missing saved temp path: %q", stderr)
	}
	savedPath, _, ok := strings.Cut(after, ")")
	if !ok || savedPath == "" {
		t.Fatalf("could not parse saved temp path from %q", stderr)
	}
	t.Cleanup(func() { _ = os.Remove(savedPath) })

	gotBytes, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("saved temp file %q unreadable: %v", savedPath, err)
	}
	if string(gotBytes) != editedDoc {
		t.Errorf("saved temp file = %q, want %q", string(gotBytes), editedDoc)
	}
	// Neither existing note was clobbered.
	if m := noteByTarget(t, path, "ns:first"); m.Content != "original first" {
		t.Errorf("ns:first modified: %q", m.Content)
	}
	if m := noteByTarget(t, path, "ns:second"); m.Content != "original second" {
		t.Errorf("ns:second modified: %q", m.Content)
	}
}
