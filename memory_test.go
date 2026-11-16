package main

import (
	"path/filepath"
	"strings"
	"testing"
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
