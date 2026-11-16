package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShellEnv(t *testing.T) {
	path := testDB(t)
	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for _, sh := range []string{"fish", "zsh", "bash"} {
		code, err := shellEnv(sh, db)
		if err != nil {
			t.Fatalf("shellEnv(%s): %v", sh, err)
		}
		if !strings.Contains(code, "nmap") || !strings.Contains(code, "nuclei") {
			t.Errorf("shellEnv(%s) missing default tools: %s", sh, code)
		}
		if !strings.Contains(code, "iz --") {
			t.Errorf("shellEnv(%s) missing iz invocation: %s", sh, code)
		}
	}

	if _, err := shellEnv("unknown", db); err == nil {
		t.Errorf("shellEnv(unknown) should fail")
	}
}

func TestPatchManagedBlock(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "CLAUDE.md")

	// 1. First installation (append)
	if err := patchManagedBlock(p, "<!-- iz:begin -->", "<!-- iz:end -->", "<!-- iz:begin -->\nline1\n<!-- iz:end -->"); err != nil {
		t.Fatal(err)
	}
	data, _ := osReadFile(p)
	if !strings.Contains(data, "line1") {
		t.Fatalf("missing line1: %q", data)
	}

	// 2. Re-install / update (replace in place)
	if err := patchManagedBlock(p, "<!-- iz:begin -->", "<!-- iz:end -->", "<!-- iz:begin -->\nupdated\n<!-- iz:end -->"); err != nil {
		t.Fatal(err)
	}
	data, _ = osReadFile(p)
	if !strings.Contains(data, "updated") || strings.Contains(data, "line1") {
		t.Fatalf("replace failed: %q", data)
	}
}

func osReadFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	return string(b), err
}
