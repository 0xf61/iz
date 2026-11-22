package main

import (
	"os"
	"os/exec"
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
	if changed, err := patchManagedBlock(p, "<!-- iz:begin -->", "<!-- iz:end -->", "<!-- iz:begin -->\nline1\n<!-- iz:end -->"); err != nil || !changed {
		t.Fatalf("first patch: changed=%v err=%v", changed, err)
	}
	data, _ := osReadFile(p)
	if !strings.Contains(data, "line1") {
		t.Fatalf("missing line1: %q", data)
	}

	// 2. Re-install / update (replace in place)
	if changed, err := patchManagedBlock(p, "<!-- iz:begin -->", "<!-- iz:end -->", "<!-- iz:begin -->\nupdated\n<!-- iz:end -->"); err != nil || !changed {
		t.Fatalf("update patch: changed=%v err=%v", changed, err)
	}
	data, _ = osReadFile(p)
	if !strings.Contains(data, "updated") || strings.Contains(data, "line1") {
		t.Fatalf("replace failed: %q", data)
	}

	// 3. No-op re-run
	if changed, err := patchManagedBlock(p, "<!-- iz:begin -->", "<!-- iz:end -->", "<!-- iz:begin -->\nupdated\n<!-- iz:end -->"); err != nil || changed {
		t.Fatalf("noop patch: changed=%v err=%v", changed, err)
	}
}

func osReadFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	return string(b), err
}

// The generated integration parses and loads in each shell, also next to
// user aliases named like wrapped tools (oh-my-zsh: gau, gf), which keep
// winning over the wrapper.
func TestShellEnvParses(t *testing.T) {
	path := testDB(t)
	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("IZ", path)

	const aliases = "alias gau='echo user-gau'\nalias gf='echo user-gf'\n"
	for _, c := range []struct {
		sh    string
		check []string // syntax check only
		load  []string // source the file after defining the aliases
	}{
		{"zsh", []string{"-f", "-n"}, []string{"-f", "-c", aliases + `source "$1" && alias gau && whence -w nmap`}},
		{"bash", []string{"--norc", "--noprofile", "-n"}, []string{"--norc", "--noprofile", "-c",
			"shopt -s expand_aliases\n" + aliases + `source "$1" 2>/dev/null; alias gau && declare -F nmap`}},
		{"fish", []string{"--no-config", "--no-execute"}, nil},
	} {
		t.Run(c.sh, func(t *testing.T) {
			bin, err := exec.LookPath(c.sh)
			if err != nil {
				t.Skipf("%s not installed", c.sh)
			}
			code, err := shellEnv(c.sh, db)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, "iz."+c.sh)
			if err := os.WriteFile(file, []byte(code), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(bin, append(c.check, file)...).CombinedOutput(); err != nil {
				t.Fatalf("%s syntax check: %v\n%s", c.sh, err, out)
			}
			if c.load == nil {
				return
			}
			out, err := exec.Command(bin, append(c.load, c.sh, file)...).CombinedOutput()
			if err != nil {
				t.Fatalf("%s load: %v\n%s", c.sh, err, out)
			}
			if !strings.Contains(string(out), "user-gau") || !strings.Contains(string(out), "nmap") {
				t.Errorf("%s: alias lost or wrapper missing:\n%s", c.sh, out)
			}
		})
	}
}

// A start marker without its end marker is an error, and the file (with
// the user's text after the marker) is left as it was.
func TestPatchManagedBlockMissingEndMarker(t *testing.T) {
	p := filepath.Join(t.TempDir(), "AGENTS.md")
	orig := "# mine\n<!-- iz:begin -->\nold block\n\nuser text that must survive\n"
	if err := os.WriteFile(p, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := patchManagedBlock(p, "<!-- iz:begin -->", "<!-- iz:end -->", "<!-- iz:begin -->\nnew\n<!-- iz:end -->")
	if err == nil || changed {
		t.Fatalf("changed=%v err=%v, want an error", changed, err)
	}
	if got, _ := osReadFile(p); got != orig {
		t.Errorf("file modified: %q", got)
	}
}

// Antigravity: plugin files are written once, a changed skill alone counts
// as a change, and only legacy files iz wrote are removed — never the
// user's rules directory.
func TestInstallAntigravityPluginAndRemoveIfOurs(t *testing.T) {
	home := t.TempDir()
	config := filepath.Join(home, ".gemini", "config")
	files := map[string]string{
		filepath.Join(config, "rules", "IZ.md"):           "use iz recall first",
		filepath.Join(config, "rules", "MINE.md"):         "my own rules",
		filepath.Join(config, "skills", "iz", "SKILL.md"): "old skill: iz recall",
		filepath.Join(config, "skills", "other", "x.md"):  "someone else's iz recall notes",
	}
	for p, c := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if changed, err := installAgentInstructions(home, "antigravity"); err != nil || !changed {
		t.Fatalf("first install: changed=%v err=%v", changed, err)
	}
	pluginDir := filepath.Join(config, "plugins", "iz")
	for _, p := range []string{"plugin.json", "skills/iz/SKILL.md", "rules/AGENTS.md"} {
		if _, err := os.Stat(filepath.Join(pluginDir, p)); err != nil {
			t.Errorf("plugin file missing: %v", err)
		}
	}
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	if exists(filepath.Join(config, "rules", "IZ.md")) || exists(filepath.Join(config, "skills", "iz")) {
		t.Error("legacy iz files not removed")
	}
	for _, p := range []string{filepath.Join(config, "rules", "MINE.md"), filepath.Join(config, "skills", "other", "x.md")} {
		if !exists(p) {
			t.Errorf("user file removed: %s", p)
		}
	}

	if changed, err := installAgentInstructions(home, "antigravity"); err != nil || changed {
		t.Errorf("re-install: changed=%v err=%v, want no change", changed, err)
	}
	skill := filepath.Join(pluginDir, "skills", "iz", "SKILL.md")
	if err := os.WriteFile(skill, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if changed, err := installAgentInstructions(home, "antigravity"); err != nil || !changed {
		t.Errorf("stale skill: changed=%v err=%v, want a change", changed, err)
	}
	if got, _ := osReadFile(skill); got != antigravitySkillMD {
		t.Error("skill not rewritten")
	}

	// the rules directory survives even when IZ.md was its only file
	os.Remove(filepath.Join(config, "rules", "MINE.md"))                              //nolint
	os.WriteFile(filepath.Join(config, "rules", "IZ.md"), []byte("iz recall"), 0o644) //nolint
	if _, err := installAgentInstructions(home, "antigravity"); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(config, "rules")) {
		t.Error("user's rules directory removed")
	}
}
