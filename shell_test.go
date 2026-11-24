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
			"shopt -s expand_aliases\n" + aliases + `source "$1" && alias gau && declare -F nmap`}},
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
			// a non-interactive shell loads it silently (no "line editing not enabled")
			if strings.Contains(string(out), "warning") || strings.Contains(string(out), "bind") {
				t.Errorf("%s: noisy load:\n%s", c.sh, out)
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

// A whitespace-only file gets the block alone, without leading blank lines.
func TestPatchManagedBlockBlankFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "AGENTS.md")
	if err := os.WriteFile(p, []byte(" \n\n\t\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := patchManagedBlock(p, "<!-- b -->", "<!-- e -->", "<!-- b -->\nx\n<!-- e -->"); err != nil {
		t.Fatal(err)
	}
	if data, _ := osReadFile(p); data != "<!-- b -->\nx\n<!-- e -->\n" {
		t.Errorf("file = %q", data)
	}
}

// End-to-end zsh pipeline integration: two wrapped tools in a pipeline
// ("subfinder -d de2.in | httpx -silent") produce a single runs row and a
// single "[iz] #... saved" banner on stderr.
func TestShellPipelineIntegration(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh not installed")
	}
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	izBin := filepath.Join(binDir, "iz")
	if out, err := exec.Command("go", "build", "-o", izBin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	// Stub wrapped binaries subfinder and httpx
	if err := os.WriteFile(filepath.Join(binDir, "subfinder"), []byte("#!/bin/sh\necho a.de2.in\necho b.de2.in\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "httpx"), []byte("#!/bin/sh\ngrep '^a\\.'\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	dbPath := testDB(t)
	db, err := openDBAt(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	code, err := shellEnv("zsh", db)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	initFile := filepath.Join(dir, "iz.zsh")
	if err := os.WriteFile(initFile, []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}

	script := `
source "$1"
__iz_preexec "subfinder -d de2.in | httpx -silent"
subfinder -d de2.in | httpx -silent
__iz_precmd
`
	cmd := exec.Command(zsh, "-f", "-c", script, "zsh", initFile)
	cmd.Env = []string{
		"PATH=" + binDir + ":" + os.Getenv("PATH"),
		"HOME=" + dir,
		"IZ=" + dbPath,
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("zsh pipeline failed: %v\n%s", err, out)
	}
	if cnt := strings.Count(string(out), "[iz] #"); cnt != 1 {
		t.Errorf("expected 1 [iz] saved line, got %d:\n%s", cnt, out)
	}
	if n := countRuns(t, dbPath); n != 1 {
		t.Fatalf("expected 1 run in db, got %d", n)
	}
	r, recorded := lastRun(t, dbPath)
	if r.Cmd != "subfinder -d de2.in | httpx -silent" {
		t.Errorf("cmd = %q", r.Cmd)
	}
	if !strings.Contains(recorded, "b.de2.in") || !strings.Contains(recorded, "a.de2.in") {
		t.Errorf("recorded output missing expected content:\n%s", recorded)
	}
}

func TestDetectShellAndInitUnsupportedShell(t *testing.T) {
	for sh, want := range map[string]string{
		"/bin/zsh":            "zsh",
		"/usr/local/bin/fish": "fish",
		"/bin/bash":           "bash",
		"/usr/bin/nu":         "",
		"/bin/csh":            "",
		"":                    "",
	} {
		t.Setenv("SHELL", sh)
		if got := detectShell(); got != want {
			t.Errorf("detectShell(SHELL=%q) = %q, want %q", sh, got, want)
		}
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/usr/bin/nu")

	var code int
	stderr := captureStderr(t, func() {
		code = initCmd(nil)
	})
	if code != 0 {
		t.Fatalf("initCmd(nil) exit=%d, want 0 (stderr: %q)", code, stderr)
	}
	if !strings.Contains(stderr, "unsupported shell") || !strings.Contains(stderr, "/usr/bin/nu") {
		t.Errorf("stderr = %q, want unsupported shell message for /usr/bin/nu", stderr)
	}
	for _, rc := range []string{
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".config", "fish", "config.fish"),
	} {
		if _, err := os.Stat(rc); !os.IsNotExist(err) {
			t.Errorf("unsupported shell wrote %s (err=%v)", rc, err)
		}
	}
}
