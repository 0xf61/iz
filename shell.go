package main

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// isToolName rejects anything that is not a plain binary name (injection
// guard); a leading '-' would read as an option ("iz a --help").
func isToolName(s string) bool {
	if s == "" || s[0] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// wrappable reports whether name may get a recording wrapper function.
func wrappable(name string) bool { return name != "iz" && isToolName(name) && !isShellReserved(name) }

// shellEnv emits shell integration code for fish, zsh, or bash.
func shellEnv(sh string, db *sql.DB) (string, error) {
	tools := queryNames(db, "tools")
	var b strings.Builder

	switch sh {
	case "fish":
		b.WriteString(`# --- iz: begin (iz init fish | source) ---
if not set -q IZ
    set -gx IZ ~/.iz/iz.db
end
set -l __iz_key \cg
if set -q IZ_KEY
    set __iz_key $IZ_KEY
end

function __iz_widget --description 'iz: search commands + output'
    set -l sel (command iz --pick 2>/dev/null)
    if test $status -eq 0 -a -n "$sel"
        commandline -i -- $sel
    end
    commandline -f repaint
end
if status is-interactive
    bind -M default $__iz_key __iz_widget
    bind -M insert  $__iz_key __iz_widget
end

set -l __iz_notes_key \co
if set -q IZ_NOTES_KEY
    set __iz_notes_key $IZ_NOTES_KEY
end

function __iz_notes_widget --description 'iz: interactive notes & pentest memory'
    command iz n
    commandline -f repaint
end
if status is-interactive
    bind -M default $__iz_notes_key __iz_notes_widget
    bind -M insert  $__iz_notes_key __iz_notes_widget
end

`)
		for _, name := range tools {
			if !wrappable(name) {
				continue
			}
			fmt.Fprintf(&b, `function %[1]s --wraps %[1]s --description 'iz: recorded %[1]s'
    if set -q IZ
        command iz -- %[1]s $argv
    else
        command %[1]s $argv
    end
end
`, name)
		}
		b.WriteString("\n# --- iz: end ---\n")

	case "zsh":
		b.WriteString(`# --- iz: begin (eval "$(iz init zsh)") ---
export IZ="${IZ:-$HOME/.iz/iz.db}"

__iz_zsh_widget() {
    local cmd
    zle -I
    cmd=$(command iz --pick </dev/tty 2>/dev/null)
    if [ -n "$cmd" ]; then
        LBUFFER+="$cmd"
    fi
    zle reset-prompt
}
zle -N __iz_zsh_widget
bindkey "${IZ_KEY:-^G}" __iz_zsh_widget

__iz_zsh_notes_widget() {
    zle -I
    command iz n </dev/tty
    zle reset-prompt
}
zle -N __iz_zsh_notes_widget
bindkey "${IZ_NOTES_KEY:-^O}" __iz_zsh_notes_widget

`)
		posixWrappers(&b, tools)

	case "bash":
		b.WriteString(`# --- iz: begin (eval "$(iz init bash)") ---
export IZ="${IZ:-$HOME/.iz/iz.db}"

__iz_bash_widget() {
    local cmd
    cmd=$(command iz --pick 2>/dev/null)
    if [ -n "$cmd" ]; then
        READLINE_LINE="${READLINE_LINE:0:$READLINE_POINT}$cmd${READLINE_LINE:$READLINE_POINT}"
        READLINE_POINT=$(( READLINE_POINT + ${#cmd} ))
    fi
}
bind -x "\"${IZ_KEY:-\\C-g}\": __iz_bash_widget"

__iz_bash_notes_widget() {
    command iz n
}
bind -x "\"${IZ_NOTES_KEY:-\\C-o}\": __iz_bash_notes_widget"

`)
		posixWrappers(&b, tools)

	default:
		return "", fmt.Errorf("unsupported shell %q (supported: fish, zsh, bash)", sh)
	}

	return b.String(), nil
}

// posixWrappers writes the zsh/bash recording wrappers. `function name {`
// keeps the name out of command position, so an alias of the same name
// (oh-my-zsh: gau, gf) is not expanded while the code is parsed; such an
// alias is the user's and wins, so no wrapper is defined for it.
func posixWrappers(b *strings.Builder, tools []string) {
	for _, name := range tools {
		if !wrappable(name) {
			continue
		}
		fmt.Fprintf(b, `if ! alias %[1]s >/dev/null 2>&1; then
function %[1]s {
    if [ -n "$IZ" ]; then
        command iz -- %[1]s "$@"
    else
        command %[1]s "$@"
    fi
}
fi
`, name)
	}
	b.WriteString("\n# --- iz: end ---\n")
}

// fishCmd maintains backwards compatibility for `iz f` / `iz fish`.
func fishCmd() int {
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	defer db.Close()

	code, err := shellEnv("fish", db)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	io.WriteString(os.Stdout, code) //nolint
	return 0
}

const aiPromptSnippet = `<!-- iz-memory:begin -->
# iz — Terminal Execution & Persistent Memory Ledger

iz is available on the PATH. It is your persistent second-brain memory and command execution ledger across sessions and harnesses.

- Recall First (before asking questions or assuming context is missing):
    iz prime                        # compact namespace & note title index (--json available)
    iz recall "<query>"             # search memory & past command runs
    iz recall --json "<query>"      # structured JSON (token-efficient)
    iz recall --full "<query>"      # full untruncated note contents
    iz n show <id|ns:title>         # inspect full note content
    iz sh <run_id>                  # view full recorded terminal output
    iz sh <run_id> -- "<pattern>"   # same, with the pattern highlighted

- Persist All Learnings Proactively:
    Whenever you discover user preferences, project architecture, credentials, bug fixes, or runbooks:
    iz n <namespace:title> [-t tags] "<content>"  # upsert note (no duplicates)
    iz n -a <namespace:title> "<extra>"            # append to existing note

- Persistent Command Execution:
    iz -- <command> [args...]       # record command metadata and full output in SQLite FTS5

- Multi-Machine Sync (Turso/LibSQL):
    iz sync                         # two-way sync to pull latest notes or push new learnings
    Run 'iz sync' at session start to pull fresh context, and after recording important notes/runs.

- Non-interactive rule: NEVER run bare 'iz', 'iz n', 'iz n edit', 'iz n new', or 'iz e' (they open fzf/$EDITOR).
<!-- iz-memory:end -->
`

const antigravitySkillMD = `---
name: iz
description: >-
  Persistent second-brain memory, knowledge recall, and terminal command execution ledger.
  Use whenever searching for previous context, decisions, credentials, machine details, or past command outputs with ` + "`iz recall`" + ` and ` + "`iz prime`" + `.
  Also use proactively to record and persist anything learned (preferences, project architecture, bug workarounds, runbooks) using ` + "`iz n <namespace:title>`" + `.
---

# iz — Persistent Memory, Recall & Execution Ledger

` + "`iz`" + ` stores structured knowledge notes alongside full terminal command executions and their complete outputs in a local SQLite FTS5 database (` + "`~/.iz/iz.db`" + `), with optional LibSQL/Turso cloud sync.

## Query & Recall Workflow

Before asking the user questions or assuming context is missing:

1. **Check Available Namespaces & Titles**:
   ` + "```bash" + `
   iz prime
   iz prime --json
   ` + "```" + `

2. **Recall Memories and Runs**:
   ` + "```bash" + `
   iz recall "<query>"              # Hybrid search across notes and runs
   iz recall --json "<query>"       # Compact JSON (token-efficient)
   iz recall --full "<query>"       # Untruncated note bodies
   iz recall -n "<query>"           # Knowledge notes only
   iz recall -r "<query>"           # Historical command runs only
   iz recall -l 20 "<query>"        # Custom limit
   ` + "```" + `

3. **Inspect Full Note or Past Command Output**:
   ` + "```bash" + `
   iz n show <id|ns:title>          # View complete note in markdown
   iz sh <run_id>                   # Replay full colored terminal output of a past run
   iz sh <run_id> -- "<pattern>"    # Replay and highlight matching text
   ` + "```" + `

## Recording Learnings (Proactive Knowledge Persistence)

Store new discoveries, configurations, and decisions as they happen:

` + "```bash" + `
# Upsert note (replaces if <namespace:title> exists, preventing duplicates)
iz n <namespace:title> [-t tag1,tag2] "<content>"

# Append to existing note
iz n -a <namespace:title> "<additional lines>"
` + "```" + `

### Recommended Namespaces:
- ` + "`user:preferences`" + ` — User work style, guidelines, communication preferences.
- ` + "`project:<name>`" + ` — Repo layout, architecture, conventions, quirks.
- ` + "`machines:<host>`" + ` — IPs, hostnames, open ports, SSH config, credentials.
- ` + "`debug:<issue>`" + ` — Root causes, tricky bug solutions, diagnostic steps.
- ` + "`runbook:<topic>`" + ` — Operational steps, deployments, migration commands.
- ` + "`findings:<target>`" + ` — Pentest / audit findings, proof of concepts.

## Persistent Command Execution

When executing commands whose full output should be preserved for debugging, proof, or historical record:

` + "```bash" + `
iz -- <command> [args...]
` + "```" + `

## Multi-Machine Cloud Sync (Turso / LibSQL)

` + "```bash" + `
iz sync
` + "```" + `
- Run ` + "`iz sync`" + ` at session startup to pull the latest notes and context from other machines.
- Run ` + "`iz sync`" + ` after recording important notes or findings so they propagate immediately.

## Safety & Non-Interactive Usage

NEVER execute interactive commands that launch a TTY/fzf interface or ` + "`$EDITOR`" + `:
- Do NOT run: ` + "`iz`" + `, ` + "`iz n`" + `, ` + "`iz n new`" + `, ` + "`iz n edit`" + `, ` + "`iz e`" + `.
- Always use the non-interactive CLI subcommands shown above.
`

// initCmd handles `iz init`:
//
//	iz init                     (detects shell, auto-installs hooks to shell rc + agents)
//	iz init <fish|zsh|bash>     (prints shell integration script to stdout)
//	iz init --shell [fish|zsh]  (installs hook into shell rc)
//	iz init --agent [claude|..] (installs instructions into AI assistant config)
//	iz init --show              (displays detected shells and agents)
func initCmd(args []string) int {
	if len(args) == 1 {
		sh := args[0]
		if sh == "fish" || sh == "zsh" || sh == "bash" {
			db, err := openDB()
			if err != nil {
				fmt.Fprintln(os.Stderr, "iz:", err)
				return 1
			}
			defer db.Close()
			code, err := shellEnv(sh, db)
			if err != nil {
				fmt.Fprintln(os.Stderr, "iz:", err)
				return 1
			}
			io.WriteString(os.Stdout, code) //nolint
			return 0
		}
	}

	targetShell := ""
	targetAgent := ""
	showOnly := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--show":
			showOnly = true
		case "--shell", "-s":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "iz init: --shell requires a shell name (fish, zsh, bash)")
				return 2
			}
			targetShell = args[i+1]
			i++
		case "--agent", "-a":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "iz init: --agent requires an agent name (claude, opencode, antigravity, cursor)")
				return 2
			}
			targetAgent = args[i+1]
			i++
		case "-h", "--help":
			fmt.Println(`iz init — shell & AI assistant initialization

Usage:
  iz init                     Auto-detect current shell & AI assistants and configure them
  iz init <fish|zsh|bash>     Print shell integration script to stdout
  iz init --shell <name>      Install hook into shell config (fish, zsh, bash)
  iz init --agent <name>      Install memory instructions into AI config (claude, opencode, antigravity, cursor)
  iz init --show              Show detected shells, agents and installation status`)
			return 0
		default:
			fmt.Fprintf(os.Stderr, "iz init: unknown argument %q (run 'iz init --help')\n", args[i])
			return 2
		}
	}

	home, _ := os.UserHomeDir()
	if showOnly {
		return showInitStatus(home)
	}

	autoMode := targetShell == "" && targetAgent == ""
	failed := false

	// 1. Configure Shells
	installedShells := 0
	if targetShell != "" {
		changed, err := installShellHook(home, targetShell)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[iz] shell install (%s): %v\n", targetShell, err)
			return 1
		}
		if changed {
			fmt.Fprintf(os.Stderr, "[iz] shell %s configured successfully\n", targetShell)
			installedShells++
		} else {
			fmt.Fprintf(os.Stderr, "[iz] shell %s already configured\n", targetShell)
		}
	} else if autoMode {
		// Detect default shell
		detected := detectShell()
		if detected != "" {
			changed, err := installShellHook(home, detected)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[iz] shell install (%s): %v\n", detected, err)
				failed = true
			} else if changed {
				fmt.Fprintf(os.Stderr, "[iz] configured shell hook in %s\n", detected)
				installedShells++
			}
		}
	}

	// 2. Configure AI Assistants
	installedAgents := 0
	if targetAgent != "" {
		if targetAgent == "gemini" {
			targetAgent = "antigravity"
		}
		changed, err := installAgentInstructions(home, targetAgent)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[iz] agent install (%s): %v\n", targetAgent, err)
			return 1
		}
		if changed {
			fmt.Fprintf(os.Stderr, "[iz] assistant %s configured successfully\n", targetAgent)
			installedAgents++
		} else {
			fmt.Fprintf(os.Stderr, "[iz] assistant %s already configured\n", targetAgent)
		}
	} else if autoMode {
		for _, ag := range []string{"claude", "opencode", "antigravity", "cursor"} {
			if isAgentInstalled(home, ag) {
				changed, err := installAgentInstructions(home, ag)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[iz] agent install (%s): %v\n", ag, err)
					failed = true
				} else if changed {
					fmt.Fprintf(os.Stderr, "[iz] configured memory instructions for %s\n", ag)
					installedAgents++
				}
			}
		}
	}

	if failed {
		return 1
	}
	if installedShells == 0 && installedAgents == 0 && autoMode {
		fmt.Fprintln(os.Stderr, "[iz] nothing needed update (already configured). Run 'iz init --show' to check.")
	}
	return 0
}

func detectShell() string {
	sh := os.Getenv("SHELL")
	base := filepath.Base(sh)
	if base == "fish" || base == "zsh" || base == "bash" {
		return base
	}
	return "zsh" // default on modern macOS
}

func installShellHook(home, sh string) (bool, error) {
	var rcPath, hookLine string
	switch sh {
	case "fish":
		rcPath = filepath.Join(home, ".config", "fish", "config.fish")
		hookLine = "if status is-interactive; and type -q iz; iz init fish | source; end"
	case "zsh":
		rcPath = filepath.Join(home, ".zshrc")
		hookLine = `if command -v iz >/dev/null 2>&1; then eval "$(iz init zsh)"; fi`
	case "bash":
		rcPath = filepath.Join(home, ".bashrc")
		hookLine = `if command -v iz >/dev/null 2>&1; then eval "$(iz init bash)"; fi`
	default:
		return false, fmt.Errorf("unsupported shell %s", sh)
	}

	return appendLineIfMissing(rcPath, hookLine, "# iz shell integration")
}

func isAgentInstalled(home, agent string) bool {
	switch agent {
	case "claude":
		fi, err := os.Stat(filepath.Join(home, ".claude"))
		return err == nil && fi.IsDir()
	case "opencode":
		fi, err := os.Stat(filepath.Join(home, ".config", "opencode"))
		return err == nil && fi.IsDir()
	case "antigravity", "gemini":
		fi, err := os.Stat(filepath.Join(home, ".gemini"))
		return err == nil && fi.IsDir()
	case "cursor":
		fi, err := os.Stat(filepath.Join(home, ".cursor"))
		return err == nil && fi.IsDir()
	}
	return false
}

// installAgentInstructions installs the iz memory instructions for agent;
// changed reports whether any file was written or removed.
func installAgentInstructions(home, agent string) (changed bool, err error) {
	var targetPath string
	switch agent {
	case "claude":
		targetPath = filepath.Join(home, ".claude", "CLAUDE.md")
	case "opencode":
		targetPath = filepath.Join(home, ".config", "opencode", "AGENTS.md")
	case "antigravity", "gemini":
		config := filepath.Join(home, ".gemini", "config")
		pluginDir := filepath.Join(config, "plugins", "iz")
		if changed, err = installAntigravityPlugin(pluginDir); err != nil {
			return false, err
		}
		// Remove legacy duplicate rule/skill files, but only when iz wrote
		// them; the skills/iz directory is ours too, the rules directory is not.
		if removeIfOurs(filepath.Join(config, "rules", "IZ.md")) {
			changed = true
		}
		if legacySkill := filepath.Join(config, "skills", "iz"); removeIfOurs(filepath.Join(legacySkill, "SKILL.md")) {
			changed = true
			os.Remove(legacySkill) //nolint — fails unless empty
		}
		targetPath = filepath.Join(pluginDir, "rules", "AGENTS.md")
	case "cursor":
		targetPath = filepath.Join(home, ".cursorrules")
	default:
		return false, fmt.Errorf("unknown agent %s", agent)
	}

	patched, err := patchManagedBlock(targetPath, "<!-- iz-memory:begin -->", "<!-- iz-memory:end -->", aiPromptSnippet)
	return changed || patched, err
}

// installAntigravityPlugin writes the plugin manifest (kept when present)
// and the iz skill into pluginDir; changed reports whether it wrote either.
func installAntigravityPlugin(pluginDir string) (changed bool, err error) {
	for _, d := range []string{"rules", filepath.Join("skills", "iz")} {
		if err := os.MkdirAll(filepath.Join(pluginDir, d), 0o755); err != nil {
			return false, err
		}
	}
	pluginJSON := filepath.Join(pluginDir, "plugin.json")
	if _, err := os.Stat(pluginJSON); os.IsNotExist(err) {
		if err := os.WriteFile(pluginJSON, []byte(`{
  "name": "iz",
  "version": "1.0.0",
  "description": "Antigravity plugin for persistent agent memory, recall, and terminal execution ledger via iz"
}
`), 0o644); err != nil {
			return false, err
		}
		changed = true
	}
	skill := filepath.Join(pluginDir, "skills", "iz", "SKILL.md")
	if old, err := os.ReadFile(skill); err == nil && string(old) == antigravitySkillMD {
		return changed, nil
	}
	return true, os.WriteFile(skill, []byte(antigravitySkillMD), 0o644)
}

// removeIfOurs deletes a legacy file iz generated (it mentions `iz recall`);
// user files are left alone. It reports whether the file was removed.
func removeIfOurs(path string) bool {
	if b, err := os.ReadFile(path); err != nil || !strings.Contains(string(b), "iz recall") {
		return false
	}
	return os.Remove(path) == nil
}

// patchManagedBlock replaces the startMark…endMark block in path with block,
// or appends block when there is none. A start marker without an end marker
// is an error: appending a second block would make the next run delete the
// user's text between the old start and the new end.
func patchManagedBlock(path, startMark, endMark, block string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}

	content := string(data)
	if start := strings.Index(content, startMark); start >= 0 {
		end := strings.Index(content[start:], endMark)
		if end < 0 {
			return false, fmt.Errorf("%s: %q has no matching %q; fix or remove it by hand", path, startMark, endMark)
		}
		end += start
		newContent := strings.TrimSpace(content[:start]+strings.TrimSpace(block)+content[end+len(endMark):]) + "\n"
		if newContent == content {
			return false, nil
		}
		return true, os.WriteFile(path, []byte(newContent), 0o644)
	}

	// Append block
	sep := "\n\n"
	if len(content) == 0 {
		sep = ""
	}
	newContent := strings.TrimSpace(content) + sep + strings.TrimSpace(block) + "\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	return true, os.WriteFile(path, []byte(newContent), 0o644)
}

func appendLineIfMissing(path, line, comment string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}

	content := string(data)
	if strings.Contains(content, line) || strings.Contains(content, "iz init") || strings.Contains(content, "iz fish") {
		return false, nil // already configured
	}

	entry := "\n" + comment + "\n" + line + "\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return false, err
	}
	defer f.Close()
	_, err = f.WriteString(entry)
	return err == nil, err
}

func showInitStatus(home string) int {
	fmt.Println("iz initialization status:")
	fmt.Println("-------------------------")

	// Shells
	shells := []struct {
		name string
		path string
	}{
		{"fish", filepath.Join(home, ".config", "fish", "config.fish")},
		{"zsh", filepath.Join(home, ".zshrc")},
		{"bash", filepath.Join(home, ".bashrc")},
	}
	fmt.Println("\nShells:")
	for _, s := range shells {
		status := "not configured"
		data, err := os.ReadFile(s.path)
		if err == nil {
			c := string(data)
			if strings.Contains(c, "iz init") || strings.Contains(c, "iz fish") {
				status = "\x1b[32mconfigured\x1b[0m"
			}
		}
		fmt.Printf("  %-6s (%s): %s\n", s.name, s.path, status)
	}

	// Agents
	agents := []struct {
		name string
		path string
	}{
		{"claude", filepath.Join(home, ".claude", "CLAUDE.md")},
		{"opencode", filepath.Join(home, ".config", "opencode", "AGENTS.md")},
		{"antigravity", filepath.Join(home, ".gemini", "config", "plugins", "iz", "rules", "AGENTS.md")},
		{"cursor", filepath.Join(home, ".cursorrules")},
	}
	fmt.Println("\nAI Assistants:")
	for _, a := range agents {
		status := "not active"
		if isAgentInstalled(home, a.name) {
			status = "not configured"
			data, err := os.ReadFile(a.path)
			if err == nil && strings.Contains(string(data), "<!-- iz-memory:begin -->") {
				status = "\x1b[32mconfigured\x1b[0m"
			}
		}
		fmt.Printf("  %-10s (%s): %s\n", a.name, a.path, status)
	}
	return 0
}
