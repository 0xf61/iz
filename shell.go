package main

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// isToolName rejects anything that is not a plain binary name (injection guard).
func isToolName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

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
bind -M default $__iz_key __iz_widget
bind -M insert  $__iz_key __iz_widget

set -l __iz_notes_key \co
if set -q IZ_NOTES_KEY
    set __iz_notes_key $IZ_NOTES_KEY
end

function __iz_notes_widget --description 'iz: interactive notes & pentest memory'
    command iz n
    commandline -f repaint
end
bind -M default $__iz_notes_key __iz_notes_widget
bind -M insert  $__iz_notes_key __iz_notes_widget

`)
		for _, name := range tools {
			if name == "" || !isToolName(name) {
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
    cmd=$(command iz --pick 2>/dev/null)
    if [ -n "$cmd" ]; then
        LBUFFER+="$cmd"
    fi
    zle reset-prompt
}
zle -N __iz_zsh_widget
bindkey "${IZ_KEY:-\^G}" __iz_zsh_widget

__iz_zsh_notes_widget() {
    command iz n
    zle reset-prompt
}
zle -N __iz_zsh_notes_widget
bindkey "${IZ_NOTES_KEY:-\^O}" __iz_zsh_notes_widget

`)
		for _, name := range tools {
			if name == "" || !isToolName(name) {
				continue
			}
			fmt.Fprintf(&b, `%[1]s() {
    if [ -n "$IZ" ]; then
        command iz -- %[1]s "$@"
    else
        command %[1]s "$@"
    fi
}
`, name)
		}
		b.WriteString("\n# --- iz: end ---\n")

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
bind -x '"\C-g": __iz_bash_widget'

__iz_bash_notes_widget() {
    command iz n
}
bind -x '"\C-o": __iz_bash_notes_widget'

`)
		for _, name := range tools {
			if name == "" || !isToolName(name) {
				continue
			}
			fmt.Fprintf(&b, `%[1]s() {
    if [ -n "$IZ" ]; then
        command iz -- %[1]s "$@"
    else
        command %[1]s "$@"
    fi
}
`, name)
		}
		b.WriteString("\n# --- iz: end ---\n")

	default:
		return "", fmt.Errorf("unsupported shell %q (supported: fish, zsh, bash)", sh)
	}

	return b.String(), nil
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

// initCmd handles `iz init`:
//   iz init                     (detects shell, auto-installs hooks to shell rc + agents)
//   iz init <fish|zsh|bash>     (prints shell integration script to stdout)
//   iz init --shell [fish|zsh]  (installs hook into shell rc)
//   iz init --agent [claude|..] (installs instructions into AI assistant config)
//   iz init --show              (displays detected shells and agents)
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
			if i+1 < len(args) {
				targetShell = args[i+1]
				i++
			}
		case "--agent", "-a":
			if i+1 < len(args) {
				targetAgent = args[i+1]
				i++
			}
		case "-h", "--help":
			fmt.Println(`iz init — shell & AI assistant initialization

Usage:
  iz init                     Auto-detect current shell & AI assistants and configure them
  iz init <fish|zsh|bash>     Print shell integration script to stdout
  iz init --shell <name>      Install hook into shell config (fish, zsh, bash)
  iz init --agent <name>      Install memory instructions into AI config (claude, opencode, antigravity, cursor)
  iz init --show              Show detected shells, agents and installation status`)
			return 0
		}
	}

	home, _ := os.UserHomeDir()
	if showOnly {
		return showInitStatus(home)
	}

	// 1. Configure Shells
	installedShells := 0
	if targetShell != "" {
		if err := installShellHook(home, targetShell); err != nil {
			fmt.Fprintf(os.Stderr, "[iz] shell install (%s): %v\n", targetShell, err)
		} else {
			fmt.Fprintf(os.Stderr, "[iz] shell %s configured successfully\n", targetShell)
			installedShells++
		}
	} else {
		// Detect default shell
		detected := detectShell()
		if detected != "" {
			if err := installShellHook(home, detected); err == nil {
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
		if err := installAgentInstructions(home, targetAgent); err != nil {
			fmt.Fprintf(os.Stderr, "[iz] agent install (%s): %v\n", targetAgent, err)
		} else {
			fmt.Fprintf(os.Stderr, "[iz] assistant %s configured successfully\n", targetAgent)
			installedAgents++
		}
	} else {
		for _, ag := range []string{"claude", "opencode", "antigravity", "cursor"} {
			if isAgentInstalled(home, ag) {
				if err := installAgentInstructions(home, ag); err == nil {
					fmt.Fprintf(os.Stderr, "[iz] configured memory instructions for %s\n", ag)
					installedAgents++
				}
			}
		}
	}

	if installedShells == 0 && installedAgents == 0 && targetShell == "" && targetAgent == "" {
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

func installShellHook(home, sh string) error {
	var rcPath, hookLine string
	switch sh {
	case "fish":
		rcPath = filepath.Join(home, ".config", "fish", "config.fish")
		hookLine = "if type -q iz; iz init fish | source; end"
	case "zsh":
		rcPath = filepath.Join(home, ".zshrc")
		hookLine = `if command -v iz >/dev/null 2>&1; then eval "$(iz init zsh)"; fi`
	case "bash":
		rcPath = filepath.Join(home, ".bashrc")
		hookLine = `if command -v iz >/dev/null 2>&1; then eval "$(iz init bash)"; fi`
	default:
		return fmt.Errorf("unsupported shell %s", sh)
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

func installAgentInstructions(home, agent string) error {
	var targetPath string
	switch agent {
	case "claude":
		targetPath = filepath.Join(home, ".claude", "CLAUDE.md")
	case "opencode":
		targetPath = filepath.Join(home, ".config", "opencode", "AGENTS.md")
	case "antigravity", "gemini":
		pluginDir := filepath.Join(home, ".gemini", "config", "plugins", "iz")
		_ = os.MkdirAll(filepath.Join(pluginDir, "rules"), 0o755)
		pluginJSON := filepath.Join(pluginDir, "plugin.json")
		if _, err := os.Stat(pluginJSON); os.IsNotExist(err) {
			_ = os.WriteFile(pluginJSON, []byte(`{
  "name": "iz",
  "version": "1.0.0",
  "description": "Antigravity plugin for persistent agent memory, recall, and terminal execution ledger via iz"
}
`), 0o644)
		}
		targetPath = filepath.Join(pluginDir, "rules", "AGENTS.md")
		legacyPath := filepath.Join(home, ".gemini", "config", "rules", "IZ.md")
		_ = patchManagedBlock(legacyPath, "<!-- iz-memory:begin -->", "<!-- iz-memory:end -->", aiPromptSnippet)
	case "cursor":
		targetPath = filepath.Join(home, ".cursorrules")
	default:
		return fmt.Errorf("unknown agent %s", agent)
	}

	return patchManagedBlock(targetPath, "<!-- iz-memory:begin -->", "<!-- iz-memory:end -->", aiPromptSnippet)
}

func patchManagedBlock(path, startMark, endMark, block string) error {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	content := string(data)
	start := strings.Index(content, startMark)
	end := strings.Index(content, endMark)

	if start >= 0 && end > start {
		// Replace existing block
		newContent := content[:start] + strings.TrimSpace(block) + content[end+len(endMark):]
		return os.WriteFile(path, []byte(strings.TrimSpace(newContent)+"\n"), 0o644)
	}

	// Append block
	sep := "\n\n"
	if len(content) == 0 {
		sep = ""
	}
	content = strings.TrimSpace(content) + sep + strings.TrimSpace(block) + "\n"
	os.MkdirAll(filepath.Dir(path), 0o755) //nolint
	return os.WriteFile(path, []byte(content), 0o644)
}

func appendLineIfMissing(path, line, comment string) error {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	content := string(data)
	if strings.Contains(content, line) || (strings.Contains(content, "iz init") && strings.Contains(content, "source")) || strings.Contains(content, "iz fish") {
		return nil // already configured
	}

	entry := "\n" + comment + "\n" + line + "\n"
	os.MkdirAll(filepath.Dir(path), 0o755) //nolint
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(entry)
	return err
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
