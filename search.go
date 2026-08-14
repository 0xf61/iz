package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Run.line is the fzf list entry: id, date, tool, dir name, command, with the
// hostname in a dim run so host: filtering still works. Everything else
// (output text, size, exit code) lives in the FTS index or the preview.
func (r Run) line() string {
	cmd := r.Cmd
	if len(cmd) > 120 {
		cmd = "…" + cmd[len(cmd)-119:]
	}
	dir := filepath.Base(r.Cwd)
	if dir == "" || dir == "." {
		dir = "/"
	}
	// Visible: id, date, tool, dir, command. host stays filterable in a dim
	// run; size/exit live only in the preview. Filtering is done by FTS via
	// "iz lines {q}" (fzf runs with --phony, so it does not re-filter).
	return fmt.Sprintf("%d \x1b[90m%s\x1b[0m \x1b[36m%s\x1b[0m \x1b[34m%s\x1b[0m \x1b[2mhost:%s\x1b[0m %s",
		r.ID, fmtTs(r.Ts), r.Tool, dir, r.Hostname, cmd)
}

// tuiSearch is the fzf interface.
//
//	enter   → view output(s) with less -R (colors kept, query highlighted)
//	tab     → multi-select toggle (insert into prompt in --pick/widget mode)
//	ctrl-e  → open in $EDITOR
//	ctrl-y  → delete selected run(s) and reload
//
// In --pick mode (fish widget) tab accepts and prints the command to stdout.
func tuiSearch(query string, pick bool) int {
	iz, _ := os.Executable()
	if iz == "" {
		iz = "iz"
	}
	// The list is fed (and live-reloaded) through lines, which runs the FTS
	// query as you type — that is what makes output-content search (e.g.
	// "vmware-detect") work inside the TUI.
	src := iz + " lines {q}"
	args := []string{
		"--ansi",
		// --phony: fzf does not filter itself; every keystroke re-runs the
		// FTS query via change:reload instead. Case behavior: lowercase
		// input matches case-insensitively (FTS unicode61), mixed-case input
		// is matched exactly (queryRuns lowercases only all-lowercase terms).
		"--phony",
		// disable fzf's in-list match highlighting: matches are highlighted
		// in the preview instead (see showCmd/highlight)
		"--color", "hl:-1,hl+:-1",
		"--header", "enter:output · tab:select · ctrl-a:all · ctrl-e:editor · ctrl-y:delete",
		"--bind", "ctrl-a:select-all",
		"--bind", "start:reload(" + src + ")",
		"--bind", "change:reload(" + src + ")",
		"--preview", iz + " show {1} {q}",
		"--preview-window", "right:55%:wrap",
		"--bind", "enter:execute(" + iz + " show {+} | less -R)",
		"--bind", "ctrl-e:execute(" + iz + " edit {1})",
		"--bind", "ctrl-y:execute-silent(" + iz + " --rm {+})+reload(" + src + ")",
	}
	// The full query (filters included) seeds fzf; keystrokes flow to the
	// reload source as {q}, which re-parses them. tab accepts in widget mode
	// and toggles selection otherwise.
	args = append(args, "--query", query)
	if pick {
		args = append(args, "--bind", "tab:accept")
	} else {
		args = append(args, "--multi")
	}
	c := exec.Command("fzf", args...)
	c.Stderr = os.Stderr
	c.Stdin = strings.NewReader("") // the list comes from the reload source
	out, _ := c.StdoutPipe()
	c.Start()

	sel, _ := io.ReadAll(out) // fzf exits after accept, so this terminates
	c.Wait()
	fields := strings.Fields(string(sel))

	// print the selected command (for the fish widget)
	for _, f := range fields {
		if id, err := strconv.ParseInt(f, 10, 64); err == nil {
			if db, err := openDB(); err == nil {
				if _, r, err := getMeta(db, id); err == nil {
					fmt.Println(r.Cmd)
					db.Close()
					return 0
				}
				db.Close()
			}
		}
	}
	return 130 // cancelled or nothing selected
}

// linesCmd is the live reload source for the TUI: it runs the FTS query that
// fzf is currently showing and prints matching list entries.
func linesCmd(args []string) int {
	db, err := openDB()
	if err != nil {
		return 2
	}
	defer db.Close()
	runs, err := queryRuns(db, strings.Join(args, " "))
	if err != nil {
		return 1
	}
	for _, r := range runs {
		fmt.Println(r.line())
	}
	return 0
}
