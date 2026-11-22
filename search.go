package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// line is the fzf list entry: id (red when the run failed), date, dir,
// command (tool part colored), plus @host for runs from other machines.
// Filtering is done by FTS via "iz lines {q}" (fzf runs with --phony), so the
// line only carries what helps the eye; exit/size live in the preview.
// dw pads the date column (dates are short for recent runs).
func (r Run) line(dw int, localHost string) string {
	id := strconv.FormatInt(r.ID, 10)
	if r.ExitCode.Valid && r.ExitCode.Int64 != 0 {
		id = "\x1b[31m" + id + "\x1b[0m"
	}
	dir := filepath.Base(r.Cwd)
	if dir == "" || dir == "." {
		dir = "/"
	}
	rest := " " + r.Cmd
	if r.Cmd == r.Tool || strings.HasPrefix(r.Cmd, r.Tool+" ") {
		rest = r.Cmd[len(r.Tool):] // tool is printed (colored) in front already
	}
	host := ""
	if r.Hostname != localHost {
		host = " \x1b[2m@" + strings.TrimSuffix(r.Hostname, ".local") + "\x1b[0m"
	}
	return fmt.Sprintf("%s \x1b[90m%-*s\x1b[0m \x1b[34m%s\x1b[0m \x1b[36m%s\x1b[0m%s%s",
		id, dw, fmtTsShort(r.Ts), dir, r.Tool, truncLeft(rest, 120), host)
}

// leadID parses the leading id of an fzf line (ANSI-safe).
func leadID(s string) (int64, bool) {
	f := strings.Fields(string(stripANSI([]byte(s))))
	if len(f) == 0 {
		return 0, false
	}
	id, err := strconv.ParseInt(f[0], 10, 64)
	return id, err == nil
}

// tuiSearch is the fzf interface.
//
//	enter   → view output(s) with less -R (colors kept, query highlighted)
//	tab     → multi-select toggle (insert into prompt in --pick/widget mode)
//	ctrl-e  → open in $EDITOR
//	ctrl-y  → delete selected run(s) and reload
//	ctrl-o  → notes TUI
//
// In --pick mode (fish widget) tab accepts and prints the command to stdout.
func tuiSearch(query string, pick bool) int {
	ttyOK := isTTY()
	if pick {
		ttyOK = term.IsTerminal(int(os.Stdin.Fd()))
	}
	if !ttyOK {
		fmt.Fprintln(os.Stderr, "iz: interactive TUI requires a terminal (use 'iz recall <query>' instead)")
		return 2
	}
	iz, _ := os.Executable()
	if iz == "" {
		iz = "iz"
	}
	izCmd := "'" + strings.ReplaceAll(iz, "'", `'\''`) + "'"
	// The list is fed (and live-reloaded) through lines, which runs the FTS
	// query as you type — that is what makes output-content search (e.g.
	// "vmware-detect") work inside the TUI.
	src := izCmd + " lines {q}"
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
		"--info", "inline", // counter on the prompt line: one more row for results
		"--header", "⏎ view · ⇥ select · ^A all · ^E edit · ^Y del · ^O notes",
		"--bind", "ctrl-a:select-all",
		"--bind", "start:reload(" + src + ")",
		"--bind", "change:reload(" + src + ")",
		"--preview", izCmd + " show {1} -- {q}",
		"--preview-window", "right:55%:wrap",
		"--bind", "enter:execute(" + izCmd + " show {+} -- {q} | less -R)",
		"--bind", "ctrl-e:execute(" + izCmd + " edit {1})",
		"--bind", "ctrl-y:execute-silent(" + izCmd + " --rm {+})+reload(" + src + ")",
		"--bind", "ctrl-o:execute(" + izCmd + " n)",
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
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "iz: fzf:", err)
		return 2
	}
	sel, _ := io.ReadAll(out) // fzf exits after accept, so this terminates
	c.Wait()                  //nolint

	// print the selected command (for the fish/zsh/bash widget)
	if !pick {
		return 0
	}
	id, ok := leadID(string(sel))
	if !ok {
		return 130 // cancelled or nothing selected
	}
	db, err := openDB()
	if err != nil {
		return 2
	}
	defer db.Close()
	if _, r, err := getMeta(db, id); err == nil {
		fmt.Println(r.Cmd)
		return 0
	}
	return 130
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
	dw := 0
	for _, r := range runs {
		dw = max(dw, len(fmtTsShort(r.Ts)))
	}
	host := hostname()
	var b strings.Builder
	for _, r := range runs {
		b.WriteString(r.line(dw, host))
		b.WriteByte('\n')
	}
	os.Stdout.WriteString(b.String()) //nolint
	return 0
}
