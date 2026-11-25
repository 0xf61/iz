// iz records shell commands together with their terminal output in a single
// SQLite database, searchable via full-text search (fzf TUI).
package main

import (
	"fmt"
	"os"
	"strings"
)

var version = "dev"

const usage = `iz — command history, recorded output, and AI memory/recall

Usage:
  iz [query]                 search TUI (fzf); query: free text + filters
                                 host:machine  cmd:tool  dir:name  size:>1mb
  iz -- <cmd> [args...]      run command under a PTY, record its colored output
  iz sh <id> [id...] [--] [query]  print output(s) as-is; query terms get highlighted
  iz e <id>                  open output in $EDITOR
  iz a <tool>...             add tools to the auto-record list
  iz d <tool>...             remove tools from the auto-record list
  iz l                       list auto-record tools
  iz i [tool] <file>         import a file (e.g. iz i nmap gm.xml)
  iz m <iz.db>               merge another machine's database (runs + notes)
  iz sync                    two-way sync with remote LibSQL/Turso (IZ_SYNC_URL)
  iz update                  update iz to the latest GitHub release
  iz version                 print iz version
  iz init [fish|zsh|bash]    setup or print shell & AI assistant integration (iz init --help)

Memory & Recall:
  iz recall <query>          search notes and runs (--json, --pretty, -n, -r, -l N, --full)
  iz prime [--json]          compact index of all memory namespaces & titles
  iz n                       interactive notes TUI (fzf)
  iz n <ns:title> [-t tags] [-a] [content]  create/update note (upsert, -a to append)
  iz n new | edit <id|ns:title>       create or edit a note in $EDITOR
  iz n show <id|ns:title> | del <id|ns:title>  view or delete a note
  iz n list [namespace]      list saved notes (alias: iz nl)
  iz n import <file|dir>     import markdown files/notes into memory

AI Agents:
  iz ai                      output agent guide for memory, recall, and tool calling

TUI: enter=view · tab=select/insert · ctrl-e=editor · ctrl-y=delete · ctrl-o=notes
DB path: $IZ (default ~/.iz/iz.db). Pause recording with: set -e IZ`

func main() {
	if len(os.Args) < 2 {
		os.Exit(tuiSearch("", false))
	}
	cmd, args := os.Args[1], os.Args[2:]

	switch cmd {
	case "--", "run": // iz -- <cmd> [args...]
		os.Exit(runRecord(args))
	case "--pick": // fish widget mode: print selected command to stdout
		os.Exit(tuiSearch(strings.Join(args, " "), true))
	case "show", "sh":
		os.Exit(showCmd(args))
	case "edit", "e":
		os.Exit(oneArg("iz e <id>", args, editCmd))
	case "add", "a":
		os.Exit(toolsCmd("add", args))
	case "del", "d":
		os.Exit(toolsCmd("del", args))
	case "list", "l":
		os.Exit(toolsCmd("list", nil))
	case "note", "n":
		os.Exit(noteCmd(args))
	case "recall", "rc":
		os.Exit(recallCmd(args))
	case "prime", "context":
		os.Exit(primeCmd(args))
	case "notes", "nl":
		os.Exit(listNotes(strings.Join(args, " ")))
	case "sync", "s":
		os.Exit(syncCmd(args))
	case "update", "upgrade":
		os.Exit(updateCmd(args))
	case "version", "--version", "-v":
		fmt.Println("iz", currentVersion())
	case "ai":
		os.Exit(aiGuideCmd())
	case "--rm": // internal: delete runs, called by the TUI (ctrl-y)
		os.Exit(delRuns(args))
	case "import", "i":
		os.Exit(importCmd(args))
	case "merge", "m":
		os.Exit(oneArg("iz m <iz.db>", args, mergeCmd))
	case "init":
		os.Exit(initCmd(args))
	case "fish", "f":
		os.Exit(fishCmd())
	case "lines": // internal: live reload source for the fzf TUI
		os.Exit(linesCmd(args))
	case "-h", "--help", "help":
		fmt.Println(usage)
	default: // anything else is treated as a search query
		os.Exit(tuiSearch(strings.Join(os.Args[1:], " "), false))
	}
}

func oneArg(usageLine string, args []string, fn func(string) int) int {
	if code, done := helpOrFlag("usage: "+usageLine, args); done {
		return code
	}
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage:", usageLine)
		return 2
	}
	return fn(args[0])
}

// helpOrFlag handles the options of a command that takes none but --help:
// it prints usage and reports the exit code when args hold an option.
func helpOrFlag(usage string, args []string) (code int, done bool) {
	for _, a := range args {
		switch {
		case a == "-h" || a == "--help":
			fmt.Println(usage)
			return 0, true
		case len(a) > 1 && a[0] == '-':
			fmt.Fprintf(os.Stderr, "iz: unknown option %q\n%s\n", a, usage)
			return 2, true
		}
	}
	return 0, false
}
