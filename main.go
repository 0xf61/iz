// iz records shell commands together with their terminal output in a single
// SQLite database, searchable via full-text search (fzf TUI).
package main

import (
	"fmt"
	"os"
	"strings"
)

const usage = `iz — command history with recorded tool output

Usage:
  iz [query]                 search TUI (fzf); query: free text + filters
                                 host:machine  cmd:tool  size:>1mb  size:<500kb
  iz -- <cmd> [args...]      run command under a PTY, record its colored output
  iz sh <id> [id...] [query] print output(s) as-is; query terms get highlighted
  iz e <id>                  open output in $EDITOR
  iz a <tool>...             add tools to the auto-record list
  iz d <tool>...             remove from list and blacklist
  iz l                       list auto-record tools + blacklist
  iz i <tool> <file>         import a file (e.g. iz i nmap gm.xml; one arg: tool = file name)
  iz m <iz.db>               merge another machine's database
  iz f                       print fish integration (iz f | source)

TUI: enter=output · tab=insert command into prompt · ctrl-e=editor · ctrl-y=delete
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
	case "--rm": // internal: delete runs, called by the TUI (ctrl-y)
		os.Exit(delRuns(args))
	case "import", "i":
		os.Exit(importCmd(args))
	case "merge", "m":
		os.Exit(oneArg("iz m <iz.db>", args, mergeCmd))
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
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage:", usageLine)
		return 2
	}
	return fn(args[0])
}
