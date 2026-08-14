package main

import (
	"fmt"
	"os"
)

// fishCmd prints the fish integration; usage: iz f | source
//
//  1. sets $IZ to the default db if unset (recording gate: set -e IZ to pause)
//  2. emits a wrapper for every tool in the auto-record list
//  3. binds a search widget to ctrl-g (override with $IZ_KEY)
func fishCmd() int {
	db, err := openDB()
	if err != nil {
		fmt.Println("// iz: cannot open db:", err)
		return 1
	}
	defer db.Close()

	fmt.Fprint(os.Stdout, `# --- iz: begin (iz f | source) ---
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
`)

	// no wrappers for blacklisted tools
	blocked := map[string]bool{}
	if rows, err := db.Query(`SELECT name FROM blacklist`); err == nil {
		for rows.Next() {
			var n string
			rows.Scan(&n) //nolint
			blocked[n] = true
		}
		rows.Close()
	}

	rows, err := db.Query(`SELECT name FROM tools ORDER BY name`)
	if err != nil {
		fmt.Fprintln(os.Stdout, "# --- iz: end ---")
		return 0
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		rows.Scan(&name) //nolint
		if name == "" || !isToolName(name) || blocked[name] {
			continue
		}
		fmt.Fprintf(os.Stdout, `

function %[1]s --wraps %[1]s --description 'iz: recorded %[1]s'
    if set -q IZ
        command iz -- %[1]s $argv
    else
        command %[1]s $argv
    end
end`, name)
	}
	fmt.Fprintln(os.Stdout, "\n# --- iz: end ---")
	return 0
}

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
