package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// toolsCmd manages the auto-record list: iz a <tool> / iz d <tool> / iz l.
func toolsCmd(sub string, args []string) int {
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer db.Close()

	switch sub {
	case "add":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: iz a <tool>...")
			return 2
		}
		for _, t := range args {
			if t == "iz" || isShellBuiltin(t) {
				fmt.Fprintf(os.Stderr, "[iz] %q cannot be wrapped safely\n", t)
				continue
			}
			if !isToolName(t) {
				fmt.Fprintf(os.Stderr, "[iz] invalid tool name: %q\n", t)
				continue
			}
			if _, err := db.Exec(`INSERT OR IGNORE INTO tools(name) VALUES(?)`, t); err != nil {
				fmt.Fprintln(os.Stderr, "iz:", err)
				return 1
			}
		}
		fmt.Fprintln(os.Stderr, "[iz] added. Refresh wrappers: iz f | source")
	case "del":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: iz d <tool>...")
			return 2
		}
		for _, t := range args {
			db.Exec(`DELETE FROM tools WHERE name=?`, t) //nolint
		}
		fmt.Fprintln(os.Stderr, "[iz] removed. (drop the fish function: functions -e <tool>)")
	case "list":
		fmt.Println("# tools:")
		for _, n := range queryNames(db, "tools") {
			fmt.Println(n)
		}
	}
	return 0
}

// delRuns is the internal delete entry point used by the TUI (ctrl-y).
// Each argument may carry a whole fzf line; only the leading id is taken.
func delRuns(args []string) int {
	var ids []int64
	for _, a := range args {
		if id, ok := leadID(a); ok {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return 130
	}
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer db.Close()
	fmt.Fprintf(os.Stderr, "[iz] %d deleted\n", deleteRuns(db, ids))
	return 0
}

// importCmd archives a file as a run: iz i <tool> <file> (or iz i <file>,
// with the tool name derived from the file name).
func importCmd(args []string) int {
	var tool, file string
	switch len(args) {
	case 0:
		fmt.Fprintln(os.Stderr, "usage: iz i <tool> <file>")
		return 2
	case 1:
		file = args[0]
		tool = strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
	default:
		tool, file = args[0], args[1]
	}

	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer db.Close()

	raw := tidyRaw(data)
	z := gz(raw)
	abs, err := filepath.Abs(file)
	if err != nil {
		abs = file
	}
	r := Run{
		Ts:       float64(time.Now().UnixNano()) / 1e9,
		Hostname: hostname(),
		Tool:     tool,
		Cmd:      "import " + file,
		Cwd:      filepath.Dir(abs), // dir of the imported file, not the caller's cwd
		Size:     ni(int64(len(z))),
	}
	id, err := insertRun(db, r, z, truncFTS(stripANSI(raw)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	if isToolName(tool) && !isShellBuiltin(tool) && tool != "iz" {
		db.Exec(`INSERT OR IGNORE INTO tools(name) VALUES(?)`, tool) //nolint
	}
	fmt.Fprintf(os.Stderr, "[iz] #%d imported · tool=%s · %s\n", id, tool, humanBytes(r.Size.Int64))
	return 0
}

func isShellBuiltin(s string) bool {
	switch s {
	case "cd", "test", "set", "eval", "exec", "export", "source", "command",
		"builtin", "alias", "unalias", "read", "echo", "printf", "exit",
		"return", "shift", "trap", "umask", "unset", "wait", "jobs", "fg",
		"bg", "kill", "pwd", "pushd", "popd", "dirs", "true", "false",
		"local", "declare", "typeset", "readonly", "which", "type", "hash",
		"ulimit", "times", "getopts", "let", "break", "continue":
		return true
	}
	return false
}

// mergeCmd merges another machine's database (runs, notes and deletions),
// deduping runs on (hostname, ts, tool, cmd) and notes on their uid.
func mergeCmd(path string) int {
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer db.Close()
	other, err := openDBAt(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	defer other.Close()

	st, err := replicate(bg, other, db)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz: merge:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[iz] %d merged, %d duplicates skipped · notes: %d · deletes: %d\n",
		st.runs, st.skipped, st.notes, st.dels)
	return 0
}

// showCmd prints recorded output as-is. It accepts several ids (fzf {+} passes
// whole lines, so the leading token of each arg is used) and an optional search
// query whose terms get highlighted in reverse video — this is what the fzf
// preview ({q}) uses. Filter tokens (host:, size:...) are not highlighted.
func showCmd(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: iz sh <id> [id...] [query]")
		return 2
	}
	var ids []int64
	var terms []string
	for i, a := range args {
		if a == "--" { // everything after is query (a numeric query is not an id)
			terms = append(terms, freeTerms(strings.Fields(strings.Join(args[i+1:], " ")))...)
			break
		}
		if id, ok := leadID(a); ok {
			ids = append(ids, id)
		} else {
			terms = append(terms, freeTerms(strings.Fields(a))...)
		}
	}
	if len(ids) == 0 {
		fmt.Fprintln(os.Stderr, "usage: iz sh <id> [id...] [query]")
		return 2
	}
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer db.Close()

	for n, id := range ids {
		raw, r, err := getMeta(db, id)
		if err != nil {
			fmt.Fprintln(os.Stderr, "iz: no such run:", id)
			continue
		}
		if n > 0 {
			fmt.Fprintln(os.Stderr)
		}
		meta := []string{"exit=?"}
		if r.ExitCode.Valid {
			meta[0] = fmt.Sprint("exit=", r.ExitCode.Int64)
			if r.ExitCode.Int64 != 0 {
				meta[0] = "\x1b[31m" + meta[0] + "\x1b[0m"
			}
		}
		if r.Dur.Valid {
			meta = append(meta, fmt.Sprintf("%.1fs", float64(r.Dur.Int64)/1000))
		}
		if r.Size.Valid {
			meta = append(meta, humanBytes(r.Size.Int64))
		}
		meta = append(meta, "\x1b[36m"+tildify(r.Cwd)+"\x1b[0m")
		out := ungz(raw)
		if k := firstMatchLine(out, terms); k > 0 {
			// start at the first matching line — the preview lands on the
			// match instead of requiring manual scrolling
			out = bytes.SplitN(out, []byte{'\n'}, k+1)[k]
			meta = append(meta, fmt.Sprintf("\x1b[33m@L%d\x1b[0m", k+1))
		}
		// host carries the header (id is already visible in the list)
		fmt.Fprintf(os.Stderr, "\x1b[2m[%s #%d]\x1b[0m %s\n$ \x1b[1m%s\x1b[0m\n",
			r.Hostname, r.ID, strings.Join(meta, " · "), r.Cmd)
		os.Stdout.Write(highlight(out, terms)) //nolint
	}
	return 0
}

// needles returns the lowercased terms worth matching (≥2 bytes).
func needles(terms []string) [][]byte {
	var out [][]byte
	for _, t := range terms {
		if len(t) >= 2 {
			out = append(out, asciiLower([]byte(t)))
		}
	}
	return out
}

// firstMatchLine returns the index of the first line whose visible text
// contains any term, or -1 when none matches (case-insensitively, like highlight).
func firstMatchLine(b []byte, terms []string) int {
	ns := needles(terms)
	if len(ns) == 0 {
		return -1
	}
	for i, line := range bytes.Split(b, []byte{'\n'}) {
		l := asciiLower(stripANSI(line))
		for _, n := range ns {
			if bytes.Contains(l, n) {
				return i
			}
		}
	}
	return -1
}

// highlight wraps case-insensitive matches of every term (≥2 chars) in
// reverse video. Escape sequences are copied verbatim and never matched, so
// a query like "31" cannot break a color code.
func highlight(b []byte, terms []string) []byte {
	ns := needles(terms)
	if len(ns) == 0 {
		return b
	}
	var out []byte
	last := 0
	for _, loc := range append(reANSI.FindAllIndex(b, -1), []int{len(b), len(b)}) {
		out = append(out, hlText(b[last:loc[0]], ns)...)
		out = append(out, b[loc[0]:loc[1]]...)
		last = loc[1]
	}
	return out
}

// hlText highlights plain (escape-free) text; asciiLower keeps offsets aligned.
func hlText(s []byte, ns [][]byte) []byte {
	low := asciiLower(s)
	var out []byte
	for i := 0; i < len(s); {
		at, w := -1, 0
		for _, n := range ns { // earliest (then longest) match wins
			if j := bytes.Index(low[i:], n); j >= 0 && (at < 0 || j < at || j == at && len(n) > w) {
				at, w = j, len(n)
			}
		}
		if at < 0 {
			return append(out, s[i:]...)
		}
		out = append(out, s[i:i+at]...)
		out = append(out, "\x1b[7m"...)
		out = append(out, s[i+at:i+at+w]...)
		out = append(out, "\x1b[27m"...)
		i += at + w
	}
	return out
}

// resolveEditor returns $EDITOR if set and non-empty. Otherwise, it checks
// nvim, vim, vi, nano in order on $PATH and returns the first one found.
func resolveEditor() string {
	if ed := os.Getenv("EDITOR"); ed != "" {
		return ed
	}
	for _, candidate := range []string{"nvim", "vim", "vi", "nano"} {
		if path, err := exec.LookPath(candidate); err == nil && path != "" {
			return candidate
		}
	}
	return "nano"
}

// runEditor opens path in the editor; $EDITOR may carry arguments
// (e.g. "code --wait").
func runEditor(path string) error {
	f := strings.Fields(resolveEditor())
	c := exec.Command(f[0], append(f[1:], path)...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}

// editCmd opens the raw ANSI output in $EDITOR (fallback: nvim -> vim -> vi -> nano).
func editCmd(idArg string) int {
	if !isTTY() {
		fmt.Fprintln(os.Stderr, "iz e: interactive editor requires a terminal (use 'iz sh <id>' instead)")
		return 2
	}
	id, err := strconv.ParseInt(idArg, 10, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "usage: iz e <id>")
		return 2
	}
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer db.Close()
	raw, r, err := getMeta(db, id)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz: no such run:", id)
		return 1
	}
	f, err := os.CreateTemp("", fmt.Sprintf("iz-%d-*.ansi", id))
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	defer os.Remove(f.Name())
	f.Write(ungz(raw)) //nolint
	f.Close()

	fmt.Fprintf(os.Stderr, "[iz] %s\n", r.Cmd)
	runEditor(f.Name()) //nolint
	return 0
}

// queryNames reads the name column from the tools table.
func queryNames(db *sql.DB, table string) []string {
	rows, err := db.Query(`SELECT name FROM ` + table + ` ORDER BY name`) //nolint
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		rows.Scan(&n) //nolint
		out = append(out, n)
	}
	return out
}
