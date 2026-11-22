package main

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

	if sub != "list" && (len(args) == 0 || args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintf(os.Stderr, "usage: iz %c <tool>...\n", sub[0])
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch sub {
	case "add":
		added := 0
		for _, t := range args {
			if !wrappable(t) {
				fmt.Fprintf(os.Stderr, "[iz] %q cannot be wrapped safely (not a plain command name, or a shell builtin/keyword)\n", t)
				continue
			}
			if _, err := db.Exec(`INSERT OR IGNORE INTO tools(name) VALUES(?)`, t); err != nil {
				fmt.Fprintln(os.Stderr, "iz:", err)
				return 1
			}
			added++
		}
		if added == 0 {
			return 1
		}
		fmt.Fprintln(os.Stderr, "[iz] added. Refresh wrappers by restarting your shell or re-sourcing 'iz init <shell>'")
	case "del":
		for _, t := range args {
			db.Exec(`DELETE FROM tools WHERE name=?`, t) //nolint
		}
		fmt.Fprintln(os.Stderr, "[iz] removed. Refresh wrappers by restarting your shell.")
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
// with the tool name derived from the file name). Only an explicitly named
// tool is added to the auto-record list (a derived "ssh" from ssh.log is not).
// The original bytes are stored (capped like recorded output); cleanup is
// applied to the indexed text only.
func importCmd(args []string) int {
	const usage = "usage: iz i [tool] <file>"
	if code, done := helpOrFlag(usage, args); done {
		return code
	}
	var tool, file string
	switch len(args) {
	case 1:
		file = args[0]
		tool = strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
	case 2:
		tool, file = args[0], args[1]
	default:
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}

	f, err := os.Open(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	capture := newCapture()
	_, err = io.Copy(capture, f)
	f.Close()
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

	data := capture.Bytes()
	z := gz(data)
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
	id, err := insertRun(db, r, z, truncFTS(plainText(data)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	if len(args) == 2 && wrappable(tool) {
		db.Exec(`INSERT OR IGNORE INTO tools(name) VALUES(?)`, tool) //nolint
	}
	fmt.Fprintf(os.Stderr, "[iz] #%d imported · tool=%s · %s\n", id, tool, humanBytes(r.Size.Int64))
	return 0
}

// isShellReserved reports shell builtins and keywords (fish, zsh, bash):
// a wrapper function with such a name breaks the shell.
func isShellReserved(s string) bool {
	switch s {
	case "cd", "test", "set", "eval", "exec", "export", "source", "command",
		"builtin", "alias", "unalias", "read", "echo", "printf", "exit",
		"return", "shift", "trap", "umask", "unset", "wait", "jobs", "fg",
		"bg", "kill", "pwd", "pushd", "popd", "dirs", "true", "false",
		"local", "declare", "typeset", "readonly", "which", "type", "hash",
		"ulimit", "times", "getopts", "let", "break", "continue",
		// keywords
		"if", "then", "else", "elif", "fi", "case", "esac", "for", "select",
		"while", "until", "do", "done", "in", "function", "time", "coproc",
		"repeat", "foreach", "end", "begin", "switch", "not", "and", "or",
		"nocorrect", "noglob", "status", "string", "functions", "emit":
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
	other, closeOther, err := openSnapshot(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz: merge:", err)
		return 1
	}
	defer closeOther()

	st, err := replicate(bg, other, db)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz: merge:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[iz] %d merged, %d duplicates skipped · notes: %d · deletes: %d\n",
		st.runs, st.skipped, st.notes, st.dels)
	return 0
}

// openSnapshot opens a migrated private copy of the database at path, so a
// merge never writes to the source yet reads older schemas (pre-uid notes,
// undated or NUL-keyed tombstones) through the current one.
func openSnapshot(path string) (*sql.DB, func(), error) {
	dir, err := os.MkdirTemp("", "iz-merge-")
	if err != nil {
		return nil, nil, err
	}
	tmp := filepath.Join(dir, "src.db")
	abs, err := filepath.Abs(path)
	var src *sql.DB
	if err == nil {
		// a URI path is percent-encoded: '?', '#' and '%' are literal in file names
		u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs), RawQuery: "mode=ro&_pragma=busy_timeout(5000)"}
		src, err = sql.Open("sqlite", u.String())
	}
	if err == nil {
		_, err = src.Exec(`VACUUM INTO ?`, tmp) // consistent copy, WAL included
		src.Close()
	}
	var db *sql.DB
	if err == nil {
		db, err = openDBAt(tmp) // migrates the copy to the current schema
	}
	if err != nil {
		os.RemoveAll(dir)
		return nil, nil, err
	}
	return db, func() { db.Close(); os.RemoveAll(dir) }, nil
}

const showUsage = `usage: iz sh <id> [id...] [query]
       iz sh <id> -- <query>   everything after -- is query (e.g. a number)`

// showCmd prints recorded output as-is, with the terms of an optional search
// query highlighted in reverse video (filter tokens like host: are not).
// It exits 1 when a requested run does not exist.
func showCmd(args []string) int {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Println(showUsage)
		return 0
	}
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer db.Close()

	ids, terms := showArgs(db, args)
	if len(ids) == 0 {
		fmt.Fprintln(os.Stderr, showUsage)
		return 2
	}

	code := 0
	for n, id := range ids {
		raw, r, err := getMeta(db, id)
		if err != nil {
			fmt.Fprintln(os.Stderr, "iz: no such run:", id)
			code = 1
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
		if os.Getenv("FZF_PREVIEW_LINES") != "" {
			if k := firstMatchLine(out, terms); k > 0 {
				// start at the first matching line — the preview lands on the
				// match instead of requiring manual scrolling
				out = bytes.SplitN(out, []byte{'\n'}, k+1)[k]
				meta = append(meta, fmt.Sprintf("\x1b[33m@L%d\x1b[0m", k+1))
			}
		}
		// host carries the header (id is already visible in the list)
		fmt.Fprintf(os.Stderr, "\x1b[2m[%s #%d]\x1b[0m %s\n$ \x1b[1m%s\x1b[0m\n",
			r.Hostname, r.ID, strings.Join(meta, " · "), r.Cmd)
		os.Stdout.Write(highlight(out, terms)) //nolint
	}
	return code
}

// showArgs splits run ids from the query. Before a "--" each arg is an id or
// a whole fzf line (its leading id counts) and everything after it is query;
// the TUI always passes "--". Without one, leading bare integers are ids
// (after the first, only ids of existing runs) and the first other arg starts
// the query, so `iz sh 1 "443 open"` searches run 1 for "443 open".
func showArgs(db *sql.DB, args []string) (ids []int64, terms []string) {
	if i := slices.Index(args, "--"); i >= 0 {
		for _, a := range args[:i] {
			if id, ok := leadID(a); ok {
				ids = append(ids, id)
			}
		}
		return ids, strings.Fields(strings.Join(args[i+1:], " "))
	}
	for i, a := range args {
		id, err := strconv.ParseInt(strings.TrimSpace(a), 10, 64)
		if err == nil && (len(ids) == 0 || db.QueryRow(`SELECT 1 FROM runs WHERE id=?`, id).Scan(new(int)) == nil) {
			ids = append(ids, id)
			continue
		}
		return ids, strings.Fields(strings.Join(args[i:], " "))
	}
	return ids, nil
}

// firstMatchLine returns the index of the first line whose visible text
// contains any term, or -1 when none matches (case-insensitively, like highlight).
func firstMatchLine(b []byte, terms []string) int {
	ns := needles(terms)
	if len(ns) == 0 {
		return -1
	}
	for i, line := range bytes.Split(b, []byte{'\n'}) {
		if containsAny(stripANSI(line), ns) {
			return i
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

// hlText highlights plain (escape-free) text line by line: needles are single
// words, so matches never span lines, and folding stays bounded per line.
func hlText(s []byte, ns [][]byte) []byte {
	var out []byte
	for len(s) > 0 {
		line := s
		if i := bytes.IndexByte(s, '\n'); i >= 0 {
			line = s[:i+1]
		}
		s = s[len(line):]
		out = hlLine(out, line, ns)
	}
	return out
}

// hlLine appends s to out with every needle match (case-folded; earliest,
// then longest wins) wrapped in reverse video.
func hlLine(out, s []byte, ns [][]byte) []byte {
	low, off := foldMap(s)
	orig := func(i int) int { // folded offset → offset in s
		if off == nil {
			return i
		}
		return off[i]
	}
	last := 0
	for i := 0; i < len(low); {
		at, w := -1, 0
		for _, n := range ns {
			if j := bytes.Index(low[i:], n); j >= 0 && (at < 0 || j < at || j == at && len(n) > w) {
				at, w = j, len(n)
			}
		}
		if at < 0 {
			break
		}
		a, b := orig(i+at), orig(i+at+w)
		out = append(out, s[last:a]...)
		out = append(out, "\x1b[7m"...)
		out = append(out, s[a:b]...)
		out = append(out, "\x1b[27m"...)
		last, i = b, i+at+w
	}
	return append(out, s[last:]...)
}

// resolveEditor returns $EDITOR if set and non-blank. Otherwise, it checks
// nvim, vim, vi, nano in order on $PATH and returns the first one found.
func resolveEditor() string {
	if ed := strings.TrimSpace(os.Getenv("EDITOR")); ed != "" {
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
	if len(f) == 0 {
		return errors.New("no editor found (set $EDITOR)")
	}
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
	if err := runEditor(f.Name()); err != nil {
		fmt.Fprintln(os.Stderr, "iz: editor:", err)
		return 1
	}
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
