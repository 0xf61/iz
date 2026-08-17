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
			if t == "iz" {
				fmt.Fprintln(os.Stderr, "[iz] 'iz' cannot record itself")
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
		f := strings.Fields(a)
		if len(f) == 0 {
			continue
		}
		if id, err := strconv.ParseInt(f[0], 10, 64); err == nil {
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
	abs, err := filepath.Abs(file)
	if err != nil {
		abs = file
	}
	r := Run{
		Ts:       float64(time.Now().Unix()),
		Hostname: hostname(),
		Tool:     tool,
		Cmd:      "import " + file,
		Cwd:      filepath.Dir(abs), // dir of the imported file, not the caller's cwd
		Size:     ni(int64(len(gz(raw)))),
	}
	id, err := insertRun(db, r, gz(raw), stripANSI(raw))
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	db.Exec(`INSERT OR IGNORE INTO tools(name) VALUES(?)`, tool) //nolint
	fmt.Fprintf(os.Stderr, "[iz] #%d imported · tool=%s · %s\n", id, tool, humanBytes(int64(r.Size.Int64)))
	return 0
}

// mergeCmd merges another machine's database, deduping on (hostname, ts, cmd).
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

	// Dedup key: the same run from the same machine has identical (hostname,
	// tool, ts, cmd). Loading existing keys once makes this O(n+m) instead of
	// one index-less scan per incoming row.
	type key struct {
		host string
		tool string
		ts   float64
		cmd  string
	}
	seen := map[key]bool{}
	if kr, err := db.Query(`SELECT ts,hostname,tool,cmd FROM runs`); err == nil {
		for kr.Next() {
			var k key
			kr.Scan(&k.ts, &k.host, &k.tool, &k.cmd) //nolint
			seen[k] = true
		}
		kr.Close()
	}

	rows, err := other.Query(`SELECT ts,hostname,tool,cmd,cwd,exit_code,duration_ms,size,raw FROM runs`)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	defer rows.Close()

	// One transaction for the whole merge: a single WAL commit instead of one
	// fsync pair per row.
	tx, err := db.Begin()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	defer tx.Rollback() //nolint

	added, skipped := 0, 0
	for rows.Next() {
		var r Run
		var raw []byte
		if err := rows.Scan(&r.Ts, &r.Hostname, &r.Tool, &r.Cmd, &r.Cwd,
			&r.ExitCode, &r.Dur, &r.Size, &raw); err != nil {
			continue
		}
		if seen[key{r.Hostname, r.Tool, r.Ts, r.Cmd}] {
			skipped++
			continue
		}
		if _, err := insertRunTx(tx, r, raw, stripANSI(ungz(raw))); err == nil {
			seen[key{r.Hostname, r.Tool, r.Ts, r.Cmd}] = true
			added++
		}
	}
	tx.Commit() //nolint
	fmt.Fprintf(os.Stderr, "[iz] %d merged, %d duplicates skipped\n", added, skipped)
	return 0
}

// showCmd prints recorded output as-is. It accepts several ids (fzf {+} passes
// whole lines, so the leading token of each arg is used) and an optional search
// query whose terms get highlighted in reverse video — this is what the fzf
// preview ({q}) uses.
func showCmd(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: iz sh <id> [id...] [query]")
		return 2
	}
	var ids []int64
	var terms []string
	for _, a := range args {
		f := strings.Fields(a)
		if len(f) == 0 {
			continue
		}
		if id, err := strconv.ParseInt(f[0], 10, 64); err == nil {
			ids = append(ids, id)
		} else {
			terms = append(terms, f...)
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
		dur, size := "", ""
		if r.Dur.Valid {
			dur = fmt.Sprintf("%.1fs", float64(r.Dur.Int64)/1000)
		}
		if r.Size.Valid {
			size = humanBytes(int64(r.Size.Int64))
		}
		exit := "?"
		if r.ExitCode.Valid {
			exit = fmt.Sprint(r.ExitCode.Int64)
		}
		// host carries the header (id is already visible in the list)
		fmt.Fprintf(os.Stderr, "\x1b[2m[%s #%d]\x1b[0m \x1b[1m%s\x1b[0m · exit=%s · %s · %s · \x1b[36m%s\x1b[0m\n$ \x1b[1m%s\x1b[0m\n",
			r.Hostname, r.ID, r.Tool, exit, dur, size, r.Cwd, r.Cmd)
		out := ungz(raw)
		if n := firstMatchLine(out, terms); n > 0 {
			// skip to the first matching line — the preview lands on the
			// match instead of requiring manual scrolling
			lines := bytes.SplitN(out, []byte{'\n'}, n+1)
			out = lines[n]
			fmt.Fprintln(os.Stderr, "\x1b[2m··· (jumped to first match) ···\x1b[0m")
		}
		os.Stdout.Write(highlight(out, terms))
	}
	return 0
}

// highlight wraps case-insensitive matches of every term (≥2 chars) in
// reverse video, leaving the rest of the output untouched.
// firstMatchLine returns the index of the first line containing any term,
// or -1 when none matches (case-insensitively, like highlight).
func firstMatchLine(b []byte, terms []string) int {
	for i, line := range bytes.Split(b, []byte{'\n'}) {
		l := strings.ToLower(string(line))
		for _, t := range terms {
			if len(t) >= 2 && strings.Contains(l, strings.ToLower(t)) {
				return i
			}
		}
	}
	return -1
}

func highlight(b []byte, terms []string) []byte {
	for _, t := range terms {
		if len(t) < 2 {
			continue
		}
		needle := strings.ToLower(t)
		hay := strings.ToLower(string(b))
		var res []byte
		for i := 0; i < len(hay); {
			j := strings.Index(hay[i:], needle)
			if j < 0 {
				res = append(res, b[i:]...)
				break
			}
			res = append(res, b[i:i+j]...)
			res = append(res, "\x1b[7m"...)
			res = append(res, b[i+j:i+j+len(t)]...)
			res = append(res, "\x1b[27m"...)
			i += j + len(t)
		}
		b = res
	}
	return b
}

// editCmd opens the raw ANSI output in $EDITOR (default: vim).
func editCmd(idArg string) int {
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

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vim"
	}
	fmt.Fprintf(os.Stderr, "[iz] %s\n", r.Cmd)
	c := exec.Command(editor, f.Name())
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.Run() //nolint
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
