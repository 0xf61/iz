package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo → static binaries)
)

// dbPath: $IZ wins (wrappers also gate on it), default ~/.iz/iz.db.
func dbPath() string {
	if p := os.Getenv("IZ"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".iz", "iz.db")
}

func openDB() (*sql.DB, error) { return openDBAt(dbPath()) }

// openDBAt opens (and initializes) the database at path.
func openDBAt(p string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", p+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	const schema = `
CREATE TABLE IF NOT EXISTS runs(
  id          INTEGER PRIMARY KEY,
  ts          REAL NOT NULL,   -- start time (unix)
  hostname    TEXT NOT NULL,
  tool        TEXT NOT NULL,   -- "table" concept: nmap, certipy, an import name...
  cmd         TEXT NOT NULL,
  cwd         TEXT NOT NULL,
  exit_code   INTEGER,
  duration_ms INTEGER,
  size        INTEGER,         -- compressed size in bytes
  raw         BLOB             -- original output incl. ANSI, gzipped
);
CREATE TABLE IF NOT EXISTS tools(name TEXT PRIMARY KEY);     -- auto-record list
CREATE VIRTUAL TABLE IF NOT EXISTS outputs_fts USING fts5(text, tokenize='unicode61');`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return db, nil
}

// Run is one recorded command execution.
type Run struct {
	ID       int64
	Ts       float64
	Hostname string
	Tool     string
	Cmd      string
	Cwd      string
	ExitCode sql.NullInt64
	Dur      sql.NullInt64
	Size     sql.NullInt64
	Snippet  string // first ~2000 chars of output: hidden but searchable fzf field
}

func ni(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: true} }

// insertRun writes the run and its FTS row (rowid = run id) atomically. The
// FTS text is hostname+tool+cmd+plain output, so a single MATCH searches everything.
func insertRun(db *sql.DB, r Run, raw, text []byte) (int64, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	id, err := insertRunTx(tx, r, raw, text)
	if err != nil {
		tx.Rollback() //nolint
		return 0, err
	}
	return id, tx.Commit()
}

// insertRunTx is the transactional core of insertRun; merges use it to batch
// thousands of rows into one commit.
func insertRunTx(tx *sql.Tx, r Run, raw, text []byte) (int64, error) {
	res, err := tx.Exec(
		`INSERT INTO runs(ts,hostname,tool,cmd,cwd,exit_code,duration_ms,size,raw)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		r.Ts, r.Hostname, r.Tool, r.Cmd, r.Cwd, r.ExitCode, r.Dur, r.Size, raw)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return id, err
	}
	fts := append([]byte(r.Hostname+" "+r.Tool+" "+r.Cmd+" "), text...)
	// string() is critical: []byte binds as BLOB, and SQLite LIKE never matches BLOBs
	// (FTS MATCH still would, silently hiding the bug).
	_, err = tx.Exec(`INSERT INTO outputs_fts(rowid,text) VALUES(?,?)`, id, string(fts))
	return id, err
}

// deleteRuns removes runs and their FTS rows in one transaction; returns how
// many were deleted.
func deleteRuns(db *sql.DB, ids []int64) int {
	tx, err := db.Begin()
	if err != nil {
		return 0
	}
	defer tx.Rollback() //nolint
	n := 0
	for _, id := range ids {
		tx.Exec(`DELETE FROM outputs_fts WHERE rowid=?`, id) //nolint
		if res, err := tx.Exec(`DELETE FROM runs WHERE id=?`, id); err == nil {
			if k, _ := res.RowsAffected(); k > 0 {
				n++
			}
		}
	}
	tx.Commit() //nolint
	return n
}

// getMeta returns the gzipped output plus all metadata, for show/edit headers.
func getMeta(db *sql.DB, id int64) (raw []byte, r Run, err error) {
	err = db.QueryRow(`SELECT id,ts,hostname,tool,cmd,cwd,exit_code,duration_ms,size,raw
	                   FROM runs WHERE id=?`, id).
		Scan(&r.ID, &r.Ts, &r.Hostname, &r.Tool, &r.Cmd, &r.Cwd, &r.ExitCode, &r.Dur, &r.Size, &raw)
	return raw, r, err
}

// queryRuns parses "failed host:build01 tool:cargo": free terms go to FTS5 MATCH
// (output text is indexed), host:/tool: become SQL filters.
func queryRuns(db *sql.DB, query string) ([]Run, error) {
	var conds string
	var args []any
	var terms []string
	for _, t := range strings.Fields(query) {
		switch {
		case strings.HasPrefix(t, "host:"):
			conds += " AND r.hostname LIKE ?"
			args = append(args, strings.TrimPrefix(t, "host:")+"%")
		case strings.HasPrefix(t, "dir:"):
			// directory name only (the cwd column holds full paths)
			conds += " AND r.cwd LIKE ?"
			args = append(args, "%/"+strings.TrimPrefix(t, "dir:")+"%")
		case strings.HasPrefix(t, "cmd:"), strings.HasPrefix(t, "tool:"):
			conds += " AND r.tool LIKE ?"
			args = append(args, t[strings.Index(t, ":")+1:]+"%")
		case strings.HasPrefix(t, "size:"):
			if op, n, ok := parseSize(strings.TrimPrefix(t, "size:")); ok {
				conds += fmt.Sprintf(" AND r.size %s ?", op)
				args = append(args, n)
			}
		default:
			terms = append(terms, t)
		}
	}
	q := strings.Join(terms, " ")

	const selectSQL = `SELECT r.id,r.ts,r.hostname,r.tool,r.cmd,r.cwd,r.exit_code,r.duration_ms,r.size,
	                   substr(f.text,1,2000)
	                   FROM runs r JOIN outputs_fts f ON f.rowid = r.id`
	const tail = " ORDER BY r.ts DESC LIMIT 1000"

	// Case rule: all-lowercase terms match case-insensitively via FTS; terms
	// with any uppercase must occur verbatim (instr compares BINARY).
	for _, t := range terms {
		if strings.ToLower(t) != t {
			conds += " AND instr(f.text, ?) > 0"
			args = append(args, t)
		}
	}
	if q == "" {
		return scanRuns(db, selectSQL+" WHERE 1=1"+conds+tail, args)
	}
	// Probe MATCH validity first: through the JOIN, invalid FTS syntax
	// (e.g. unquoted "signing:False") silently yields zero rows instead of erroring.
	base := selectSQL + " WHERE outputs_fts MATCH ? AND 1=1" + conds + tail
	if err := db.QueryRow(`SELECT 1 FROM outputs_fts WHERE outputs_fts MATCH ? LIMIT 1`, q).Scan(new(int)); err == nil || err == sql.ErrNoRows {
		return scanRuns(db, base, append([]any{q}, args...))
	}
	base = selectSQL + " WHERE f.text LIKE ? AND 1=1" + conds + tail
	return scanRuns(db, base, append([]any{"%" + q + "%"}, args...))
}

// parseSize accepts ">1mb", "<500kb", ">=2gb", ">1024" and returns the SQL
// comparison operator and the size in bytes.
func parseSize(s string) (op string, n int64, ok bool) {
	for _, o := range []string{">=", "<=", ">", "<"} {
		if strings.HasPrefix(s, o) {
			op, s = o, s[len(o):]
			break
		}
	}
	if op == "" {
		op = ">" // bare "size:1mb" means "bigger than"
	}
	s = strings.ToLower(strings.TrimSpace(s))
	unit := int64(1)
	switch {
	case strings.HasSuffix(s, "gb"):
		unit, s = 1<<30, s[:len(s)-2]
	case strings.HasSuffix(s, "mb"):
		unit, s = 1<<20, s[:len(s)-2]
	case strings.HasSuffix(s, "kb"):
		unit, s = 1<<10, s[:len(s)-2]
	case strings.HasSuffix(s, "b"):
		s = s[:len(s)-1]
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || v < 0 {
		return "", 0, false
	}
	return op, int64(v * float64(unit)), true
}

func scanRuns(db *sql.DB, q string, args []any) ([]Run, error) {
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.Ts, &r.Hostname, &r.Tool, &r.Cmd, &r.Cwd,
			&r.ExitCode, &r.Dur, &r.Size, &r.Snippet); err != nil {
			return out, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func fmtTs(ts float64) string { return time.Unix(int64(ts), 0).Format("2006-01-02 15:04") }
