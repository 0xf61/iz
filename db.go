package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo → static binaries)
)

// dbtx is what *sql.DB and *sql.Tx have in common.
type dbtx interface {
	ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

var bg = context.Background()

// dbPath: $IZ wins (wrappers also gate on it), default ~/.iz/iz.db.
func dbPath() string {
	if p := os.Getenv("IZ"); p != "" {
		if strings.HasPrefix(p, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				return filepath.Join(home, p[2:])
			}
		}
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
	db, err := sql.Open("sqlite", p+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if err := ensureSchema(bg, db, false); err != nil {
		db.Close()
		return nil, err
	}
	if p != ":memory:" && !strings.HasPrefix(p, "file:") {
		_ = os.Chmod(p, 0o600)
		_ = os.Chmod(p+"-wal", 0o600)
		_ = os.Chmod(p+"-shm", 0o600)
	}
	return db, nil
}

// Schema shared by local databases and the sync remote. One statement per
// entry: remote drivers execute a single statement per call.
//
// Notes carry a uid (stable identity across machines, survives edits and
// renames) and an mtime (last edit, for last-write-wins sync). Deleting a run
// or note leaves a tombstone so sync/merge propagate the delete instead of
// resurrecting the row from the other side.
var schema = []string{
	`CREATE TABLE IF NOT EXISTS runs(
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
)`,
	`CREATE INDEX IF NOT EXISTS runs_ts ON runs(ts)`,
	`CREATE TABLE IF NOT EXISTS tools(name TEXT PRIMARY KEY)`,
	`CREATE VIRTUAL TABLE IF NOT EXISTS outputs_fts USING fts5(text, tokenize='unicode61')`,
	`CREATE TABLE IF NOT EXISTS memories(
  id          INTEGER PRIMARY KEY,
  ts          REAL NOT NULL,   -- creation time, never changed
  hostname    TEXT NOT NULL,
  namespace   TEXT NOT NULL,
  title       TEXT NOT NULL,
  content     TEXT NOT NULL,
  author      TEXT NOT NULL,
  tags        TEXT NOT NULL DEFAULT '',
  uid         TEXT,
  mtime       REAL NOT NULL DEFAULT 0
)`,
	`CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
  title, content, namespace, tags, tokenize='unicode61'
)`,
	`CREATE TABLE IF NOT EXISTS tombstones(key TEXT PRIMARY KEY, ts REAL NOT NULL DEFAULT 0)`,
	// pre-uid / pre-v4 databases: these fail with "duplicate column" once applied
	`ALTER TABLE memories ADD COLUMN uid TEXT`,
	`ALTER TABLE memories ADD COLUMN mtime REAL NOT NULL DEFAULT 0`,
	`ALTER TABLE tombstones ADD COLUMN ts REAL NOT NULL DEFAULT 0`,
	// v4: reset legacy NUL-delimited or truncated 1-byte tombstones
	`DELETE FROM tombstones WHERE instr(key, char(0)) > 0 OR length(key) <= 1`,
	`CREATE INDEX IF NOT EXISTS memories_uid ON memories(uid)`,
	`CREATE INDEX IF NOT EXISTS memories_ns ON memories(namespace, title)`,
	backfillUID,
	seedDefaultTools,
}

// defaultTools is the list of penetration testing and security assessment tools
// automatically registered in the tools table on database creation.
var defaultTools = []string{
	// Network & Port Scanning
	"nmap", "masscan", "rustscan", "naabu",
	// Web Recon & Discovery
	"httpx", "httprobe", "subfinder", "assetfinder", "waybackurls", "gau",
	// Web Fuzzing, Scanning & Testing
	"ffuf", "feroxbuster", "gobuster", "dirsearch", "nuclei", "shortscan", "wpscan", "sqlmap",
	// Active Directory, Network Exploitation & Auth
	"nxc", "crackmapexec", "certipy", "bloodyad", "coercer", "kerbrute",
	"evil-winrm", "responder", "mitm6", "smbclient", "enum4linux-ng",
	// Tunneling, Pivoting & Infrastructure
	"chisel", "ligolo-ng", "bettercap",
	// Analysis, Cracking & Utilities
	"hashcat", "radare2", "tshark", "meg", "qsreplace", "gf", "unew",
}

const seedDefaultTools = `INSERT OR IGNORE INTO tools(name) VALUES
('nmap'),('masscan'),('rustscan'),('naabu'),
('httpx'),('httprobe'),('subfinder'),('assetfinder'),('waybackurls'),('gau'),
('ffuf'),('feroxbuster'),('gobuster'),('dirsearch'),('nuclei'),('shortscan'),('wpscan'),('sqlmap'),
('nxc'),('crackmapexec'),('certipy'),('bloodyad'),('coercer'),('kerbrute'),
('evil-winrm'),('responder'),('mitm6'),('smbclient'),('enum4linux-ng'),
('chisel'),('ligolo-ng'),('bettercap'),
('hashcat'),('radare2'),('tshark'),('meg'),('qsreplace'),('gf'),('unew')`

// backfillUID gives legacy notes a deterministic uid, so copies of the same
// note on two machines (made by older syncs) still match each other.
const backfillUID = `UPDATE memories SET uid = hostname||'|'||ts||'|'||namespace||'|'||title WHERE uid IS NULL`

const schemaVersion = 4

// ensureSchema creates/migrates the schema. Local databases skip the work
// once PRAGMA user_version says they are current; force always runs it
// (the remote may be shared with older clients).
func ensureSchema(ctx context.Context, db dbtx, force bool) error {
	var v int
	if !force && db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v) == nil && v >= schemaVersion {
		return nil
	}
	for _, s := range schema {
		if _, err := db.ExecContext(ctx, s); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}
	if err := dedupMemories(ctx, db); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS memories_ns_title ON memories(namespace, title)`); err != nil {
		return err
	}
	db.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version=%d`, schemaVersion)) //nolint — optional on remotes
	return nil
}

// dedupMemories removes older duplicate (namespace, title) notes, keeping the
// newest row by max(mtime, ts), id. Their FTS rows are cleaned up too.
func dedupMemories(ctx context.Context, db dbtx) error {
	rows, err := db.QueryContext(ctx, `
		SELECT id FROM memories m
		WHERE EXISTS (
			SELECT 1 FROM memories m2
			WHERE m2.namespace = m.namespace AND m2.title = m.title
			  AND (max(m2.mtime, m2.ts) > max(m.mtime, m.ts)
			       OR (max(m2.mtime, m2.ts) = max(m.mtime, m.ts) AND m2.id > m.id))
		)`)
	if err != nil {
		return err
	}
	var ids []any
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	return purge(ctx, db, "memories", "memories_fts", ids)
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
	Snippet  string // matching output line (recall only)
}

func ni(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: true} }

// runKey / memTomb identify rows across machines (tombstones, sync dedup).
// Printable colon-separated keys avoid NUL-byte truncation in SQLite/Turso UIs.
func runKey(host string, ts float64, tool, cmd string) string {
	return "r:" + host + ":" + strconv.FormatFloat(ts, 'f', -1, 64) + ":" + tool + ":" + cmd
}
func memTomb(uid string) string { return "m:" + uid }

// ftsPrefix is prepended to the indexed output so one MATCH searches
// hostname, tool and command line as well.
func ftsPrefix(r Run) string { return r.Hostname + " " + r.Tool + " " + r.Cmd + " " }

// insertRun writes the run and its FTS row (rowid = run id) atomically.
func insertRun(db *sql.DB, r Run, raw, text []byte) (int64, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint
	id, err := insertRunTx(tx, r, raw, text)
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

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
	// string() is critical: []byte binds as BLOB, and SQLite LIKE never matches BLOBs
	// (FTS MATCH still would, silently hiding the bug).
	_, err = tx.Exec(`INSERT INTO outputs_fts(rowid,text) VALUES(?,?)`, id, ftsPrefix(r)+string(text))
	return id, err
}

// deleteRuns removes runs and their FTS rows in one transaction, leaving
// tombstones; returns how many were deleted.
func deleteRuns(db *sql.DB, ids []int64) int {
	tx, err := db.Begin()
	if err != nil {
		return 0
	}
	defer tx.Rollback() //nolint
	n := 0
	for _, id := range ids {
		var r Run
		if tx.QueryRow(`SELECT hostname,ts,tool,cmd FROM runs WHERE id=?`, id).Scan(&r.Hostname, &r.Ts, &r.Tool, &r.Cmd) != nil {
			continue
		}
		if tombstone(tx, runKey(r.Hostname, r.Ts, r.Tool, r.Cmd)) != nil || purge(bg, tx, "runs", "outputs_fts", []any{id}) != nil {
			return 0
		}
		n++
	}
	if tx.Commit() != nil {
		return 0
	}
	return n
}

func tombstone(ex dbtx, key string) error {
	_, err := ex.ExecContext(bg, `INSERT OR REPLACE INTO tombstones(key, ts) VALUES(?, ?)`, key, now())
	return err
}

func pruneTombstones(ctx context.Context, ex dbtx, maxAge time.Duration) (int64, error) {
	cutoff := float64(time.Now().Add(-maxAge).Unix())
	res, err := ex.ExecContext(ctx, `DELETE FROM tombstones WHERE ts > 0 AND ts < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// purge deletes rows by id from table and its FTS index (no tombstone).
func purge(ctx context.Context, ex dbtx, table, fts string, ids []any) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := ex.ExecContext(ctx, `DELETE FROM `+fts+` WHERE rowid IN `+inList(len(ids)), ids...); err != nil {
		return err
	}
	_, err := ex.ExecContext(ctx, `DELETE FROM `+table+` WHERE id IN `+inList(len(ids)), ids...)
	return err
}

// getMeta returns the gzipped output plus all metadata, for show/edit headers.
func getMeta(db *sql.DB, id int64) (raw []byte, r Run, err error) {
	err = db.QueryRow(`SELECT id,ts,hostname,tool,cmd,cwd,exit_code,duration_ms,size,raw
	                   FROM runs WHERE id=?`, id).
		Scan(&r.ID, &r.Ts, &r.Hostname, &r.Tool, &r.Cmd, &r.Cwd, &r.ExitCode, &r.Dur, &r.Size, &raw)
	return raw, r, err
}

// Filter prefixes: runs understand runFilters, notes memFilters; host: is
// shared. Anything else is a free search term.
var (
	runFilters = []string{"dir:", "cmd:", "tool:", "size:"}
	memFilters = []string{"ns:", "namespace:", "author:", "tag:", "tags:"}
)

func hasPrefixAny(t string, ps []string) bool {
	for _, p := range ps {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

func isFilter(t string) bool {
	return strings.HasPrefix(t, "host:") || hasPrefixAny(t, runFilters) || hasPrefixAny(t, memFilters)
}

// freeTerms drops filter tokens, leaving what should be highlighted.
func freeTerms(fields []string) []string {
	var out []string
	for _, t := range fields {
		if !isFilter(t) {
			out = append(out, t)
		}
	}
	return out
}

// ftsQuoteQuery wraps each search term in double quotes so punctuation like
// '-', '.', ':', '/' is treated as literal tokens by FTS5 instead of syntax
// operators. op should be " " (AND) or " OR ".
func ftsQuoteQuery(terms []string, op string) string {
	if len(terms) == 0 {
		return ""
	}
	quoted := make([]string, len(terms))
	for i, t := range terms {
		quoted[i] = `"` + strings.ReplaceAll(t, `"`, `""`) + `"`
	}
	return strings.Join(quoted, op)
}

// ftsValid probes MATCH syntax: through a JOIN, invalid FTS syntax (e.g.
// unquoted "signing:False") silently yields zero rows instead of erroring.
func ftsValid(db *sql.DB, table, q string) bool {
	err := db.QueryRow(`SELECT 1 FROM `+table+` WHERE `+table+` MATCH ? LIMIT 1`, q).Scan(new(int))
	return err == nil || err == sql.ErrNoRows
}

// queryRuns parses "failed host:build01 tool:cargo": free terms go to FTS5 MATCH
// (output text is indexed), host:/dir:/tool:/size: become SQL filters.
func queryRuns(db *sql.DB, query string) ([]Run, error) { return searchRuns(db, query, 1000, false) }

// searchRuns is queryRuns with a limit; withText also loads the indexed text
// and keeps the first matching line in Snippet (recall).
func searchRuns(db *sql.DB, query string, limit int, withText bool) ([]Run, error) {
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

	text := "''"
	joinFTS := ""
	if withText {
		text = "f.text"
		joinFTS = " JOIN outputs_fts f ON f.rowid = r.id"
	} else if q != "" {
		joinFTS = " JOIN outputs_fts f ON f.rowid = r.id"
	}
	selectSQL := `SELECT r.id,r.ts,r.hostname,r.tool,r.cmd,r.cwd,r.exit_code,r.duration_ms,r.size,` + text + `
	              FROM runs r` + joinFTS
	tail := fmt.Sprintf(" ORDER BY r.ts DESC LIMIT %d", limit)

	// Case rule: all-lowercase terms match case-insensitively via FTS; terms
	// with any uppercase must occur verbatim (instr compares BINARY).
	// Skip caseConds when the query uses an explicit OR operator.
	var caseConds string
	var caseArgs []any
	hasOR := false
	for _, t := range terms {
		if t == "OR" {
			hasOR = true
			break
		}
	}
	if !hasOR {
		for idx, t := range terms {
			if idx > 0 && terms[idx-1] == "NOT" {
				continue
			}
			clean := strings.Trim(t, `"'`)
			if clean == "" || clean == "AND" || clean == "OR" || clean == "NOT" || clean == "NEAR" {
				continue
			}
			if strings.ToLower(clean) != clean {
				caseConds += " AND instr(f.text, ?) > 0"
				caseArgs = append(caseArgs, clean)
			}
		}
	}

	var runs []Run
	var err error
	switch {
	case q == "":
		runs, err = scanRuns(db, selectSQL+" WHERE 1=1"+conds+tail, args)
	default:
		ftsQ := ftsQuoteQuery(terms, " ")
		if ftsValid(db, "outputs_fts", q) {
			runs, err = scanRuns(db, selectSQL+" WHERE outputs_fts MATCH ?"+conds+caseConds+tail, append(append([]any{q}, args...), caseArgs...))
		} else if ftsValid(db, "outputs_fts", ftsQ) {
			runs, err = scanRuns(db, selectSQL+" WHERE outputs_fts MATCH ?"+conds+caseConds+tail, append(append([]any{ftsQ}, args...), caseArgs...))
		} else {
			runs, err = scanRuns(db, selectSQL+" WHERE f.text LIKE ?"+conds+caseConds+tail, append(append([]any{"%" + q + "%"}, args...), caseArgs...))
		}
		// Multi-term fallback: if strict AND returned 0 rows, try OR ranked by bm25
		if err == nil && len(runs) == 0 && len(terms) > 1 {
			orQ := ftsQuoteQuery(terms, " OR ")
			if ftsValid(db, "outputs_fts", orQ) {
				orTail := fmt.Sprintf(" ORDER BY bm25(outputs_fts), r.ts DESC LIMIT %d", limit)
				runs, err = scanRuns(db, selectSQL+" WHERE outputs_fts MATCH ?"+conds+orTail, append([]any{orQ}, args...))
			}
		}
	}
	if withText {
		for i := range runs {
			runs[i].Snippet = matchLine(strings.TrimPrefix(runs[i].Snippet, ftsPrefix(runs[i])), terms)
		}
	}
	return runs, err
}

// matchLine returns the first line containing a term (Unicode case-insensitive),
// or the first non-empty line when nothing matches.
func matchLine(text string, terms []string) string {
	first := ""
	lowTerms := make([]string, 0, len(terms))
	for _, t := range terms {
		if len([]rune(t)) >= 2 {
			lowTerms = append(lowTerms, strings.ToLower(t))
		}
	}
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if first == "" {
			first = l
		}
		ll := strings.ToLower(l)
		for _, lt := range lowTerms {
			if strings.Contains(ll, lt) {
				return l
			}
		}
	}
	return first
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

// fmtTsShort: "15:04" today, "01-02 15:04" this year, "2006-01-02" before.
func fmtTsShort(ts float64) string {
	t, now := time.Unix(int64(ts), 0), time.Now()
	switch {
	case t.Year() != now.Year():
		return t.Format("2006-01-02")
	case t.YearDay() == now.YearDay():
		return t.Format("15:04")
	}
	return t.Format("01-02 15:04")
}

// inList renders "(?,?,?)"; ph renders n value tuples of k placeholders.
func inList(n int) string { return "(" + strings.TrimSuffix(strings.Repeat("?,", n), ",") + ")" }
func ph(n, k int) string     { return strings.TrimSuffix(strings.Repeat(inList(k)+",", n), ",") }
