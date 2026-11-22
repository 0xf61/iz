package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
	// busy_timeout comes first so the WAL switch already waits on a busy file.
	// _txlock=immediate: write transactions take the lock at BEGIN, so a
	// read-then-write transaction never fails with an instant SQLITE_BUSY
	// (SQLite skips the busy handler when a deferred reader must upgrade).
	db, err := sql.Open("sqlite", p+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_txlock=immediate")
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
	`CREATE INDEX IF NOT EXISTS memories_uid ON memories(uid)`,
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

// legacyUID is the deterministic uid of a pre-uid note, so copies of the same
// note on two machines (made by older syncs) still match each other.
// uidCol reads a uid even from rows an older client inserted without one.
const (
	legacyUID   = `hostname||'|'||ts||'|'||namespace||'|'||title`
	backfillUID = `UPDATE memories SET uid = ` + legacyUID + ` WHERE uid IS NULL`
	uidCol      = `coalesce(uid, ` + legacyUID + `)`
)

const schemaVersion = 5 // 5: memories_ns dropped (memories_ns_title covers it)

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
	if err := fixLegacyTombs(ctx, db); err != nil {
		return err
	}
	if err := dedupMemories(ctx, db); err != nil {
		return err
	}
	for _, s := range []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS memories_ns_title ON memories(namespace, title)`,
		`DROP INDEX IF EXISTS memories_ns`, // redundant with the unique index
	} {
		if _, err := db.ExecContext(ctx, s); err != nil {
			return err
		}
	}
	db.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version=%d`, schemaVersion)) //nolint — optional on remotes
	return nil
}

// fixLegacyTombs rewrites pre-v4 tombstone keys (NUL-delimited, which
// length() sees as 1 character) to the ':' form, keeping their deletes; keys
// tombKey rejects are dropped. Done in Go: SQL replace() treats a NUL pattern
// as empty.
func fixLegacyTombs(ctx context.Context, db dbtx) error {
	var old []string
	err := each(ctx, db, `SELECT key FROM tombstones WHERE length(key) <= 1 OR instr(key, char(0)) > 0`, func(r *sql.Rows) error {
		var k string
		err := r.Scan(&k)
		old = append(old, k)
		return err
	})
	if err != nil {
		return err
	}
	for _, k := range old {
		if nk, ok := tombKey(k); ok {
			if _, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO tombstones(key, ts) SELECT ?, ts FROM tombstones WHERE key = ?`, nk, k); err != nil {
				return err
			}
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM tombstones WHERE key = ?`, k); err != nil {
			return err
		}
	}
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
	for c := range chunks(ids, 500) {
		if err := purge(ctx, db, "memories", "memories_fts", c); err != nil {
			return err
		}
	}
	return nil
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

// tombKey normalizes a stored tombstone key: legacy NUL-delimited keys, which
// older clients (or a merged pre-v4 database) may still carry, map to the
// current ':' form so their deletes still apply; truncated keys are rejected.
// Since v4 these are rewritten at migration (fixLegacyTombs); sync still
// normalizes because older clients may keep writing them to a shared remote.
func tombKey(k string) (string, bool) {
	k = strings.ReplaceAll(k, "\x00", ":")
	return k, len(k) > 2
}

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

// pruneTombstones deletes tombstones older than maxAge. Undated ones (ts=0,
// written by pre-TTL clients) are stamped first, so they expire maxAge after
// they were first seen instead of never (or instantly).
func pruneTombstones(ctx context.Context, ex dbtx, maxAge time.Duration) (int64, error) {
	if _, err := ex.ExecContext(ctx, `UPDATE tombstones SET ts = ? WHERE ts = 0`, now()); err != nil {
		return 0, err
	}
	cutoff := float64(time.Now().Add(-maxAge).Unix())
	res, err := ex.ExecContext(ctx, `DELETE FROM tombstones WHERE ts < ?`, cutoff)
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

// isFTSOp reports FTS5 boolean operators: query syntax, not words.
func isFTSOp(t string) bool { return t == "AND" || t == "OR" || t == "NOT" || t == "NEAR" }

// cleanTerm strips FTS syntax around a word: quotes, parens and the prefix
// star (`("ESC*` → "ESC").
func cleanTerm(t string) string { return strings.Trim(t, `"'()*`) }

func hasUpper(s string) bool { return strings.IndexFunc(s, unicode.IsUpper) >= 0 }

// searchWords returns the plain words of a query — operators and filters
// dropped, FTS syntax stripped — i.e. what highlighting should look for.
func searchWords(terms []string) []string {
	var out []string
	for _, t := range terms {
		if isFTSOp(t) || isFilter(t) {
			continue
		}
		if w := cleanTerm(t); w != "" {
			out = append(out, w)
		}
	}
	return out
}

// ftsTerm quotes one term so punctuation ('-', '.', ':', '/') is literal for
// FTS5; a trailing '*' stays a prefix query outside the quotes.
func ftsTerm(t string) string {
	w := cleanTerm(t)
	if w == "" {
		return ""
	}
	q := `"` + strings.ReplaceAll(w, `"`, `""`) + `"`
	if strings.HasSuffix(strings.TrimRight(t, `"')`), "*") {
		q += "*"
	}
	return q
}

// ftsQuoteQuery quotes every term (see ftsTerm) and joins them with op: " "
// (AND) or " OR ". Boolean operators pass through unquoted in AND joins.
func ftsQuoteQuery(terms []string, op string) string {
	var parts []string
	for _, t := range terms {
		if isFTSOp(t) {
			if op == " " {
				parts = append(parts, t)
			}
			continue
		}
		if q := ftsTerm(t); q != "" {
			parts = append(parts, q)
		}
	}
	return strings.Join(parts, op)
}

// ftsValid probes MATCH syntax: through a JOIN, invalid FTS syntax (e.g.
// unquoted "signing:False") silently yields zero rows instead of erroring.
func ftsValid(db *sql.DB, table, q string) bool {
	err := db.QueryRow(`SELECT 1 FROM `+table+` WHERE `+table+` MATCH ? LIMIT 1`, q).Scan(new(int))
	return err == nil || err == sql.ErrNoRows
}

// matchFTS picks the free-text condition for terms: the raw query when it is
// valid FTS5 syntax, else every term quoted, else likeCond (n placeholders,
// each bound to "%query%"); fts reports a MATCH condition.
func matchFTS(db *sql.DB, table string, terms []string, likeCond string, n int) (cond string, args []any, fts bool) {
	q := strings.Join(terms, " ")
	if ftsValid(db, table, q) {
		return table + " MATCH ?", []any{q}, true
	}
	if fq := ftsQuoteQuery(terms, " "); ftsValid(db, table, fq) {
		return table + " MATCH ?", []any{fq}, true
	}
	args = make([]any, n)
	for i := range args {
		args[i] = "%" + likeEsc(q) + "%"
	}
	return likeCond, args, false
}

// orFallback returns the relaxed query (any word, quoted) used when a plain
// multi-word query (no operators) found nothing, or "" when it does not apply.
func orFallback(db *sql.DB, table string, terms []string) string {
	if len(terms) < 2 {
		return ""
	}
	for _, t := range terms {
		if isFTSOp(t) {
			return ""
		}
	}
	if q := ftsQuoteQuery(terms, " OR "); ftsValid(db, table, q) {
		return q
	}
	return ""
}

// orWords returns the words of a pure "a OR b OR c" query.
func orWords(terms []string) ([]string, bool) {
	if len(terms) < 3 || len(terms)%2 == 0 {
		return nil, false
	}
	var ws []string
	for i, t := range terms {
		if i%2 == 1 {
			if t != "OR" {
				return nil, false
			}
		} else if isFTSOp(t) {
			return nil, false
		} else {
			ws = append(ws, t)
		}
	}
	return ws, true
}

// smartCase is the run search case rule: all-lowercase words match
// case-insensitively via FTS; words with any uppercase letter must also occur
// verbatim (instr compares BINARY). A pure OR query applies the rule per
// alternative; mixed AND/OR (FTS precedence) gets no case conditions.
func smartCase(terms []string) (string, []any) {
	if ws, ok := orWords(terms); ok {
		return caseCond(ws, true)
	}
	var ws []string
	for i, t := range terms {
		switch {
		case t == "OR":
			return "", nil
		case isFTSOp(t), i > 0 && terms[i-1] == "NOT":
		default:
			ws = append(ws, t)
		}
	}
	return caseCond(ws, false)
}

// caseCond builds the smartCase SQL for words, joined with AND, or with OR
// where a lowercase alternative is tested through its own FTS match.
func caseCond(words []string, or bool) (string, []any) {
	var conds []string
	var args []any
	upper := false
	for _, w := range words {
		c := cleanTerm(w)
		switch {
		case c == "":
		case hasUpper(c):
			upper = true
			conds = append(conds, "instr(f.text, ?) > 0")
			args = append(args, c)
		case or:
			conds = append(conds, "f.rowid IN (SELECT rowid FROM outputs_fts WHERE outputs_fts MATCH ?)")
			args = append(args, ftsTerm(w))
		}
	}
	if !upper {
		return "", nil
	}
	if or {
		return " AND (" + strings.Join(conds, " OR ") + ")", args
	}
	return " AND " + strings.Join(conds, " AND "), args
}

// LIKE filters: values are escaped so '%' and '_' match literally.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func likeEsc(s string) string { return likeEscaper.Replace(s) }

// likePrefix filters col on a literal prefix.
func likePrefix(col, v string) (string, any) {
	return " AND " + col + ` LIKE ? ESCAPE '\'`, likeEsc(v) + "%"
}

// dirCond matches the cwd by whole path components: "dir:eng" is any
// directory named eng (or below it), "dir:a/b" that pair of components,
// "dir:/abs" or "dir:~/x" that subtree ("dir:/" is everything).
func dirCond(v string) (string, []any) {
	if home, err := os.UserHomeDir(); err == nil && (v == "~" || strings.HasPrefix(v, "~/")) {
		v = home + v[1:]
	}
	if strings.HasPrefix(v, "/") {
		v = strings.TrimRight(v, "/")
		if v == "" {
			return ` AND r.cwd LIKE '/%'`, nil
		}
		return ` AND (r.cwd = ? OR r.cwd LIKE ? ESCAPE '\')`, []any{v, likeEsc(v) + "/%"}
	}
	if v = strings.Trim(v, "/"); v == "" {
		return "", nil
	}
	e := "%/" + likeEsc(v)
	return ` AND (r.cwd LIKE ? ESCAPE '\' OR r.cwd LIKE ? ESCAPE '\')`, []any{e, e + "/%"}
}

// queryRuns parses "failed host:build01 tool:cargo": free terms go to FTS5 MATCH
// (output text is indexed), host:/dir:/tool:/size: become SQL filters.
func queryRuns(db *sql.DB, query string) ([]Run, error) { return searchRuns(db, query, 1000, false) }

// searchRuns is queryRuns with a limit; withText also loads the indexed text
// and keeps the first matching line in Snippet (recall). Note filters (ns:,
// tag:...) belong to the other side of recall and are ignored.
func searchRuns(db *sql.DB, query string, limit int, withText bool) ([]Run, error) {
	var conds string
	var args []any
	var terms []string
	for _, t := range strings.Fields(query) {
		switch {
		case strings.HasPrefix(t, "host:"):
			c, a := likePrefix("r.hostname", strings.TrimPrefix(t, "host:"))
			conds, args = conds+c, append(args, a)
		case strings.HasPrefix(t, "dir:"):
			c, a := dirCond(strings.TrimPrefix(t, "dir:"))
			conds, args = conds+c, append(args, a...)
		case strings.HasPrefix(t, "cmd:"), strings.HasPrefix(t, "tool:"):
			c, a := likePrefix("r.tool", t[strings.Index(t, ":")+1:])
			conds, args = conds+c, append(args, a)
		case strings.HasPrefix(t, "size:"):
			if op, n, ok := parseSize(strings.TrimPrefix(t, "size:")); ok {
				conds += fmt.Sprintf(" AND r.size %s ?", op)
				args = append(args, n)
			}
		case hasPrefixAny(t, memFilters):
		default:
			terms = append(terms, t)
		}
	}

	text := "''"
	joinFTS := ""
	if withText {
		text = "f.text"
		joinFTS = " JOIN outputs_fts f ON f.rowid = r.id"
	} else if len(terms) > 0 {
		joinFTS = " JOIN outputs_fts f ON f.rowid = r.id"
	}
	selectSQL := `SELECT r.id,r.ts,r.hostname,r.tool,r.cmd,r.cwd,r.exit_code,r.duration_ms,r.size,` + text + `
	              FROM runs r` + joinFTS
	order := fmt.Sprintf(" ORDER BY r.ts DESC LIMIT %d", limit)

	var runs []Run
	var err error
	if len(terms) == 0 {
		runs, err = scanRuns(db, selectSQL+" WHERE 1=1"+conds+order, args)
	} else {
		where, wargs, _ := matchFTS(db, "outputs_fts", terms, `f.text LIKE ? ESCAPE '\'`, 1)
		cc, cargs := smartCase(terms)
		runs, err = scanRuns(db, selectSQL+" WHERE "+where+conds+cc+order, concat(wargs, args, cargs))
		if err == nil && len(runs) == 0 {
			if orQ := orFallback(db, "outputs_fts", terms); orQ != "" {
				cc, cargs := caseCond(terms, true)
				order := fmt.Sprintf(" ORDER BY bm25(outputs_fts), r.ts DESC LIMIT %d", limit)
				runs, err = scanRuns(db, selectSQL+" WHERE outputs_fts MATCH ?"+conds+cc+order, concat([]any{orQ}, args, cargs))
			}
		}
	}
	if withText {
		ns := needles(terms)
		for i := range runs {
			runs[i].Snippet = matchLine(strings.TrimPrefix(runs[i].Snippet, ftsPrefix(runs[i])), ns)
		}
	}
	return runs, err
}

func concat(parts ...[]any) []any {
	var out []any
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// needles returns the case-folded search words worth matching (≥2 runes).
func needles(terms []string) [][]byte {
	var out [][]byte
	for _, w := range searchWords(terms) {
		if utf8.RuneCountInString(w) >= 2 {
			out = append(out, []byte(fold(w)))
		}
	}
	return out
}

// containsAny reports whether text (case-folded) contains any needle.
func containsAny(text []byte, ns [][]byte) bool {
	low, _ := foldMap(text)
	for _, n := range ns {
		if bytes.Contains(low, n) {
			return true
		}
	}
	return false
}

// matchLine returns the first line containing a needle (case-folded), or the
// first non-empty line when nothing matches.
func matchLine(text string, ns [][]byte) string {
	first := ""
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if first == "" {
			first = l
		}
		if containsAny([]byte(l), ns) {
			return l
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
func ph(n, k int) string  { return strings.TrimSuffix(strings.Repeat(inList(k)+",", n), ",") }
