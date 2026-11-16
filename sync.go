package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	_ "github.com/tursodatabase/libsql-client-go/libsql"
)

// Replication between two iz databases. One primitive, replicate(src, dst),
// copies to dst what it lacks; `iz sync` runs it both ways against a
// LibSQL/Turso remote, `iz m` runs it once from another database file.
//
//   - runs are immutable, identified by (hostname, ts, tool, cmd)
//   - notes are identified by uid; the newer mtime wins (edits, renames)
//   - tombstones travel first, so deletes propagate instead of being undone
//
// Only keys are read up front; output blobs are fetched for missing rows
// only, and rows are written in multi-row chunks (few round trips per chunk).

// getSyncConfig reads connection parameters from environment variables,
// falling back to Atuin KV store if unset (e.g. across machines with atuin sync).
func getSyncConfig() (remoteURL, authToken string) {
	remoteURL = firstEnv("IZ_SYNC_URL", "IZ_URL", "TURSO_DATABASE_URL")
	authToken = firstEnv("IZ_AUTH_TOKEN", "IZ_TOKEN", "TURSO_AUTH_TOKEN")

	if remoteURL == "" {
		remoteURL = atuinKVGet("IZ_SYNC_URL")
	}
	if authToken == "" {
		authToken = atuinKVGet("IZ_AUTH_TOKEN")
	}

	return strings.TrimSpace(remoteURL), strings.TrimSpace(authToken)
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// atuinKVGet retrieves a key from atuin's key-value store if atuin is installed.
func atuinKVGet(key string) string {
	out, err := exec.Command("atuin", "kv", "get", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func buildLibsqlURL(rawURL, token string) string {
	if rawURL == "" {
		return ""
	}
	if token == "" || strings.Contains(rawURL, "authToken=") {
		return rawURL
	}
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return rawURL + sep + "authToken=" + url.QueryEscape(token)
}

// syncCmd executes a two-way sync between the local database and the remote
// LibSQL/Turso database: IZ_SYNC_URL (or TURSO_DATABASE_URL), IZ_AUTH_TOKEN,
// optional IZ_SYNC_TIMEOUT (Go duration, default 5m).
func syncCmd(args []string) int {
	remoteURL, token := getSyncConfig()
	if remoteURL == "" {
		fmt.Fprintln(os.Stderr, "iz sync: no remote database configured.")
		fmt.Fprintln(os.Stderr, "Set IZ_SYNC_URL (and optional IZ_AUTH_TOKEN) in your environment.")
		fmt.Fprintln(os.Stderr, "Example: export IZ_SYNC_URL='libsql://your-db.turso.io' IZ_AUTH_TOKEN='ey...'")
		return 1
	}
	timeout := 5 * time.Minute
	if d, err := time.ParseDuration(os.Getenv("IZ_SYNC_TIMEOUT")); err == nil && d > 0 {
		timeout = d
	}

	localDB, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz sync: cannot open local database:", err)
		return 2
	}
	defer localDB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Fprintf(os.Stderr, "[iz] connecting to remote (%s)...\n", sanitizeURL(remoteURL))
	remoteDB, err := sql.Open("libsql", buildLibsqlURL(remoteURL, token))
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz sync: failed to connect to remote:", err)
		return 1
	}
	defer remoteDB.Close()

	pctx, pcancel := context.WithTimeout(ctx, 15*time.Second)
	err = remoteDB.PingContext(pctx)
	pcancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz sync: remote unreachable or authentication failed:", err)
		return 1
	}
	if err := ensureSchema(ctx, remoteDB, true); err != nil {
		fmt.Fprintln(os.Stderr, "iz sync: failed to verify remote schema:", err)
		return 1
	}

	up, down, err := syncPair(ctx, localDB, remoteDB)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz sync:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[iz] sync complete · notes: ↑%d ↓%d · runs: ↑%d ↓%d · deletes: ↑%d ↓%d\n",
		up.notes, down.notes, up.runs, down.runs, up.dels, down.dels)
	return 0
}

// syncPair replicates local→remote, then remote→local.
func syncPair(ctx context.Context, local, remote *sql.DB) (up, down repStats, err error) {
	if up, err = replicate(ctx, local, remote); err != nil {
		return up, down, fmt.Errorf("push: %w", err)
	}
	if down, err = replicate(ctx, remote, local); err != nil {
		return up, down, fmt.Errorf("pull: %w", err)
	}
	return up, down, nil
}

type repStats struct{ runs, skipped, notes, dels int }

// replicate copies tombstones, runs and notes from src into dst.
func replicate(ctx context.Context, src, dst *sql.DB) (st repStats, err error) {
	tomb, dels, err := copyTombstones(ctx, src, dst)
	if err != nil {
		return st, fmt.Errorf("tombstones: %w", err)
	}
	st.dels = dels
	if st.runs, st.skipped, err = copyRuns(ctx, src, dst, tomb); err != nil {
		return st, fmt.Errorf("runs: %w", err)
	}
	if st.notes, err = copyMemories(ctx, src, dst, tomb); err != nil {
		return st, fmt.Errorf("notes: %w", err)
	}
	return st, nil
}

// copyTombstones adds src's tombstones to dst and returns the union.
func copyTombstones(ctx context.Context, src, dst *sql.DB) (map[string]bool, int, error) {
	have := map[string]bool{}
	var fresh []any
	for i, db := range []*sql.DB{dst, src} {
		err := each(ctx, db, `SELECT key FROM tombstones`, func(r *sql.Rows) error {
			var k string
			if err := r.Scan(&k); err != nil {
				return err
			}
			if i == 1 && !have[k] {
				fresh = append(fresh, k)
			}
			have[k] = true
			return nil
		})
		if err != nil {
			return nil, 0, err
		}
	}
	for c := range chunks(fresh, 500) {
		if _, err := dst.ExecContext(ctx, `INSERT OR IGNORE INTO tombstones(key) VALUES`+ph(len(c), 1), c...); err != nil {
			return nil, 0, err
		}
	}
	return have, len(fresh), nil
}

const runChunk = 32 // rows per round trip; outputs can be large

func copyRuns(ctx context.Context, src, dst *sql.DB, tomb map[string]bool) (added, skipped int, err error) {
	const keysSQL = `SELECT id,hostname,ts,tool,cmd FROM runs`
	have := map[string]bool{}
	var dead []any
	err = each(ctx, dst, keysSQL, func(r *sql.Rows) error {
		var id int64
		var x Run
		if err := r.Scan(&id, &x.Hostname, &x.Ts, &x.Tool, &x.Cmd); err != nil {
			return err
		}
		k := runKey(x.Hostname, x.Ts, x.Tool, x.Cmd)
		if tomb[k] {
			dead = append(dead, id)
		}
		have[k] = true
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	if err := purgeChunked(ctx, dst, "runs", "outputs_fts", dead); err != nil {
		return 0, 0, err
	}

	var want []any
	err = each(ctx, src, keysSQL, func(r *sql.Rows) error {
		var id int64
		var x Run
		if err := r.Scan(&id, &x.Hostname, &x.Ts, &x.Tool, &x.Cmd); err != nil {
			return err
		}
		if k := runKey(x.Hostname, x.Ts, x.Tool, x.Cmd); have[k] || tomb[k] {
			skipped++
		} else {
			have[k] = true
			want = append(want, id)
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}

	for c := range chunks(want, runChunk) {
		var rows, fts [][]any
		err := each(ctx, src, `SELECT r.ts,r.hostname,r.tool,r.cmd,r.cwd,r.exit_code,r.duration_ms,r.size,r.raw,f.text
		     FROM runs r LEFT JOIN outputs_fts f ON f.rowid = r.id WHERE r.id IN `+inList(len(c)), func(q *sql.Rows) error {
			var x Run
			var raw []byte
			var text sql.NullString
			if err := q.Scan(&x.Ts, &x.Hostname, &x.Tool, &x.Cmd, &x.Cwd, &x.ExitCode, &x.Dur, &x.Size, &raw, &text); err != nil {
				return err
			}
			if !text.Valid { // index row missing on src: rebuild it
				text.String = ftsPrefix(x) + string(stripANSI(ungz(raw)))
			}
			rows = append(rows, []any{x.Ts, x.Hostname, x.Tool, x.Cmd, x.Cwd, x.ExitCode, x.Dur, x.Size, raw})
			fts = append(fts, []any{text.String})
			return nil
		}, c...)
		if err != nil {
			return added, skipped, err
		}
		if err := insertBatch(ctx, dst, "runs", "ts,hostname,tool,cmd,cwd,exit_code,duration_ms,size,raw",
			"outputs_fts", "text", rows, fts); err != nil {
			return added, skipped, err
		}
		added += len(rows)
	}
	return added, skipped, nil
}

func copyMemories(ctx context.Context, src, dst *sql.DB, tomb map[string]bool) (n int, err error) {
	for _, db := range []*sql.DB{src, dst} { // rows written by older clients
		if _, err := db.ExecContext(ctx, backfillUID); err != nil {
			return 0, err
		}
	}
	if err := fixMemFTS(ctx, dst); err != nil {
		return 0, err
	}

	type ver struct {
		id    int64
		mtime float64
	}
	have := map[string]ver{}
	var dead []any
	err = each(ctx, dst, `SELECT id,uid,max(mtime,ts) FROM memories`, func(r *sql.Rows) error {
		var uid string
		var v ver
		if err := r.Scan(&v.id, &uid, &v.mtime); err != nil {
			return err
		}
		if tomb[memTomb(uid)] {
			dead = append(dead, v.id)
		}
		have[uid] = v
		return nil
	})
	if err != nil {
		return 0, err
	}
	if err := purgeChunked(ctx, dst, "memories", "memories_fts", dead); err != nil {
		return 0, err
	}

	var rows, fts [][]any
	var upd []Memory
	err = each(ctx, src, `SELECT uid,ts,max(mtime,ts),hostname,namespace,title,content,author,tags FROM memories`, func(r *sql.Rows) error {
		var m Memory
		if err := r.Scan(&m.UID, &m.Ts, &m.Mtime, &m.Hostname, &m.Namespace, &m.Title, &m.Content, &m.Author, &m.Tags); err != nil {
			return err
		}
		if tomb[memTomb(m.UID)] {
			return nil
		}
		v, ok := have[m.UID]
		switch {
		case !ok:
			rows = append(rows, []any{m.UID, m.Ts, m.Mtime, m.Hostname, m.Namespace, m.Title, m.Content, m.Author, m.Tags})
			fts = append(fts, []any{m.Title, m.Content, m.Namespace, m.Tags})
		case m.Mtime > v.mtime: // last write wins
			m.ID = v.id
			upd = append(upd, m)
		default:
			return nil
		}
		have[m.UID] = ver{v.id, m.Mtime}
		return nil
	})
	if err != nil {
		return 0, err
	}

	for i := 0; i < len(rows); i += 100 {
		j := min(i+100, len(rows))
		if err := insertBatch(ctx, dst, "memories", "uid,ts,mtime,hostname,namespace,title,content,author,tags",
			"memories_fts", "title,content,namespace,tags", rows[i:j], fts[i:j]); err != nil {
			return n, err
		}
		n += j - i
	}
	if len(upd) > 0 {
		tx, err := dst.BeginTx(ctx, nil)
		if err != nil {
			return n, err
		}
		defer tx.Rollback() //nolint
		for _, m := range upd {
			if err := updateMemoryTx(tx, m); err != nil {
				return n, err
			}
		}
		if err := tx.Commit(); err != nil {
			return n, err
		}
		n += len(upd)
	}
	return n, nil
}

// fixMemFTS rebuilds memories_fts when it no longer mirrors memories (older
// syncs inserted remote index rows without an explicit rowid).
func fixMemFTS(ctx context.Context, db *sql.DB) error {
	var bad int
	err := db.QueryRowContext(ctx, `SELECT
	  (SELECT count(*) FROM memories m LEFT JOIN memories_fts f ON f.rowid = m.id
	    WHERE f.rowid IS NULL OR f.title IS NOT m.title OR f.content IS NOT m.content)
	  + abs((SELECT count(*) FROM memories) - (SELECT count(*) FROM memories_fts))`).Scan(&bad)
	if err != nil || bad == 0 {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint
	if _, err := tx.ExecContext(ctx, `DELETE FROM memories_fts`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO memories_fts(rowid,title,content,namespace,tags)
	                                  SELECT id,title,content,namespace,tags FROM memories`); err != nil {
		return err
	}
	return tx.Commit()
}

// insertBatch writes rows into table and their FTS entries with two multi-row
// statements in one transaction. Ids are assigned explicitly past both the
// table and the index, so the FTS rowid always equals the row id.
func insertBatch(ctx context.Context, db *sql.DB, table, cols, fts, ftsCols string, rows, ftsRows [][]any) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint
	var next int64
	if err := tx.QueryRowContext(ctx, `SELECT max(coalesce((SELECT max(id) FROM `+table+`),0),
	    coalesce((SELECT rowid FROM `+fts+` ORDER BY rowid DESC LIMIT 1),0)) + 1`).Scan(&next); err != nil {
		return err
	}
	var a, b []any
	for i := range rows {
		id := next + int64(i)
		a = append(append(a, id), rows[i]...)
		b = append(append(b, id), ftsRows[i]...)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO `+table+`(id,`+cols+`) VALUES`+ph(len(rows), len(rows[0])+1), a...); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO `+fts+`(rowid,`+ftsCols+`) VALUES`+ph(len(rows), len(ftsRows[0])+1), b...); err != nil {
		return err
	}
	return tx.Commit()
}

func purgeChunked(ctx context.Context, db *sql.DB, table, fts string, ids []any) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint
	for c := range chunks(ids, 500) {
		if err := purge(ctx, tx, table, fts, c); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// each runs q and calls fn for every row.
func each(ctx context.Context, db dbtx, q string, fn func(*sql.Rows) error, args ...any) error {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// chunks yields consecutive slices of at most n elements.
func chunks(s []any, n int) func(func([]any) bool) {
	return func(yield func([]any) bool) {
		for i := 0; i < len(s); i += n {
			if !yield(s[i:min(i+n, len(s))]) {
				return
			}
		}
	}
}

func sanitizeURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	// Hide user info and sensitive query params
	parsed.User = nil
	q := parsed.Query()
	if q.Has("authToken") {
		q.Set("authToken", "***")
		parsed.RawQuery = q.Encode()
	}
	return parsed.String()
}
