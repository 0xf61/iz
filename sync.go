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
	resetTombs := false
	for _, a := range args {
		switch a {
		case "-h", "--help":
			fmt.Println(`iz sync — two-way sync with Turso / LibSQL

Usage:
  iz sync                     Sync runs, notes and deletes with remote
  iz sync --reset-tombstones  Clear all tombstones on local and remote before syncing

Environment:
  IZ_SYNC_URL     Remote LibSQL URL (e.g. libsql://your-db.turso.io)
  IZ_AUTH_TOKEN   Auth token (falls back to atuin kv if unset)
  IZ_SYNC_TIMEOUT Sync timeout duration (default 5m)`)
			return 0
		case "--reset-tombstones", "--prune":
			resetTombs = true
		}
	}

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
	if err := ensureSchema(ctx, remoteDB, false); err != nil {
		fmt.Fprintln(os.Stderr, "iz sync: failed to verify remote schema:", err)
		return 1
	}

	if resetTombs {
		if _, err := localDB.ExecContext(ctx, `DELETE FROM tombstones`); err != nil {
			fmt.Fprintln(os.Stderr, "iz sync: failed to reset local tombstones:", err)
			return 1
		}
		if _, err := remoteDB.ExecContext(ctx, `DELETE FROM tombstones`); err != nil {
			fmt.Fprintln(os.Stderr, "iz sync: failed to reset remote tombstones:", err)
			return 1
		}
		fmt.Fprintln(os.Stderr, "[iz] tombstones cleared on local and remote")
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

// syncPair performs a single-pass bidirectional sync between local and remote.
func syncPair(ctx context.Context, local, remote *sql.DB) (up, down repStats, err error) {
	tomb, upDels, downDels, err := syncTombstones(ctx, local, remote)
	if err != nil {
		return up, down, fmt.Errorf("tombstones: %w", err)
	}
	up.dels, down.dels = upDels, downDels

	if up.runs, down.runs, err = syncRunsBidirectional(ctx, local, remote, tomb); err != nil {
		return up, down, fmt.Errorf("runs: %w", err)
	}
	if up.notes, down.notes, err = syncMemoriesBidirectional(ctx, local, remote, tomb); err != nil {
		return up, down, fmt.Errorf("notes: %w", err)
	}
	return up, down, nil
}

type repStats struct{ runs, skipped, notes, dels int }

// replicate copies tombstones, runs and notes one-way from src into dst (used by iz merge).
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

const tombstoneTTL = 30 * 24 * time.Hour

// syncTombstones reads tombstones once from each side, propagates differences
// both ways, and prunes tombstones older than tombstoneTTL.
func syncTombstones(ctx context.Context, local, remote *sql.DB) (map[string]bool, int, int, error) {
	pruneTombstones(ctx, local, tombstoneTTL)  //nolint
	pruneTombstones(ctx, remote, tombstoneTTL) //nolint

	localTombs := map[string]float64{}
	if err := each(ctx, local, `SELECT key, ts FROM tombstones`, func(r *sql.Rows) error {
		var k string
		var ts float64
		if err := r.Scan(&k, &ts); err != nil {
			return err
		}
		localTombs[k] = ts
		return nil
	}); err != nil {
		return nil, 0, 0, err
	}

	remoteTombs := map[string]float64{}
	if err := each(ctx, remote, `SELECT key, ts FROM tombstones`, func(r *sql.Rows) error {
		var k string
		var ts float64
		if err := r.Scan(&k, &ts); err != nil {
			return err
		}
		remoteTombs[k] = ts
		return nil
	}); err != nil {
		return nil, 0, 0, err
	}

	var push, pull []any
	union := make(map[string]bool, len(localTombs)+len(remoteTombs))
	for k, ts := range localTombs {
		union[k] = true
		if _, ok := remoteTombs[k]; !ok {
			if ts == 0 {
				ts = now()
			}
			push = append(push, k, ts)
		}
	}
	for k, ts := range remoteTombs {
		union[k] = true
		if _, ok := localTombs[k]; !ok {
			if ts == 0 {
				ts = now()
			}
			pull = append(pull, k, ts)
		}
	}
	if err := insertTombstonesBatch(ctx, remote, push); err != nil {
		return nil, 0, 0, err
	}
	if err := insertTombstonesBatch(ctx, local, pull); err != nil {
		return nil, 0, 0, err
	}
	return union, len(push) / 2, len(pull) / 2, nil
}

func insertTombstonesBatch(ctx context.Context, db *sql.DB, kts []any) error {
	for c := range chunks(kts, 500) {
		if _, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO tombstones(key, ts) VALUES`+ph(len(c)/2, 2), c...); err != nil {
			return err
		}
	}
	return nil
}

// copyTombstones adds src's tombstones to dst and returns the union.
func copyTombstones(ctx context.Context, src, dst *sql.DB) (map[string]bool, int, error) {
	have := map[string]bool{}
	var fresh []any
	for i, db := range []*sql.DB{dst, src} {
		err := each(ctx, db, `SELECT key, ts FROM tombstones`, func(r *sql.Rows) error {
			var k string
			var ts float64
			if err := r.Scan(&k, &ts); err != nil {
				return err
			}
			if i == 1 && !have[k] {
				if ts == 0 {
					ts = now()
				}
				fresh = append(fresh, k, ts)
			}
			have[k] = true
			return nil
		})
		if err != nil {
			return nil, 0, err
		}
	}
	if err := insertTombstonesBatch(ctx, dst, fresh); err != nil {
		return nil, 0, err
	}
	return have, len(fresh) / 2, nil
}

const runChunk = 32 // rows per round trip; outputs can be large

// syncRunsBidirectional reads run keys once from local and remote, purges
// tombstoned rows on both sides, and transfers only missing runs each way.
func syncRunsBidirectional(ctx context.Context, local, remote *sql.DB, tomb map[string]bool) (pushed, pulled int, err error) {
	const keysSQL = `SELECT id,hostname,ts,tool,cmd FROM runs`
	readKeys := func(db *sql.DB) (map[string]int64, []any, error) {
		have := map[string]int64{}
		var dead []any
		err := each(ctx, db, keysSQL, func(r *sql.Rows) error {
			var id int64
			var x Run
			if err := r.Scan(&id, &x.Hostname, &x.Ts, &x.Tool, &x.Cmd); err != nil {
				return err
			}
			k := runKey(x.Hostname, x.Ts, x.Tool, x.Cmd)
			if tomb[k] {
				dead = append(dead, id)
				return nil
			}
			have[k] = id
			return nil
		})
		return have, dead, err
	}

	localHave, localDead, err := readKeys(local)
	if err != nil {
		return 0, 0, err
	}
	remoteHave, remoteDead, err := readKeys(remote)
	if err != nil {
		return 0, 0, err
	}
	if err := purgeChunked(ctx, local, "runs", "outputs_fts", localDead); err != nil {
		return 0, 0, err
	}
	if err := purgeChunked(ctx, remote, "runs", "outputs_fts", remoteDead); err != nil {
		return 0, 0, err
	}

	var wantPush, wantPull []any
	for k, id := range localHave {
		if _, ok := remoteHave[k]; !ok {
			wantPush = append(wantPush, id)
		}
	}
	for k, id := range remoteHave {
		if _, ok := localHave[k]; !ok {
			wantPull = append(wantPull, id)
		}
	}

	if pushed, err = transferRuns(ctx, local, remote, wantPush); err != nil {
		return pushed, pulled, err
	}
	if pulled, err = transferRuns(ctx, remote, local, wantPull); err != nil {
		return pushed, pulled, err
	}
	return pushed, pulled, nil
}

func transferRuns(ctx context.Context, src, dst *sql.DB, ids []any) (int, error) {
	added := 0
	for c := range chunks(ids, runChunk) {
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
				text.String = ftsPrefix(x) + string(truncFTS(stripANSI(ungz(raw))))
			}
			rows = append(rows, []any{x.Ts, x.Hostname, x.Tool, x.Cmd, x.Cwd, x.ExitCode, x.Dur, x.Size, raw})
			fts = append(fts, []any{text.String})
			return nil
		}, c...)
		if err != nil {
			return added, err
		}
		if err := insertBatch(ctx, dst, "runs", "ts,hostname,tool,cmd,cwd,exit_code,duration_ms,size,raw",
			"outputs_fts", "text", rows, fts); err != nil {
			return added, err
		}
		added += len(rows)
	}
	return added, nil
}

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
	added, err = transferRuns(ctx, src, dst, want)
	return added, skipped, err
}

type memMeta struct {
	id    int64
	uid   string
	mtime float64
	ns    string
	title string
}

func nsKey(ns, title string) string { return ns + "\x00" + title }

func readMemMeta(ctx context.Context, db *sql.DB, tomb map[string]bool) (byUID map[string]memMeta, byNS map[string]memMeta, dead []any, err error) {
	byUID = map[string]memMeta{}
	byNS = map[string]memMeta{}
	err = each(ctx, db, `SELECT id,uid,max(mtime,ts),namespace,title FROM memories`, func(r *sql.Rows) error {
		var m memMeta
		if err := r.Scan(&m.id, &m.uid, &m.mtime, &m.ns, &m.title); err != nil {
			return err
		}
		if tomb[memTomb(m.uid)] {
			dead = append(dead, m.id)
			return nil
		}
		byUID[m.uid] = m
		byNS[nsKey(m.ns, m.title)] = m
		return nil
	})
	return byUID, byNS, dead, err
}

// syncMemoriesBidirectional fetches only metadata first, resolves tombstones and
// (namespace, title) LWW conflicts, and transfers content only for changed/missing notes.
func syncMemoriesBidirectional(ctx context.Context, local, remote *sql.DB, tomb map[string]bool) (pushed, pulled int, err error) {
	lByUID, lByNS, lDead, err := readMemMeta(ctx, local, tomb)
	if err != nil {
		return 0, 0, err
	}
	rByUID, rByNS, rDead, err := readMemMeta(ctx, remote, tomb)
	if err != nil {
		return 0, 0, err
	}
	if err := purgeChunked(ctx, local, "memories", "memories_fts", lDead); err != nil {
		return 0, 0, err
	}
	if err := purgeChunked(ctx, remote, "memories", "memories_fts", rDead); err != nil {
		return 0, 0, err
	}

	var pushIDs, pullIDs []any
	// Track update targets on dst when matched by uid or (namespace, title)
	pushTargets := map[string]int64{} // src uid -> dst id
	pullTargets := map[string]int64{} // src uid -> dst id

	for uid, lm := range lByUID {
		if rm, ok := rByUID[uid]; ok {
			if lm.mtime > rm.mtime {
				pushIDs = append(pushIDs, lm.id)
				pushTargets[uid] = rm.id
			}
			continue
		}
		if rm, ok := rByNS[nsKey(lm.ns, lm.title)]; ok {
			if lm.mtime >= rm.mtime {
				pushIDs = append(pushIDs, lm.id)
				pushTargets[uid] = rm.id
			}
			continue
		}
		pushIDs = append(pushIDs, lm.id)
	}

	for uid, rm := range rByUID {
		if lm, ok := lByUID[uid]; ok {
			if rm.mtime > lm.mtime {
				pullIDs = append(pullIDs, rm.id)
				pullTargets[uid] = lm.id
			}
			continue
		}
		if lm, ok := lByNS[nsKey(rm.ns, rm.title)]; ok {
			if rm.mtime > lm.mtime {
				pullIDs = append(pullIDs, rm.id)
				pullTargets[uid] = lm.id
			}
			continue
		}
		pullIDs = append(pullIDs, rm.id)
	}

	if pushed, err = transferMemories(ctx, local, remote, pushIDs, pushTargets); err != nil {
		return pushed, pulled, err
	}
	if pulled, err = transferMemories(ctx, remote, local, pullIDs, pullTargets); err != nil {
		return pushed, pulled, err
	}
	return pushed, pulled, nil
}

func transferMemories(ctx context.Context, src, dst *sql.DB, ids []any, targets map[string]int64) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	var rows, fts [][]any
	var upd []Memory
	for c := range chunks(ids, 100) {
		err := each(ctx, src, `SELECT uid,ts,max(mtime,ts),hostname,namespace,title,content,author,tags FROM memories WHERE id IN `+inList(len(c)), func(r *sql.Rows) error {
			var m Memory
			if err := r.Scan(&m.UID, &m.Ts, &m.Mtime, &m.Hostname, &m.Namespace, &m.Title, &m.Content, &m.Author, &m.Tags); err != nil {
				return err
			}
			if dstID, ok := targets[m.UID]; ok {
				m.ID = dstID
				upd = append(upd, m)
			} else {
				rows = append(rows, []any{m.UID, m.Ts, m.Mtime, m.Hostname, m.Namespace, m.Title, m.Content, m.Author, m.Tags})
				fts = append(fts, []any{m.Title, m.Content, m.Namespace, m.Tags})
			}
			return nil
		}, c...)
		if err != nil {
			return 0, err
		}
	}

	n := 0
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
			if err := updateMemoryFullTx(tx, m); err != nil {
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

func copyMemories(ctx context.Context, src, dst *sql.DB, tomb map[string]bool) (n int, err error) {
	if err := fixMemFTS(ctx, dst); err != nil {
		return 0, err
	}

	have, haveNS, dead, err := readMemMeta(ctx, dst, tomb)
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
		if !ok {
			v, ok = haveNS[nsKey(m.Namespace, m.Title)]
		}
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
		have[m.UID] = memMeta{v.id, m.UID, m.Mtime, m.Namespace, m.Title}
		haveNS[nsKey(m.Namespace, m.Title)] = have[m.UID]
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
			if err := updateMemoryFullTx(tx, m); err != nil {
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
