package main

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Replication between two iz databases. One primitive, replicate(src, dst),
// copies to dst what it lacks; `iz sync` runs it both ways against a
// LibSQL/Turso remote, `iz m` runs it once from another database file.
//
//   - runs are immutable, identified by (hostname, ts, tool, cmd), ts within sameTime
//   - notes are identified by uid; the newer mtime wins (edits, renames)
//   - tombstones travel first, so deletes propagate instead of being undone
//   - notes travel before runs, so a failing (large) run never blocks them
//
// Only keys are read up front; output blobs are fetched for missing rows
// only, and rows are written in multi-row chunks (few round trips per chunk).

// getSyncConfig reads connection parameters from environment variables,
// falling back to Atuin KV store if unset (e.g. across machines with atuin sync).
func getSyncConfig() (remoteURL, authToken string) {
	fromAtuin := false
	remoteURL = firstEnv("IZ_SYNC_URL", "IZ_URL", "TURSO_DATABASE_URL")
	if remoteURL == "" {
		remoteURL = atuinKVGet("IZ_SYNC_URL")
		fromAtuin = true
	}
	if remoteURL = strings.TrimSpace(remoteURL); remoteURL == "" {
		return "", "" // no remote: a token lookup would only cost another atuin call
	}
	authToken = firstEnv("IZ_AUTH_TOKEN", "IZ_TOKEN", "TURSO_AUTH_TOKEN")
	if authToken == "" && fromAtuin {
		authToken = atuinKVGet("IZ_AUTH_TOKEN")
	}
	return remoteURL, strings.TrimSpace(authToken)
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// atuinKVGet retrieves a key from atuin's key-value store if atuin is
// installed; a hanging atuin cannot stall iz sync (it runs before the sync
// timeout starts).
func atuinKVGet(key string) string {
	ctx, cancel := context.WithTimeout(context.Background(), atuinTimeout)
	defer cancel()
	c := exec.CommandContext(ctx, "atuin", "kv", "get", key)
	c.WaitDelay = time.Second // a killed atuin's children may hold stdout open
	out, err := c.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

var atuinTimeout = 5 * time.Second

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
	resetTombs, prune := false, false
	for _, a := range args {
		switch a {
		case "-h", "--help":
			fmt.Println(`iz sync — two-way sync with Turso / LibSQL

Usage:
  iz sync                     Sync notes, runs and deletes with remote
  iz sync --prune             Also report the expired tombstones (older than 30 days)
                              pruned after a complete sync
  iz sync --reset-tombstones  Clear ALL tombstones on local and remote before syncing
                              (deleted rows still present elsewhere come back)

Environment:
  IZ_SYNC_URL     Remote LibSQL URL (e.g. libsql://your-db.turso.io)
  IZ_AUTH_TOKEN   Auth token (falls back to atuin kv when URL is also from atuin)
  IZ_SYNC_TIMEOUT Sync timeout duration (default 5m)`)
			return 0
		case "--reset-tombstones":
			resetTombs = true
		case "--prune":
			prune = true
		default:
			fmt.Fprintf(os.Stderr, "iz sync: unknown argument %q (see 'iz sync --help')\n", a)
			return 2
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

	unlock, err := acquireSyncLock(dbPath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz sync:", err)
		return 1
	}
	defer unlock()

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
	if err := ensureSchema(ctx, remoteDB); err != nil {
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
	status := "complete"
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz sync:", err)
		status = "incomplete"
	}
	fmt.Fprintf(os.Stderr, "[iz] sync %s · notes: ↑%d ↓%d · runs: ↑%d ↓%d · deletes: ↑%d ↓%d\n",
		status, up.notes, down.notes, up.runs, down.runs, up.dels, down.dels)
	if prune {
		if err != nil {
			fmt.Fprintln(os.Stderr, "[iz] expired tombstones kept: sync incomplete")
		} else {
			fmt.Fprintf(os.Stderr, "[iz] expired tombstones pruned · local %d · remote %d\n", down.pruned, up.pruned)
		}
	}
	if err != nil {
		return 1
	}
	return 0
}

// syncPair performs a single-pass bidirectional sync between local and remote.
// Notes and runs are attempted independently, so either can fail alone.
// Expired tombstones are pruned only after everything synced: a tombstone
// dropped earlier would let the other side resurrect the row it deletes.
// In the stats, up is what changed on remote, down what changed locally.
func syncPair(ctx context.Context, local, remote *sql.DB) (up, down repStats, err error) {
	tomb, stale, upDels, downDels, err := syncTombstones(ctx, local, remote)
	if err != nil {
		return up, down, fmt.Errorf("tombstones: %w", err)
	}
	up.dels, down.dels = upDels, downDels

	var errs []error
	if up.notes, down.notes, err = syncMemoriesBidirectional(ctx, local, remote, tomb); err != nil {
		errs = append(errs, fmt.Errorf("notes: %w", err))
	}
	if up.runs, down.runs, err = syncRunsBidirectional(ctx, local, remote, tomb); err != nil {
		errs = append(errs, fmt.Errorf("runs: %w", err))
	}
	if len(errs) > 0 {
		return up, down, errors.Join(errs...)
	}
	for _, s := range []struct {
		db     *sql.DB
		stale  bool
		pruned *int
	}{{local, stale[0], &down.pruned}, {remote, stale[1], &up.pruned}} {
		if !s.stale {
			continue // nothing undated or expired: skip the write round trips
		}
		n, err := pruneTombstones(ctx, s.db, tombstoneTTL)
		if err != nil {
			return up, down, fmt.Errorf("prune tombstones: %w", err)
		}
		*s.pruned = int(n)
	}
	return up, down, nil
}

type repStats struct{ runs, skipped, notes, dels, pruned int }

// replicate copies tombstones, runs and notes one-way from src into dst (used by iz merge).
func replicate(ctx context.Context, src, dst *sql.DB) (st repStats, err error) {
	tomb, dels, err := copyTombstones(ctx, src, dst)
	if err != nil {
		return st, fmt.Errorf("tombstones: %w", err)
	}
	st.dels = dels
	if st.notes, err = copyMemories(ctx, src, dst, tomb); err != nil {
		return st, fmt.Errorf("notes: %w", err)
	}
	if st.runs, st.skipped, err = copyRuns(ctx, src, dst, tomb); err != nil {
		return st, fmt.Errorf("runs: %w", err)
	}
	return st, nil
}

const tombstoneTTL = 30 * 24 * time.Hour

// syncTombstones reads tombstones once from each side and propagates
// differences both ways. stale reports per side (local, remote) whether it
// now holds undated or expired tombstones, i.e. whether pruning has work.
func syncTombstones(ctx context.Context, local, remote *sql.DB) (union map[string]bool, stale [2]bool, up, down int, err error) {
	var tombs [2]map[string]float64
	for i, db := range []*sql.DB{local, remote} {
		if tombs[i], err = readTombs(ctx, db); err != nil {
			return nil, stale, 0, 0, err
		}
	}
	cutoff := float64(time.Now().Add(-tombstoneTTL).Unix())
	union = make(map[string]bool, len(tombs[0])+len(tombs[1]))
	var missing [2][]any // tombstones side i lacks
	for i, own := range tombs {
		other := tombs[1-i]
		for k, ts := range own {
			union[k] = true
			stale[i] = stale[i] || ts < cutoff // includes undated (0)
			if _, ok := other[k]; !ok {
				if ts == 0 {
					ts = now()
				}
				stale[1-i] = stale[1-i] || ts < cutoff
				missing[1-i] = append(missing[1-i], k, ts)
			}
		}
	}
	if err := insertTombstonesBatch(ctx, remote, missing[1]); err != nil {
		return nil, stale, 0, 0, err
	}
	if err := insertTombstonesBatch(ctx, local, missing[0]); err != nil {
		return nil, stale, 0, 0, err
	}
	return union, stale, len(missing[1]) / 2, len(missing[0]) / 2, nil
}

func insertTombstonesBatch(ctx context.Context, db *sql.DB, kts []any) error {
	for c := range chunks(kts, 500) {
		if _, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO tombstones(key, ts) VALUES`+ph(len(c)/2, 2), c...); err != nil {
			return err
		}
	}
	return nil
}

// readTombs reads a database's tombstones (key → deletion time), keys
// normalized by tombKey.
func readTombs(ctx context.Context, db *sql.DB) (map[string]float64, error) {
	tombs := map[string]float64{}
	err := each(ctx, db, `SELECT key, ts FROM tombstones`, func(r *sql.Rows) error {
		var k string
		var ts float64
		if err := r.Scan(&k, &ts); err != nil {
			return err
		}
		if k, ok := tombKey(k); ok {
			tombs[k] = max(tombs[k], ts)
		}
		return nil
	})
	return tombs, err
}

// copyTombstones adds src's tombstones to dst and returns the union.
func copyTombstones(ctx context.Context, src, dst *sql.DB) (map[string]bool, int, error) {
	have := map[string]bool{}
	var fresh []any
	for i, db := range []*sql.DB{dst, src} {
		tombs, err := readTombs(ctx, db)
		if err != nil {
			return nil, 0, err
		}
		for k, ts := range tombs {
			if i == 1 && !have[k] {
				if ts == 0 {
					ts = now()
				}
				fresh = append(fresh, k, ts)
			}
			have[k] = true
		}
	}
	if err := insertTombstonesBatch(ctx, dst, fresh); err != nil {
		return nil, 0, err
	}
	return have, len(fresh) / 2, nil
}

var (
	runKeyPageSize       = 5000    // key rows per page when scanning runs
	runChunk             = 32      // max rows per round trip; outputs can be large
	runChunkBytes  int64 = 4 << 20 // compressed raw byte budget per chunk
)

// Runs have no uid: they match across machines on (hostname, tool, cmd) and
// a start time within sameTime. A remote may hand a float back a digit short
// (and older runs carry nanoseconds), so exact keys would copy such a run
// again, and miss its tombstone, on every sync.
type runSlot struct {
	host, tool, cmd string
	bucket          int64 // ts in 1e-4 s buckets, wider than the tolerance
}

type runSet map[runSlot][]float64

func tsBucket(ts float64) int64 { return int64(math.Floor(ts * 1e4)) }

func (s runSet) add(x Run) {
	k := runSlot{x.Hostname, x.Tool, x.Cmd, tsBucket(x.Ts)}
	s[k] = append(s[k], x.Ts)
}

// has reports whether s holds a run matching x; a match within the
// tolerance lies in x's bucket or a neighbor.
func (s runSet) has(x Run) bool {
	for _, b := range []int64{tsBucket(x.Ts - timeTol), tsBucket(x.Ts + timeTol)} {
		for _, ts := range s[runSlot{x.Hostname, x.Tool, x.Cmd, b}] {
			if sameTime(ts, x.Ts) {
				return true
			}
		}
	}
	return false
}

// runTombs matches runs against the run tombstones among tomb.
type runTombs struct {
	keys map[string]bool
	near runSet // "r:host:ts:tool:cmd" keys as (host, "", "tool:cmd", ts)
}

func newRunTombs(tomb map[string]bool) runTombs {
	t := runTombs{keys: tomb, near: runSet{}}
	for k := range tomb {
		rest, ok := strings.CutPrefix(k, "r:")
		host, rest, ok2 := strings.Cut(rest, ":")
		ts, what, ok3 := strings.Cut(rest, ":")
		if v, err := strconv.ParseFloat(ts, 64); ok && ok2 && ok3 && err == nil {
			t.near.add(Run{Hostname: host, Cmd: what, Ts: v})
		}
	}
	return t
}

// has reports whether a tombstone deletes x: by its exact key, or (the key's
// timestamp drifted) by its fields and a time within the tolerance.
func (t runTombs) has(x Run) bool {
	return t.keys[runKey(x.Hostname, x.Ts, x.Tool, x.Cmd)] ||
		t.near.has(Run{Hostname: x.Hostname, Cmd: x.Tool + ":" + x.Cmd, Ts: x.Ts})
}

// readRuns reads db's run identities in id-ordered pages: the live runs
// (ID, key fields, and compressed size) and the ids of runs a tombstone deletes.
func readRuns(ctx context.Context, db *sql.DB, dead runTombs) (live []Run, deadIDs []any, err error) {
	var afterID int64
	for {
		n := 0
		err = each(ctx, db, `SELECT id,hostname,ts,tool,cmd,size FROM runs WHERE id > ? ORDER BY id LIMIT ?`, func(r *sql.Rows) error {
			var x Run
			if err := r.Scan(&x.ID, &x.Hostname, &x.Ts, &x.Tool, &x.Cmd, &x.Size); err != nil {
				return err
			}
			afterID = x.ID
			n++
			if dead.has(x) {
				deadIDs = append(deadIDs, x.ID)
			} else {
				live = append(live, x)
			}
			return nil
		}, afterID, runKeyPageSize)
		if err != nil {
			return nil, nil, err
		}
		if n < runKeyPageSize {
			break
		}
	}
	return live, deadIDs, nil
}

// excludePendingRuns filters out local runs that belong to an active in-flight
// pipeline (pending=1 in pipeline_stages within the last 24h) so sync never
// pushes partial output while orphaned rows age out cleanly.
func excludePendingRuns(ctx context.Context, db *sql.DB, runs []Run) []Run {
	pending := map[int64]bool{}
	cutoff := now() - 86400
	_ = each(ctx, db, `SELECT DISTINCT run_id FROM pipeline_stages WHERE pending=1 AND run_id>0 AND end_ts>?`, func(r *sql.Rows) error {
		var id int64
		if err := r.Scan(&id); err == nil {
			pending[id] = true
		}
		return nil
	}, cutoff)
	if len(pending) == 0 {
		return runs
	}
	out := make([]Run, 0, len(runs))
	for _, r := range runs {
		if !pending[r.ID] {
			out = append(out, r)
		}
	}
	return out
}

// missingRuns returns the runs that have lacks, each key once.
func missingRuns(runs, have []Run) (missing []Run) {
	set := runSet{}
	for _, x := range have {
		set.add(x)
	}
	for _, x := range runs {
		if !set.has(x) {
			set.add(x)
			missing = append(missing, x)
		}
	}
	return missing
}

// chunkRunsBySize groups runs into chunks of at most maxRows rows and at most
// maxBytes total compressed size (a single run larger than maxBytes gets its
// own 1-row chunk).
func chunkRunsBySize(runs []Run, maxRows int, maxBytes int64) [][]Run {
	if len(runs) == 0 {
		return nil
	}
	if maxRows <= 0 {
		maxRows = 1
	}
	var out [][]Run
	var cur []Run
	var curBytes int64
	for _, r := range runs {
		sz := max(int64(0), r.Size.Int64)
		if len(cur) > 0 && (len(cur) >= maxRows || (maxBytes > 0 && curBytes+sz > maxBytes)) {
			out = append(out, cur)
			cur = nil
			curBytes = 0
		}
		cur = append(cur, r)
		curBytes += sz
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// syncRunsBidirectional reads run keys once from local and remote, purges
// tombstoned rows on both sides, and transfers only missing runs each way.
func syncRunsBidirectional(ctx context.Context, local, remote *sql.DB, tomb map[string]bool) (pushed, pulled int, err error) {
	dead := newRunTombs(tomb)
	localRuns, localDead, err := readRuns(ctx, local, dead)
	if err != nil {
		return 0, 0, err
	}
	localRuns = excludePendingRuns(ctx, local, localRuns)
	remoteRuns, remoteDead, err := readRuns(ctx, remote, dead)
	if err != nil {
		return 0, 0, err
	}
	// Dead rows are left out of the transfers either way, so a failed purge
	// does not stop them.
	purgeErr := errors.Join(
		purgeChunked(ctx, local, "runs", "outputs_fts", localDead),
		purgeChunked(ctx, remote, "runs", "outputs_fts", remoteDead))

	// Both directions run even if one fails: a run the remote rejects must
	// not keep the other machines' runs from arriving.
	pushed, pushErr := transferRuns(ctx, local, remote, missingRuns(localRuns, remoteRuns), false)
	pulled, pullErr := transferRuns(ctx, remote, local, missingRuns(remoteRuns, localRuns), true)
	return pushed, pulled, errors.Join(purgeErr, pushErr, pullErr)
}

// readRunChunk fetches full run rows for ids from src. When rebuildFTS is true
// (pulling from a remote), outputs_fts is not queried over the wire and the
// search text is rebuilt locally from the compressed output.
func readRunChunk(ctx context.Context, src *sql.DB, ids []any, rebuildFTS bool) (rows, fts [][]any, err error) {
	if rebuildFTS {
		err = each(ctx, src, `SELECT ts,hostname,tool,cmd,cwd,exit_code,duration_ms,size,raw
		     FROM runs WHERE id IN `+inList(len(ids)), func(q *sql.Rows) error {
			var x Run
			var raw []byte
			if err := q.Scan(&x.Ts, &x.Hostname, &x.Tool, &x.Cmd, &x.Cwd, &x.ExitCode, &x.Dur, &x.Size, &raw); err != nil {
				return err
			}
			text := ftsPrefix(x) + string(truncFTS(stripANSI(tidyRaw(ungz(raw)))))
			rows = append(rows, []any{x.Ts, x.Hostname, x.Tool, x.Cmd, x.Cwd, x.ExitCode, x.Dur, x.Size, raw})
			fts = append(fts, []any{text})
			return nil
		}, ids...)
		return rows, fts, err
	}
	err = each(ctx, src, `SELECT r.ts,r.hostname,r.tool,r.cmd,r.cwd,r.exit_code,r.duration_ms,r.size,r.raw,f.text
	     FROM runs r LEFT JOIN outputs_fts f ON f.rowid = r.id WHERE r.id IN `+inList(len(ids)), func(q *sql.Rows) error {
		var x Run
		var raw []byte
		var text sql.NullString
		if err := q.Scan(&x.Ts, &x.Hostname, &x.Tool, &x.Cmd, &x.Cwd, &x.ExitCode, &x.Dur, &x.Size, &raw, &text); err != nil {
			return err
		}
		if !text.Valid { // index row missing on src: rebuild it
			text.String = ftsPrefix(x) + string(truncFTS(stripANSI(tidyRaw(ungz(raw)))))
		}
		rows = append(rows, []any{x.Ts, x.Hostname, x.Tool, x.Cmd, x.Cwd, x.ExitCode, x.Dur, x.Size, raw})
		fts = append(fts, []any{text.String})
		return nil
	}, ids...)
	return rows, fts, err
}

// transferRuns copies runs from src to dst in size- and count-bounded chunks.
// A chunk that fails to read or write (e.g. an oversized response or request)
// is retried row by row, so one oversized output does not block the others.
func transferRuns(ctx context.Context, src, dst *sql.DB, runs []Run, rebuildFTS bool) (int, error) {
	added := 0
	var failed []error
	for _, c := range chunkRunsBySize(runs, runChunk, runChunkBytes) {
		if ctx.Err() != nil {
			return added, ctx.Err()
		}
		ids := make([]any, len(c))
		for i, r := range c {
			ids[i] = r.ID
		}
		rows, fts, err := readRunChunk(ctx, src, ids, rebuildFTS)
		if err != nil {
			if ctx.Err() != nil {
				return added, ctx.Err()
			}
			if len(ids) == 1 {
				failed = append(failed, err)
				continue
			}
			rows, fts = nil, nil
			for _, id := range ids {
				if ctx.Err() != nil {
					return added, ctx.Err()
				}
				r1, f1, rerr := readRunChunk(ctx, src, []any{id}, rebuildFTS)
				if rerr != nil {
					if ctx.Err() != nil {
						return added, ctx.Err()
					}
					failed = append(failed, rerr)
					continue
				}
				rows = append(rows, r1...)
				fts = append(fts, f1...)
			}
			if len(rows) == 0 {
				continue
			}
		}
		insert := func(rows, fts [][]any) error {
			return insertBatch(ctx, dst, "runs", "ts,hostname,tool,cmd,cwd,exit_code,duration_ms,size,raw",
				"outputs_fts", "text", rows, fts)
		}
		if err := insert(rows, fts); err == nil {
			added += len(rows)
			continue
		} else if len(rows) == 1 {
			failed = append(failed, err)
			continue
		}
		for i := range rows {
			if ctx.Err() != nil { // canceled or timed out: no point retrying each row
				return added, ctx.Err()
			}
			if err := insert(rows[i:i+1], fts[i:i+1]); err != nil {
				failed = append(failed, err)
			} else {
				added++
			}
		}
	}
	if len(failed) > 0 {
		return added, fmt.Errorf("%d run(s) not copied (first error: %w)", len(failed), failed[0])
	}
	return added, nil
}

func copyRuns(ctx context.Context, src, dst *sql.DB, tomb map[string]bool) (added, skipped int, err error) {
	dead := newRunTombs(tomb)
	have, dstDead, err := readRuns(ctx, dst, dead)
	if err != nil {
		return 0, 0, err
	}
	if err := purgeChunked(ctx, dst, "runs", "outputs_fts", dstDead); err != nil {
		return 0, 0, err
	}
	runs, srcDead, err := readRuns(ctx, src, dead)
	if err != nil {
		return 0, 0, err
	}
	want := missingRuns(runs, have)
	added, err = transferRuns(ctx, src, dst, want, false)
	return added, len(srcDead) + len(runs) - len(want), err
}

type memMeta struct {
	id    int64
	uid   string
	mtime float64
	ns    string
	title string
}

func nsKey(ns, title string) string { return ns + "\x00" + title }

// slot is the note's (namespace, title) key, unique per database.
func (m memMeta) slot() string { return nsKey(m.ns, m.title) }

// sameTime treats timestamps within timeTol as equal so JSON/HTTP float
// round-tripping on remote databases (e.g. Turso losing a trailing digit)
// cannot trigger endless re-uploads.
func sameTime(a, b float64) bool { return math.Abs(a-b) <= timeTol }

const timeTol = 1e-5 // seconds

// newer orders notes for last-write-wins: later mtime, then smaller uid.
func (m memMeta) newer(o memMeta) bool {
	if !sameTime(m.mtime, o.mtime) {
		return m.mtime > o.mtime
	}
	return m.uid < o.uid
}

// memSide indexes one database's live (not tombstoned) notes.
type memSide struct {
	byUID map[string]memMeta
	byNS  map[string]memMeta
}

func readMemMeta(ctx context.Context, db *sql.DB, tomb map[string]bool) (side memSide, dead []any, err error) {
	side = memSide{byUID: map[string]memMeta{}, byNS: map[string]memMeta{}}
	err = each(ctx, db, `SELECT id,`+uidCol+`,max(mtime,ts),namespace,title FROM memories`, func(r *sql.Rows) error {
		var m memMeta
		if err := r.Scan(&m.id, &m.uid, &m.mtime, &m.ns, &m.title); err != nil {
			return err
		}
		if tomb[memTomb(m.uid)] {
			dead = append(dead, m.id)
			return nil
		}
		side.byUID[m.uid] = m
		side.byNS[m.slot()] = m
		return nil
	})
	return side, dead, err
}

// memNote is a note as both sides hold it after the merge.
type memNote struct {
	memMeta         // final slot and mtime; id: its row on the side with the winning content
	ver     float64 // mtime of that content (before a conflict rename)
	winSide int     // index (0 or 1) of the side that supplied the winning content
}

// memMerge is the outcome of merging two sides' notes.
type memMerge struct {
	sides    [2]memSide
	notes    map[string]memNote    // uid → final note
	replaced [2]map[string]memMeta // per side: surviving uid → the row it overwrites
}

// mergeMemories decides which notes both sides end with:
//
//  1. a note both sides know (uid) takes the newer copy — edits and renames;
//  2. two notes on the same (namespace, title), each known to one side only,
//     at least one with a legacy uid, are the same note created on two
//     machines (older syncs had no uids): the newer survives and overwrites
//     the other's row; two uid'd notes are distinct (created offline on two
//     machines) and both kept by step 3;
//  3. (namespace, title) stays unique: of notes wanting one slot the newer
//     keeps it, the others are renamed "title (uid8)" with an mtime just past
//     the winner's, so the rename wins the next sync everywhere.
//
// The result depends only on the union of both sides' notes — not on which
// side is which — so every direction and machine reaches the same state.
func mergeMemories(a, b memSide) memMerge {
	g := memMerge{sides: [2]memSide{a, b}, notes: map[string]memNote{}}
	for sideIdx, s := range g.sides {
		for uid, m := range s.byUID {
			n, ok := g.notes[uid]
			eq := ok && sameTime(m.mtime, n.mtime)
			if !ok || (!eq && m.mtime > n.mtime) || (eq && m.slot() < n.slot()) {
				g.notes[uid] = memNote{m, m.mtime, sideIdx}
			}
		}
	}
	for i := range g.replaced {
		g.replaced[i] = map[string]memMeta{}
	}
	for slot, x := range a.byNS {
		y, ok := b.byNS[slot]
		if !ok || x.uid == y.uid || !isLegacyUID(x.uid) && !isLegacyUID(y.uid) {
			continue
		}
		if _, known := b.byUID[x.uid]; known {
			continue
		}
		if _, known := a.byUID[y.uid]; known {
			continue
		}
		win, lose, loser := x, y, 1
		if y.newer(x) {
			win, lose, loser = y, x, 0
		}
		delete(g.notes, lose.uid)
		g.replaced[loser][win.uid] = lose
	}

	owner := map[string]memMeta{} // slot → note keeping it
	var losers []memNote
	for _, uid := range slices.Sorted(maps.Keys(g.notes)) {
		n := g.notes[uid]
		o, taken := owner[n.slot()]
		switch {
		case !taken:
			owner[n.slot()] = n.memMeta
		case n.newer(o):
			owner[n.slot()] = n.memMeta
			losers = append(losers, g.notes[o.uid])
		default:
			losers = append(losers, n)
		}
	}
	slices.SortFunc(losers, func(x, y memNote) int { return cmp.Compare(x.uid, y.uid) })
	for _, n := range losers {
		win := owner[n.slot()]
		n.title = conflictTitle(n.memMeta, owner)
		n.mtime = math.Round((max(win.mtime, n.mtime)+0.001)*1e3) / 1e3
		owner[n.slot()] = n.memMeta
		g.notes[n.uid] = n
	}
	return g
}

// isLegacyUID reports a uid derived by legacyUID ("host|ts|ns|title") for a
// note written before notes had uids; newUID never contains '|'.
func isLegacyUID(uid string) bool { return strings.Contains(uid, "|") }

// conflictTitle is m's title made unique among owner's slots: "title (uid8)".
func conflictTitle(m memMeta, owner map[string]memMeta) string {
	base := m.title + " (" + m.uid[:min(8, len(m.uid))] + ")"
	t := base
	for n := 2; ; n++ {
		if _, taken := owner[nsKey(m.ns, t)]; !taken {
			return t
		}
		t = numbered(base, n)
	}
}

// memPlan is what side dst writes to reach the merged notes.
type memPlan struct {
	ids     []any              // rows of the other side whose content dst needs
	final   map[string]memMeta // uid → slot and mtime it ends with
	targets map[string]memMeta // uid → dst row it overwrites (else: insert)
	renames []memMeta          // dst rows keeping their content, moving slot (final values)
}

// plan lists what side dst must write.
func (g memMerge) plan(dst int) memPlan {
	p := memPlan{final: map[string]memMeta{}, targets: map[string]memMeta{}}
	side := g.sides[dst]
	for uid, n := range g.notes {
		cur, has := side.byUID[uid]
		winSlot := g.sides[n.winSide].byUID[uid].slot()
		if has && (cur.mtime > n.ver && !sameTime(cur.mtime, n.ver) || (sameTime(cur.mtime, n.ver) && (dst == n.winSide || cur.slot() == winSlot))) { // dst holds this content
			if cur.slot() != n.slot() || !sameTime(cur.mtime, n.mtime) {
				r := n.memMeta
				r.id = cur.id
				p.renames = append(p.renames, r)
			}
			continue
		}
		// the content comes from the other side
		if !has {
			cur, has = g.replaced[dst][uid]
		}
		if has {
			p.targets[uid] = cur
		}
		p.ids = append(p.ids, n.id)
		p.final[uid] = n.memMeta
	}
	return p
}

// syncMemoriesBidirectional fetches only metadata first, merges both sides
// once, and transfers content only for changed/missing notes. Both
// directions run even if one fails.
func syncMemoriesBidirectional(ctx context.Context, local, remote *sql.DB, tomb map[string]bool) (pushed, pulled int, err error) {
	// an index older clients left out of step (either side) is rebuilt first:
	// setNotes/insertBatch rely on FTS rowid = note id
	for _, db := range []*sql.DB{local, remote} {
		if err := fixMemFTS(ctx, db); err != nil {
			return 0, 0, err
		}
	}
	l, lDead, err := readMemMeta(ctx, local, tomb)
	if err != nil {
		return 0, 0, err
	}
	r, rDead, err := readMemMeta(ctx, remote, tomb)
	if err != nil {
		return 0, 0, err
	}
	// a dead row still holds its slot: no point writing around it
	if err := purgeChunked(ctx, local, "memories", "memories_fts", lDead); err != nil {
		return 0, 0, err
	}
	if err := purgeChunked(ctx, remote, "memories", "memories_fts", rDead); err != nil {
		return 0, 0, err
	}
	g := mergeMemories(l, r)
	pushed, pushErr := transferMemories(ctx, local, remote, g.plan(1))
	pulled, pullErr := transferMemories(ctx, remote, local, g.plan(0))
	return pushed, pulled, errors.Join(pushErr, pullErr)
}

// copyMemories merges src's notes into dst (dst's half of the same merge).
func copyMemories(ctx context.Context, src, dst *sql.DB, tomb map[string]bool) (int, error) {
	if err := fixMemFTS(ctx, dst); err != nil {
		return 0, err
	}
	s, _, err := readMemMeta(ctx, src, tomb)
	if err != nil {
		return 0, err
	}
	d, dead, err := readMemMeta(ctx, dst, tomb)
	if err != nil {
		return 0, err
	}
	if err := purgeChunked(ctx, dst, "memories", "memories_fts", dead); err != nil {
		return 0, err
	}
	return transferMemories(ctx, src, dst, mergeMemories(s, d).plan(1))
}

// memUpdateChunk bounds the rows one note UPDATE statement writes.
const memUpdateChunk = 50

// transferMemories fetches the planned notes from src and writes them to
// dst in an order that never breaks UNIQUE(namespace, title): first, in one
// transaction, every row changing slot (renames, moves) is parked on a
// unique temporary title and then set to its final slot, so swaps and
// rename chains work; then content-only updates; then inserts, whose slots
// are free by now. Updates are multi-row statements, so round trips grow
// with chunks, not notes. It returns how many notes it copied from src.
func transferMemories(ctx context.Context, src, dst *sql.DB, p memPlan) (int, error) {
	var moves, updates, rows, fts [][]any
	for c := range chunks(p.ids, 100) {
		err := each(ctx, src, `SELECT `+uidCol+`,ts,hostname,content,author,tags FROM memories WHERE id IN `+inList(len(c)), func(r *sql.Rows) error {
			var m Memory
			if err := r.Scan(&m.UID, &m.Ts, &m.Hostname, &m.Content, &m.Author, &m.Tags); err != nil {
				return err
			}
			f := p.final[m.UID]
			d, ok := p.targets[m.UID]
			switch {
			case !ok:
				rows = append(rows, []any{m.UID, m.Ts, f.mtime, m.Hostname, f.ns, f.title, m.Content, m.Author, m.Tags})
				fts = append(fts, []any{f.title, m.Content, f.ns, m.Tags})
			case d.slot() == f.slot():
				updates = append(updates, []any{d.id, m.UID, m.Hostname, f.ns, f.title, m.Content, m.Author, m.Tags, f.mtime})
			default:
				moves = append(moves, []any{d.id, m.UID, m.Hostname, f.ns, f.title, m.Content, m.Author, m.Tags, f.mtime})
			}
			return nil
		}, c...)
		if err != nil {
			return 0, err
		}
	}

	full := []string{"uid", "hostname", "namespace", "title", "content", "author", "tags", "mtime"}
	if len(p.renames)+len(moves) > 0 {
		renames := make([][]any, len(p.renames))
		for i, r := range p.renames {
			// uid too: a pre-uid row's derived uid would change with its title
			renames[i] = []any{r.id, r.uid, r.ns, r.title, r.mtime}
		}
		parked := make([]any, 0, len(renames)+len(moves))
		for _, r := range slices.Concat(renames, moves) {
			parked = append(parked, r[0])
		}
		err := inTx(ctx, dst, func(tx *sql.Tx) error {
			for c := range chunks(parked, 500) {
				if _, err := tx.ExecContext(ctx, `UPDATE memories SET title = 'iz-park:' || id || ':' || coalesce(uid, '') WHERE id IN `+inList(len(c)), c...); err != nil {
					return err
				}
			}
			if err := setNotes(ctx, tx, []string{"uid", "namespace", "title", "mtime"}, renames); err != nil {
				return err
			}
			return setNotes(ctx, tx, full, moves)
		})
		if err != nil {
			return 0, err
		}
	}
	n := len(moves)
	for c := range chunks(updates, memUpdateChunk) {
		if err := inTx(ctx, dst, func(tx *sql.Tx) error { return setNotes(ctx, tx, full, c) }); err != nil {
			return n, err
		}
		n += len(c)
	}
	for c := range chunks(rows, 100) {
		if err := insertBatch(ctx, dst, "memories", "uid,ts,mtime,hostname,namespace,title,content,author,tags",
			"memories_fts", "title,content,namespace,tags", c, fts[:len(c)]); err != nil {
			return n, err
		}
		fts = fts[len(c):]
		n += len(c)
	}
	return n, nil
}

// setNotes updates notes from (id, values of cols...) tuples, memUpdateChunk
// rows per statement, and rebuilds their index rows.
func setNotes(ctx context.Context, tx *sql.Tx, cols []string, rows [][]any) error {
	set := make([]string, len(cols))
	for i, c := range cols {
		set[i] = fmt.Sprintf("%s = v.column%d", c, i+2)
	}
	for c := range chunks(rows, memUpdateChunk) {
		args, ids := make([]any, 0, len(c)*(len(cols)+1)), make([]any, len(c))
		for i, r := range c {
			args, ids[i] = append(args, r...), r[0]
		}
		if _, err := tx.ExecContext(ctx, `UPDATE memories SET `+strings.Join(set, ", ")+
			` FROM (VALUES `+ph(len(c), len(cols)+1)+`) AS v WHERE memories.id = v.column1`, args...); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM memories_fts WHERE rowid IN `+inList(len(ids)), ids...); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO memories_fts(rowid, title, content, namespace, tags)
			SELECT id, title, content, namespace, tags FROM memories WHERE id IN `+inList(len(ids)), ids...); err != nil {
			return err
		}
	}
	return nil
}

// acquireSyncLock takes an exclusive non-blocking advisory flock on <db>.lock
// so two local `iz sync` processes cannot race against the same database.
func acquireSyncLock(dbFile string) (func(), error) {
	if dbFile == "" || dbFile == ":memory:" || strings.HasPrefix(dbFile, "file:") {
		return func() {}, nil
	}
	lockPath := dbFile + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("another iz sync is already running (lock: %s)", lockPath)
		}
		return nil, err
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

// fixMemFTS rebuilds memories_fts when it no longer mirrors memories (older
// syncs inserted remote index rows without an explicit rowid). A fast count
// and rowid-bound check avoids scanning/joining full note bodies on every sync.
func fixMemFTS(ctx context.Context, db *sql.DB) error {
	var memCnt, ftsCnt, memMin, ftsMin, memMax, ftsMax int64
	err := db.QueryRowContext(ctx, `SELECT
	  (SELECT count(*) FROM memories),
	  (SELECT count(*) FROM memories_fts),
	  coalesce((SELECT id FROM memories ORDER BY id ASC LIMIT 1), 0),
	  coalesce((SELECT rowid FROM memories_fts ORDER BY rowid ASC LIMIT 1), 0),
	  coalesce((SELECT id FROM memories ORDER BY id DESC LIMIT 1), 0),
	  coalesce((SELECT rowid FROM memories_fts ORDER BY rowid DESC LIMIT 1), 0)`).
		Scan(&memCnt, &ftsCnt, &memMin, &ftsMin, &memMax, &ftsMax)
	if err != nil {
		return err
	}
	if memCnt == ftsCnt && memMin == ftsMin && memMax == ftsMax {
		return nil
	}
	return inTx(ctx, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM memories_fts`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO memories_fts(rowid,title,content,namespace,tags)
		                               SELECT id,title,content,namespace,tags FROM memories`)
		return err
	})
}

// insertBatch writes rows into table and their FTS entries with two multi-row
// statements in one transaction. Ids are assigned explicitly past both the
// table and the index, so the FTS rowid always equals the row id.
func insertBatch(ctx context.Context, db *sql.DB, table, cols, fts, ftsCols string, rows, ftsRows [][]any) error {
	if len(rows) == 0 {
		return nil
	}
	return inTx(ctx, db, func(tx *sql.Tx) error {
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
		_, err := tx.ExecContext(ctx, `INSERT INTO `+fts+`(rowid,`+ftsCols+`) VALUES`+ph(len(rows), len(ftsRows[0])+1), b...)
		return err
	})
}

func purgeChunked(ctx context.Context, db *sql.DB, table, fts string, ids []any) error {
	if len(ids) == 0 {
		return nil
	}
	return inTx(ctx, db, func(tx *sql.Tx) error {
		for c := range chunks(ids, 500) {
			if err := purge(ctx, tx, table, fts, c); err != nil {
				return err
			}
		}
		return nil
	})
}

// inTx runs fn in a transaction on db and commits when fn succeeds.
func inTx(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint
	if err := fn(tx); err != nil {
		return err
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
func chunks[T any](s []T, n int) func(func([]T) bool) {
	return func(yield func([]T) bool) {
		for i := 0; i < len(s); i += n {
			if !yield(s[i:min(i+n, len(s))]) {
				return
			}
		}
	}
}

// sanitizeURL hides credentials in a remote URL for display; an unparsable
// URL is not shown at all (it may still carry a token).
func sanitizeURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return "unparsable URL"
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
