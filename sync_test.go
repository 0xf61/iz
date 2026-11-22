package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBuildLibsqlURL(t *testing.T) {
	cases := []struct {
		url   string
		token string
		want  string
	}{
		{"", "tok", ""},
		{"libsql://db.turso.io", "", "libsql://db.turso.io"},
		{"libsql://db.turso.io", "my-token", "libsql://db.turso.io?authToken=my-token"},
		{"libsql://db.turso.io?tls=true", "my-token", "libsql://db.turso.io?tls=true&authToken=my-token"},
		{"libsql://db.turso.io?authToken=existing", "other", "libsql://db.turso.io?authToken=existing"},
	}

	for _, c := range cases {
		got := buildLibsqlURL(c.url, c.token)
		if got != c.want {
			t.Errorf("buildLibsqlURL(%q, %q) = %q, want %q", c.url, c.token, got, c.want)
		}
	}
}

func TestSyncTwoWayNotesRunsEditsAndDeletes(t *testing.T) {
	dir := t.TempDir()
	local, err := openDBAt(filepath.Join(dir, "local.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()

	remote, err := openDBAt(filepath.Join(dir, "remote.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()

	ctx := context.Background()

	// 1. Insert note + run on local
	mLocalID, err := insertMemory(local, Memory{
		Namespace: "machines",
		Title:     "mac-local",
		Content:   "Note from local mac",
		Author:    "alice",
		Ts:        1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insertRun(local, sampleRun("nmap", "nmap -sV 10.0.0.1", "80/tcp open"), gz([]byte("80/tcp open")), []byte("80/tcp open")); err != nil {
		t.Fatal(err)
	}

	// 2. Insert and delete a dummy note on remote first (creates an ID gap on remote!)
	gapID, err := insertMemory(remote, Memory{
		Namespace: "tmp",
		Title:     "ephemeral",
		Content:   "to be deleted before sync",
		Author:    "hermes",
		Ts:        1500,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := deleteMemory(remote, gapID); err != nil {
		t.Fatal(err)
	}

	// Insert active note + run on remote
	if _, err := insertMemory(remote, Memory{
		Namespace: "machines",
		Title:     "pi-remote",
		Content:   "Note from remote pi",
		Author:    "hermes",
		Ts:        2000,
	}); err != nil {
		t.Fatal(err)
	}
	rRemote := sampleRun("nuclei", "nuclei -u https://example.com", "[critical] CVE-2026-0001")
	rRemote.Ts = 1700000500
	if _, err := insertRun(remote, rRemote, gz([]byte("[critical] CVE-2026-0001")), []byte("[critical] CVE-2026-0001")); err != nil {
		t.Fatal(err)
	}

	// 3. Run two-way sync
	up, down, err := syncPair(ctx, local, remote)
	if err != nil {
		t.Fatalf("syncPair: %v", err)
	}
	if up.notes != 1 || down.notes != 1 || up.runs != 1 || down.runs != 1 {
		t.Errorf("unexpected sync counts: up=%+v down=%+v", up, down)
	}

	// Verify FTS search works on both local and remote despite the ID gap on remote
	if lRes, err := queryMemories(local, "pi-remote", 10); err != nil || len(lRes) != 1 {
		t.Fatalf("expected local to have pi-remote via FTS, got %d (%v)", len(lRes), err)
	}
	if rRes, err := queryMemories(remote, "mac-local", 10); err != nil || len(rRes) != 1 {
		t.Fatalf("expected remote to have mac-local via FTS, got %d (%v)", len(rRes), err)
	}
	if lRuns, err := queryRuns(local, "CVE-2026-0001"); err != nil || len(lRuns) != 1 {
		t.Fatalf("expected local to find synced remote run via FTS, got %d (%v)", len(lRuns), err)
	}
	if rRuns, err := queryRuns(remote, "80/tcp"); err != nil || len(rRuns) != 1 {
		t.Fatalf("expected remote to find synced local run via FTS, got %d (%v)", len(rRuns), err)
	}

	// 4. Second sync is idempotent (0 pushed, 0 pulled)
	up2, down2, err := syncPair(ctx, local, remote)
	if err != nil {
		t.Fatalf("second syncPair: %v", err)
	}
	if up2.notes != 0 || down2.notes != 0 || up2.runs != 0 || down2.runs != 0 {
		t.Errorf("expected 0/0 on idempotent sync, got up=%+v down=%+v", up2, down2)
	}

	// 5. Edit note on local (last-write-wins: updates remote without duplicating)
	if err := updateMemory(local, Memory{
		ID:        mLocalID,
		Namespace: "machines",
		Title:     "mac-local",
		Content:   "Updated content from local mac",
		Mtime:     5000,
	}); err != nil {
		t.Fatal(err)
	}
	up3, down3, err := syncPair(ctx, local, remote)
	if err != nil {
		t.Fatalf("edit syncPair: %v", err)
	}
	if up3.notes != 1 || down3.notes != 0 {
		t.Errorf("expected 1 updated note pushed and 0 pulled, got up=%+v down=%+v", up3, down3)
	}
	rAll, _ := queryMemories(remote, "ns:machines", 10)
	if len(rAll) != 2 {
		t.Fatalf("editing a note must not duplicate it; got %d notes on remote", len(rAll))
	}
	if rUpd, _ := queryMemories(remote, "Updated", 10); len(rUpd) != 1 {
		t.Fatalf("remote FTS did not index updated note content: %+v", rUpd)
	}

	// 6. Delete note on local — tombstone propagates deletion to remote instead of resurrecting
	if err := deleteMemory(local, mLocalID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := syncPair(ctx, local, remote); err != nil {
		t.Fatalf("delete syncPair: %v", err)
	}
	if lAfter, _ := queryMemories(local, "mac-local", 10); len(lAfter) != 0 {
		t.Errorf("deleted note resurrected on local: %+v", lAfter)
	}
	if rAfter, _ := queryMemories(remote, "mac-local", 10); len(rAfter) != 0 {
		t.Errorf("deletion did not propagate to remote: %+v", rAfter)
	}
}

// syncDBs opens two fresh databases standing for local and remote.
func syncDBs(t *testing.T) (local, remote *sql.DB) {
	t.Helper()
	dir := t.TempDir()
	var dbs [2]*sql.DB
	for i, name := range []string{"local.db", "remote.db"} {
		db, err := openDBAt(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		dbs[i] = db
	}
	return dbs[0], dbs[1]
}

func putNote(t *testing.T, db *sql.DB, uid, ns, title string, mtime float64) int64 {
	t.Helper()
	id, err := insertMemory(db, Memory{UID: uid, Namespace: ns, Title: title, Content: "body of " + uid,
		Author: "test", Hostname: "h", Ts: min(mtime, 1), Mtime: mtime})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// noteDump lists a database's notes as "uid ns:title @mtime content", and
// fails when its search index does not mirror them.
func noteDump(t *testing.T, db *sql.DB) []string {
	t.Helper()
	var out []string
	err := each(bg, db, `SELECT `+uidCol+`, namespace, title, max(mtime, ts), content FROM memories ORDER BY 1`, func(r *sql.Rows) error {
		var uid, ns, title, content string
		var mtime float64
		err := r.Scan(&uid, &ns, &title, &mtime, &content)
		out = append(out, fmt.Sprintf("%s %s:%s @%s %s", uid, ns, title, strconv.FormatFloat(mtime, 'f', -1, 64), content))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var bad int
	if err := db.QueryRow(`SELECT count(*) FROM memories m LEFT JOIN memories_fts f ON f.rowid = m.id
		WHERE f.rowid IS NULL OR f.title IS NOT m.title OR f.content IS NOT m.content`).Scan(&bad); err != nil || bad > 0 {
		t.Fatalf("memories_fts out of sync: %d rows (%v)", bad, err)
	}
	return out
}

// syncConverged syncs until nothing moves (at most 3 passes) and checks that
// both sides then hold the same notes, and a further sync changes nothing.
func syncConverged(t *testing.T, local, remote *sql.DB) []string {
	t.Helper()
	if _, _, err := syncPair(bg, local, remote); err != nil {
		t.Fatalf("sync: %v", err)
	}
	l, r := noteDump(t, local), noteDump(t, remote)
	if !slices.Equal(l, r) {
		t.Fatalf("sides diverged after one sync:\nlocal  %q\nremote %q", l, r)
	}
	up, down, err := syncPair(bg, local, remote)
	if err != nil || up.notes+down.notes+up.dels+down.dels != 0 {
		t.Fatalf("second sync not idempotent: up=%+v down=%+v err=%v", up, down, err)
	}
	if l2 := noteDump(t, local); !slices.Equal(l, l2) {
		t.Fatalf("second sync changed notes:\n%q\n%q", l, l2)
	}
	return l
}

// Titles swapped on one machine (a rename cycle on a UNIQUE slot) arrive as
// a swap on the other.
func TestSyncRenameSwap(t *testing.T) {
	local, remote := syncDBs(t)
	a := putNote(t, local, "uida", "ns", "x", 100)
	b := putNote(t, local, "uidb", "ns", "y", 100)
	syncConverged(t, local, remote)

	for _, s := range []struct {
		id    int64
		title string
	}{{a, "tmp"}, {b, "x"}, {a, "y"}} {
		if err := updateMemory(local, Memory{ID: s.id, Namespace: "ns", Title: s.title, Content: "c " + s.title, Mtime: 200}); err != nil {
			t.Fatal(err)
		}
	}
	got := syncConverged(t, local, remote)
	want := []string{"uida ns:y @200 c y", "uidb ns:x @200 c x"}
	if !slices.Equal(got, want) {
		t.Errorf("after swap = %q, want %q", got, want)
	}
}

// Notes renamed onto one title on two machines keep both: the newer keeps
// the title, the other gets "title (uid8)" — the same on both sides, even
// when that conflict title is itself taken by a third note.
func TestSyncTitleCollisionConverges(t *testing.T) {
	t.Run("two notes", func(t *testing.T) {
		local, remote := syncDBs(t)
		putNote(t, local, "u1", "ns", "A", 100)
		putNote(t, local, "u2", "ns", "B", 100)
		syncConverged(t, local, remote)
		rename := func(db *sql.DB, uid, title string, mtime float64) {
			var id int64
			if err := db.QueryRow(`SELECT id FROM memories WHERE uid=?`, uid).Scan(&id); err != nil {
				t.Fatal(err)
			}
			if err := updateMemory(db, Memory{ID: id, Namespace: "ns", Title: title, Content: "body of " + uid, Mtime: mtime}); err != nil {
				t.Fatal(err)
			}
		}
		rename(local, "u1", "C", 300)
		rename(remote, "u2", "C", 400)
		got := syncConverged(t, local, remote)
		want := []string{"u1 ns:C (u1) @400.001 body of u1", "u2 ns:C @400 body of u2"}
		if !slices.Equal(got, want) {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("three notes", func(t *testing.T) {
		local, remote := syncDBs(t)
		putNote(t, local, "U1", "ns", "A", 200)
		putNote(t, local, "U4", "ns", "A (U2)", 50)
		putNote(t, remote, "U1", "ns", "B", 100)
		putNote(t, remote, "U2", "ns", "A", 150)
		got := syncConverged(t, local, remote)
		want := []string{
			"U1 ns:A @200 body of U1",
			"U2 ns:A (U2) (2) @200.001 body of U2",
			"U4 ns:A (U2) @50 body of U4",
		}
		if !slices.Equal(got, want) {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

// A row an older client wrote without a uid keeps its identity (derived
// from its title) when sync renames it off a slot it lost.
func TestSyncRenamesPreUIDRow(t *testing.T) {
	local, remote := syncDBs(t)
	if _, err := remote.Exec(`INSERT INTO memories(uid, ts, mtime, hostname, namespace, title, content, author)
		VALUES(NULL, 100, 0, 'old', 'ns', 'A', 'legacy', 'me')`); err != nil {
		t.Fatal(err)
	}
	if err := fixMemFTS(bg, remote); err != nil {
		t.Fatal(err)
	}
	syncConverged(t, local, remote)
	var lid, rid int64
	local.QueryRow(`SELECT id FROM memories WHERE title='A'`).Scan(&lid)  //nolint
	remote.QueryRow(`SELECT id FROM memories WHERE title='A'`).Scan(&rid) //nolint
	// remote edits the note (its version wins), local renames it away and
	// puts a newer note on its old title: the remote row must move
	if err := updateMemory(remote, Memory{ID: rid, Namespace: "ns", Title: "A", Content: "edited", Mtime: 300}); err != nil {
		t.Fatal(err)
	}
	if err := updateMemory(local, Memory{ID: lid, Namespace: "ns", Title: "X", Content: "legacy", Mtime: 200}); err != nil {
		t.Fatal(err)
	}
	putNote(t, local, "new", "ns", "A", 500)
	got := syncConverged(t, local, remote)
	want := []string{"new ns:A @500 body of new", "old|100.0|ns|A ns:A (old|100.) @500.001 edited"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// seedConflicts fills two databases with edits, renames, a slot collision,
// two notes created on one title offline, and the same pre-uid note on both
// (different legacy uids).
func seedConflicts(t *testing.T, a, b *sql.DB) {
	t.Helper()
	putNote(t, a, "U1", "ns", "A", 200)
	putNote(t, a, "U4", "ns", "A (U2)", 50)
	putNote(t, a, "E1", "ns", "edited", 300)
	putNote(t, a, "S1", "dup", "same", 120)
	putNote(t, b, "U1", "ns", "B", 100)
	putNote(t, b, "U2", "ns", "A", 150)
	putNote(t, b, "E1", "ns", "edited", 100)
	putNote(t, b, "S2", "dup", "same", 120)
	putNote(t, a, "h|1|old|n", "old", "n", 110)
	putNote(t, b, "h|2|old|n", "old", "n", 130)
}

// Merging a into b gives what merging b into a gives.
func TestCopyMemoriesOrderIndependent(t *testing.T) {
	a1, b1 := syncDBs(t)
	a2, b2 := syncDBs(t)
	seedConflicts(t, a1, b1)
	seedConflicts(t, a2, b2)
	if _, err := copyMemories(bg, a1, b1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := copyMemories(bg, b2, a2, nil); err != nil {
		t.Fatal(err)
	}
	intoB, intoA := noteDump(t, b1), noteDump(t, a2)
	if !slices.Equal(intoB, intoA) {
		t.Fatalf("merge depends on direction:\na→b %q\nb→a %q", intoB, intoA)
	}
	// S1/S2 (separate notes created on one title offline) are both kept, the
	// legacy-uid pair L1/L2 (one note from before uids) only once
	want := []string{
		"E1 ns:edited @300 body of E1",
		"S1 dup:same @120 body of S1",
		"S2 dup:same (S2) @120.001 body of S2",
		"U1 ns:A @200 body of U1",
		"U2 ns:A (U2) (2) @200.001 body of U2",
		"U4 ns:A (U2) @50 body of U4",
		"h|2|old|n old:n @130 body of h|2|old|n",
	}
	if !slices.Equal(intoB, want) {
		t.Errorf("merged notes = %q, want %q", intoB, want)
	}
	// and a sync of the same pair converges to that state too
	a3, b3 := syncDBs(t)
	seedConflicts(t, a3, b3)
	if got := syncConverged(t, a3, b3); !slices.Equal(got, intoB) {
		t.Errorf("sync = %q, merge = %q", got, intoB)
	}
}

// iz m reads a pre-v4 database (no uid/mtime columns, NUL-keyed and undated
// tombstones) through a migrated copy, from a path that needs URI escaping,
// and leaves the source untouched.
func TestMergePreV4Source(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "old.db") // built here, then moved to an awkward path
	src, err := sql.Open("sqlite", plain)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE runs(id INTEGER PRIMARY KEY, ts REAL NOT NULL, hostname TEXT NOT NULL, tool TEXT NOT NULL,
			cmd TEXT NOT NULL, cwd TEXT NOT NULL, exit_code INTEGER, duration_ms INTEGER, size INTEGER, raw BLOB)`,
		`CREATE VIRTUAL TABLE outputs_fts USING fts5(text)`,
		`CREATE TABLE memories(id INTEGER PRIMARY KEY, ts REAL NOT NULL, hostname TEXT NOT NULL, namespace TEXT NOT NULL,
			title TEXT NOT NULL, content TEXT NOT NULL, author TEXT NOT NULL, tags TEXT NOT NULL DEFAULT '')`,
		`CREATE VIRTUAL TABLE memories_fts USING fts5(title, content, namespace, tags)`,
		`CREATE TABLE tombstones(key TEXT PRIMARY KEY)`,
		`INSERT INTO memories VALUES(1, 1000, 'old', 'legacy', 'kept', 'from pre-v4', 'me', '')`,
		`INSERT INTO memories_fts(rowid, title, content, namespace, tags) VALUES(1, 'kept', 'from pre-v4', 'legacy', '')`,
		`INSERT INTO runs VALUES(1, 1600000000, 'old', 'httpx', 'httpx -l x', '/tmp', 0, 1, 1, NULL)`,
		`INSERT INTO outputs_fts(rowid, text) VALUES(1, 'old httpx httpx -l x legacyoutput')`,
	} {
		if _, err := src.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := src.Exec(`INSERT INTO tombstones VALUES(?)`, "r\x00kali\x001700000000\x00nmap\x00nmap -sV"); err != nil {
		t.Fatal(err)
	}
	src.Close()
	srcDir := filepath.Join(dir, "backup #1 ?50%")
	srcPath := filepath.Join(srcDir, "iz.db")
	if err := os.Mkdir(srcDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(plain, srcPath); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatal(err)
	}

	path := testDB(t)
	t.Setenv("IZ", path)
	mustInsert(t, path, sampleRun("nmap", "nmap -sV", "80/tcp open"), "80/tcp open") // deleted by the source
	for range 2 {                                                                    // idempotent
		if code := mergeCmd(srcPath); code != 0 {
			t.Fatalf("merge exit=%d", code)
		}
	}
	db, err := openDBAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if notes, _ := queryMemories(db, "ns:legacy", 10); len(notes) != 1 || notes[0].Content != "from pre-v4" {
		t.Errorf("legacy notes = %+v", notes)
	}
	if runs, _ := queryRuns(db, "nmap"); len(runs) != 0 {
		t.Errorf("legacy tombstone not applied: %+v", runs)
	}
	if runs, _ := queryRuns(db, "legacyoutput"); len(runs) != 1 {
		t.Errorf("legacy run not merged: %+v", runs)
	}
	if after, _ := os.ReadFile(srcPath); !bytes.Equal(before, after) {
		t.Error("merge modified the source database")
	}
}

// Expired tombstones still delete on the other side before they are pruned,
// fresh ones stay, undated ones get a date, and nothing comes back.
func TestPruneOnlyExpired(t *testing.T) {
	local, remote := syncDBs(t)
	old := putNote(t, local, "old", "ns", "old", 100)
	fresh := putNote(t, local, "fresh", "ns", "fresh", 100)
	if _, err := insertRun(local, sampleRun("nmap", "nmap -sV", "x"), gz([]byte("x")), []byte("x")); err != nil {
		t.Fatal(err)
	}
	syncConverged(t, local, remote)

	for _, id := range []int64{old, fresh} {
		if err := deleteMemory(local, id); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := deleteRuns(local, []int64{1}); n != 1 || err != nil {
		t.Fatalf("deleted %d runs (%v)", n, err)
	}
	expired := float64(time.Now().Add(-31 * 24 * time.Hour).Unix())
	runTomb := runKey("kali", 1700000000, "nmap", "nmap -sV")
	if _, err := local.Exec(`UPDATE tombstones SET ts=? WHERE key IN (?, ?)`, expired, memTomb("old"), runTomb); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Exec(`INSERT INTO tombstones(key, ts) VALUES('m:ghost', 0)`); err != nil {
		t.Fatal(err)
	}

	up, down, err := syncPair(bg, local, remote)
	if err != nil {
		t.Fatal(err)
	}
	if up.pruned != 2 || down.pruned != 2 {
		t.Errorf("pruned remote=%d local=%d, want 2 and 2", up.pruned, down.pruned)
	}
	for _, db := range []*sql.DB{local, remote} {
		var notes, runs int
		db.QueryRow(`SELECT count(*) FROM memories`).Scan(&notes) //nolint
		db.QueryRow(`SELECT count(*) FROM runs`).Scan(&runs)      //nolint
		if notes != 0 || runs != 0 {
			t.Errorf("deleted rows survive: %d notes, %d runs", notes, runs)
		}
		tombs, err := readTombs(bg, db)
		if err != nil {
			t.Fatal(err)
		}
		if len(tombs) != 2 || tombs["m:fresh"] == 0 || tombs["m:ghost"] == 0 {
			t.Errorf("tombstones after prune = %v (want m:fresh and a dated m:ghost)", tombs)
		}
	}

	up, down, err = syncPair(bg, local, remote)
	if err != nil || up.pruned+down.pruned+up.notes+down.notes+up.runs+down.runs != 0 {
		t.Errorf("second sync: up=%+v down=%+v err=%v", up, down, err)
	}
}

// A run the remote rejects neither stops the other runs going up nor the
// remote's runs coming down; the failed sync prunes nothing.
func TestSyncPartialRunPushDoesNotBlockPull(t *testing.T) {
	local, remote := syncDBs(t)
	if _, err := remote.Exec(`CREATE TRIGGER too_big BEFORE INSERT ON runs WHEN NEW.tool = 'huge'
		BEGIN SELECT RAISE(ABORT, 'payload too large'); END`); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Run{sampleRun("huge", "huge", ""), sampleRun("ok", "ok", "")} {
		if _, err := insertRun(local, r, gz(nil), nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := insertRun(remote, sampleRun("remote", "remote", ""), gz(nil), nil); err != nil {
		t.Fatal(err)
	}
	expired := float64(time.Now().Add(-31 * 24 * time.Hour).Unix())
	if _, err := local.Exec(`INSERT INTO tombstones(key, ts) VALUES('m:gone', ?)`, expired); err != nil {
		t.Fatal(err)
	}

	up, down, err := syncPair(bg, local, remote)
	if err == nil || !strings.Contains(err.Error(), "payload too large") {
		t.Fatalf("err = %v, want the rejected run reported", err)
	}
	if up.runs != 1 || down.runs != 1 {
		t.Errorf("runs up=%d down=%d, want 1 and 1", up.runs, down.runs)
	}
	if runs, _ := queryRuns(local, "tool:remote"); len(runs) != 1 {
		t.Errorf("remote run not pulled: %+v", runs)
	}
	for _, db := range []*sql.DB{local, remote} {
		if tombs, _ := readTombs(bg, db); tombs["m:gone"] == 0 {
			t.Error("expired tombstone pruned after an incomplete sync")
		}
	}
}

func TestTransferRunsStopsOnCancel(t *testing.T) {
	local, remote := syncDBs(t)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, err := transferRuns(ctx, local, remote, []any{1, 2}); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestSyncUnknownArgRejected(t *testing.T) {
	for _, args := range [][]string{{"--bogus"}, {"--prune", "now"}} {
		if code := syncCmd(args); code != 2 {
			t.Errorf("iz sync %q exit=%d, want 2", args, code)
		}
	}
}

// Remote JSON/HTTP float formatting can drop a trailing digit (e.g. .2044601
// vs .20446); syncPair must treat that as equal instead of re-uploading forever.
func TestSyncFloatPrecisionIdempotent(t *testing.T) {
	local, remote := syncDBs(t)
	putNote(t, local, "u1", "machines", "st20", 1795348751.2044601)
	putNote(t, remote, "u1", "machines", "st20", 1795348751.20446)

	up, down, err := syncPair(bg, local, remote)
	if err != nil {
		t.Fatal(err)
	}
	if up.notes != 0 || down.notes != 0 {
		t.Errorf("got up=%d down=%d, want 0/0 despite 1e-7 float rounding", up.notes, down.notes)
	}
}

// Run timestamps drifting by 1 ULP on a remote (.2044601 vs .20446) neither
// duplicate the run nor let it escape its tombstone, in sync and in merge.
func TestSyncRunFloatPrecisionIdempotent(t *testing.T) {
	const ts, drifted = 1795348751.2044601, 1795348751.20446
	put := func(t *testing.T, db *sql.DB, ts float64) int64 {
		t.Helper()
		r := sampleRun("nmap", "nmap -sV", "")
		r.Ts = ts
		id, err := insertRun(db, r, gz([]byte("out")), []byte("out"))
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	count := func(db *sql.DB) (n int) {
		db.QueryRow(`SELECT count(*) FROM runs`).Scan(&n) //nolint
		return n
	}
	syncQuiet := func(t *testing.T, local, remote *sql.DB) {
		t.Helper()
		for range 2 {
			if up, down, err := syncPair(bg, local, remote); err != nil || up.runs+down.runs != 0 {
				t.Fatalf("sync moved runs: up=%+v down=%+v err=%v", up, down, err)
			}
		}
	}

	t.Run("live runs", func(t *testing.T) {
		local, remote := syncDBs(t)
		put(t, local, ts)
		put(t, remote, drifted)
		syncQuiet(t, local, remote)
		if count(local) != 1 || count(remote) != 1 {
			t.Errorf("runs duplicated: local %d, remote %d", count(local), count(remote))
		}
		if added, skipped, err := copyRuns(bg, remote, local, nil); added != 0 || skipped != 1 || err != nil {
			t.Errorf("merge: added %d, skipped %d, err %v", added, skipped, err)
		}
	})

	t.Run("local tombstone, drifted remote row", func(t *testing.T) {
		local, remote := syncDBs(t)
		id := put(t, local, ts)
		put(t, remote, drifted)
		if n, err := deleteRuns(local, []int64{id}); n != 1 || err != nil {
			t.Fatalf("deleteRuns = %d, %v", n, err)
		}
		syncQuiet(t, local, remote)
		if count(local)+count(remote) != 0 {
			t.Errorf("deleted run resurrected: local %d, remote %d", count(local), count(remote))
		}
	})

	t.Run("drifted remote tombstone", func(t *testing.T) {
		local, remote := syncDBs(t)
		put(t, local, ts)
		key := runKey("kali", drifted, "nmap", "nmap -sV")
		if _, err := remote.Exec(`INSERT INTO tombstones(key, ts) VALUES(?, ?)`, key, now()); err != nil {
			t.Fatal(err)
		}
		syncQuiet(t, local, remote)
		if count(local)+count(remote) != 0 {
			t.Errorf("tombstoned run survives: local %d, remote %d", count(local), count(remote))
		}
		src, dst := syncDBs(t)
		put(t, src, ts)
		if added, skipped, err := copyRuns(bg, src, dst, map[string]bool{key: true}); added != 0 || skipped != 1 || err != nil {
			t.Errorf("merge past a drifted tombstone: added %d, skipped %d, err %v", added, skipped, err)
		}
	})

	// matches straddling a bucket boundary are still found; distinct runs not
	s := runSet{}
	s.add(Run{Hostname: "h", Tool: "t", Cmd: "c", Ts: 1795348751.2045 - 2e-6})
	if !s.has(Run{Hostname: "h", Tool: "t", Cmd: "c", Ts: 1795348751.2045 + 2e-6}) {
		t.Error("match across a bucket boundary missed")
	}
	if s.has(Run{Hostname: "h", Tool: "t", Cmd: "c", Ts: 1795348751.2046}) || s.has(Run{Hostname: "h", Tool: "t", Cmd: "x", Ts: 1795348751.2045}) {
		t.Error("distinct run matched")
	}
}

// Two notes created offline on one title (different machines, real uids)
// are both kept: the newer keeps the title, the older moves to "title (uid8)".
func TestSyncOfflineSameTitlePreservesBoth(t *testing.T) {
	local, remote := syncDBs(t)
	putNote(t, local, "aaaa1111bbbb2222", "proj", "todo", 100)
	putNote(t, remote, "cccc3333dddd4444", "proj", "todo", 200)
	got := syncConverged(t, local, remote)
	want := []string{
		"aaaa1111bbbb2222 proj:todo (aaaa1111) @200.001 body of aaaa1111bbbb2222",
		"cccc3333dddd4444 proj:todo @200 body of cccc3333dddd4444",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// iz sync rebuilds a note index an older client left out of step, on either
// side (syncConverged fails on an index not mirroring the notes).
func TestSyncRepairsNoteIndex(t *testing.T) {
	local, remote := syncDBs(t)
	putNote(t, local, "u1", "ns", "a", 100)
	putNote(t, remote, "u2", "ns", "b", 100)
	for _, db := range []*sql.DB{local, remote} {
		if _, err := db.Exec(`DELETE FROM memories_fts`); err != nil {
			t.Fatal(err)
		}
	}
	syncConverged(t, local, remote)
	if ms, err := queryMemories(local, "body", 10); err != nil || len(ms) != 2 {
		t.Errorf("search after repair: %d notes (%v)", len(ms), err)
	}
}

func TestSanitizeURL(t *testing.T) {
	if got := sanitizeURL("libsql://u:pw@db.turso.io?authToken=secret"); strings.Contains(got, "secret") || strings.Contains(got, "pw") {
		t.Errorf("credentials shown: %q", got)
	}
	if got := sanitizeURL("libsql://db\x7f.io?authToken=secret"); strings.Contains(got, "secret") {
		t.Errorf("unparsable URL shown raw: %q", got)
	}
}

// A hanging atuin cannot stall iz sync's config lookup.
func TestAtuinKVGetTimeout(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "atuin"), []byte("#!/bin/sh\nexec sleep 10\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	old := atuinTimeout
	atuinTimeout = 100 * time.Millisecond
	t.Cleanup(func() { atuinTimeout = old })
	start := time.Now()
	if v := atuinKVGet("IZ_SYNC_URL"); v != "" {
		t.Errorf("got %q", v)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("atuin not timed out (took %s)", d)
	}
}
