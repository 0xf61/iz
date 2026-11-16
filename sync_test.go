package main

import (
	"context"
	"path/filepath"
	"testing"
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
