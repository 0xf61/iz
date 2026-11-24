package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

// Memory is a structured note, fact, runbook, or agent decision.
type Memory struct {
	ID        int64   `json:"id"`
	Ts        float64 `json:"ts"`
	Date      string  `json:"date,omitempty"`
	Hostname  string  `json:"hostname"`
	Namespace string  `json:"namespace"` // e.g. "user", "machines", "lessons", "pentest"
	Title     string  `json:"title"`
	Content   string  `json:"content"`
	Author    string  `json:"author"` // e.g. "user", "claude", "agent"
	Tags      string  `json:"tags,omitempty"`
	UID       string  `json:"-"`               // identity across machines
	Mtime     float64 `json:"mtime,omitempty"` // last edit (sync: last write wins)
	TagsSet   bool    `json:"-"`
}

func now() float64 { return unixTime(time.Now()) }

// unixTime is t in unix seconds at millisecond precision: at most 13
// significant digits, which survive a remote's JSON float round trip intact
// (nanoseconds would fill the mantissa, and lose its last digit there).
func unixTime(t time.Time) float64 { return float64(t.UnixMilli()) / 1e3 }

func isTTY() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func newUID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint
	return hex.EncodeToString(b)
}

// insertMemory writes or updates a memory (by namespace+title) atomically.
func insertMemory(db *sql.DB, m Memory) (int64, error) {
	id, _, err := upsertMemory(db, m, false)
	return id, err
}

func upsertMemory(db *sql.DB, m Memory, appendMode bool) (int64, string, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, "", err
	}
	defer tx.Rollback() //nolint
	id, status, err := upsertMemoryTx(tx, m, appendMode)
	if err != nil {
		return 0, "", err
	}
	return id, status, tx.Commit()
}

func upsertMemoryTx(ex dbtx, m Memory, appendMode bool) (int64, string, error) {
	var old Memory
	err := ex.QueryRowContext(bg, `SELECT id, content, tags FROM memories WHERE namespace=? AND title=?`,
		m.Namespace, m.Title).Scan(&old.ID, &old.Content, &old.Tags)
	switch {
	case err == sql.ErrNoRows:
		id, err := insertMemoryTx(ex, m)
		return id, "saved", err
	case err != nil:
		return 0, "", err
	}
	m.ID = old.ID
	if appendMode && old.Content != "" {
		m.Content = strings.TrimRight(old.Content, "\n") + "\n" + m.Content
	}
	if m.Tags == "" && !m.TagsSet {
		m.Tags = old.Tags
	}
	if m.Content == old.Content && normTags(m.Tags) == old.Tags {
		return old.ID, "unchanged", nil
	}
	return old.ID, "updated", updateMemoryTx(ex, m)
}

// defaultAuthor is who writes a note when no author is given.
func defaultAuthor() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "user"
}

// normTags trims tags and drops empty ones: "a, b,," → "a,b".
func normTags(s string) string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return strings.Join(out, ",")
}

func insertMemoryTx(ex dbtx, m Memory) (int64, error) {
	if m.Ts == 0 {
		m.Ts = now()
	}
	if m.Mtime == 0 {
		m.Mtime = m.Ts
	}
	if m.UID == "" {
		m.UID = newUID()
	}
	if m.Hostname == "" {
		m.Hostname = hostname()
	}
	if m.Author == "" {
		m.Author = defaultAuthor()
	}
	res, err := ex.ExecContext(bg, `
		INSERT INTO memories(uid, ts, mtime, hostname, namespace, title, content, author, tags)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.UID, m.Ts, m.Mtime, m.Hostname, m.Namespace, m.Title, m.Content, m.Author, normTags(m.Tags))
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, reindexMemory(ex, id)
}

// updateMemoryTx rewrites a note's editable fields (namespace, title,
// content, tags, and author when given) and its FTS row; ts (creation) and
// uid never change.
func updateMemoryTx(ex dbtx, m Memory) error {
	if m.Mtime == 0 {
		m.Mtime = now()
	}
	return updateNoteRow(ex, m.ID, `UPDATE memories SET namespace=?, title=?, content=?, tags=?,
		author=coalesce(nullif(?, ''), author), mtime=? WHERE id=?`,
		m.Namespace, m.Title, m.Content, normTags(m.Tags), m.Author, m.Mtime, m.ID)
}

// updateNoteRow runs an UPDATE of note id and refreshes its FTS row.
func updateNoteRow(ex dbtx, id int64, q string, args ...any) error {
	res, err := ex.ExecContext(bg, q, args...)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return fmt.Errorf("note #%d not found", id)
	}
	return reindexMemory(ex, id)
}

// reindexMemory rebuilds the FTS row of note id from the table.
func reindexMemory(ex dbtx, id int64) error {
	if _, err := ex.ExecContext(bg, `DELETE FROM memories_fts WHERE rowid=?`, id); err != nil {
		return err
	}
	_, err := ex.ExecContext(bg, `INSERT INTO memories_fts(rowid, title, content, namespace, tags)
		SELECT id, title, content, namespace, tags FROM memories WHERE id=?`, id)
	return err
}

func updateMemory(db *sql.DB, m Memory) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint
	if err := updateMemoryTx(tx, m); err != nil {
		return err
	}
	return tx.Commit()
}

// deleteMemory removes a memory and its FTS row, leaving a tombstone.
func deleteMemory(db *sql.DB, id int64) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint
	var uid string
	if err := tx.QueryRow(`SELECT `+uidCol+` FROM memories WHERE id=?`, id).Scan(&uid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("note #%d not found", id)
		}
		return err
	}
	if err := tombstone(tx, memTomb(uid)); err != nil {
		return err
	}
	if err := purge(bg, tx, "memories", "memories_fts", []any{id}); err != nil {
		return err
	}
	return tx.Commit()
}

func getMemory(db *sql.DB, id int64) (m Memory, err error) {
	err = db.QueryRow(`SELECT id, ts, mtime, hostname, namespace, title, content, author, tags FROM memories WHERE id=?`, id).
		Scan(&m.ID, &m.Ts, &m.Mtime, &m.Hostname, &m.Namespace, &m.Title, &m.Content, &m.Author, &m.Tags)
	m.Date = fmtTs(m.Ts)
	return m, err
}

// resolveMemoryID accepts either a numeric ID ("42") or "namespace:title".
func resolveMemoryID(db *sql.DB, target string) (int64, error) {
	if id, err := strconv.ParseInt(target, 10, 64); err == nil {
		return id, nil
	}
	ns, title := parseTarget(target)
	if title == "" {
		return 0, fmt.Errorf("invalid note target %q", target)
	}
	var id int64
	if err := db.QueryRow(`SELECT id FROM memories WHERE namespace=? AND title=?`, ns, title).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, fmt.Errorf("note %q not found", target)
		}
		return 0, err
	}
	return id, nil
}

// queryMemories searches the memories table via FTS5; ns:/author:/tag:/host:
// filter on columns. Run filters (cmd:, dir:...) belong to the other side of
// recall and are ignored.
func queryMemories(db *sql.DB, query string, limit int) ([]Memory, error) {
	if limit <= 0 {
		limit = 20
	}
	var conds string
	var args []any
	var terms []string
	for _, t := range strings.Fields(query) {
		val := t[strings.IndexByte(t, ':')+1:]
		switch {
		case strings.HasPrefix(t, "ns:"), strings.HasPrefix(t, "namespace:"):
			if v := strings.TrimRight(val, "/"); v != "" {
				conds += ` AND (m.namespace = ? OR m.namespace LIKE ? ESCAPE '\')`
				args = append(args, v, likeEsc(v)+"/%")
			}
		case strings.HasPrefix(t, "author:"):
			c, a := likePrefix("m.author", val)
			conds, args = conds+c, append(args, a)
		case strings.HasPrefix(t, "host:"):
			c, a := likePrefix("m.hostname", val)
			conds, args = conds+c, append(args, a)
		case strings.HasPrefix(t, "tag:"), strings.HasPrefix(t, "tags:"):
			// whole tag, tolerant of "a, b" lists written by older versions
			conds += ` AND (',' || replace(m.tags, ' ', '') || ',') LIKE ? ESCAPE '\'`
			args = append(args, "%,"+likeEsc(val)+",%")
		case hasPrefixAny(t, runFilters):
		default:
			terms = append(terms, t)
		}
	}
	const cols = `SELECT m.id, m.ts, m.mtime, m.hostname, m.namespace, m.title, m.content, m.author, m.tags FROM memories m`
	const join = ` JOIN memories_fts f ON f.rowid = m.id`
	recent := ` ORDER BY max(m.mtime, m.ts) DESC, m.id DESC LIMIT ?`

	if len(terms) == 0 {
		return scanMemories(db, cols+" WHERE 1=1"+conds+recent, append(args, limit))
	}
	where, wargs, fts := matchFTS(db, "memories_fts", terms,
		`(m.title LIKE ? ESCAPE '\' OR m.content LIKE ? ESCAPE '\' OR m.tags LIKE ? ESCAPE '\')`, 3)
	from, order := cols, recent
	if fts {
		from, order = cols+join, ` ORDER BY rank LIMIT ?`
	}
	res, err := scanMemories(db, from+" WHERE "+where+conds+order, concat(wargs, args, []any{limit}))
	if err == nil && len(res) == 0 {
		if orQ := orFallback(db, "memories_fts", terms); orQ != "" {
			res, err = scanMemories(db, cols+join+` WHERE memories_fts MATCH ?`+conds+` ORDER BY bm25(memories_fts) LIMIT ?`,
				concat([]any{orQ}, args, []any{limit}))
		}
	}
	return res, err
}

func scanMemories(db *sql.DB, query string, args []any) ([]Memory, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Memory
	for rows.Next() {
		var m Memory
		if err := rows.Scan(&m.ID, &m.Ts, &m.Mtime, &m.Hostname, &m.Namespace, &m.Title, &m.Content, &m.Author, &m.Tags); err != nil {
			return nil, err
		}
		m.Date = fmtTs(m.Ts)
		out = append(out, m)
	}
	return out, rows.Err()
}

// tuiNotes runs an interactive fzf interface for searching, previewing, and editing notes.
//
//	enter   → view note in less -R
//	ctrl-e  → edit note in $EDITOR
//	ctrl-n  → create a new note in $EDITOR
//	ctrl-y  → delete note
func tuiNotes(query string) int {
	if !isTTY() {
		fmt.Fprintln(os.Stderr, "iz n: interactive TUI requires a terminal (use 'iz n list' or 'iz recall <query>' instead)")
		return 2
	}
	iz, _ := os.Executable()
	if iz == "" {
		iz = "iz"
	}
	izCmd := "'" + strings.ReplaceAll(iz, "'", `'\''`) + "'"
	src := izCmd + " n lines {q}"
	args := []string{
		"--ansi",
		"--phony",
		"--color", "hl:-1,hl+:-1",
		"--info", "inline",
		"--header", "⏎ view · ^N new · ^E edit · ^Y del · esc exit",
		"--bind", "start:reload(" + src + ")",
		"--bind", "change:reload(" + src + ")",
		"--preview", izCmd + " n show {1}",
		"--preview-window", "right:60%:wrap",
		"--bind", "enter:execute(" + izCmd + " n show {1} | less -R)",
		"--bind", "ctrl-e:execute(" + izCmd + " n edit {1})+reload(" + src + ")",
		"--bind", "ctrl-n:execute(" + izCmd + " n new)+reload(" + src + ")",
		"--bind", "ctrl-y:execute-silent(" + izCmd + " n del {1})+reload(" + src + ")",
		"--query", query,
	}

	c := exec.Command("fzf", args...)
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	return fzfExit(c.Run())
}

// fzfExit is iz's exit code after fzf ran: fzf's own non-zero exits (esc,
// no match) are normal, failing to run it at all is an error.
func fzfExit(err error) int {
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		fmt.Fprintln(os.Stderr, "iz: fzf:", err)
		return 2
	}
	return 0
}

// notesLines is the reload source of the notes TUI: id, ns:title (padded to
// the widest shown, capped), one-line snippet. Author/date are in the preview.
func notesLines(query string) int {
	db, err := openDB()
	if err != nil {
		return 1
	}
	defer db.Close()

	memories, err := queryMemories(db, query, 250)
	if err != nil {
		return 1
	}
	w := 0
	for i := range memories {
		memories[i].Title = trunc(memories[i].Namespace+":"+memories[i].Title, 32)
		w = max(w, len([]rune(memories[i].Title)))
	}
	var b strings.Builder
	for _, m := range memories {
		fmt.Fprintf(&b, "%d \x1b[36m%-*s\x1b[0m \x1b[2m%s\x1b[0m\n", m.ID, w, m.Title, trunc(oneLine(m.Content), 80))
	}
	os.Stdout.WriteString(b.String()) //nolint
	return 0
}

// Note documents (editor): the first line is "# ns:title [tag1,tag2]", the
// rest is the content.
const noteHint = "# (First line above is namespace:title [tags]. Write note/creds/findings below. Save and close)"

func noteDoc(m Memory) string {
	h := "# " + m.Namespace + ":" + m.Title
	if m.Tags != "" || strings.HasSuffix(m.Title, "]") { // "[]" keeps a title ending in ']' intact
		h += " [" + m.Tags + "]"
	}
	return h + "\n\n" + m.Content + "\n"
}

// parseNoteDoc splits a note document; ok=false when there is no header line.
func parseNoteDoc(text string) (ns, title, tags, body string, ok bool) {
	lines := strings.Split(text, "\n")
	var rest []string
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" && !ok && len(rest) == 0 {
			continue
		}
		if !ok && len(rest) == 0 && strings.HasPrefix(t, "#") {
			ns, title, tags = parseHeader(strings.TrimLeft(t, "# "))
			ok = true
			continue
		}
		if t == noteHint {
			continue
		}
		rest = append(rest, l)
	}
	return ns, title, tags, strings.TrimSpace(strings.Join(rest, "\n")), ok
}

// parseHeader reads a note document header: "ns:title [tags]".
func parseHeader(h string) (ns, title, tags string) {
	h = strings.TrimSpace(h)
	if i := strings.LastIndex(h, " ["); i >= 0 && strings.HasSuffix(h, "]") {
		h, tags = h[:i], normTags(h[i+2:len(h)-1])
	}
	ns, title = parseTarget(h)
	return ns, title, tags
}

// parseTarget reads "ns:title". The first ':' splits, so titles may contain
// colons ("guide:Faz 1: Setup") and namespaces slashes ("projeler/aktif:x").
// Without a colon the last '/' splits ("machines/kali"). A bare title or an
// empty namespace means "notes".
func parseTarget(s string) (ns, title string) {
	s = strings.TrimSpace(s)
	i := strings.IndexByte(s, ':')
	if i < 0 {
		i = strings.LastIndexByte(s, '/')
	}
	title = s
	if i >= 0 {
		ns, title = strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
	}
	if ns == "" {
		ns = "notes"
	}
	return ns, title
}

func editNoteCmd(target string) int {
	if !isTTY() {
		fmt.Fprintln(os.Stderr, "iz n edit: interactive editor requires a terminal (use 'iz n <ns:title> \"content\"' to update)")
		return 2
	}
	db, err := openDB()
	if err != nil {
		return 2
	}
	defer db.Close()

	id, err := resolveMemoryID(db, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "iz: %v\n", err)
		return 1
	}

	m, err := getMemory(db, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Fprintf(os.Stderr, "iz: note #%d not found\n", id)
		} else {
			fmt.Fprintln(os.Stderr, "iz:", err)
		}
		return 1
	}
	text, err := editText(fmt.Sprintf("iz-note-%d-*.md", id), noteDoc(m))
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz: editor:", err)
		return 1
	}
	ns, title, tags, body, ok := parseNoteDoc(text)
	if body == "" {
		return 0 // emptied: keep the note (delete is explicit)
	}
	e := m
	if ok && title != "" {
		e.Namespace, e.Title, e.Tags = ns, title, tags
	}
	e.Content = body
	if e == m {
		return 0
	}
	e.Mtime = 0
	if err := updateMemory(db, e); err != nil {
		if tmp, werr := os.CreateTemp("", fmt.Sprintf("iz-note-%d-*.md", id)); werr == nil {
			_, werr = tmp.WriteString(text)
			cerr := tmp.Close()
			if werr == nil && cerr == nil {
				fmt.Fprintf(os.Stderr, "iz: update failed: %v (saved edit to %s)\n", err, tmp.Name())
				return 1
			}
			_ = os.Remove(tmp.Name())
		}
		fmt.Fprintf(os.Stderr, "iz: update failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[iz] note #%d updated\n", id)
	return 0
}

// editText opens content in the editor and returns the saved text.
func editText(pattern, content string) (string, error) {
	tmp, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString(content) //nolint
	tmp.Close()
	if err := runEditor(tmp.Name()); err != nil {
		return "", err
	}
	b, err := os.ReadFile(tmp.Name())
	return string(b), err
}

func newNoteCmd() int {
	if !isTTY() {
		fmt.Fprintln(os.Stderr, "iz n new: interactive editor requires a terminal (use 'iz n <ns:title> \"content\"' instead)")
		return 2
	}
	// A fresh, dated default title: keeping the header unchanged must not
	// land on (and overwrite) some existing note.
	untitled := "note-" + time.Now().Format("20060102-150405")
	text, err := editText("iz-new-note-*.md", "# notes:"+untitled+"\n"+noteHint+"\n\n")
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz: editor:", err)
		return 1
	}
	ns, title, tags, body, ok := parseNoteDoc(text)
	if body == "" {
		fmt.Fprintln(os.Stderr, "[iz] empty note discarded.")
		return 0
	}
	if !ok || title == "" {
		ns, title = "notes", untitled
	}
	return saveNote(Memory{Namespace: ns, Title: title, Tags: tags, TagsSet: true, Content: body}, false, true)
}

// numbered renders the n-th (n ≥ 2) variant of a taken title: "x (2)".
func numbered(title string, n int) string { return fmt.Sprintf("%s (%d)", title, n) }

// freeTitle returns title, or its first numbered variant not yet used in ns.
func freeTitle(db *sql.DB, ns, title string) (string, error) {
	for n := 1; ; n++ {
		t := title
		if n > 1 {
			t = numbered(title, n)
		}
		err := db.QueryRow(`SELECT 1 FROM memories WHERE namespace=? AND title=?`, ns, t).Scan(new(int))
		if err == sql.ErrNoRows {
			return t, nil
		}
		if err != nil {
			return "", err
		}
	}
}

// saveNote upserts m by (namespace, title); appendMode appends the content to
// an existing note, create never touches one (a taken title gets numbered).
func saveNote(m Memory, appendMode, create bool) int {
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer db.Close()
	if create {
		if m.Title, err = freeTitle(db, m.Namespace, m.Title); err != nil {
			fmt.Fprintln(os.Stderr, "iz:", err)
			return 1
		}
	}
	if m.Author == "" {
		m.Author = defaultAuthor()
	}
	id, status, err := upsertMemory(db, m, appendMode)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz: failed to save note:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[iz] %s note #%d [%s:%s]\n", status, id, m.Namespace, m.Title)
	return 0
}

// noteCmd handles `iz note` / `iz n` subcommands:
//
//	iz n                                  interactive TUI search & management
//	iz n <ns:title> [-t tag,..] [content] save note (content may be piped)
//	iz n edit <id>                        open in $EDITOR (title/tags too)
//	iz n new                              create note in $EDITOR
//	iz n lines [query]                    internal reload source for TUI
//	iz n import <file|dir>                import markdown
//	iz n list [namespace]                 list notes
//	iz n del <id>                         delete note
//	iz n show <id>                        print note
func noteCmd(args []string) int {
	if len(args) == 0 {
		return tuiNotes("")
	}

	switch args[0] {
	case "-h", "--help", "help":
		fmt.Println(`iz n — structured notes & AI memory

Usage:
  iz n                                       interactive notes TUI (TTY only)
  iz n <ns:title> [-t tags] [-a] [content]   create or update note (upsert by ns:title);
                                             trailing -t/-a after one content arg apply
                                             only when nothing else follows them; '--'
                                             forces everything after it to be content:
                                             iz n tools:ffuf -- ffuf -u URL -t 50
  iz n show <id|ns:title>                    print full note content
  iz n edit <id|ns:title>                    edit note in $EDITOR (TTY only)
  iz n del <id|ns:title>                     delete note
  iz n list [namespace]                      list saved notes
  iz n index                                 compact namespace/title index
  iz n import <file|dir>                     import markdown files into memory`)
		return 0
	case "lines":
		return notesLines(strings.Join(args[1:], " "))
	case "edit", "e":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: iz n edit <id|ns:title>")
			return 2
		}
		return editNoteCmd(args[1])
	case "new":
		return newNoteCmd()
	case "import", "i":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: iz note import <file|dir>")
			return 2
		}
		return importNotes(args[1])
	case "list", "l":
		return listNotes(strings.Join(args[1:], " "))
	case "index", "idx":
		return primeCmd(args[1:])
	case "del", "rm":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: iz note del <id|ns:title>")
			return 2
		}
		db, err := openDB()
		if err != nil {
			fmt.Fprintln(os.Stderr, "iz:", err)
			return 2
		}
		defer db.Close()
		id, err := resolveMemoryID(db, args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "iz:", err)
			return 1
		}
		if err := deleteMemory(db, id); err != nil {
			fmt.Fprintln(os.Stderr, "iz:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "[iz] memory #%d deleted\n", id)
		return 0
	case "show", "s":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: iz note show <id|ns:title>")
			return 2
		}
		db, err := openDB()
		if err != nil {
			fmt.Fprintln(os.Stderr, "iz:", err)
			return 2
		}
		defer db.Close()
		id, err := resolveMemoryID(db, args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "iz:", err)
			return 1
		}
		m, err := getMemory(db, id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				fmt.Fprintf(os.Stderr, "iz: note #%d not found\n", id)
			} else {
				fmt.Fprintln(os.Stderr, "iz:", err)
			}
			return 1
		}
		tags := ""
		if m.Tags != "" {
			tags = " · " + m.Tags
		}
		fmt.Printf("\x1b[1;36m#%d %s:%s\x1b[0m \x1b[90m· @%s · %s · %s%s\x1b[0m\n%s\n",
			m.ID, m.Namespace, m.Title, m.Author, m.Hostname, noteDates(m), tags, m.Content)
		return 0
	}

	// Adding or updating a note: `iz n [-t tags] [-a] <target> [content...]`.
	// Flags are recognized before the content, and after a single content
	// argument only when the remaining args are purely flags (`x:y "text" -a`).
	// Unquoted commands (`tools:ffuf ffuf -t 50 -u URL`) stay verbatim, and
	// "--" forces the rest to be content.
	var tags string
	tagsSet, appendMode := false, false
	var pos []string
flags:
	for i := 0; i < len(args); i++ {
		if len(pos) >= 3 {
			pos = append(pos, args[i:]...)
			break
		}
		if len(pos) == 2 && args[i] != "--" && !trailingFlagsOnly(args[i:]) {
			pos = append(pos, args[i:]...)
			break
		}
		switch args[i] {
		case "--":
			pos = append(pos, args[i+1:]...)
			break flags
		case "-t", "--tags":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "iz n: -t needs a value (comma-separated tags)")
				return 2
			}
			tags, tagsSet = args[i+1], true
			i++
		case "-a", "--append":
			appendMode = true
		default:
			pos = append(pos, args[i])
		}
	}
	if len(pos) == 0 {
		fmt.Fprintln(os.Stderr, "usage: iz n <ns:title> [-t tags] [-a] [content]")
		return 2
	}

	m := Memory{Tags: tags, TagsSet: tagsSet}
	if m.Namespace, m.Title = parseTarget(pos[0]); m.Title == "" {
		fmt.Fprintf(os.Stderr, "iz n: invalid note target %q (want namespace:title)\n", pos[0])
		return 2
	}
	words := pos[1:]
	content := strings.Join(words, " ")
	if len(words) == 0 {
		// Read from stdin if piped
		if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice == 0 {
			if b, err := io.ReadAll(os.Stdin); err == nil {
				content = string(b)
			}
		}
	}
	m.Content = strings.TrimSpace(content)
	if m.Content == "" {
		fmt.Fprintln(os.Stderr, "iz: note content cannot be empty (provide text or pipe via stdin)")
		return 2
	}
	return saveNote(m, appendMode, false)
}

func trailingFlagsOnly(rest []string) bool {
	for j := 0; j < len(rest); j++ {
		switch rest[j] {
		case "-a", "--append":
		case "-t", "--tags":
			j++
		default:
			return false
		}
	}
	return true
}

// noteDates renders when a note was created and, if later, last updated.
func noteDates(m Memory) string {
	d := fmtTsShort(m.Ts)
	if m.Mtime > m.Ts+1 {
		d += " · updated " + fmtTsShort(m.Mtime)
	}
	return d
}

// listNotes prints one aligned line per note: id, ns:title, last update, size.
func listNotes(namespace string) int {
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer db.Close()

	q := "SELECT id, max(mtime, ts), namespace, title, author, length(content) FROM memories WHERE 1=1"
	var args []any
	if namespace = strings.TrimRight(namespace, "/"); namespace != "" { // it and its sub-namespaces
		q += ` AND (namespace = ? OR namespace LIKE ? ESCAPE '\')`
		args = append(args, namespace, likeEsc(namespace)+"/%")
	}
	rows, err := db.Query(q+" ORDER BY namespace, title, ts DESC", args...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	defer rows.Close()

	type row struct {
		id     int64
		name   string
		author string
		date   string
		size   int64
	}
	var out []row
	w := 0
	for rows.Next() {
		var r row
		var ts float64
		var ns, title string
		if err := rows.Scan(&r.id, &ts, &ns, &title, &r.author, &r.size); err != nil {
			fmt.Fprintln(os.Stderr, "iz:", err)
			return 1
		}
		r.name, r.date = trunc(ns+":"+title, 40), fmtTsShort(ts)
		w = max(w, len([]rune(r.name)))
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	if len(out) == 0 {
		fmt.Fprintln(os.Stderr, "No notes found.")
		return 0
	}
	for _, r := range out {
		fmt.Printf("%4d  %-*s  %-11s  %-6s  @%s\n", r.id, w, r.name, r.date, humanBytes(r.size), r.author)
	}
	return 0
}

// importNotes walks a file or directory and imports markdown sections as
// memories, in one transaction: any error imports nothing.
func importNotes(path string) int {
	fi, err := os.Stat(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}

	files := []string{path}
	if fi.IsDir() {
		files = nil
		err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(d.Name(), ".md") {
				files = append(files, p)
			}
			return err
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "iz:", err)
			return 1
		}
	}

	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	defer tx.Rollback() //nolint

	imported := 0
	updated := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, "iz:", err)
			return 1
		}
		ns := strings.TrimSuffix(filepath.Base(f), ".md")
		if fi.IsDir() {
			if rel, err := filepath.Rel(path, f); err == nil {
				ns = strings.TrimSuffix(filepath.ToSlash(rel), ".md")
			}
		}
		ns = strings.ReplaceAll(ns, ":", "-") // keep "ns:title" targets unambiguous
		seen := map[string]bool{}
		for _, sec := range splitMarkdown(string(data), ns) {
			// a repeated heading in one file is its own note, not an overwrite;
			// generated titles count too ("Foo", "Foo (2)", "Foo" → "Foo (3)")
			title := sec.title
			for n := 2; seen[title]; n++ {
				title = numbered(sec.title, n)
			}
			seen[title] = true
			m := Memory{Namespace: ns, Title: title, Content: sec.body, Author: "import"}
			_, status, err := upsertMemoryTx(tx, m, false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "iz: import %s [%s]: %v (nothing imported)\n", f, title, err)
				return 1
			}
			switch status {
			case "saved":
				imported++
			case "updated":
				updated++
			}
		}
	}
	if err := tx.Commit(); err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[iz] imported %d new, updated %d notes from %s\n", imported, updated, path)
	return 0
}

type mdSection struct{ title, body string }

// splitMarkdown splits a markdown document into titled sections: at "§"
// marker lines ("§" alone or "§ …") when the document has any, otherwise at
// "#"/"##" headings. Lines inside fenced code blocks never split. A heading
// becomes the title and is not repeated in the body; text before the first
// heading is titled defTitle. A § section is titled by its first line: a
// heading moves out of the body, plain text stays and is abbreviated.
func splitMarkdown(text, defTitle string) []mdSection {
	lines := strings.Split(text, "\n")
	isMark := func(l string) bool { return strings.TrimRight(l, " \t\r") == "§" || strings.HasPrefix(l, "§ ") }
	marks := false
	var fence codeFence
	for _, l := range lines {
		if !fence.inside(l) && isMark(l) {
			marks = true
			break
		}
	}

	var out []mdSection
	title := defTitle
	var body []string
	flush := func() {
		b := strings.TrimSpace(strings.Join(body, "\n"))
		t := title
		if marks {
			first, rest, _ := strings.Cut(b, "\n")
			if h, ok := headingText(first, 6); ok {
				t, b = h, strings.TrimSpace(rest)
			} else {
				t = trunc(strings.TrimSpace(first), 40)
			}
		}
		if t != "" && b != "" {
			out = append(out, mdSection{t, b})
		}
		body = nil
	}
	fence = codeFence{}
	for _, l := range lines {
		if fence.inside(l) {
			body = append(body, l)
			continue
		}
		if marks && isMark(l) {
			flush()
			l = strings.TrimSpace(strings.TrimPrefix(l, "§")) // rest of the marker line is content
		} else if h, ok := headingText(l, 2); ok && !marks {
			flush()
			title = h
			continue
		}
		body = append(body, l)
	}
	flush()
	return out
}

// headingText returns the text of an ATX heading ("## Title") of level ≤ max.
func headingText(l string, max int) (string, bool) {
	n := len(l) - len(strings.TrimLeft(l, "#"))
	if n == 0 || n > max || n == len(l) || l[n] != ' ' && l[n] != '\t' {
		return "", false
	}
	h := strings.TrimSpace(l[n:])
	return h, h != "" // an empty heading would title (and so drop) the text after it
}

// codeFence tracks fenced code blocks: ``` and ~~~ fences are independent,
// and a block closes only with the same character, at least as long. As in
// CommonMark, a backtick fence's info string has no backticks, so a line
// like "```inline``` text" is not a fence.
type codeFence struct{ open string }

// inside reports whether line is a fence line or inside a code block.
func (f *codeFence) inside(line string) bool {
	t := strings.TrimSpace(line)
	if f.open != "" {
		if len(t) >= len(f.open) && strings.Trim(t, f.open[:1]) == "" {
			f.open = ""
		}
		return true
	}
	for _, c := range []string{"`", "~"} {
		if n := len(t) - len(strings.TrimLeft(t, c)); n >= 3 && !(c == "`" && strings.Contains(t[n:], "`")) {
			f.open = strings.Repeat(c, n)
			return true
		}
	}
	return false
}

// recallCmd searches both memories and runs for AI agents or terminal queries:
//
//	iz recall <query> [--json] [--pretty] [--notes-only] [--runs-only] [-l N] [--full]
//
// A filter that only one side understands (cmd:, size:... vs ns:, tag:...)
// limits the search to that side.
func recallCmd(args []string) int {
	const usage = "usage: iz recall <query> [--json] [--pretty] [--notes-only] [--runs-only] [-l N] [--full]"
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}

	jsonOutput, pretty, notesOnly, runsOnly, full := false, false, false, false, false
	limit, limitSet := 10, false
	var queryTerms []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--":
			queryTerms = append(queryTerms, args[i+1:]...)
			i = len(args)
		case "-h", "--help":
			fmt.Println(usage)
			return 0
		case "--json", "-j":
			jsonOutput = true
		case "--pretty", "-p":
			jsonOutput, pretty = true, true
		case "--notes-only", "-n":
			notesOnly = true
		case "--runs-only", "-r":
			runsOnly = true
		case "--full", "-f":
			full = true
		case "-l", "--limit":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, usage)
				return 2
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n <= 0 {
				fmt.Fprintf(os.Stderr, "iz recall: invalid limit %q\n", args[i+1])
				return 2
			}
			limit = n
			limitSet = true
			i++
		default:
			queryTerms = append(queryTerms, a)
		}
	}

	query := strings.Join(queryTerms, " ")
	if query == "" {
		fmt.Fprintln(os.Stderr, "iz: empty recall query")
		return 2
	}
	// Explicit -n/-r win; otherwise a filter only one side understands
	// (cmd:, size:… vs ns:, tag:…) limits the search to that side.
	if !runsOnly && !notesOnly {
		for _, t := range strings.Fields(query) {
			runsOnly = runsOnly || hasPrefixAny(t, runFilters)
			notesOnly = notesOnly || hasPrefixAny(t, memFilters)
		}
	}
	if runsOnly && notesOnly {
		runsOnly, notesOnly = false, false
	}

	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer db.Close()

	var memories []Memory
	if !runsOnly {
		if memories, err = queryMemories(db, query, limit); err != nil {
			fmt.Fprintln(os.Stderr, "iz recall: notes:", err)
			return 1
		}
	}
	var runs []Run
	if !notesOnly {
		runLimit := limit
		if !runsOnly && !limitSet {
			runLimit = min(limit, 5)
		}
		if runs, err = searchRuns(db, query, runLimit, true); err != nil {
			fmt.Fprintln(os.Stderr, "iz recall: runs:", err)
			return 1
		}
	}

	if jsonOutput {
		type runJSON struct {
			ID    int64  `json:"id"`
			Date  string `json:"date"`
			Host  string `json:"host"`
			Tool  string `json:"tool"`
			Cmd   string `json:"cmd"`
			Cwd   string `json:"cwd"`
			Exit  *int64 `json:"exit,omitempty"`
			DurMs *int64 `json:"dur_ms,omitempty"`
			Size  int64  `json:"size,omitempty"`
			Match string `json:"match,omitempty"`
		}
		res := struct {
			Query    string    `json:"query"`
			Memories []Memory  `json:"memories"`
			Runs     []runJSON `json:"runs"`
		}{Query: query, Memories: memories, Runs: []runJSON{}}
		if res.Memories == nil {
			res.Memories = []Memory{}
		}
		for _, r := range runs {
			j := runJSON{ID: r.ID, Date: fmtTs(r.Ts), Host: r.Hostname, Tool: r.Tool, Cmd: r.Cmd,
				Cwd: r.Cwd, Size: r.Size.Int64, Match: trunc(r.Snippet, 300)}
			if r.ExitCode.Valid {
				j.Exit = &r.ExitCode.Int64
			}
			if r.Dur.Valid {
				j.DurMs = &r.Dur.Int64
			}
			res.Runs = append(res.Runs, j)
		}
		enc := json.NewEncoder(os.Stdout)
		if pretty {
			enc.SetIndent("", "  ")
		}
		enc.Encode(res) //nolint
		return 0
	}

	if len(memories) == 0 && len(runs) == 0 {
		fmt.Printf("No memories or command runs found for %q.\n", query)
		return 0
	}
	useColor := term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == ""
	for _, m := range memories {
		tags := ""
		if m.Tags != "" {
			tags = " [" + m.Tags + "]"
		}
		if useColor {
			fmt.Printf("\x1b[32m#%d %s:%s\x1b[0m\x1b[90m%s · %s\x1b[0m\n",
				m.ID, m.Namespace, m.Title, tags, noteDates(m))
		} else {
			fmt.Printf("#%d %s:%s%s · %s\n",
				m.ID, m.Namespace, m.Title, tags, noteDates(m))
		}
		body := strings.TrimSpace(m.Content)
		if full {
			fmt.Println(body)
		} else {
			preview := trunc(body, 600)
			fmt.Println(preview)
			if preview != body {
				if useColor {
					fmt.Printf("  \x1b[90m(truncated · full: iz n show %d)\x1b[0m\n", m.ID)
				} else {
					fmt.Printf("  (truncated · full: iz n show %d)\n", m.ID)
				}
			}
		}
	}
	for _, r := range runs {
		exit := ""
		if r.ExitCode.Valid && r.ExitCode.Int64 != 0 {
			if useColor {
				exit = fmt.Sprintf(" \x1b[31mexit=%d\x1b[0m", r.ExitCode.Int64)
			} else {
				exit = fmt.Sprintf(" exit=%d", r.ExitCode.Int64)
			}
		}
		if useColor {
			fmt.Printf("\x1b[33mrun#%d\x1b[0m \x1b[90m%s\x1b[0m \x1b[34m%s\x1b[0m%s $ %s\n",
				r.ID, fmtTsShort(r.Ts), tildify(r.Cwd), exit, r.Cmd)
		} else {
			fmt.Printf("run#%d %s %s%s $ %s\n",
				r.ID, fmtTsShort(r.Ts), tildify(r.Cwd), exit, r.Cmd)
		}
		if r.Snippet != "" {
			if useColor {
				fmt.Printf("  \x1b[90m↳ %s\x1b[0m\n", trunc(r.Snippet, 200))
			} else {
				fmt.Printf("  ↳ %s\n", trunc(r.Snippet, 200))
			}
		}
	}
	return 0
}

// primeCmd outputs a compact index of all namespaces and note titles so AI
// agents know what is stored in memory before querying.
func primeCmd(args []string) int {
	jsonOut := false
	for _, a := range args {
		switch a {
		case "--json", "-j":
			jsonOut = true
		case "-h", "--help":
			fmt.Println("usage: iz prime [--json]   # compact memory namespace/title index for AI agents")
			return 0
		default:
			fmt.Fprintf(os.Stderr, "iz prime: unknown argument %q (usage: iz prime [--json])\n", a)
			return 2
		}
	}
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer db.Close()

	rows, err := db.Query(`SELECT namespace, title FROM memories ORDER BY namespace, title`)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	defer rows.Close()

	byNS := map[string][]string{}
	var order []string
	total := 0
	for rows.Next() {
		var ns, title string
		if rows.Scan(&ns, &title) != nil {
			continue
		}
		if _, ok := byNS[ns]; !ok {
			order = append(order, ns)
		}
		byNS[ns] = append(byNS[ns], title)
		total++
	}
	if err := rows.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	var runCount int
	db.QueryRow(`SELECT count(*) FROM runs`).Scan(&runCount) //nolint

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.Encode(map[string]any{ //nolint
			"notes":      total,
			"runs":       runCount,
			"namespaces": byNS,
		})
		return 0
	}

	fmt.Printf("iz memory index (%d notes, %d runs):\n", total, runCount)
	for _, ns := range order {
		fmt.Printf("  %s (%d): %s\n", ns, len(byNS[ns]), strings.Join(byNS[ns], " | "))
	}
	return 0
}
