package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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
	UID       string  `json:"-"` // identity across machines
	Mtime     float64 `json:"mtime,omitempty"` // last edit (sync: last write wins)
}

func now() float64 { return float64(time.Now().Unix()) }

func isTTY() bool {
	fiIn, errIn := os.Stdin.Stat()
	fiOut, errOut := os.Stdout.Stat()
	return errIn == nil && errOut == nil &&
		fiIn.Mode()&os.ModeCharDevice != 0 &&
		fiOut.Mode()&os.ModeCharDevice != 0
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

func upsertMemory(db *sql.DB, m Memory, appendMode bool) (int64, bool, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback() //nolint
	id, updated, err := upsertMemoryTx(tx, m, appendMode)
	if err != nil {
		return 0, false, err
	}
	return id, updated, tx.Commit()
}

func upsertMemoryTx(ex dbtx, m Memory, appendMode bool) (int64, bool, error) {
	var existingID int64
	var oldContent, oldTags, oldAuthor string
	err := ex.QueryRowContext(bg,
		`SELECT id, content, tags, author FROM memories WHERE namespace=? AND title=?`,
		m.Namespace, m.Title).Scan(&existingID, &oldContent, &oldTags, &oldAuthor)
	if err == nil {
		m.ID = existingID
		if appendMode && oldContent != "" {
			m.Content = strings.TrimRight(oldContent, "\n") + "\n" + m.Content
		}
		if m.Tags == "" {
			m.Tags = oldTags
		}
		if m.Mtime == 0 {
			m.Mtime = now()
		}
		if err := updateMemoryTx(ex, m); err != nil {
			return 0, false, err
		}
		return existingID, true, nil
	}
	id, err := insertMemoryTx(ex, m)
	return id, false, err
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
		m.Author = os.Getenv("USER")
		if m.Author == "" {
			m.Author = "user"
		}
	}
	res, err := ex.ExecContext(bg, `
		INSERT INTO memories(uid, ts, mtime, hostname, namespace, title, content, author, tags)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.UID, m.Ts, m.Mtime, m.Hostname, m.Namespace, m.Title, m.Content, m.Author, m.Tags)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	_, err = ex.ExecContext(bg, `INSERT INTO memories_fts(rowid, title, content, namespace, tags) VALUES(?, ?, ?, ?, ?)`,
		id, m.Title, m.Content, m.Namespace, m.Tags)
	return id, err
}

// updateMemoryTx rewrites a note's editable fields (namespace, title,
// content, tags) and its FTS row; ts (creation) and uid never change.
func updateMemoryTx(ex dbtx, m Memory) error {
	if m.Mtime == 0 {
		m.Mtime = now()
	}
	res, err := ex.ExecContext(bg, `UPDATE memories SET namespace=?, title=?, content=?, tags=?, mtime=? WHERE id=?`,
		m.Namespace, m.Title, m.Content, m.Tags, m.Mtime, m.ID)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return fmt.Errorf("note #%d not found", m.ID)
	}
	if _, err := ex.ExecContext(bg, `DELETE FROM memories_fts WHERE rowid=?`, m.ID); err != nil {
		return err
	}
	_, err = ex.ExecContext(bg, `INSERT INTO memories_fts(rowid, title, content, namespace, tags) VALUES(?, ?, ?, ?, ?)`,
		m.ID, m.Title, m.Content, m.Namespace, m.Tags)
	return err
}

// updateMemoryFullTx is used by sync when LWW replaces a note including uid/author/hostname.
func updateMemoryFullTx(ex dbtx, m Memory) error {
	if m.Mtime == 0 {
		m.Mtime = now()
	}
	res, err := ex.ExecContext(bg, `UPDATE memories SET uid=?, hostname=?, namespace=?, title=?, content=?, author=?, tags=?, mtime=? WHERE id=?`,
		m.UID, m.Hostname, m.Namespace, m.Title, m.Content, m.Author, m.Tags, m.Mtime, m.ID)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return fmt.Errorf("note #%d not found", m.ID)
	}
	if _, err := ex.ExecContext(bg, `DELETE FROM memories_fts WHERE rowid=?`, m.ID); err != nil {
		return err
	}
	_, err = ex.ExecContext(bg, `INSERT INTO memories_fts(rowid, title, content, namespace, tags) VALUES(?, ?, ?, ?, ?)`,
		m.ID, m.Title, m.Content, m.Namespace, m.Tags)
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
	if err := tx.QueryRow(`SELECT uid FROM memories WHERE id=?`, id).Scan(&uid); err != nil {
		return fmt.Errorf("note #%d not found", id)
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
	ns, title, _ := parseTarget(target)
	if title == "" {
		return 0, fmt.Errorf("invalid note target %q", target)
	}
	var id int64
	if err := db.QueryRow(`SELECT id FROM memories WHERE namespace=? AND title=?`, ns, title).Scan(&id); err != nil {
		return 0, fmt.Errorf("note %q not found", target)
	}
	return id, nil
}

// queryMemories searches the memories table via FTS5; ns:/author:/tag:/host:
// filter on columns.
func queryMemories(db *sql.DB, query string, limit int) ([]Memory, error) {
	if limit <= 0 {
		limit = 20
	}
	var conds string
	var args []any
	var terms []string

	for _, t := range strings.Fields(query) {
		idx := strings.Index(t, ":")
		if idx < 0 {
			terms = append(terms, t)
			continue
		}
		val := t[idx+1:]
		switch {
		case strings.HasPrefix(t, "ns:"), strings.HasPrefix(t, "namespace:"):
			conds += " AND m.namespace LIKE ?"
			args = append(args, val+"%")
		case strings.HasPrefix(t, "author:"):
			conds += " AND m.author LIKE ?"
			args = append(args, val+"%")
		case strings.HasPrefix(t, "host:"):
			conds += " AND m.hostname LIKE ?"
			args = append(args, val+"%")
		case strings.HasPrefix(t, "tag:"), strings.HasPrefix(t, "tags:"):
			conds += " AND (',' || m.tags || ',') LIKE ?"
			args = append(args, "%,"+val+",%")
		default:
			terms = append(terms, t)
		}
	}
	q := strings.Join(terms, " ")
	const cols = `SELECT m.id, m.ts, m.mtime, m.hostname, m.namespace, m.title, m.content, m.author, m.tags FROM memories m`

	if q == "" {
		return scanMemories(db, cols+" WHERE 1=1"+conds+" ORDER BY max(m.mtime, m.ts) DESC, m.id DESC LIMIT ?", append(args, limit))
	}

	ftsQ := ftsQuoteQuery(terms, " ")
	var res []Memory
	var err error
	if ftsValid(db, "memories_fts", q) {
		res, err = scanMemories(db, cols+` JOIN memories_fts f ON f.rowid = m.id WHERE memories_fts MATCH ?`+conds+
			` ORDER BY rank LIMIT ?`, append(append([]any{q}, args...), limit))
	} else if ftsValid(db, "memories_fts", ftsQ) {
		res, err = scanMemories(db, cols+` JOIN memories_fts f ON f.rowid = m.id WHERE memories_fts MATCH ?`+conds+
			` ORDER BY rank LIMIT ?`, append(append([]any{ftsQ}, args...), limit))
	} else {
		like := "%" + q + "%"
		res, err = scanMemories(db, cols+` WHERE (m.title LIKE ? OR m.content LIKE ? OR m.tags LIKE ?)`+conds+
			` ORDER BY max(m.mtime, m.ts) DESC LIMIT ?`, append(append([]any{like, like, like}, args...), limit))
	}
	// Multi-term fallback: if strict AND returned 0 rows, try OR ranked by bm25
	if err == nil && len(res) == 0 && len(terms) > 1 {
		orQ := ftsQuoteQuery(terms, " OR ")
		if ftsValid(db, "memories_fts", orQ) {
			res, err = scanMemories(db, cols+` JOIN memories_fts f ON f.rowid = m.id WHERE memories_fts MATCH ?`+conds+
				` ORDER BY bm25(memories_fts) LIMIT ?`, append(append([]any{orQ}, args...), limit))
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
	src := iz + " n lines {q}"
	args := []string{
		"--ansi",
		"--phony",
		"--color", "hl:-1,hl+:-1",
		"--info", "inline",
		"--header", "⏎ view · ^N new · ^E edit · ^Y del · esc exit",
		"--bind", "start:reload(" + src + ")",
		"--bind", "change:reload(" + src + ")",
		"--preview", iz + " n show {1}",
		"--preview-window", "right:60%:wrap",
		"--bind", "enter:execute(" + iz + " n show {1} | less -R)",
		"--bind", "ctrl-e:execute(" + iz + " n edit {1})+reload(" + src + ")",
		"--bind", "ctrl-n:execute(" + iz + " n new)+reload(" + src + ")",
		"--bind", "ctrl-y:execute-silent(" + iz + " n del {1})+reload(" + src + ")",
		"--query", query,
	}

	c := exec.Command("fzf", args...)
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	_ = c.Run()
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
	if m.Tags != "" {
		h += " [" + m.Tags + "]"
	}
	return h + "\n\n" + m.Content + "\n"
}

// parseNoteDoc splits a note document; ok=false when there is no header line.
func parseNoteDoc(text string) (ns, title, tags, body string, ok bool) {
	lines := strings.Split(text, "\n")
	var rest []string
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" && !ok && len(rest) == 0 {
			continue
		}
		if !ok && len(rest) == 0 && strings.HasPrefix(t, "#") && i < len(lines) {
			ns, title, tags = parseTarget(strings.TrimLeft(t, "# "))
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

// parseTarget reads "ns:title [tags]" (also "ns/title"; bare title → notes).
func parseTarget(s string) (ns, title, tags string) {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, " ["); i >= 0 && strings.HasSuffix(s, "]") {
		s, tags = strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+2:len(s)-1])
	}
	if i := strings.IndexAny(s, ":/"); i >= 0 {
		return s[:i], s[i+1:], tags
	}
	return "notes", s, tags
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
		fmt.Fprintf(os.Stderr, "iz: note #%d not found\n", id)
		return 1
	}
	text, err := editText(fmt.Sprintf("iz-note-%d-*.md", id), noteDoc(m))
	if err != nil {
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
	text, err := editText("iz-new-note-*.md", "# pentest:target-creds\n"+noteHint+"\n\n")
	if err != nil {
		return 1
	}
	ns, title, tags, body, ok := parseNoteDoc(text)
	if body == "" {
		fmt.Fprintln(os.Stderr, "[iz] empty note discarded.")
		return 0
	}
	if !ok || title == "" {
		ns, title = "notes", "quick-note"
	}
	return saveNote(Memory{Namespace: ns, Title: title, Tags: tags, Content: body}, false)
}

func saveNote(m Memory, appendMode bool) int {
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer db.Close()
	id, updated, err := upsertMemory(db, m, appendMode)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz: failed to save note:", err)
		return 1
	}
	verb := "saved"
	if updated {
		verb = "updated"
	}
	fmt.Fprintf(os.Stderr, "[iz] %s note #%d [%s:%s]\n", verb, id, m.Namespace, m.Title)
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
  iz n <ns:title> [-t tags] [-a] [content]   create or update note (upsert by ns:title)
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
			fmt.Fprintf(os.Stderr, "iz: note #%d not found\n", id)
			return 1
		}
		tags := ""
		if m.Tags != "" {
			tags = " · " + m.Tags
		}
		fmt.Printf("\x1b[1;36m#%d %s:%s\x1b[0m \x1b[90m· @%s · %s · %s%s\x1b[0m\n%s\n",
			m.ID, m.Namespace, m.Title, m.Author, m.Hostname, fmtTsShort(m.Ts), tags, m.Content)
		return 0
	}

	// Adding or updating a note: `iz n [-t tags] [-a] <target> [content...]`
	var tagsFlag string
	appendMode := false
	var pos []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-t", "--tags":
			if i+1 < len(args) {
				tagsFlag = args[i+1]
				i++
			}
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

	m := Memory{}
	m.Namespace, m.Title, m.Tags = parseTarget(pos[0])
	if tagsFlag != "" {
		m.Tags = tagsFlag
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
	return saveNote(m, appendMode)
}

// listNotes prints one aligned line per note: id, ns:title, date, size.
func listNotes(namespace string) int {
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer db.Close()

	q := "SELECT id, ts, namespace, title, author, length(content) FROM memories"
	var args []any
	if namespace != "" {
		q += " WHERE namespace LIKE ?"
		args = append(args, namespace+"%")
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
			continue
		}
		r.name, r.date = trunc(ns+":"+title, 40), fmtTsShort(ts)
		w = max(w, len([]rune(r.name)))
		out = append(out, r)
	}
	if len(out) == 0 {
		fmt.Println("No notes found.")
		return 0
	}
	for _, r := range out {
		fmt.Printf("%4d  %-*s  %-11s  %-6s  @%s\n", r.id, w, r.name, r.date, humanBytes(r.size), r.author)
	}
	return 0
}

// importNotes walks a file or directory and imports markdown sections as
// memories, in one transaction.
func importNotes(path string) int {
	fi, err := os.Stat(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}

	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer db.Close()

	var files []string
	if fi.IsDir() {
		filepath.Walk(path, func(p string, info os.FileInfo, err error) error { //nolint
			if err == nil && !info.IsDir() && strings.HasSuffix(info.Name(), ".md") {
				files = append(files, p)
			}
			return nil
		})
	} else {
		files = append(files, path)
	}

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
			continue
		}
		text := string(data)
		ns := strings.TrimSuffix(filepath.Base(f), ".md")
		if fi.IsDir() {
			if rel, err := filepath.Rel(path, f); err == nil {
				ns = strings.TrimSuffix(filepath.ToSlash(rel), ".md")
			}
		}
		add := func(title, body string) {
			body = strings.TrimSpace(body)
			title = strings.TrimSpace(title)
			if body == "" || title == "" {
				return
			}
			m := Memory{Namespace: ns, Title: title, Content: body, Author: "import"}
			if _, wasUpd, err := upsertMemoryTx(tx, m, false); err == nil {
				if wasUpd {
					updated++
				} else {
					imported++
				}
			}
		}

		// Split by line-start § only if the document actually uses § section markers
		if strings.HasPrefix(strings.TrimSpace(text), "§") || strings.Contains(text, "\n§ ") {
			for i, p := range strings.Split(text, "\n§") {
				title := fmt.Sprintf("Section %d", i+1)
				for _, l := range strings.Split(strings.TrimSpace(p), "\n") {
					l = strings.TrimSpace(strings.TrimPrefix(l, "§"))
					if strings.HasPrefix(l, "#") {
						title = strings.TrimLeft(l, "# ")
						break
					} else if l != "" {
						title = trunc(l, 40)
						break
					}
				}
				add(title, strings.TrimPrefix(p, "§"))
			}
			continue
		}

		// Split by Markdown headers (#, ##), ignoring headers inside fenced code blocks
		currTitle := ns
		var curr []string
		inCode := false
		for _, l := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(l)
			if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
				inCode = !inCode
			}
			if !inCode && (strings.HasPrefix(l, "## ") || strings.HasPrefix(l, "# ")) {
				add(currTitle, strings.Join(curr, "\n"))
				curr = nil
				currTitle = strings.TrimLeft(l, "# ")
			}
			curr = append(curr, l)
		}
		add(currTitle, strings.Join(curr, "\n"))
	}
	if err := tx.Commit(); err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[iz] imported %d new, updated %d notes from %s\n", imported, updated, path)
	return 0
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
	limit := 10
	var queryTerms []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
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
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 {
					limit = n
				}
				i++
			}
		default:
			queryTerms = append(queryTerms, a)
		}
	}

	query := strings.Join(queryTerms, " ")
	if query == "" {
		fmt.Fprintln(os.Stderr, "iz: empty recall query")
		return 2
	}
	for _, t := range strings.Fields(query) {
		runsOnly = runsOnly || hasPrefixAny(t, runFilters)
		notesOnly = notesOnly || hasPrefixAny(t, memFilters)
	}

	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz:", err)
		return 2
	}
	defer db.Close()

	var memories []Memory
	if !runsOnly {
		memories, _ = queryMemories(db, query, limit)
	}
	var runs []Run
	if !notesOnly {
		runLimit := min(limit, 5)
		if runsOnly {
			runLimit = limit
		}
		runs, _ = searchRuns(db, query, runLimit, true)
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
	for _, m := range memories {
		tags := ""
		if m.Tags != "" {
			tags = " [" + m.Tags + "]"
		}
		fmt.Printf("\x1b[32m#%d %s:%s\x1b[0m\x1b[90m%s · %s\x1b[0m\n",
			m.ID, m.Namespace, m.Title, tags, fmtTsShort(m.Ts))
		body := strings.TrimSpace(m.Content)
		if full {
			fmt.Println(body)
		} else {
			preview := trunc(body, 600)
			fmt.Println(preview)
			if preview != body {
				fmt.Printf("  \x1b[90m(truncated · full: iz n show %d)\x1b[0m\n", m.ID)
			}
		}
	}
	for _, r := range runs {
		exit := ""
		if r.ExitCode.Valid && r.ExitCode.Int64 != 0 {
			exit = fmt.Sprintf(" \x1b[31mexit=%d\x1b[0m", r.ExitCode.Int64)
		}
		fmt.Printf("\x1b[33mrun#%d\x1b[0m \x1b[90m%s\x1b[0m \x1b[34m%s\x1b[0m%s $ %s\n",
			r.ID, fmtTsShort(r.Ts), tildify(r.Cwd), exit, r.Cmd)
		if r.Snippet != "" {
			fmt.Printf("  \x1b[90m↳ %s\x1b[0m\n", trunc(r.Snippet, 200))
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
