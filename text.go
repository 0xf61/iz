package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Terminal output post-processing.
//
// Recorded output is later replayed with `iz sh <id>` (cat / less -R / fzf
// preview), so before storing it we:
//   - drop clear-screen sequences (\x1b[2J, \x1b[3J, \x1b[H, \f) — no ctrl-l smears
//   - collapse \r re-draws (progress bars) to their final state
// while keeping color/cursor escapes intact.

var (
	reClear = regexp.MustCompile(`\x1b\[(2J|3J|H)|\f`)
	// CSI / OSC / nF (charset "ESC ( B") / single-character escape sequences
	// (colors, cursor, titles, "ESC 7"/"ESC 8" save/restore, "ESC ="/"ESC >"
	// keypad...). CSI parameter bytes are 0x30-0x3F, which includes ':'
	// (truecolor "38:2:r:g:b"); a lone "ESC [" is a broken CSI and kept.
	reANSI = regexp.MustCompile("\x1b\\[[0-?]*[ -/]*[@-~]|\x1b\\][^\x07\x1b]*(\x07|\x1b\\\\)|\x1b[ -/]+[0-~]|\x1b[0-Z\\\\-~]")
)

// tidyRaw removes clear-screen sequences and collapses progress-bar redraws.
// Note: PTY output ends lines with "\r\n"; that trailing \r is a line ending,
// not a redraw, and is normalized away.
func tidyRaw(b []byte) []byte {
	b = reClear.ReplaceAll(b, nil)
	lines := bytes.Split(b, []byte{'\n'})
	for i, l := range lines {
		l = bytes.TrimSuffix(l, []byte{'\r'})
		if j := bytes.LastIndexByte(l, '\r'); j >= 0 { // keep last redraw only
			l = l[j+1:]
		}
		lines[i] = l
	}
	return bytes.Join(lines, []byte{'\n'})
}

// stripANSI removes escape sequences from already-tidied output.
func stripANSI(b []byte) []byte { return reANSI.ReplaceAll(b, nil) }

// plainText tidies raw terminal output and returns the ANSI-free text used
// for the search index.
func plainText(b []byte) []byte {
	return stripANSI(tidyRaw(b))
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b) //nolint
	w.Close()  //nolint
	return buf.Bytes()
}

// maxUngz bounds decompressed output: stored runs are capped at maxCapture
// plus a marker, so anything larger is corrupt or a gzip bomb from a merge/sync.
const maxUngz = 2 * maxCapture

func ungz(b []byte) []byte { return ungzLimit(b, maxUngz) }

// ungzLimit decompresses b to at most limit bytes; b is returned as-is when
// it is not valid gzip, and what decoded when the stream breaks off midway.
func ungzLimit(b []byte, limit int64) []byte {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil { // not gzip: return as-is
		return b
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil && len(out) == 0 {
		return b
	}
	return out
}

// asciiLower folds A-Z only, so byte offsets stay valid for the original.
func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// foldRune is a 1:1 case fold for search: Unicode lower-casing plus the
// Turkish dotted/dotless i family (İ, I, ı → i), so "ışık" finds "IŞIK" and
// "istanbul" finds "İSTANBUL".
func foldRune(r rune) rune {
	switch r {
	case 'İ', 'I', 'ı':
		return 'i'
	}
	if r < utf8.RuneSelf {
		if 'A' <= r && r <= 'Z' {
			r += 'a' - 'A'
		}
		return r
	}
	return unicode.ToLower(r)
}

// fold case-folds s with foldRune.
func fold(s string) string { return strings.Map(foldRune, s) }

// foldMap folds b for case-insensitive matching. Folding can change byte
// lengths ('İ' is 2 bytes, 'i' is 1), so off maps every byte offset of the
// folded text back to b (off[len(folded)] == len(b)); off is nil when the
// offsets are identical (ASCII fast path).
func foldMap(b []byte) (folded []byte, off []int) {
	ascii := true
	for _, c := range b {
		if c >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return asciiLower(b), nil
	}
	folded = make([]byte, 0, len(b))
	off = make([]int, 0, len(b)+1)
	for i := 0; i < len(b); {
		r, w := utf8.DecodeRune(b[i:])
		n := len(folded)
		if r == utf8.RuneError && w == 1 {
			folded = append(folded, b[i]) // keep invalid bytes as-is
		} else {
			folded = utf8.AppendRune(folded, foldRune(r))
		}
		for range len(folded) - n {
			off = append(off, i)
		}
		i += w
	}
	return folded, append(off, len(b))
}

// trunc cuts s to at most n runes (never inside a UTF-8 sequence) without
// allocating a []rune slice for the entire string.
func trunc(s string, n int) string {
	if n <= 0 {
		return ""
	}
	count := 0
	cutByte := -1
	for i := range s {
		if count == n-1 {
			cutByte = i
		}
		if count >= n {
			return s[:cutByte] + "…"
		}
		count++
	}
	return s
}

// truncLeft keeps the tail of s (for commands: the arguments matter most).
func truncLeft(s string, n int) string {
	if n <= 0 {
		return ""
	}
	total := utf8.RuneCountInString(s)
	if total <= n {
		return s
	}
	skip := total - n + 1
	count := 0
	for i := range s {
		if count == skip {
			return "…" + s[i:]
		}
		count++
	}
	return s
}

// truncFTS caps indexed plain text to maxFTSBytes on a valid UTF-8 boundary
// so huge command outputs don't bloat memory or SQLite FTS5.
const maxFTSBytes = 2 << 20 // 2 MB

func truncFTS(b []byte) []byte {
	if len(b) <= maxFTSBytes {
		return b
	}
	// b[cut] is the first dropped byte: back up (at most one rune) until it
	// starts a rune, so the kept prefix never ends inside a sequence.
	cut := maxFTSBytes
	for cut > maxFTSBytes-utf8.UTFMax && !utf8.RuneStart(b[cut]) {
		cut--
	}
	return b[:cut]
}

// oneLine collapses all whitespace (newlines included) to single spaces.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// tildify shortens $HOME to ~.
func tildify(p string) string {
	if home, _ := os.UserHomeDir(); home != "" && (p == home || strings.HasPrefix(p, home+"/")) {
		return "~" + p[len(home):]
	}
	return p
}
