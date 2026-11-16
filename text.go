package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"regexp"
	"strings"
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
	// CSI / OSC / single-character escape sequences (colors, cursor, titles...).
	reANSI = regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]|\x1b\\][^\x07\x1b]*(\x07|\x1b\\\\)|\x1b[@-Z\\\\-_]")
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

func ungz(b []byte) []byte {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil { // not gzip: return as-is
		return b
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return b
	}
	return out
}

// asciiLower folds A-Z only, so byte offsets stay valid for the original
// (unicode.ToLower changes lengths, e.g. 'İ' is 2 bytes, 'i' is 1).
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

// trunc cuts s to at most n runes (never inside a UTF-8 sequence).
func trunc(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// truncLeft keeps the tail of s (for commands: the arguments matter most).
func truncLeft(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return "…" + string(r[len(r)-n+1:])
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
