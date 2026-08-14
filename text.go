package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"regexp"
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

// plainText returns the ANSI-free text used for the search index.
func plainText(b []byte) []byte {
	return reANSI.ReplaceAll(tidyRaw(b), nil)
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
