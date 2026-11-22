package main

import (
	"bytes"
	"testing"
	"unicode/utf8"
)

func TestTidyRawKeepsCRLF(t *testing.T) {
	// PTY output ends lines with \r\n — must survive as plain \n without losing content.
	got := tidyRaw([]byte("hello\r\nworld\r\n"))
	want := "hello\nworld\n"
	if string(got) != want {
		t.Errorf("tidyRaw = %q, want %q", got, want)
	}
}

func TestTidyRawCollapsesProgressBars(t *testing.T) {
	// \r re-draws (progress bars) collapse to their final state.
	got := tidyRaw([]byte("esc8 vuln\r...loading 99%\r...done\n"))
	want := "...done\n"
	if string(got) != want {
		t.Errorf("tidyRaw = %q, want %q", got, want)
	}
}

func TestTidyRawRemovesClearScreen(t *testing.T) {
	got := tidyRaw([]byte("a\x1b[2J\x1b[Hb\f c\n"))
	want := "ab c\n"
	if string(got) != want {
		t.Errorf("tidyRaw = %q, want %q", got, want)
	}
}

func TestTidyRawKeepsColors(t *testing.T) {
	in := []byte("\x1b[31mRED\x1b[0m ok\r\n")
	if got := tidyRaw(in); !bytes.Contains(got, []byte("\x1b[31m")) {
		t.Errorf("tidyRaw dropped color: %q", got)
	}
}

func TestPlainTextStripsANSI(t *testing.T) {
	got := plainText([]byte("\x1b[31mRED\x1b[0m esc8\r\n"))
	want := "RED esc8\n"
	if string(got) != want {
		t.Errorf("plainText = %q, want %q", got, want)
	}
}

func TestGzRoundTrip(t *testing.T) {
	in := bytes.Repeat([]byte("\x1b[31mRED\x1b[0m some long repetitive output\n"), 50)
	if out := ungz(gz(in)); !bytes.Equal(out, in) {
		t.Errorf("gz round-trip mismatch")
	}
	if len(gz(in)) > len(in) { // repetitive input must compress
		t.Errorf("expected compression, got %d > %d", len(gz(in)), len(in))
	}
}

func TestUngzPassthrough(t *testing.T) {
	in := []byte("not gzip at all")
	if out := ungz(in); !bytes.Equal(out, in) {
		t.Errorf("ungz should pass through non-gzip input, got %q", out)
	}
}

func TestTruncUTF8Safe(t *testing.T) {
	tr := "Şifreli bağlantı çözüldü ğüşıöçİ"
	got := trunc(tr, 10)
	if got != "Şifreli b…" {
		t.Errorf("trunc(%q, 10) = %q, want %q", tr, got, "Şifreli b…")
	}
	left := truncLeft("nmap -sV --script=vuln 10.0.0.1", 10)
	if left != "… 10.0.0.1" {
		t.Errorf("truncLeft = %q, want %q", left, "… 10.0.0.1")
	}
}

func TestFoldTurkish(t *testing.T) {
	if a, b := fold("İSTANBUL IŞIK"), fold("istanbul ışık"); a != b {
		t.Errorf("fold mismatch: %q vs %q", a, b)
	}
	folded, off := foldMap([]byte("aİb"))
	if string(folded) != "aib" || len(off) != len(folded)+1 || off[2] != 3 || off[3] != 4 {
		t.Errorf("foldMap = %q %v", folded, off)
	}
	if _, off := foldMap([]byte("ascii")); off != nil {
		t.Error("ASCII input must take the identity fast path")
	}
}

// Truecolor SGR with ':' separators is an escape sequence too.
func TestStripANSITruecolor(t *testing.T) {
	if got := string(stripANSI([]byte("\x1b[38:2:255:0:0mred\x1b[0m"))); got != "red" {
		t.Errorf("stripANSI = %q", got)
	}
}

// truncFTS never cuts inside a rune and keeps as much as fits.
func TestTruncFTSRuneBoundary(t *testing.T) {
	b := append([]byte("x"), bytes.Repeat([]byte("ş"), maxFTSBytes)...) // odd offset: limit lands mid-rune
	got := truncFTS(b)
	if !utf8.Valid(got) || len(got) > maxFTSBytes || len(got) < maxFTSBytes-utf8.UTFMax {
		t.Errorf("truncFTS: len=%d valid=%v", len(got), utf8.Valid(got))
	}
}

// ungz caps decompressed size (a gzip bomb from a merged database).
func TestUngzLimit(t *testing.T) {
	const limit = 64 << 10
	z := gz(make([]byte, 4*limit))
	if got := len(ungzLimit(z, limit)); got != limit {
		t.Errorf("ungzLimit = %d bytes, want cap %d", got, limit)
	}
	if got := len(ungzLimit(z, 8*limit)); got != 4*limit {
		t.Errorf("ungzLimit under the cap = %d bytes, want %d", got, 4*limit)
	}
}

// Charset (ESC ( B, as tput sgr0 emits), save/restore cursor and keypad
// mode escapes are stripped from the indexed text too.
func TestStripANSIShortEscapes(t *testing.T) {
	in := "a\x1b(Bb\x1b7c\x1b8d\x1b=e\x1b>f\x1b[0mg\x1bch"
	if got := string(stripANSI([]byte(in))); got != "abcdefgh" {
		t.Errorf("stripANSI = %q, want %q", got, "abcdefgh")
	}
}

// A gzip stream broken off midway yields the part that decoded, not the
// compressed bytes.
func TestUngzTruncatedStream(t *testing.T) {
	var data []byte
	for i := range 200000 {
		data = append(data, byte('a'+(i*7919)%26), byte('A'+(i*104729)%26))
	}
	z := gz(data)
	got := ungz(z[:len(z)/2])
	if len(got) == 0 || !bytes.HasPrefix(data, got) {
		t.Errorf("ungz(truncated) = %d bytes, not a prefix of the original", len(got))
	}
}
