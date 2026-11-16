package main

import (
	"bytes"
	"testing"
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
