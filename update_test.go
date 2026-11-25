package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpectedAssetName(t *testing.T) {
	cases := []struct {
		goos, goarch, want string
	}{
		{"linux", "amd64", "iz-linux-amd64"},
		{"linux", "arm64", "iz-linux-arm64"},
		{"darwin", "arm64", "iz-darwin-arm64"},
		{"windows", "amd64", "iz-windows-amd64.exe"},
	}
	for _, tc := range cases {
		if got := expectedAssetName(tc.goos, tc.goarch); got != tc.want {
			t.Errorf("expectedAssetName(%q, %q) = %q, want %q", tc.goos, tc.goarch, got, tc.want)
		}
	}
}

func TestVerifyChecksum(t *testing.T) {
	bin := []byte("fake-iz-binary-payload")
	sum := sha256.Sum256(bin)
	hexSum := hex.EncodeToString(sum[:])

	// Standard two-space format, binary * prefix, ./ prefix, uppercase hex.
	for _, line := range []string{
		hexSum + "  iz-linux-amd64\n",
		strings.ToUpper(hexSum) + " *iz-linux-amd64\n",
		hexSum + "  ./iz-linux-amd64\n",
	} {
		if err := verifyChecksum(bin, "iz-linux-amd64", []byte(line)); err != nil {
			t.Errorf("verifyChecksum(%q) unexpected error: %v", line, err)
		}
	}

	if err := verifyChecksum(bin, "iz-linux-amd64", []byte(strings.Repeat("0", 64)+"  iz-linux-amd64\n")); err == nil {
		t.Error("expected mismatch error, got nil")
	}
	if err := verifyChecksum(bin, "iz-darwin-arm64", []byte(hexSum+"  iz-linux-amd64\n")); err == nil {
		t.Error("expected missing asset error, got nil")
	}
}

func TestUpdateCmdRejectsBadArgs(t *testing.T) {
	if code := updateCmd([]string{"--unknown"}); code != 2 {
		t.Errorf("updateCmd(--unknown) = %d, want 2", code)
	}
	if code := updateCmd([]string{"extra"}); code != 2 {
		t.Errorf("updateCmd(extra) = %d, want 2", code)
	}
	if code := updateCmd([]string{"--help"}); code != 0 {
		t.Errorf("updateCmd(--help) = %d, want 0", code)
	}
}

func TestRunUpdateEndToEnd(t *testing.T) {
	payload := []byte("#!/bin/sh\necho new-iz\n")
	sum := sha256.Sum256(payload)
	sumsTxt := fmt.Sprintf("%s  iz-linux-amd64\n", hex.EncodeToString(sum[:]))

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			if r.Header.Get("User-Agent") == "" {
				t.Errorf("missing User-Agent header")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v2026.11.25",
				"assets": []map[string]string{
					{"name": "iz-linux-amd64", "browser_download_url": srv.URL + "/bin"},
					{"name": "checksums.txt", "browser_download_url": srv.URL + "/sums"},
				},
			})
		case "/bin":
			_, _ = w.Write(payload)
		case "/sums":
			_, _ = w.Write([]byte(sumsTxt))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	exe := filepath.Join(dir, "iz")
	if err := os.WriteFile(exe, []byte("old"), 0o700); err != nil {
		t.Fatal(err)
	}

	// Already up to date (with or without leading v).
	var stderr bytes.Buffer
	if code := runUpdate(srv.URL+"/latest", srv.Client(), exe, "linux", "amd64", "v2026.11.25", &stderr); code != 0 {
		t.Fatalf("already-up-to-date exit=%d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "already up to date") {
		t.Errorf("unexpected stderr: %q", stderr.String())
	}

	// Actual update from older version.
	stderr.Reset()
	if code := runUpdate(srv.URL+"/latest", srv.Client(), exe, "linux", "amd64", "v2026.01.01", &stderr); code != 0 {
		t.Fatalf("update exit=%d, stderr=%s", code, stderr.String())
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("exe content = %q, want %q", got, payload)
	}
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("exe mode = %04o, want 0700 (preserved)", info.Mode().Perm())
	}
}

func TestRunUpdateRejectsMissingChecksums(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": "v2026.11.25",
			"assets": []map[string]string{
				{"name": "iz-linux-amd64", "browser_download_url": srv.URL + "/bin"},
			},
		})
	}))
	defer srv.Close()

	exe := filepath.Join(t.TempDir(), "iz")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	if code := runUpdate(srv.URL+"/latest", srv.Client(), exe, "linux", "amd64", "dev", &stderr); code != 1 {
		t.Fatalf("missing checksums exit=%d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "checksums.txt missing") {
		t.Errorf("stderr = %q, want checksums.txt missing", stderr.String())
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "old" {
		t.Errorf("exe was modified despite missing checksums.txt")
	}
}

func TestRunUpdateRejectsBadChecksumBeforeReplace(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v2026.11.25",
				"assets": []map[string]string{
					{"name": "iz-linux-amd64", "browser_download_url": srv.URL + "/bin"},
					{"name": "checksums.txt", "browser_download_url": srv.URL + "/sums"},
				},
			})
		case "/bin":
			_, _ = w.Write([]byte("tampered"))
		case "/sums":
			_, _ = w.Write([]byte(strings.Repeat("a", 64) + "  iz-linux-amd64\n"))
		}
	}))
	defer srv.Close()

	exe := filepath.Join(t.TempDir(), "iz")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	if code := runUpdate(srv.URL+"/latest", srv.Client(), exe, "linux", "amd64", "dev", &stderr); code != 1 {
		t.Fatalf("bad checksum exit=%d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "checksum mismatch") {
		t.Errorf("stderr = %q, want checksum mismatch", stderr.String())
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "old" {
		t.Errorf("exe was modified despite checksum mismatch")
	}
}

func TestFetchLatestReleaseMissingTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"assets":[]}`))
	}))
	defer srv.Close()

	if _, err := fetchLatestRelease(srv.Client(), srv.URL, "dev"); err == nil {
		t.Error("expected error for missing tag_name, got nil")
	}
}
