package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

const releaseAPI = "https://api.github.com/repos/0xf61/iz/releases/latest"

type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// currentVersion returns the ldflags-injected version, falling back to the
// Go module version embedded by `go install github.com/0xf61/iz@v...`.
func currentVersion() string {
	if version != "" && version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

func updateCmd(args []string) int {
	const usage = "usage: iz update"
	if code, done := helpOrFlag(usage, args); done {
		return code
	}
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "iz update:", err)
		return 1
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	client := &http.Client{
		Timeout: 2 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return errors.New("refusing redirect from HTTPS to non-HTTPS")
			}
			return nil
		},
	}

	return runUpdate(releaseAPI, client, exe, runtime.GOOS, runtime.GOARCH, currentVersion(), os.Stderr)
}

func runUpdate(apiURL string, client *http.Client, exe, goos, goarch, curVersion string, stderr io.Writer) int {
	rel, err := fetchLatestRelease(client, apiURL, curVersion)
	if err != nil {
		fmt.Fprintln(stderr, "iz update:", err)
		return 1
	}
	if curVersion != "dev" && strings.TrimPrefix(curVersion, "v") == strings.TrimPrefix(rel.TagName, "v") {
		fmt.Fprintf(stderr, "[iz] already up to date (%s)\n", curVersion)
		return 0
	}

	assetName := expectedAssetName(goos, goarch)
	var assetURL, checksumsURL string
	for _, a := range rel.Assets {
		switch a.Name {
		case assetName:
			assetURL = a.BrowserDownloadURL
		case "checksums.txt":
			checksumsURL = a.BrowserDownloadURL
		}
	}
	if assetURL == "" {
		fmt.Fprintf(stderr, "iz update: no release binary for %s/%s in %s\n", goos, goarch, rel.TagName)
		return 1
	}
	if checksumsURL == "" {
		fmt.Fprintf(stderr, "iz update: checksums.txt missing from release %s\n", rel.TagName)
		return 1
	}
	if strings.HasPrefix(apiURL, "https://") {
		if !strings.HasPrefix(assetURL, "https://") || !strings.HasPrefix(checksumsURL, "https://") {
			fmt.Fprintln(stderr, "iz update: refusing non-HTTPS download URL")
			return 1
		}
	}

	sums, err := downloadBytes(client, checksumsURL, curVersion, 1<<20)
	if err != nil {
		fmt.Fprintln(stderr, "iz update: checksums:", err)
		return 1
	}
	if _, err := lookupChecksum(sums, assetName); err != nil {
		fmt.Fprintln(stderr, "iz update:", err)
		return 1
	}

	fmt.Fprintf(stderr, "[iz] downloading %s (%s)...\n", rel.TagName, assetName)
	bin, err := downloadBytes(client, assetURL, curVersion, 128<<20)
	if err != nil {
		fmt.Fprintln(stderr, "iz update: download:", err)
		return 1
	}
	if len(bin) == 0 {
		fmt.Fprintln(stderr, "iz update: downloaded binary is empty")
		return 1
	}
	if err := verifyChecksum(bin, assetName, sums); err != nil {
		fmt.Fprintln(stderr, "iz update:", err)
		return 1
	}

	if err := replaceExecutable(exe, bin); err != nil {
		fmt.Fprintln(stderr, "iz update:", err)
		return 1
	}
	fmt.Fprintf(stderr, "[iz] updated to %s\n", rel.TagName)
	return 0
}

func expectedAssetName(goos, goarch string) string {
	name := fmt.Sprintf("iz-%s-%s", goos, goarch)
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

func fetchLatestRelease(client *http.Client, url, curVersion string) (*ghRelease, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "iz/"+curVersion)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api %s", resp.Status)
	}
	var rel ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, errors.New("github api response missing tag_name")
	}
	return &rel, nil
}

func downloadBytes(client *http.Client, url, curVersion string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "iz/"+curVersion)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxBytes)
	}
	return data, nil
}

func lookupChecksum(sums []byte, assetName string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(strings.TrimPrefix(fields[1], "*"), "./")
		if name == assetName {
			return fields[0], nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("reading checksums: %w", err)
	}
	return "", fmt.Errorf("checksum not found for %s", assetName)
}

func verifyChecksum(bin []byte, assetName string, sums []byte) error {
	want, err := lookupChecksum(sums, assetName)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bin)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(want, got) {
		return fmt.Errorf("checksum mismatch for %s: got %s, want %s", assetName, got, want)
	}
	return nil
}

func replaceExecutable(exe string, bin []byte) error {
	mode := os.FileMode(0o755)
	if info, err := os.Stat(exe); err == nil {
		mode = info.Mode().Perm() | 0o700
	}

	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".iz-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(bin); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if runtime.GOOS == "darwin" {
		// Ad-hoc sign the temp file before renaming so the installed binary
		// is never mutated in place or exposed unsigned.
		_ = exec.Command("codesign", "-s", "-", "-f", tmpPath).Run()
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		oldPath := exe + ".old"
		_ = os.Remove(oldPath)
		movedOld := false
		if err := os.Rename(exe, oldPath); err == nil {
			movedOld = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(tmpPath, exe); err != nil {
			if movedOld {
				_ = os.Rename(oldPath, exe)
			}
			return err
		}
		cleanup = false
		_ = os.Remove(oldPath)
		return nil
	}
	if err := os.Rename(tmpPath, exe); err != nil {
		return err
	}
	cleanup = false
	return nil
}
