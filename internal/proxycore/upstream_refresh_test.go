package proxycore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMetadataPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	metaPath := filepath.Join(tmpDir, "last_pull_metadata.json")

	// Missing metadata returns nil
	if meta := GetStoredMetadata(metaPath); meta != nil {
		t.Errorf("expected nil for missing metadata, got %+v", meta)
	}

	testMeta := &PullMetadata{
		SHA:                  "abcdef123456",
		CommitMessage:        "Updated 📦",
		LastUpdatedTimestamp: 1729400000000,
		LastUpdatedDate:      "Mon Oct 20 2026",
		LastPulledAt:         time.Now().UTC().Format(time.RFC3339),
		FileSizeBytes:        123456,
	}

	if err := SaveStoredMetadata(metaPath, testMeta); err != nil {
		t.Fatalf("failed to save metadata: %v", err)
	}

	loaded := GetStoredMetadata(metaPath)
	if loaded == nil || loaded.SHA != testMeta.SHA || loaded.FileSizeBytes != testMeta.FileSizeBytes {
		t.Fatalf("loaded metadata mismatch: %+v", loaded)
	}
}

func TestDownloadFileStreamMock(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "11")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello world"))
	}))
	defer ts.Close()

	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "downloaded.txt")

	var reportedDown, reportedTotal int64
	err := DownloadFileStreamContext(context.Background(), ts.URL, dest, func(d, total int64) {
		reportedDown = d
		reportedTotal = total
	})

	if err != nil {
		t.Fatalf("download stream failed: %v", err)
	}

	content, err := os.ReadFile(dest)
	if err != nil || string(content) != "hello world" {
		t.Fatalf("downloaded content mismatch: %s", string(content))
	}
	_ = reportedDown
	_ = reportedTotal
}

func TestRefreshProxyDataPolicies(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "socks5.txt")
	_ = os.WriteFile(targetFile, []byte("127.0.0.1:1080\n"), 0600)

	// NoUpdate flag
	res, err := RefreshProxyDataIfNeeded(RefreshOptions{
		TargetFile: targetFile,
		NoUpdate:   true,
	})
	if err != nil {
		t.Fatalf("unexpected error for NoUpdate: %v", err)
	}
	if res.Updated || res.Reason != "skipped_by_flag" {
		t.Errorf("expected skipped_by_flag, got: %+v", res)
	}
}

func TestResolveFetchURL(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"", RAW_PROXY_DATA_URL},
		{DEFAULT_GITHUB_REPO, RAW_PROXY_DATA_URL},
		{"https://github.com/proxifly/free-proxy-list", RAW_PROXY_DATA_URL},
		{"https://github.com/proxifly/free-proxy-list.git", RAW_PROXY_DATA_URL},
		{"https://github.com/custom/repo", "https://raw.githubusercontent.com/custom/repo/main/proxies/protocols/socks5/data.txt"},
		{"https://github.com/custom/repo/blob/master/proxies.txt", "https://raw.githubusercontent.com/custom/repo/master/proxies.txt"},
		{"https://example.com/raw.txt", "https://example.com/raw.txt"},
	}

	for _, c := range cases {
		got := ResolveFetchURL(c.input)
		if got != c.expected {
			t.Errorf("ResolveFetchURL(%q) = %q; want %q", c.input, got, c.expected)
		}
	}
}

func TestResolveCommitAPIURL(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"", GITHUB_COMMITS_API_URL},
		{DEFAULT_GITHUB_REPO, GITHUB_COMMITS_API_URL},
		{"https://github.com/proxifly/free-proxy-list", GITHUB_COMMITS_API_URL},
		{"https://github.com/custom/repo", "https://api.github.com/repos/custom/repo/commits?path=proxies/protocols/socks5/data.txt&per_page=1"},
		{"https://github.com/custom/repo/blob/main/my/path.txt", "https://api.github.com/repos/custom/repo/commits?path=my/path.txt&per_page=1"},
		{"https://example.com/raw.txt", ""},
	}

	for _, c := range cases {
		got := ResolveCommitAPIURL(c.input)
		if got != c.expected {
			t.Errorf("ResolveCommitAPIURL(%q) = %q; want %q", c.input, got, c.expected)
		}
	}
}