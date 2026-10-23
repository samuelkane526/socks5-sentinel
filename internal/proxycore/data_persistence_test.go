package proxycore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureDataDir(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Nested parent directories created safely cross-platform
	nestedBase := filepath.Join(tmpDir, "level1", "level2")
	expectedDataDir := filepath.Join(nestedBase, "data")

	if _, err := os.Stat(expectedDataDir); !os.IsNotExist(err) {
		t.Fatalf("expected dataDir %s to not exist prior to EnsureDataDir", expectedDataDir)
	}

	created, err := EnsureDataDir(nestedBase)
	if err != nil {
		t.Fatalf("EnsureDataDir failed: %v", err)
	}
	if created != expectedDataDir {
		t.Errorf("expected returned path %s, got %s", expectedDataDir, created)
	}

	info, err := os.Stat(expectedDataDir)
	if err != nil {
		t.Fatalf("expected dataDir to exist on disk: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected %s to be a directory", expectedDataDir)
	}

	// 2. Idempotent on second call
	createdAgain, err := EnsureDataDir(nestedBase)
	if err != nil {
		t.Fatalf("subsequent EnsureDataDir call failed: %v", err)
	}
	if createdAgain != expectedDataDir {
		t.Errorf("expected idempotent path %s, got %s", expectedDataDir, createdAgain)
	}
}

func TestVettingRun_CreatesDataDirWhenWritingVettingOutput(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")

	// Ensure ./data does not exist before vetting output write
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("expected ./data to not exist initially in %s", tmpDir)
	}

	sampleProxies := []*ProxyItem{
		{
			IP:          "198.51.100.1",
			Port:        1080,
			Proxy:       "socks5h://198.51.100.1:1080",
			Protocol:    "socks5h",
			Anonymity:   "elite",
			VettedAt:    "2026-10-22T20:00:00Z",
			LastChecked: "2026-10-22T20:00:00Z",
		},
	}

	// 1. Save vetted results targeting data/vetted_proxies.json
	outputTarget := filepath.Join("data", "vetted_proxies.json")
	savedPaths, err := SaveVettedResults(tmpDir, outputTarget, sampleProxies)
	if err != nil {
		t.Fatalf("SaveVettedResults failed: %v", err)
	}

	// Verify ./data was created automatically on first output write
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatalf("expected ./data to be created automatically when writing output, err: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected %s to be a directory", dataDir)
	}

	// Verify files written into ./data
	masterPath := filepath.Join(dataDir, "vetted_proxies.json")
	if _, err := os.Stat(masterPath); os.IsNotExist(err) {
		t.Fatalf("expected master file %s to exist in ./data", masterPath)
	}

	foundMaster := false
	for _, p := range savedPaths {
		if p == masterPath {
			foundMaster = true
			break
		}
	}
	if !foundMaster {
		t.Errorf("savedPaths %v does not contain masterPath %s", savedPaths, masterPath)
	}

	// Verify content
	content, err := os.ReadFile(masterPath)
	if err != nil {
		t.Fatalf("failed reading master file: %v", err)
	}
	var loaded []*ProxyItem
	if err := json.Unmarshal(content, &loaded); err != nil {
		t.Fatalf("failed unmarshaling master file: %v", err)
	}
	if len(loaded) != 1 || loaded[0].IP != "198.51.100.1" {
		t.Errorf("unexpected content in master file: %+v", loaded)
	}
}

func TestVettingRun_DoesNotCreateDataDirWhenNotWritingToData(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")

	// Ensure ./data does not exist
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("expected ./data to not exist initially in %s", tmpDir)
	}

	// Input file is outside data/
	inputPath := filepath.Join(tmpDir, "custom_candidates.txt")
	if err := os.WriteFile(inputPath, []byte("127.0.0.1:1080\n"), 0600); err != nil {
		t.Fatalf("failed writing input candidate file: %v", err)
	}

	// Output is in elite_proxies (default)
	pipeline := NewSocksVettingPipeline(PipelineOptions{
		BaseDir:   tmpDir,
		InputFile: inputPath,
		NoUpdate:  true,
		Timeout:   100 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately so no network calls happen

	_, _ = pipeline.RunContext(ctx, nil)

	// ./data should NOT have been created because no file was targeted or written there
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("expected ./data NOT to be created when no files are written there")
	}
}

func TestRequiredDataFile_CreatesDataDirWhenAboutToWrite(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")

	// Ensure ./data does not exist before sync
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("expected ./data to not exist initially in %s", tmpDir)
	}

	// Mock upstream HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/commits" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"sha": "test-sha-12345",
					"commit": map[string]interface{}{
						"message": "Update proxy list (2026-10-22 20:00:00)",
						"author": map[string]interface{}{
							"date": "2026-10-22T20:00:00Z",
						},
					},
				},
			})
			return
		}
		// Data download endpoint
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("127.0.0.1:1080\n127.0.0.2:1080\n"))
	}))
	defer server.Close()

	targetFile := filepath.Join(dataDir, "socks5.txt")
	beforeSync := time.Now().Add(-1 * time.Second)

	res, err := RefreshProxyDataIfNeededContext(context.Background(), RefreshOptions{
		BaseDir:     tmpDir,
		TargetFile:  targetFile,
		ForceUpdate: true,
		SourceURL:   server.URL,
	}, nil)

	if err != nil {
		t.Fatalf("RefreshProxyDataIfNeededContext failed: %v", err)
	}
	if res == nil || !res.Updated {
		t.Fatalf("expected updated=true, got %+v", res)
	}

	// Verify ./data was created automatically when writing required data file
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatalf("expected ./data to exist: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected %s to be a directory", dataDir)
	}
	if info.ModTime().Before(beforeSync) {
		t.Errorf("expected dataDir mod time to be updated upon socks5.txt fetch")
	}

	// Verify files written into ./data
	if _, err := os.Stat(targetFile); err != nil {
		t.Fatalf("expected target file %s to exist in ./data: %v", targetFile, err)
	}
	metaPath := filepath.Join(dataDir, "last_pull_metadata.json")
	if _, err := os.Stat(metaPath); err != nil {
		t.Fatalf("expected metadata file %s to exist in ./data: %v", metaPath, err)
	}

	meta := GetStoredMetadata(metaPath)
	if meta == nil || meta.FileSizeBytes <= 0 {
		t.Fatalf("expected saved metadata with positive size, got %+v", meta)
	}
}

func TestVettingPipeline_CreatesDataDirOnFirstVettingRunWhenDownloadingData(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")

	// Ensure ./data does not exist before pipeline runs
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("expected ./data to not exist initially in %s", tmpDir)
	}

	// Mock upstream HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/commits" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"sha": "vet-run-sha",
					"commit": map[string]interface{}{
						"message": "Proxies for vetting run",
						"author": map[string]interface{}{
							"date": "2026-10-22T20:00:00Z",
						},
					},
				},
			})
			return
		}
		// Data download endpoint
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("127.0.0.1:1080\n"))
	}))
	defer server.Close()

	// First vetting run without local candidate file:
	// Default input file resolves to data/socks5.txt
	pipeline := NewSocksVettingPipeline(PipelineOptions{
		BaseDir:     tmpDir,
		ForceUpdate: true,
		SourceURL:   server.URL,
		Timeout:     50 * time.Millisecond,
		Limit:       1,
	})

	// Before RunContext, ./data must still NOT exist (not created on pipeline initialization)
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("expected ./data to not exist before RunContext executes")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _ = pipeline.RunContext(ctx, nil)

	// After the first vetting run executed and downloaded data, ./data must exist
	if info, err := os.Stat(dataDir); err != nil || !info.IsDir() {
		t.Fatalf("expected ./data to exist after first vetting run wrote files there, err: %v", err)
	}

	expectedCandidateFile := filepath.Join(dataDir, "socks5.txt")
	if _, err := os.Stat(expectedCandidateFile); err != nil {
		t.Fatalf("expected %s to be written in ./data: %v", expectedCandidateFile, err)
	}
}
