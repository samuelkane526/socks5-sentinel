package proxycore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveProxiesToFile(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "subfolder", "vetted.json")

	proxies := []*ProxyItem{
		{
			IP:       "1.2.3.4",
			Port:     1080,
			Proxy:    "socks5h://1.2.3.4:1080",
			Protocol: "socks5h",
		},
	}

	// 1. Success with directory creation
	if err := SaveProxiesToFile(outPath, proxies); err != nil {
		t.Fatalf("failed to save proxies: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read saved file: %v", err)
	}

	var loaded []*ProxyItem
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to unmarshal saved json: %v", err)
	}
	if len(loaded) != 1 || loaded[0].IP != "1.2.3.4" {
		t.Errorf("saved content mismatch: %+v", loaded)
	}

	// 2. Empty/nil proxies saves as []
	outEmpty := filepath.Join(tmpDir, "empty.json")
	if err := SaveProxiesToFile(outEmpty, nil); err != nil {
		t.Fatalf("failed to save nil proxies: %v", err)
	}
	dataEmpty, _ := os.ReadFile(outEmpty)
	if string(dataEmpty) != "[]" {
		t.Errorf("expected [], got %s", string(dataEmpty))
	}
}

func TestMergeVettedProxies(t *testing.T) {
	existing := []*ProxyItem{
		{IP: "1.1.1.1", Port: 1080, Proxy: "socks5h://1.1.1.1:1080", VettedAt: "2026-10-01T00:00:00Z"},
		{IP: "2.2.2.2", Port: 1080, Proxy: "socks5h://2.2.2.2:1080", VettedAt: "2026-10-01T00:00:00Z"},
		{IP: "3.3.3.3", Port: 1080, Proxy: "socks5h://3.3.3.3:1080", VettedAt: "2026-10-01T00:00:00Z"},
	}

	newVetted := []*ProxyItem{
		{IP: "2.2.2.2", Port: 1080, Proxy: "socks5h://2.2.2.2:1080", VettedAt: "2026-10-20T12:00:00Z", LastChecked: "2026-10-20T12:00:00Z"},
		{IP: "4.4.4.4", Port: 1080, Proxy: "socks5h://4.4.4.4:1080", VettedAt: "2026-10-20T12:00:00Z", LastChecked: "2026-10-20T12:00:00Z"},
	}

	merged := MergeVettedProxies(existing, newVetted)
	if len(merged) != 4 {
		t.Fatalf("expected 4 proxies in merged list, got %d", len(merged))
	}

	// 2.2.2.2 and 4.4.4.4 should be at top
	if merged[0].IP != "2.2.2.2" {
		t.Errorf("expected 2.2.2.2 at index 0 (moved to top), got %s", merged[0].IP)
	}
	if merged[0].LastChecked != "2026-10-20T12:00:00Z" {
		t.Errorf("expected updated LastChecked for 2.2.2.2, got %s", merged[0].LastChecked)
	}

	if merged[1].IP != "4.4.4.4" {
		t.Errorf("expected 4.4.4.4 at index 1 (new at top), got %s", merged[1].IP)
	}

	// 1.1.1.1 and 3.3.3.3 should be preserved below
	if merged[2].IP != "1.1.1.1" {
		t.Errorf("expected 1.1.1.1 at index 2, got %s", merged[2].IP)
	}
	if merged[3].IP != "3.3.3.3" {
		t.Errorf("expected 3.3.3.3 at index 3, got %s", merged[3].IP)
	}

	// Every proxy must have LastChecked populated
	for i, p := range merged {
		if p.LastChecked == "" {
			t.Errorf("proxy at index %d (%s) missing LastChecked timestamp", i, p.IP)
		}
	}
}

func TestSaveVettedResults(t *testing.T) {
	tmpDir := t.TempDir()

	proxiesBatch1 := []*ProxyItem{
		{IP: "10.0.0.1", Port: 1080, Proxy: "socks5h://10.0.0.1:1080", VettedAt: "2026-10-20T10:00:00Z", LastChecked: "2026-10-20T10:00:00Z"},
		{IP: "10.0.0.2", Port: 1080, Proxy: "socks5h://10.0.0.2:1080", VettedAt: "2026-10-20T10:00:00Z", LastChecked: "2026-10-20T10:00:00Z"},
	}

	savedPaths, err := SaveVettedResults(tmpDir, "", proxiesBatch1)
	if err != nil {
		t.Fatalf("SaveVettedResults failed: %v", err)
	}

	if len(savedPaths) != 2 {
		t.Fatalf("expected 2 saved paths (session + master), got %d", len(savedPaths))
	}

	// Check elite_proxies directory
	eliteDir := filepath.Join(tmpDir, "elite_proxies")
	masterFile := filepath.Join(eliteDir, "vetted_proxies.json")

	if _, err := os.Stat(masterFile); os.IsNotExist(err) {
		t.Fatalf("expected master list %s to exist", masterFile)
	}

	// Verify master file content
	data, err := os.ReadFile(masterFile)
	if err != nil {
		t.Fatalf("failed reading master file: %v", err)
	}
	var loadedMaster []*ProxyItem
	if err := json.Unmarshal(data, &loadedMaster); err != nil {
		t.Fatalf("failed unmarshaling master: %v", err)
	}
	if len(loadedMaster) != 2 {
		t.Fatalf("expected 2 items in master, got %d", len(loadedMaster))
	}

	// Second batch: re-vets 10.0.0.2 and adds 10.0.0.3
	proxiesBatch2 := []*ProxyItem{
		{IP: "10.0.0.2", Port: 1080, Proxy: "socks5h://10.0.0.2:1080", VettedAt: "2026-10-20T11:00:00Z", LastChecked: "2026-10-20T11:00:00Z"},
		{IP: "10.0.0.3", Port: 1080, Proxy: "socks5h://10.0.0.3:1080", VettedAt: "2026-10-20T11:00:00Z", LastChecked: "2026-10-20T11:00:00Z"},
	}

	savedPaths2, err := SaveVettedResults(tmpDir, "", proxiesBatch2)
	if err != nil {
		t.Fatalf("SaveVettedResults batch 2 failed: %v", err)
	}
	if len(savedPaths2) != 2 {
		t.Fatalf("expected 2 paths in batch 2, got %d", len(savedPaths2))
	}

	// Read master file again
	data2, _ := os.ReadFile(masterFile)
	var loadedMaster2 []*ProxyItem
	_ = json.Unmarshal(data2, &loadedMaster2)

	if len(loadedMaster2) != 3 {
		t.Fatalf("expected 3 items in master after batch 2, got %d", len(loadedMaster2))
	}
	// 10.0.0.2 should be at index 0 (moved to top)
	if loadedMaster2[0].IP != "10.0.0.2" {
		t.Errorf("expected 10.0.0.2 at top of master file, got %s", loadedMaster2[0].IP)
	}
	if loadedMaster2[0].LastChecked != "2026-10-20T11:00:00Z" {
		t.Errorf("expected updated LastChecked timestamp for 10.0.0.2, got %s", loadedMaster2[0].LastChecked)
	}

	// Check that session files exist in elite_proxies
	entries, err := os.ReadDir(eliteDir)
	if err != nil {
		t.Fatalf("failed reading eliteDir: %v", err)
	}
	sessionFileCount := 0
	for _, e := range entries {
		if e.Name() != "vetted_proxies.json" && filepath.Ext(e.Name()) == ".json" {
			sessionFileCount++
		}
	}
	if sessionFileCount < 1 {
		t.Errorf("expected at least 1 session file, got %d", sessionFileCount)
	}
}

func TestProxyItemJSONUnmarshalCompatibility(t *testing.T) {
	// 1. JSON with snake_case last_checked
	rawSnake := []byte(`{"ip":"1.2.3.4","port":1080,"proxy":"socks5h://1.2.3.4:1080","last_checked":"2026-10-20T12:00:00Z"}`)
	var item1 ProxyItem
	if err := json.Unmarshal(rawSnake, &item1); err != nil {
		t.Fatalf("failed unmarshaling snake_case: %v", err)
	}
	if item1.LastChecked != "2026-10-20T12:00:00Z" {
		t.Errorf("expected LastChecked from snake_case, got %s", item1.LastChecked)
	}
	if item1.VettedAt != "2026-10-20T12:00:00Z" {
		t.Errorf("expected VettedAt synchronized from LastChecked, got %s", item1.VettedAt)
	}

	// 2. JSON with only vettedAt
	rawVetted := []byte(`{"ip":"5.6.7.8","port":1080,"proxy":"socks5h://5.6.7.8:1080","vettedAt":"2026-10-19T22:00:00Z"}`)
	var item2 ProxyItem
	if err := json.Unmarshal(rawVetted, &item2); err != nil {
		t.Fatalf("failed unmarshaling vettedAt: %v", err)
	}
	if item2.LastChecked != "2026-10-19T22:00:00Z" {
		t.Errorf("expected LastChecked to sync from vettedAt, got %s", item2.LastChecked)
	}
}

func TestSaveVettedResults_RefusesMalformedOrEmptyMaster(t *testing.T) {
	tmpDir := t.TempDir()
	eliteDir := filepath.Join(tmpDir, "elite_proxies")
	_ = os.MkdirAll(eliteDir, 0755)
	masterFile := filepath.Join(eliteDir, "vetted_proxies.json")

	candidates := []*ProxyItem{
		{IP: "1.1.1.1", Port: 1080, Proxy: "socks5h://1.1.1.1:1080"},
	}

	// 1. Empty master file
	_ = os.WriteFile(masterFile, []byte(""), 0600)
	_, err := SaveVettedResults(tmpDir, "", candidates)
	if err == nil {
		t.Fatal("expected error on empty master file, got nil")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error to mention 'empty', got %v", err)
	}
	// Verify master file remained empty and untouched
	dataEmpty, _ := os.ReadFile(masterFile)
	if len(dataEmpty) != 0 {
		t.Fatalf("master file bytes were modified: %s", string(dataEmpty))
	}

	// 2. Whitespace-only master file
	_ = os.WriteFile(masterFile, []byte("   \n\t  \r\n"), 0600)
	_, err = SaveVettedResults(tmpDir, "", candidates)
	if err == nil {
		t.Fatal("expected error on whitespace master file, got nil")
	}

	// 3. Malformed JSON master file
	malformedBytes := []byte("{ this is not valid json")
	_ = os.WriteFile(masterFile, malformedBytes, 0600)
	_, err = SaveVettedResults(tmpDir, "", candidates)
	if err == nil {
		t.Fatal("expected error on malformed master file, got nil")
	}
	if !strings.Contains(err.Error(), masterFile) {
		t.Errorf("expected error to contain affected path %s, got %v", masterFile, err)
	}
	dataMalformed, _ := os.ReadFile(masterFile)
	if string(dataMalformed) != string(malformedBytes) {
		t.Fatalf("master file bytes were corrupted on error: %s", string(dataMalformed))
	}
}

func TestReplaceFile_PreservesOriginalOnFailure(t *testing.T) {
	tmpDir := t.TempDir()
	destFile := filepath.Join(tmpDir, "target.txt")
	sentinel := []byte("original sentinel content that must survive")
	_ = os.WriteFile(destFile, sentinel, 0600)

	// Open destination exclusively to cause replacement failure / sharing violation
	lockFile, err := os.OpenFile(destFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("failed to open lock file: %v", err)
	}

	newBytes := []byte("new data that should fail replacement")
	replaceErr := ReplaceFileWithBytes(destFile, newBytes, 0644)
	lockFile.Close()

	if replaceErr != nil {
		// Verify sentinel content is 100% intact
		currentData, err := os.ReadFile(destFile)
		if err != nil {
			t.Fatalf("failed reading destFile: %v", err)
		}
		if string(currentData) != string(sentinel) {
			t.Fatalf("sentinel data was overwritten despite error: %s", string(currentData))
		}
	} else {
		// On non-Windows platforms that permit rename over open files, verify new data
		currentData, _ := os.ReadFile(destFile)
		if string(currentData) != string(newBytes) {
			t.Fatalf("expected newBytes, got %s", string(currentData))
		}
	}
}
