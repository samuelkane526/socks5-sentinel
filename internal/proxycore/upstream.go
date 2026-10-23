package proxycore

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	DEFAULT_GITHUB_REPO    = "https://github.com/proxifly/free-proxy-list"
	RAW_PROXY_DATA_URL     = "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt"
	GITHUB_COMMITS_API_URL = "https://api.github.com/repos/proxifly/free-proxy-list/commits?path=proxies/protocols/socks5/data.txt&per_page=1"
)

// ResolveFetchURL normalizes a GitHub repository URL, raw URL, or HTTP(S) address to a downloadable proxy list URL.
func ResolveFetchURL(source string) string {
	s := strings.TrimSpace(source)
	if s == "" || s == DEFAULT_GITHUB_REPO || s == DEFAULT_GITHUB_REPO+"/" {
		return RAW_PROXY_DATA_URL
	}
	s = strings.TrimSuffix(s, ".git")
	s = strings.TrimRight(s, "/")

	// If it contains /blob/, convert github blob to raw content URL
	if strings.Contains(s, "github.com") && strings.Contains(s, "/blob/") {
		s = strings.Replace(s, "https://github.com/", "https://raw.githubusercontent.com/", 1)
		s = strings.Replace(s, "http://github.com/", "http://raw.githubusercontent.com/", 1)
		s = strings.Replace(s, "/blob/", "/", 1)
		return s
	}

	// If it's a bare github repo URL (e.g., https://github.com/owner/repo)
	if strings.HasPrefix(s, "https://github.com/") || strings.HasPrefix(s, "http://github.com/") {
		trimmed := strings.TrimPrefix(s, "https://github.com/")
		trimmed = strings.TrimPrefix(trimmed, "http://github.com/")
		parts := strings.Split(trimmed, "/")
		if len(parts) == 2 {
			if parts[0] == "proxifly" && parts[1] == "free-proxy-list" {
				return RAW_PROXY_DATA_URL
			}
			return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/main/proxies/protocols/socks5/data.txt", parts[0], parts[1])
		}
	}

	return s
}

// ResolveCommitAPIURL derives the GitHub commits API endpoint for a given repo or source URL.
func ResolveCommitAPIURL(source string) string {
	s := strings.TrimSpace(source)
	if s == "" || s == DEFAULT_GITHUB_REPO || s == RAW_PROXY_DATA_URL {
		return GITHUB_COMMITS_API_URL
	}
	s = strings.TrimSuffix(s, ".git")
	s = strings.TrimRight(s, "/")
	if strings.HasPrefix(s, "https://github.com/") || strings.HasPrefix(s, "http://github.com/") {
		trimmed := strings.TrimPrefix(s, "https://github.com/")
		trimmed = strings.TrimPrefix(trimmed, "http://github.com/")
		parts := strings.Split(trimmed, "/")
		if len(parts) >= 2 {
			owner := parts[0]
			repo := parts[1]
			if len(parts) > 3 && parts[2] == "blob" {
				filePath := strings.Join(parts[4:], "/")
				return fmt.Sprintf("https://api.github.com/repos/%s/%s/commits?path=%s&per_page=1", owner, repo, filePath)
			}
			if owner == "proxifly" && repo == "free-proxy-list" {
				return GITHUB_COMMITS_API_URL
			}
			return fmt.Sprintf("https://api.github.com/repos/%s/%s/commits?path=proxies/protocols/socks5/data.txt&per_page=1", owner, repo)
		}
	}
	return ""
}

func shaFromCommit(c *CommitMeta) string {
	if c != nil {
		return c.SHA
	}
	return ""
}

// FetchLocalPublicIP retrieves the host machine's public IPv4 address from trusted endpoints
func FetchLocalPublicIP(timeout time.Duration) (string, error) {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return FetchLocalPublicIPContext(ctx, timeout)
}

// FetchLocalPublicIPContext retrieves public IP with context cancellation support
func FetchLocalPublicIPContext(ctx context.Context, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	endpoints := []string{
		"https://api.ipify.org?format=json",
		"https://httpbin.org/ip",
		"https://ifconfig.me/ip",
	}

	client := &http.Client{
		Timeout: timeout,
	}

	for _, ep := range endpoints {
		if err := ctx.Err(); err != nil {
			return "", err
		}

		req, err := http.NewRequestWithContext(ctx, "GET", ep, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}

		var parsed map[string]interface{}
		if err := json.Unmarshal(body, &parsed); err == nil {
			if ipVal, ok := parsed["ip"].(string); ok && ipVal != "" {
				ip := strings.TrimSpace(strings.Split(ipVal, ",")[0])
				if net.ParseIP(ip) != nil {
					return ip, nil
				}
			}
			if originVal, ok := parsed["origin"].(string); ok && originVal != "" {
				ip := strings.TrimSpace(strings.Split(originVal, ",")[0])
				if net.ParseIP(ip) != nil {
					return ip, nil
				}
			}
		}

		text := strings.TrimSpace(string(body))
		parts := strings.Fields(text)
		if len(parts) > 0 {
			candidate := strings.Trim(parts[0], ",\"'")
			if net.ParseIP(candidate) != nil {
				return candidate, nil
			}
		}
	}

	return "", fmt.Errorf("failed to retrieve host public IP from all trusted endpoints")
}

// CommitTimestamp holds parsed timestamp information from commit messages
type CommitTimestamp struct {
	Timestamp  int64
	DateString string
	ISOString  string
}

var reCommitDate = regexp.MustCompile(`(?i)(?:Updated|Date)[:\s]+(.+)$`)

// ParseCommitMessageTimestamp parses timestamps like "Updated 📦 Mon Oct 19 23:43:54 UTC 2026"
func ParseCommitMessageTimestamp(message string) *CommitTimestamp {
	if message == "" {
		return nil
	}

	var datePart string
	if strings.Contains(message, "📦") {
		parts := strings.Split(message, "📦")
		if len(parts) > 1 {
			datePart = strings.TrimSpace(parts[1])
		}
	} else {
		matches := reCommitDate.FindStringSubmatch(message)
		if len(matches) > 1 {
			datePart = strings.TrimSpace(matches[1])
		} else {
			datePart = strings.TrimSpace(message)
		}
	}

	if datePart == "" {
		return nil
	}

	layouts := []string{
		"Mon Jan 2 15:04:05 MST 2006",
		"Mon Jan 02 15:04:05 MST 2006",
		time.UnixDate,
		time.RFC1123,
		time.RFC1123Z,
		time.RFC3339,
		time.ANSIC,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, datePart); err == nil {
			return &CommitTimestamp{
				Timestamp:  t.UnixMilli(),
				DateString: datePart,
				ISOString:  t.UTC().Format(time.RFC3339),
			}
		}
	}

	return nil
}

// CommitMeta contains upstream commit details
type CommitMeta struct {
	SHA        string `json:"sha"`
	Message    string `json:"message"`
	Timestamp  int64  `json:"timestamp"`
	DateString string `json:"dateString"`
}

// CheckUpstreamCommit fetches latest commit info for data.json from GitHub Commits API
func CheckUpstreamCommit(apiURL string) (*CommitMeta, error) {
	return CheckUpstreamCommitContext(context.Background(), apiURL)
}

// CheckUpstreamCommitContext fetches latest commit info with context
func CheckUpstreamCommitContext(ctx context.Context, apiURL string) (*CommitMeta, error) {
	if apiURL == "" {
		apiURL = GITHUB_COMMITS_API_URL
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SocksProxyClient/1.0")
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		return nil, fmt.Errorf("GitHub API rate limit reached (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GitHub API returned HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var commits []map[string]interface{}
	if err := json.Unmarshal(body, &commits); err != nil {
		return nil, fmt.Errorf("failed parsing GitHub commits response: %w", err)
	}

	if len(commits) == 0 {
		return nil, fmt.Errorf("GitHub API returned an empty commit array")
	}

	first := commits[0]
	sha, _ := first["sha"].(string)

	var message string
	var commitDateStr string
	if commitObj, ok := first["commit"].(map[string]interface{}); ok {
		if msg, ok := commitObj["message"].(string); ok {
			message = msg
		}
		if committer, ok := commitObj["committer"].(map[string]interface{}); ok {
			if d, ok := committer["date"].(string); ok {
				commitDateStr = d
			}
		}
		if commitDateStr == "" {
			if author, ok := commitObj["author"].(map[string]interface{}); ok {
				if d, ok := author["date"].(string); ok {
					commitDateStr = d
				}
			}
		}
	}

	parsedTs := ParseCommitMessageTimestamp(message)
	var timestamp int64
	var dateString string

	if parsedTs != nil {
		timestamp = parsedTs.Timestamp
		dateString = parsedTs.DateString
	} else if commitDateStr != "" {
		if t, err := time.Parse(time.RFC3339, commitDateStr); err == nil {
			timestamp = t.UnixMilli()
			dateString = commitDateStr
		}
	}

	return &CommitMeta{
		SHA:        sha,
		Message:    message,
		Timestamp:  timestamp,
		DateString: dateString,
	}, nil
}

// DownloadFileStream streams a remote file to destination path following redirects
func DownloadFileStream(sourceURL, destPath string, onProgress func(downloaded, total int64)) error {
	return DownloadFileStreamContext(context.Background(), sourceURL, destPath, onProgress)
}

// DownloadFileStreamContext streams a remote file with context cancellation and progress tracking
func DownloadFileStreamContext(ctx context.Context, sourceURL, destPath string, onProgress func(downloaded, total int64)) error {
	currentURL := sourceURL
	if strings.Contains(currentURL, "github.com") && strings.Contains(currentURL, "/blob/") {
		currentURL = strings.Replace(currentURL, "https://github.com/", "https://raw.githubusercontent.com/", 1)
		currentURL = strings.Replace(currentURL, "/blob/", "/", 1)
	}

	client := &http.Client{
		Timeout: 180 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", currentURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SocksProxyClient/1.0")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}

	outFile, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	totalBytes := resp.ContentLength
	var downloadedBytes int64
	var lastReported int64

	buf := make([]byte, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := outFile.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
			downloadedBytes += int64(n)
			if onProgress != nil && (downloadedBytes-lastReported >= 512*1024 || (totalBytes > 0 && downloadedBytes == totalBytes)) {
				lastReported = downloadedBytes
				onProgress(downloadedBytes, totalBytes)
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return readErr
		}
	}

	return nil
}

// PullMetadata defines schema for last_pull_metadata.json
type PullMetadata struct {
	SourceURL            string `json:"sourceURL,omitempty"`
	TargetFilePath       string `json:"targetFilePath,omitempty"`
	SHA                  string `json:"sha"`
	CommitMessage        string `json:"commitMessage"`
	LastUpdatedTimestamp int64  `json:"lastUpdatedTimestamp"`
	LastUpdatedDate      string `json:"lastUpdatedDate"`
	LastPulledAt         string `json:"lastPulledAt"`
	FileSizeBytes        int64  `json:"fileSizeBytes"`
}

// GetStoredMetadata loads stored metadata from disk
func GetStoredMetadata(metadataPath string) *PullMetadata {
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil
	}
	var meta PullMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil
	}
	return &meta
}

// SaveStoredMetadata saves metadata JSON to disk atomically
func SaveStoredMetadata(metadataPath string, meta *PullMetadata) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return ReplaceFileWithBytes(metadataPath, data, 0644)
}

// RefreshOptions configures RefreshProxyDataIfNeeded
type RefreshOptions struct {
	BaseDir     string
	TargetFile  string
	ForceUpdate bool
	NoUpdate    bool
	Verbose     bool
	SourceURL   string
}

// RefreshResult details the outcome of an upstream sync check
type RefreshResult struct {
	Updated        bool        `json:"updated"`
	Reason         string      `json:"reason"`
	TargetFilePath string      `json:"targetFilePath"`
	Commit         *CommitMeta `json:"commit,omitempty"`
	FileSizeBytes  int64       `json:"fileSizeBytes,omitempty"`
}

// RefreshProxyDataIfNeeded checks GitHub commit metadata and downloads fresh proxy list if newer
func RefreshProxyDataIfNeeded(options RefreshOptions) (*RefreshResult, error) {
	return RefreshProxyDataIfNeededContext(context.Background(), options, nil)
}

// RefreshProxyDataIfNeededContext checks and synchronizes proxy data with context and event listener
func RefreshProxyDataIfNeededContext(ctx context.Context, options RefreshOptions, listener Listener) (*RefreshResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	targetFilePath := options.TargetFile
	if targetFilePath == "" || targetFilePath == DefaultDataFileName {
		targetFilePath = ResolveDataFilePathWithBase(options.BaseDir, DefaultDataFileName)
	} else if !filepath.IsAbs(targetFilePath) {
		baseDir := options.BaseDir
		if baseDir == "" {
			baseDir, _ = os.Getwd()
		}
		targetFilePath = filepath.Join(baseDir, targetFilePath)
	}

	metadataPath := filepath.Join(filepath.Dir(targetFilePath), "last_pull_metadata.json")

	emitLog := func(level, msg string) {
		if listener != nil {
			listener(Event{
				Kind:      EventLog,
				Timestamp: time.Now(),
				Level:     level,
				Message:   msg,
			})
		}
	}

	if options.NoUpdate {
		if options.Verbose {
			emitLog("info", "[Proxy Update] Skipping upstream update check (--no-update provided).")
		}
		return &RefreshResult{Updated: false, Reason: "skipped_by_flag", TargetFilePath: targetFilePath}, nil
	}

	emitLog("info", "[Proxy Update] Checking GitHub upstream for fresh proxy data...")
	if listener != nil {
		listener(Event{Kind: EventRefreshStarted, Timestamp: time.Now(), Message: "Checking upstream..."})
	}

	commitAPIURL := ResolveCommitAPIURL(options.SourceURL)
	downloadURL := ResolveFetchURL(options.SourceURL)
	targetInfo, statErr := os.Stat(targetFilePath)
	hasLocalData := statErr == nil && !os.IsNotExist(statErr) && !targetInfo.IsDir()

	var latestCommit *CommitMeta
	var commitTs int64
	var commitMsg string
	var commitDate string
	var commitSHA string
	var metaErr error

	if commitAPIURL != "" {
		latestCommit, metaErr = CheckUpstreamCommitContext(ctx, commitAPIURL)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if latestCommit != nil {
			commitTs = latestCommit.Timestamp
			commitMsg = latestCommit.Message
			commitDate = latestCommit.DateString
			commitSHA = shaFromCommit(latestCommit)
		}
	}

	storedMetadata := GetStoredMetadata(metadataPath)
	needsUpdate := false

	if options.ForceUpdate {
		needsUpdate = true
		if metaErr != nil {
			emitLog("warn", fmt.Sprintf("[Proxy Update] Upstream commit check failed: %s. Proceeding with forced download.", metaErr.Error()))
		} else {
			emitLog("info", "[Proxy Update] Force update requested. Downloading latest data...")
		}
	} else if !hasLocalData {
		needsUpdate = true
		if metaErr != nil {
			emitLog("warn", fmt.Sprintf("[Proxy Update] Upstream commit check failed: %s. Local data missing, attempting download.", metaErr.Error()))
		} else {
			emitLog("info", fmt.Sprintf("[Proxy Update] Local proxy data (%s) does not exist. Initial pull required.", targetFilePath))
		}
	} else if metaErr != nil {
		// Metadata check failed, but usable local file exists and force update was not requested: fallback to local
		emitLog("warn", fmt.Sprintf("[Proxy Update] Upstream check failed: %s. Using existing local data.", metaErr.Error()))
		res := &RefreshResult{
			Updated:        false,
			Reason:         "upstream_check_failed_fallback",
			TargetFilePath: targetFilePath,
			FileSizeBytes:  targetInfo.Size(),
		}
		if listener != nil {
			listener(Event{Kind: EventRefreshDone, Timestamp: time.Now(), Data: res})
		}
		return res, nil
	} else if commitAPIURL == "" {
		// Custom raw source with no commit API: download during automatic refresh
		needsUpdate = true
		emitLog("info", "[Proxy Update] Custom raw source without commit API. Downloading fresh data...")
	} else if storedMetadata == nil || storedMetadata.SourceURL != downloadURL || storedMetadata.TargetFilePath != targetFilePath {
		// Missing or mismatched identity metadata: treat as needing refresh
		needsUpdate = true
		emitLog("info", "[Proxy Update] No matching freshness metadata for source/target. Pulling fresh data...")
	} else if commitSHA != "" && storedMetadata.SHA != "" {
		if commitSHA != storedMetadata.SHA {
			needsUpdate = true
			emitLog("info", fmt.Sprintf("[Proxy Update] Upstream update detected! Commit: \"%s\" (%s)", commitMsg, commitDate))
		} else {
			emitLog("info", fmt.Sprintf("[Proxy Update] Proxy data is already up to date (%s).", commitDate))
		}
	} else if storedMetadata.LastUpdatedTimestamp > 0 && commitTs > 0 {
		if commitTs > storedMetadata.LastUpdatedTimestamp {
			needsUpdate = true
			emitLog("info", fmt.Sprintf("[Proxy Update] Upstream update detected! Commit: \"%s\" (%s)", commitMsg, commitDate))
		} else {
			emitLog("info", fmt.Sprintf("[Proxy Update] Proxy data is already up to date (%s).", commitDate))
		}
	} else {
		mtimeMs := targetInfo.ModTime().UnixMilli()
		if commitTs > 0 && commitTs > mtimeMs {
			needsUpdate = true
			emitLog("info", fmt.Sprintf("[Proxy Update] Upstream data is newer than local file (%s > %s). Repull needed.",
				time.UnixMilli(commitTs).UTC().Format(time.RFC3339),
				targetInfo.ModTime().UTC().Format(time.RFC3339)))
		} else {
			emitLog("info", "[Proxy Update] Local file timestamp is up to date. Initializing metadata tracking.")
			_ = SaveStoredMetadata(metadataPath, &PullMetadata{
				SourceURL:            downloadURL,
				TargetFilePath:       targetFilePath,
				SHA:                  commitSHA,
				CommitMessage:        commitMsg,
				LastUpdatedTimestamp: commitTs,
				LastUpdatedDate:      commitDate,
				LastPulledAt:         time.Now().UTC().Format(time.RFC3339),
				FileSizeBytes:        targetInfo.Size(),
			})
		}
	}

	if !needsUpdate {
		var sz int64
		if targetInfo != nil {
			sz = targetInfo.Size()
		}
		res := &RefreshResult{
			Updated:        false,
			Reason:         "up_to_date",
			TargetFilePath: targetFilePath,
			Commit:         latestCommit,
			FileSizeBytes:  sz,
		}
		if listener != nil {
			listener(Event{Kind: EventRefreshDone, Timestamp: time.Now(), Data: res})
		}
		return res, nil
	}

	if err := os.MkdirAll(filepath.Dir(targetFilePath), 0755); err != nil {
		return nil, fmt.Errorf("failed creating target directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(targetFilePath), ".download-*")
	if err != nil {
		return nil, fmt.Errorf("failed creating download temp file: %w", err)
	}
	tempPath := tmpFile.Name()
	_ = tmpFile.Close()

	emitLog("info", "[Proxy Update] Streaming fresh proxy data from upstream...")

	downloadErr := DownloadFileStreamContext(ctx, downloadURL, tempPath, func(downloaded, total int64) {
		if listener != nil {
			listener(Event{
				Kind:            EventRefreshProgress,
				Timestamp:       time.Now(),
				ProgressCurrent: downloaded,
				ProgressTotal:   total,
			})
		}
	})

	if downloadErr != nil {
		_ = os.Remove(tempPath)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		emitLog("error", fmt.Sprintf("[Proxy Update] Failed to download fresh proxy data: %s. Preserving local data.", downloadErr.Error()))
		res := &RefreshResult{Updated: false, Reason: "download_failed", TargetFilePath: targetFilePath}
		if listener != nil {
			listener(Event{Kind: EventRefreshDone, Timestamp: time.Now(), Level: "error", Message: downloadErr.Error(), Data: res})
		}
		return res, downloadErr
	}

	// Validate downloaded content before publication
	data, err := os.ReadFile(tempPath)
	if err != nil {
		_ = os.Remove(tempPath)
		return nil, fmt.Errorf("cannot read downloaded temp file: %w", err)
	}

	if _, err := ParseProxyData(data); err != nil {
		_ = os.Remove(tempPath)
		emitLog("error", fmt.Sprintf("[Proxy Update] Downloaded proxy content validation failed: %s. Preserving local data.", err.Error()))
		res := &RefreshResult{Updated: false, Reason: "validation_failed", TargetFilePath: targetFilePath}
		if listener != nil {
			listener(Event{Kind: EventRefreshDone, Timestamp: time.Now(), Level: "error", Message: err.Error(), Data: res})
		}
		return res, fmt.Errorf("downloaded proxy content validation failed: %w", err)
	}

	// Atomically replace target file
	if err := ReplaceFile(tempPath, targetFilePath); err != nil {
		return nil, err
	}

	finalInfo, _ := os.Stat(targetFilePath)
	var finalSize int64
	if finalInfo != nil {
		finalSize = finalInfo.Size()
	}

	_ = SaveStoredMetadata(metadataPath, &PullMetadata{
		SourceURL:            downloadURL,
		TargetFilePath:       targetFilePath,
		SHA:                  commitSHA,
		CommitMessage:        commitMsg,
		LastUpdatedTimestamp: commitTs,
		LastUpdatedDate:      commitDate,
		LastPulledAt:         time.Now().UTC().Format(time.RFC3339),
		FileSizeBytes:        finalSize,
	})

	// Ensure the containing data folder timestamp is explicitly updated as soon as socks5.txt is auto fetched
	dataFolder := filepath.Dir(targetFilePath)
	now := time.Now()
	_ = os.Chtimes(dataFolder, now, now)

	emitLog("success", fmt.Sprintf("[Proxy Update] Successfully updated proxy data: %.2f MB saved to %s",
		float64(finalSize)/(1024.0*1024.0), targetFilePath))

	res := &RefreshResult{
		Updated:        true,
		Reason:         "updated",
		TargetFilePath: targetFilePath,
		Commit:         latestCommit,
		FileSizeBytes:  finalSize,
	}
	if listener != nil {
		listener(Event{Kind: EventRefreshDone, Timestamp: time.Now(), Level: "success", Data: res})
	}

	return res, nil
}
