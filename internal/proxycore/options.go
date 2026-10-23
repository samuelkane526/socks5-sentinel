package proxycore

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Shared default values
const (
	DefaultConcurrency     = 100
	DefaultRetries         = 5
	DefaultBatchTimeout     = 10 * time.Second
	DefaultSingleTimeout    = 5 * time.Second
	DefaultRequestTimeout   = 10 * time.Second
	DefaultOutputDir        = "elite_proxies"
	DefaultOutputFile       = "elite_proxies/vetted_proxies.json"
	DefaultDataFileName     = "socks5.txt"
	DefaultVettedFileName   = "vetted_proxies.json"
	HealthCheckEndpoint     = "https://httpbin.org/get"
	HealthCheckRequestCount = 3
)

// TLSPolicy controls certificate integrity checking
type TLSPolicy string

const (
	TLSStrict   TLSPolicy = "strict"
	TLSInsecure TLSPolicy = "insecure"
)

// UpdatePolicy controls how upstream proxy lists are synchronized
type UpdatePolicy string

const (
	UpdateAuto  UpdatePolicy = "auto"
	UpdateForce UpdatePolicy = "force"
	UpdateNone  UpdatePolicy = "none"
)

// Validation helpers

// ValidateConcurrency ensures concurrency is at least 1
func ValidateConcurrency(n int) error {
	if n < 1 {
		return errors.New("concurrency must be at least 1 worker")
	}
	return nil
}

// ValidateRetries ensures retries count is at least 1 (preserves existing behavior)
func ValidateRetries(n int) error {
	if n < 1 {
		return errors.New("retries after first attempt must be at least 1")
	}
	return nil
}

// ValidateTimeoutMs validates a millisecond timeout and converts to time.Duration
func ValidateTimeoutMs(ms int) (time.Duration, error) {
	if ms <= 0 {
		return 0, errors.New("timeout must be greater than 0 ms")
	}
	dur := time.Duration(ms) * time.Millisecond
	if dur <= 0 {
		return 0, errors.New("timeout value causes numeric overflow")
	}
	return dur, nil
}

// ValidateTarget ensures target passed count is nonnegative (0 = unlimited)
func ValidateTarget(n int) error {
	if n < 0 {
		return errors.New("target passed count must be nonnegative (0 for unlimited)")
	}
	return nil
}

// ValidateLimit ensures candidate limit is nonnegative (0 = test all)
func ValidateLimit(n int) error {
	if n < 0 {
		return errors.New("candidate limit must be nonnegative (0 to test all)")
	}
	return nil
}

// ValidateTargetURL validates an absolute HTTP or HTTPS target URL
func ValidateTargetURL(rawURL string) (*url.URL, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, errors.New("URL cannot be empty")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL format: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, errors.New("URL scheme must be http or https")
	}
	if parsed.Hostname() == "" {
		return nil, errors.New("URL missing valid host")
	}
	return parsed, nil
}

// ValidateProxyAddress validates and parses IP:PORT or socks5h://[user:pass@]host:port
func ValidateProxyAddress(addr string) (*ProxyItem, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil, errors.New("proxy address cannot be empty")
	}

	norm := NormalizeProxy(addr)
	if norm == nil || norm.IP == "" || norm.Port <= 0 || norm.Port > 65535 {
		return nil, fmt.Errorf("invalid proxy address '%s' (expected IP:PORT or socks5h://host:port)", addr)
	}

	return norm, nil
}

var (
	reRedactURI  = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^:/@\s]+):([^/\s]+)@`)
	reRedactAuth = regexp.MustCompile(`(?i)(authorization[:\s]+(?:Bearer|Basic)\s+)([^\s\r\n]+)`)
)

// RedactSensitive masks credentials inside URLs and proxy strings for safe logging
func RedactSensitive(text string) string {
	if text == "" {
		return ""
	}
	text = reRedactURI.ReplaceAllString(text, "${1}${2}:*****@")
	return reRedactAuth.ReplaceAllString(text, "${1}*****")
}

// ResolveDataFilePath locates or defaults a data file path using the current working directory
func ResolveDataFilePath(filename string) string {
	return ResolveDataFilePathWithBase("", filename)
}

// ResolveDataFilePathWithBase locates or defaults a data file relative to a given base directory
func ResolveDataFilePathWithBase(baseDir, filename string) string {
	if filename == "" {
		filename = DefaultDataFileName
	}
	if filepath.IsAbs(filename) {
		return filename
	}

	if baseDir == "" {
		baseDir, _ = os.Getwd()
	}

	candidates := []string{
		filepath.Join(baseDir, "data", filename),
		filepath.Join(baseDir, "proxy_tool", "data", filename),
		filepath.Join(baseDir, filename),
	}

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c
		}
	}

	return filepath.Join(baseDir, "data", filename)
}

// EnsureDataDir creates the ./data directory under baseDir (or current working directory),
// including all necessary parent directories in a safe, cross-platform manner.
func EnsureDataDir(baseDir string) (string, error) {
	if baseDir == "" {
		var err error
		baseDir, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get working directory: %w", err)
		}
	}
	dataDir := filepath.Join(baseDir, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return "", fmt.Errorf("failed creating data directory %s: %w", dataDir, err)
	}
	return dataDir, nil
}

// ResolveProxyPath locates a proxy file with standard search candidates using the current working directory
func ResolveProxyPath(filePath string) string {
	return ResolveProxyPathWithBase("", filePath)
}

// ResolveProxyPathWithBase searches candidate directories for the specified proxy file with respect to baseDir
func ResolveProxyPathWithBase(baseDir, filePath string) string {
	if baseDir == "" {
		baseDir, _ = os.Getwd()
	}

	if filePath != "" {
		if filepath.IsAbs(filePath) {
			return filePath
		}
		candidates := []string{
			filepath.Join(baseDir, filePath),
			filepath.Join(baseDir, "data", filePath),
			filepath.Join(baseDir, "elite_proxies", filePath),
			filepath.Join(baseDir, "output", filePath),
			filepath.Join(baseDir, "proxy_tool", "data", filePath),
			filepath.Join(baseDir, "proxy_tool", "elite_proxies", filePath),
			filepath.Join(baseDir, "proxy_tool", filePath),
		}
		for _, p := range candidates {
			if info, err := os.Stat(p); err == nil && !info.IsDir() {
				return p
			}
		}
		// Preserve explicit path rather than falling back to default files
		return filepath.Join(baseDir, filePath)
	}

	// Default fallback search order: prefer current vetted master first,
	// then legacy vetted locations, then raw candidate lists.
	defaultCandidates := []string{
		filepath.Join(baseDir, "elite_proxies", "vetted_proxies.json"),
		filepath.Join(baseDir, "proxy_tool", "elite_proxies", "vetted_proxies.json"),
		filepath.Join(baseDir, "data", "vetted_proxies.json"),
		filepath.Join(baseDir, "output", "vetted_proxies.json"),
		filepath.Join(baseDir, "vetted_proxies.json"),
		filepath.Join(baseDir, "proxy_tool", "data", "vetted_proxies.json"),
		filepath.Join(baseDir, "data", "socks5.txt"),
		filepath.Join(baseDir, "data", "sock5_proxy_list.json"),
		filepath.Join(baseDir, "proxy_tool", "data", "socks5.txt"),
		filepath.Join(baseDir, "proxy_tool", "data", "sock5_proxy_list.json"),
		filepath.Join(baseDir, "socks5.txt"),
		filepath.Join(baseDir, "sock5_proxy_list.json"),
	}

	for _, p := range defaultCandidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}

	return filepath.Join(baseDir, "elite_proxies", "vetted_proxies.json")
}

// ParseProxyAddress splits "host:port" or returns error
func ParseProxyAddress(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %s: %w", portStr, err)
	}
	return host, port, nil
}
