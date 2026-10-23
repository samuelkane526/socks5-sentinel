package proxycore

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
)

// ProxyItem represents a normalized proxy configuration
type ProxyItem struct {
	Proxy       string      `json:"proxy"`
	IP          string      `json:"ip"`
	Host        string      `json:"host,omitempty"`
	Port        int         `json:"port"`
	Scheme      string      `json:"scheme,omitempty"`
	Username    string      `json:"username,omitempty"`
	Password    string      `json:"password,omitempty"`
	Protocol    string      `json:"protocol,omitempty"`
	Anonymity   string      `json:"anonymity,omitempty"`
	Score       int         `json:"score,omitempty"`
	Geolocation interface{} `json:"geolocation,omitempty"`
	VettedAt    string      `json:"vettedAt,omitempty"`
	LastChecked string      `json:"lastChecked,omitempty"`
}

type proxyItemAlias ProxyItem

// UnmarshalJSON supports unmarshaling both lastChecked and last_checked snake_case
func (p *ProxyItem) UnmarshalJSON(data []byte) error {
	type rawItem struct {
		proxyItemAlias
		LastCheckedSnake string `json:"last_checked,omitempty"`
	}
	var raw rawItem
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*p = ProxyItem(raw.proxyItemAlias)
	if p.LastChecked == "" && raw.LastCheckedSnake != "" {
		p.LastChecked = raw.LastCheckedSnake
	}
	if p.LastChecked == "" && p.VettedAt != "" {
		p.LastChecked = p.VettedAt
	}
	if p.VettedAt == "" && p.LastChecked != "" {
		p.VettedAt = p.LastChecked
	}
	return nil
}

// ProxyPool manages the collection of SOCKS5 proxies, rotation, and health tracking.
type ProxyPool struct {
	mu            sync.Mutex
	proxies       []*ProxyItem
	currentIndex  int
	failedProxies map[string]bool
	successCount  int
	failCount     int
	filePath      string
}

// NewProxyPool creates a new ProxyPool from a file path or existing slice
func NewProxyPool(source string, shuffle bool) (*ProxyPool, error) {
	return NewProxyPoolWithBase("", source, shuffle)
}

// NewProxyPoolWithBase creates a ProxyPool resolving relative paths from baseDir
func NewProxyPoolWithBase(baseDir, source string, shuffle bool) (*ProxyPool, error) {
	pool := &ProxyPool{
		failedProxies: make(map[string]bool),
	}

	if source != "" {
		if err := pool.LoadFromFileWithBase(baseDir, source, shuffle); err != nil {
			return nil, err
		}
	}

	return pool, nil
}

// NormalizeProxy converts raw map or string representations into a canonical ProxyItem.
func NormalizeProxy(raw interface{}) *ProxyItem {
	if raw == nil {
		return nil
	}

	var host string
	var port int
	var username string
	var password string
	var anonymity = "anonymous"
	var score int
	var geolocation interface{}
	var vettedAt string
	var lastChecked string

	switch v := raw.(type) {
	case string:
		str := strings.TrimSpace(v)
		if !strings.Contains(str, "://") {
			str = "socks5h://" + str
		}
		u, err := url.Parse(str)
		if err == nil {
			host = u.Hostname()
			p, _ := strconv.Atoi(u.Port())
			port = p
			if u.User != nil {
				username = u.User.Username()
				password, _ = u.User.Password()
			}
		} else {
			parts := strings.Split(v, ":")
			if len(parts) >= 2 {
				host = parts[0]
				port, _ = strconv.Atoi(parts[1])
			}
		}
	case map[string]interface{}:
		if h, ok := v["ip"].(string); ok && h != "" {
			host = h
		} else if h, ok := v["host"].(string); ok && h != "" {
			host = h
		}

		if p, ok := v["port"].(float64); ok {
			port = int(p)
		} else if p, ok := v["port"].(int); ok {
			port = p
		} else if p, ok := v["port"].(string); ok {
			port, _ = strconv.Atoi(p)
		}

		if u, ok := v["username"].(string); ok {
			username = u
		}
		if pw, ok := v["password"].(string); ok {
			password = pw
		}
		if a, ok := v["anonymity"].(string); ok && a != "" {
			anonymity = a
		}
		if s, ok := v["score"].(float64); ok {
			score = int(s)
		}
		if g, ok := v["geolocation"]; ok {
			geolocation = g
		}

		if va, ok := v["vettedAt"].(string); ok {
			vettedAt = va
		}
		if lc, ok := v["lastChecked"].(string); ok {
			lastChecked = lc
		} else if lc, ok := v["last_checked"].(string); ok {
			lastChecked = lc
		}
		if lastChecked == "" && vettedAt != "" {
			lastChecked = vettedAt
		}
		if vettedAt == "" && lastChecked != "" {
			vettedAt = lastChecked
		}

		if host == "" && v["proxy"] != nil {
			if proxyStr, ok := v["proxy"].(string); ok {
				return NormalizeProxy(proxyStr)
			}
		}
	case ProxyItem:
		item := v
		if item.LastChecked == "" && item.VettedAt != "" {
			item.LastChecked = item.VettedAt
		}
		if item.VettedAt == "" && item.LastChecked != "" {
			item.VettedAt = item.LastChecked
		}
		return &item
	case *ProxyItem:
		if v != nil {
			if v.LastChecked == "" && v.VettedAt != "" {
				v.LastChecked = v.VettedAt
			}
			if v.VettedAt == "" && v.LastChecked != "" {
				v.VettedAt = v.LastChecked
			}
		}
		return v
	}

	if host == "" || port <= 0 || port > 65535 {
		return nil
	}

	var authPart string
	if username != "" || password != "" {
		authPart = fmt.Sprintf("%s:%s@", url.QueryEscape(username), url.QueryEscape(password))
	}
	scheme := fmt.Sprintf("socks5h://%s%s:%d", authPart, host, port)

	return &ProxyItem{
		IP:          host,
		Host:        host,
		Port:        port,
		Scheme:      scheme,
		Proxy:       scheme,
		Username:    username,
		Password:    password,
		Protocol:    "socks5h",
		Anonymity:   anonymity,
		Score:       score,
		Geolocation: geolocation,
		VettedAt:    vettedAt,
		LastChecked: lastChecked,
	}
}

// ParseProxyData validates and parses raw proxy list content (JSON array or line-delimited text).
// Rejects HTML, empty content, malformed JSON, and data containing zero valid proxies.
func ParseProxyData(data []byte) ([]*ProxyItem, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, errors.New("proxy data is empty")
	}

	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "<!doctype") || strings.HasPrefix(lower, "<html") || strings.HasPrefix(lower, "<head") || strings.HasPrefix(lower, "<?xml") {
		return nil, errors.New("proxy data contains HTML or XML, not a valid proxy list")
	}

	var items []*ProxyItem

	if strings.HasPrefix(trimmed, "[") {
		var rawItems []interface{}
		if err := json.Unmarshal([]byte(trimmed), &rawItems); err != nil {
			return nil, fmt.Errorf("error parsing JSON array: %w", err)
		}
		for _, raw := range rawItems {
			item := NormalizeProxy(raw)
			if item != nil {
				items = append(items, item)
			}
		}
	} else if strings.HasPrefix(trimmed, "{") {
		return nil, errors.New("expected JSON array or line-delimited proxy list, got JSON object")
	} else {
		lines := strings.Split(trimmed, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			item := NormalizeProxy(line)
			if item != nil {
				items = append(items, item)
			}
		}
	}

	if len(items) == 0 {
		return nil, errors.New("no valid proxies found in data")
	}

	return items, nil
}

// LoadFromFile reads a JSON proxy file and initializes the pool.
func (p *ProxyPool) LoadFromFile(filePath string, shuffle bool) error {
	return p.LoadFromFileWithBase("", filePath, shuffle)
}

// LoadFromFileWithBase reads a proxy file (JSON array or line-delimited text) resolving relative paths from baseDir
func (p *ProxyPool) LoadFromFileWithBase(baseDir, filePath string, shuffle bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	resolved := ResolveProxyPathWithBase(baseDir, filePath)
	if resolved == "" {
		return fmt.Errorf("proxy file not found: %s", filePath)
	}

	data, err := os.ReadFile(resolved)
	if err != nil {
		return fmt.Errorf("error reading proxy file %s: %w", resolved, err)
	}

	items, err := ParseProxyData(data)
	if err != nil {
		return fmt.Errorf("failed parsing proxy file %s: %w", resolved, err)
	}

	p.proxies = items
	p.filePath = resolved
	p.currentIndex = 0

	if shuffle {
		p.shuffleLocked()
	}

	return nil
}

// Count returns the number of proxies currently in the pool.
func (p *ProxyPool) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.proxies)
}

// Items returns a copy of the slice of proxies in the pool.
func (p *ProxyPool) Items() []*ProxyItem {
	p.mu.Lock()
	defer p.mu.Unlock()
	copied := make([]*ProxyItem, len(p.proxies))
	copy(copied, p.proxies)
	return copied
}

func (p *ProxyPool) shuffleLocked() {
	rand.Shuffle(len(p.proxies), func(i, j int) {
		p.proxies[i], p.proxies[j] = p.proxies[j], p.proxies[i]
	})
}

// Shuffle randomizes the proxy list order.
func (p *ProxyPool) Shuffle() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.shuffleLocked()
}

// GetNextProxy returns the next proxy in cyclic rotation.
func (p *ProxyPool) GetNextProxy() (*ProxyItem, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.proxies) == 0 {
		return nil, fmt.Errorf("proxy pool is empty")
	}

	proxy := p.proxies[p.currentIndex]
	p.currentIndex = (p.currentIndex + 1) % len(p.proxies)
	return proxy, nil
}

// MarkFailed records a failed attempt for the proxy.
func (p *ProxyPool) MarkFailed(proxy *ProxyItem, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.failCount++
	key := fmt.Sprintf("%s:%d", proxy.IP, proxy.Port)
	p.failedProxies[key] = true
}

// MarkSuccess records a successful request through the proxy.
func (p *ProxyPool) MarkSuccess(proxy *ProxyItem) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.successCount++
}

// Stats returns rotation metrics.
type PoolStats struct {
	Total          int `json:"total"`
	CurrentIndex   int `json:"currentIndex"`
	UniqueFailed   int `json:"uniqueFailed"`
	TotalSuccesses int `json:"totalSuccesses"`
	TotalFailures  int `json:"totalFailures"`
}

// GetStats returns metrics about pool usage.
func (p *ProxyPool) GetStats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()

	return PoolStats{
		Total:          len(p.proxies),
		CurrentIndex:   p.currentIndex,
		UniqueFailed:   len(p.failedProxies),
		TotalSuccesses: p.successCount,
		TotalFailures:  p.failCount,
	}
}
