package proxycore

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// MaxResponseBodyBytes is the maximum allowed size (8 MiB) for buffered HTTP response bodies after decompression.
const MaxResponseBodyBytes = 8 * 1024 * 1024

// BROWSER_USER_AGENTS contains modern realistic User-Agents for anonymity rotation
var BROWSER_USER_AGENTS = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
}

// SENSITIVE_IP_HEADERS contains identifying headers stripped for outbound anonymity and verified for leaks
var SENSITIVE_IP_HEADERS = []string{
	"x-forwarded-for",
	"x-real-ip",
	"client-ip",
	"via",
	"true-client-ip",
	"cf-connecting-ip",
	"x-cluster-client-ip",
	"forwarded",
	"x-original-forwarded-for",
}

// RequestOptions configures a single HTTP/HTTPS request dispatch
type RequestOptions struct {
	Method             string
	Headers            map[string]string
	Body               []byte
	Timeout            time.Duration
	ProxyTimeout       time.Duration
	AllowRedirects     bool
	TLSPolicy          TLSPolicy
	RejectUnauthorized bool
	AllowInsecure      bool
	AnonymizeHeaders   bool
	UserAgent          string
	ResolveRemoteDNS   bool
	RootCAs            *x509.CertPool
}

// Response represents a parsed HTTP response
type Response struct {
	Status     int               `json:"status"`
	StatusText string            `json:"statusText"`
	Headers    map[string]string `json:"headers"`
	RawBody    []byte            `json:"-"`
	ProxyUsed  *ProxyItem        `json:"proxyUsed,omitempty"`
	Attempts   int               `json:"attempts"`
}

// Text returns the response body as a string
func (r *Response) Text() string {
	return string(r.RawBody)
}

// JSON unmarshals the response body into the destination
func (r *Response) JSON(dest interface{}) error {
	return json.Unmarshal(r.RawBody, dest)
}

// GetRandomUserAgent returns a randomly selected modern browser User-Agent
func GetRandomUserAgent() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return BROWSER_USER_AGENTS[r.Intn(len(BROWSER_USER_AGENTS))]
}

// IsSensitiveLeakHeader checks if a header name is a sensitive identifying header
func IsSensitiveLeakHeader(headerName string) bool {
	lower := strings.ToLower(strings.TrimSpace(headerName))
	for _, h := range SENSITIVE_IP_HEADERS {
		if lower == h {
			return true
		}
	}
	return false
}

// DispatchSingleProxyRequest sends an HTTP/HTTPS request through a proxy with strict anti-MITM and anonymity controls
func DispatchSingleProxyRequest(proxy *ProxyItem, targetURL string, opts RequestOptions) (*Response, error) {
	ctx := context.Background()
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	return DispatchSingleProxyRequestContext(ctx, proxy, targetURL, opts)
}

// DispatchSingleProxyRequestContext sends request through proxy with context support
func DispatchSingleProxyRequestContext(ctx context.Context, proxy *ProxyItem, targetURL string, opts RequestOptions) (*Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %w", err)
	}

	isHTTPS := strings.EqualFold(parsedURL.Scheme, "https")
	targetHost := parsedURL.Hostname()
	targetPort := 80
	if isHTTPS {
		targetPort = 443
	}

	if parsedURL.Port() != "" {
		if p, err := strconv.Atoi(parsedURL.Port()); err == nil {
			targetPort = p
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	proxyTimeout := opts.ProxyTimeout
	if proxyTimeout <= 0 {
		proxyTimeout = 5 * time.Second
	}
	if proxyTimeout > timeout {
		proxyTimeout = timeout
	}

	var conn net.Conn
	if proxy != nil && proxy.IP != "" {
		proxyAddr := fmt.Sprintf("%s:%d", proxy.IP, proxy.Port)
		c, err := DialSOCKS5Context(ctx, proxyAddr, proxy.Username, proxy.Password, targetHost, targetPort, proxyTimeout, opts.ResolveRemoteDNS)
		if err != nil {
			return nil, err
		}
		conn = c
	} else {
		dialer := &net.Dialer{Timeout: timeout}
		c, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(targetHost, strconv.Itoa(targetPort)))
		if err != nil {
			return nil, fmt.Errorf("direct connect failed: %w", err)
		}
		conn = c
	}
	defer conn.Close()

	// Ensure conn closes if ctx cancels
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed setting socket deadline: %w", err)
	}

	var activeConn net.Conn = conn
	if isHTTPS {
		strictTLS := true
		if opts.TLSPolicy == TLSInsecure || (opts.AllowInsecure && !opts.RejectUnauthorized) {
			strictTLS = false
		}

		tlsConfig := &tls.Config{
			ServerName:         targetHost,
			InsecureSkipVerify: !strictTLS,
			RootCAs:            opts.RootCAs,
		}

		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("TLS Handshake Failed: %w", err)
		}

		if strictTLS {
			state := tlsConn.ConnectionState()
			if len(state.VerifiedChains) == 0 {
				return nil, fmt.Errorf("TLS Integrity Check Failed: Unauthorized Certificate")
			}
		}
		activeConn = tlsConn
	}

	method := strings.ToUpper(opts.Method)
	if method == "" {
		method = "GET"
	}

	reqPath := parsedURL.RequestURI()
	if reqPath == "" {
		reqPath = "/"
	}

	ua := opts.UserAgent
	if ua == "" {
		ua = BROWSER_USER_AGENTS[0]
	}

	var reqBuf bytes.Buffer
	reqBuf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, reqPath))
	if (isHTTPS && targetPort == 443) || (!isHTTPS && targetPort == 80) {
		reqBuf.WriteString(fmt.Sprintf("Host: %s\r\n", targetHost))
	} else {
		reqBuf.WriteString(fmt.Sprintf("Host: %s:%d\r\n", targetHost, targetPort))
	}

	reqBuf.WriteString(fmt.Sprintf("User-Agent: %s\r\n", ua))
	reqBuf.WriteString("Accept: application/json, text/plain, */*\r\n")
	reqBuf.WriteString("Accept-Encoding: gzip, deflate\r\n")
	reqBuf.WriteString("Connection: close\r\n")

	for k, v := range opts.Headers {
		lk := strings.ToLower(k)
		if lk == "host" || lk == "user-agent" || lk == "accept" || lk == "accept-encoding" || lk == "connection" || lk == "content-length" {
			continue
		}
		if opts.AnonymizeHeaders && IsSensitiveLeakHeader(lk) {
			continue
		}
		reqBuf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}

	if len(opts.Body) > 0 {
		reqBuf.WriteString(fmt.Sprintf("Content-Length: %d\r\n\r\n", len(opts.Body)))
		reqBuf.Write(opts.Body)
	} else {
		reqBuf.WriteString("\r\n")
	}

	if _, err := activeConn.Write(reqBuf.Bytes()); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("socket transmission error: %w", err)
	}

	respReader := bufio.NewReader(activeConn)
	httpResp, err := http.ReadResponse(respReader, &http.Request{Method: method})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("failed reading HTTP response: %w", err)
	}
	defer httpResp.Body.Close()

	if !opts.AllowRedirects && httpResp.StatusCode >= 300 && httpResp.StatusCode < 400 {
		return nil, fmt.Errorf("Redirect rejected (HTTP %d): Traffic hijacking or captive portal detected", httpResp.StatusCode)
	}

	var bodyReader io.Reader = httpResp.Body
	contentEncoding := strings.ToLower(httpResp.Header.Get("Content-Encoding"))
	if strings.Contains(contentEncoding, "gzip") {
		gz, err := gzip.NewReader(httpResp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed initializing gzip decoder: %w", err)
		}
		defer gz.Close()
		bodyReader = gz
	} else if strings.Contains(contentEncoding, "deflate") {
		zr, err := zlib.NewReader(httpResp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed initializing deflate decoder: %w", err)
		}
		defer zr.Close()
		bodyReader = zr
	}

	limitedReader := io.LimitReader(bodyReader, MaxResponseBodyBytes+1)
	rawBody, err := io.ReadAll(limitedReader)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("failed reading HTTP response body: %w", err)
	}

	if int64(len(rawBody)) > MaxResponseBodyBytes {
		return nil, fmt.Errorf("response body exceeded maximum allowed limit of %d bytes", MaxResponseBodyBytes)
	}

	headers := make(map[string]string)
	for k, vals := range httpResp.Header {
		headers[strings.ToLower(k)] = strings.Join(vals, ", ")
	}

	return &Response{
		Status:     httpResp.StatusCode,
		StatusText: httpResp.Status,
		Headers:    headers,
		RawBody:    rawBody,
		ProxyUsed:  proxy,
	}, nil
}

// ClientOptions configures SocksProxyClient
type ClientOptions struct {
	BaseDir            string
	ProxyFile          string
	UseVettedOnly      bool
	MaxRetries         int
	Timeout            time.Duration
	ProxyTimeout       time.Duration
	ResolveRemoteDNS   bool
	AnonymizeHeaders   bool
	TLSPolicy          TLSPolicy
	RejectUnauthorized bool
	AllowRedirects     bool
	Verbose            bool
	Proxies            []*ProxyItem
}

// SocksProxyClient performs rotating HTTP/HTTPS requests with failover and anonymity controls
type SocksProxyClient struct {
	options ClientOptions
	pool    *ProxyPool
}

// NewSocksProxyClient instantiates a new rotating proxy client
func NewSocksProxyClient(options ClientOptions) (*SocksProxyClient, error) {
	if options.MaxRetries <= 0 {
		options.MaxRetries = DefaultRetries
	}
	if options.Timeout <= 0 {
		options.Timeout = DefaultRequestTimeout
	}
	if options.ProxyTimeout <= 0 {
		options.ProxyTimeout = 5 * time.Second
	}
	options.ResolveRemoteDNS = true
	options.AnonymizeHeaders = true

	if options.TLSPolicy == "" {
		if options.RejectUnauthorized {
			options.TLSPolicy = TLSStrict
		} else {
			options.TLSPolicy = TLSStrict
		}
	}

	baseDir := options.BaseDir
	if baseDir == "" {
		baseDir, _ = os.Getwd()
	}

	if options.ProxyFile == "" {
		options.ProxyFile = ResolveProxyPathWithBase(baseDir, "")
	}

	var pool *ProxyPool
	var err error
	if len(options.Proxies) > 0 {
		pool = &ProxyPool{
			failedProxies: make(map[string]bool),
			proxies:       options.Proxies,
		}
	} else {
		pool, err = NewProxyPoolWithBase(baseDir, options.ProxyFile, true)
		if err != nil {
			return nil, err
		}
	}

	return &SocksProxyClient{
		options: options,
		pool:    pool,
	}, nil
}

// Request dispatches a request with automatic proxy rotation and failover
func (c *SocksProxyClient) Request(targetURL string, reqOpts ...RequestOptions) (*Response, error) {
	return c.RequestWithContext(context.Background(), targetURL, nil, reqOpts...)
}

// RequestWithContext dispatches request with context cancellation and event notifications
func (c *SocksProxyClient) RequestWithContext(ctx context.Context, targetURL string, listener Listener, reqOpts ...RequestOptions) (*Response, error) {
	var opts RequestOptions
	if len(reqOpts) > 0 {
		opts = reqOpts[0]
	}

	if opts.Timeout <= 0 {
		opts.Timeout = c.options.Timeout
	}
	if opts.ProxyTimeout <= 0 {
		opts.ProxyTimeout = c.options.ProxyTimeout
	}
	opts.ResolveRemoteDNS = c.options.ResolveRemoteDNS
	opts.AnonymizeHeaders = c.options.AnonymizeHeaders
	if opts.TLSPolicy == "" {
		opts.TLSPolicy = c.options.TLSPolicy
	}
	opts.AllowRedirects = c.options.AllowRedirects

	maxRetries := c.options.MaxRetries
	attempt := 0
	var lastErr error

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

	for attempt <= maxRetries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		attempt++
		proxy, err := c.pool.GetNextProxy()
		if err != nil {
			return nil, fmt.Errorf("failed getting proxy: %w", err)
		}

		maskedTarget := RedactSensitive(targetURL)
		if c.options.Verbose {
			emitLog("info", fmt.Sprintf("[Proxy] Attempt #%d: Using %s for %s", attempt, proxy.Proxy, maskedTarget))
		}

		res, reqErr := DispatchSingleProxyRequestContext(ctx, proxy, targetURL, opts)
		if reqErr == nil {
			c.pool.MarkSuccess(proxy)
			res.Attempts = attempt
			if listener != nil {
				listener(Event{
					Kind:      EventRequestCompleted,
					Timestamp: time.Now(),
					Data:      res,
				})
			}
			return res, nil
		}

		lastErr = reqErr
		c.pool.MarkFailed(proxy, reqErr.Error())

		if listener != nil {
			listener(Event{
				Kind:      EventRequestAttempt,
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"attempt": attempt,
					"proxy":   proxy.Proxy,
					"error":   reqErr.Error(),
				},
			})
		}

		if c.options.Verbose {
			emitLog("warn", fmt.Sprintf("[Proxy Failover] Proxy %s failed: %s. Reverting to next proxy...", proxy.Proxy, reqErr.Error()))
		}
	}

	return nil, fmt.Errorf("all %d proxy attempts failed for %s. Last error: %w", attempt, RedactSensitive(targetURL), lastErr)
}

// Get executes a GET request
func (c *SocksProxyClient) Get(targetURL string) (*Response, error) {
	return c.Request(targetURL, RequestOptions{Method: "GET"})
}

// Post executes a POST request
func (c *SocksProxyClient) Post(targetURL string, body []byte) (*Response, error) {
	return c.Request(targetURL, RequestOptions{Method: "POST", Body: body})
}
