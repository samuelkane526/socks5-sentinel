package proxycore

import (
	"context"
	cryptoRand "crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// StageInfo represents pass/fail status and state of an individual vetting stage
type StageInfo struct {
	Name   string     `json:"name"`
	Passed bool       `json:"passed"`
	State  StageState `json:"state,omitempty"`
}

// VetResult contains detailed 5-stage evaluation results for a candidate proxy
type VetResult struct {
	Proxy         string             `json:"proxy"`
	IP            string             `json:"ip"`
	Port          int                `json:"port"`
	Geolocation   interface{}        `json:"geolocation"`
	Stages        map[int]*StageInfo `json:"stages"`
	Passed        bool               `json:"passed"`
	FailureReason string             `json:"failureReason,omitempty"`
	FailedStage   int                `json:"failedStage,omitempty"`
	TestedAt      string             `json:"testedAt"`
	Item          *ProxyItem         `json:"item,omitempty"`
}

var (
	vettingBaseHTTPSURL = "https://httpbin.org"
	vettingBaseHTTPURL  = "http://httpbin.org"
	vettingTLSRootCAs   *x509.CertPool
)

func checkIPLeaked(originStr, localPublicIP string) bool {
	baseIP := net.ParseIP(strings.TrimSpace(localPublicIP))
	for _, part := range strings.Split(originStr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ip := net.ParseIP(part)
		if ip != nil && baseIP != nil {
			if ip.Equal(baseIP) {
				return true
			}
		} else if strings.EqualFold(part, strings.TrimSpace(localPublicIP)) {
			return true
		}
	}
	return false
}

func validateGetResponse(getRes *Response, protocol, localPublicIP string) (string, map[string]interface{}, int, string) {
	if getRes.Status != 200 {
		return "", nil, 4, fmt.Sprintf("Stage 4 (%s Anti-Rerouting) Failed: Expected status 200, got %d", protocol, getRes.Status)
	}

	ct := getRes.Headers["content-type"]
	if !strings.Contains(ct, "application/json") {
		return "", nil, 4, fmt.Sprintf("Stage 4 (%s Anti-Rerouting) Failed: Content-Type is '%s', expected application/json", protocol, ct)
	}

	var getJSON map[string]interface{}
	if err := getRes.JSON(&getJSON); err != nil {
		return "", nil, 4, fmt.Sprintf("Stage 4 (%s Anti-Rerouting) Failed: Malformed JSON body", protocol)
	}

	origin, hasOrigin := getJSON["origin"].(string)
	headers, hasHeaders := getJSON["headers"].(map[string]interface{})
	if !hasOrigin || strings.TrimSpace(origin) == "" || !hasHeaders || headers == nil {
		return "", nil, 4, fmt.Sprintf("Stage 4 (%s Anti-Rerouting) Failed: JSON body missing expected schema keys (origin, headers)", protocol)
	}

	if checkIPLeaked(origin, localPublicIP) {
		return "", nil, 2, fmt.Sprintf("Stage 2 (%s IP Masking) Failed: Echoed origin '%s' contains real host IP '%s'", protocol, origin, localPublicIP)
	}

	for headerKey, headerVal := range headers {
		if IsSensitiveLeakHeader(headerKey) {
			return "", nil, 2, fmt.Sprintf("Stage 2 (%s Header Leak) Failed: Proxy injected tracking header '%s: %v'", protocol, headerKey, headerVal)
		}
	}

	return origin, headers, 0, ""
}

// VetSingleProxy executes all 5 security stages against a candidate proxy
func VetSingleProxy(candidate *ProxyItem, localPublicIP string, timeout time.Duration) *VetResult {
	return VetSingleProxyContext(context.Background(), candidate, localPublicIP, timeout, nil)
}

// VetSingleProxyContext executes all 5 security stages with context and optional stage callback
func VetSingleProxyContext(ctx context.Context, candidate *ProxyItem, localPublicIP string, timeout time.Duration, onStage func(stage int, state StageState, reason string)) *VetResult {
	if timeout <= 0 {
		timeout = DefaultSingleTimeout
	}

	proxyAddr := candidate.Proxy
	if proxyAddr == "" {
		if candidate.Scheme != "" {
			proxyAddr = candidate.Scheme
		} else {
			proxyAddr = fmt.Sprintf("socks5h://%s:%d", candidate.IP, candidate.Port)
		}
	}

	result := &VetResult{
		Proxy:       proxyAddr,
		IP:          candidate.IP,
		Port:        candidate.Port,
		Geolocation: candidate.Geolocation,
		Stages: map[int]*StageInfo{
			1: {Name: StageNames[1], Passed: false, State: StagePending},
			2: {Name: StageNames[2], Passed: false, State: StagePending},
			3: {Name: StageNames[3], Passed: false, State: StagePending},
			4: {Name: StageNames[4], Passed: false, State: StagePending},
			5: {Name: StageNames[5], Passed: false, State: StagePending},
		},
		Passed:   false,
		TestedAt: time.Now().UTC().Format(time.RFC3339),
	}

	notifyStage := func(stage int, state StageState, reason string) {
		result.Stages[stage].State = state
		if state == StagePassed {
			result.Stages[stage].Passed = true
		} else {
			result.Stages[stage].Passed = false
		}
		if onStage != nil {
			onStage(stage, state, reason)
		}
	}

	skipRemaining := func() {
		for s := 1; s <= 5; s++ {
			if result.Stages[s].State == StagePending || result.Stages[s].State == StageRunning {
				result.Stages[s].State = StageSkipped
				if onStage != nil {
					onStage(s, StageSkipped, "")
				}
			}
		}
	}

	if err := ctx.Err(); err != nil {
		result.FailureReason = fmt.Sprintf("Vetting canceled: %s", err.Error())
		skipRemaining()
		return result
	}

	// -------------------------------------------------------------
	// STAGE 1: Baseline Setup & Protocol Formatting
	// -------------------------------------------------------------
	notifyStage(1, StageRunning, "")
	if localPublicIP == "" {
		result.FailureReason = "Stage 1 Failed: Local public IP baseline not recorded."
		result.FailedStage = 1
		notifyStage(1, StageFailed, result.FailureReason)
		skipRemaining()
		return result
	}
	notifyStage(1, StagePassed, "")

	if err := ctx.Err(); err != nil {
		result.FailureReason = fmt.Sprintf("Vetting canceled: %s", err.Error())
		skipRemaining()
		return result
	}

	// -------------------------------------------------------------
	// STAGE 3: Strict TLS/SSL Integrity (Anti-MITM Protection)
	// (Executed first because it establishes the secure connection)
	// -------------------------------------------------------------
	notifyStage(3, StageRunning, "")
	httpsGetRes, err := DispatchSingleProxyRequestContext(ctx, candidate, vettingBaseHTTPSURL+"/get", RequestOptions{
		Timeout:          timeout,
		AllowRedirects:   false,
		TLSPolicy:        TLSStrict,
		ResolveRemoteDNS: true,
		RootCAs:          vettingTLSRootCAs,
	})
	if err != nil {
		result.FailureReason = fmt.Sprintf("Stage 3 (TLS/SSL Integrity) Failed: %s", err.Error())
		result.FailedStage = 3
		notifyStage(3, StageFailed, result.FailureReason)
		skipRemaining()
		return result
	}
	notifyStage(3, StagePassed, "")

	if err := ctx.Err(); err != nil {
		result.FailureReason = fmt.Sprintf("Vetting canceled: %s", err.Error())
		skipRemaining()
		return result
	}

	// -------------------------------------------------------------
	// STAGE 4a & STAGE 2a: Schema & Leak checks on HTTPS
	// -------------------------------------------------------------
	notifyStage(4, StageRunning, "")
	notifyStage(2, StageRunning, "")

	_, _, failedStgHTTPS, reasonHTTPS := validateGetResponse(httpsGetRes, "HTTPS", localPublicIP)
	if failedStgHTTPS > 0 {
		result.FailureReason = reasonHTTPS
		result.FailedStage = failedStgHTTPS
		notifyStage(failedStgHTTPS, StageFailed, reasonHTTPS)
		skipRemaining()
		return result
	}

	if err := ctx.Err(); err != nil {
		result.FailureReason = fmt.Sprintf("Vetting canceled: %s", err.Error())
		skipRemaining()
		return result
	}

	// -------------------------------------------------------------
	// STAGE 4b & STAGE 2b: Anti-Rerouting & Leaks on plain HTTP
	// -------------------------------------------------------------
	httpGetRes, err := DispatchSingleProxyRequestContext(ctx, candidate, vettingBaseHTTPURL+"/get", RequestOptions{
		Timeout:          timeout,
		AllowRedirects:   false,
		ResolveRemoteDNS: true,
	})
	if err != nil {
		result.FailureReason = fmt.Sprintf("Stage 4 (HTTP Anti-Rerouting) Failed: %s", err.Error())
		result.FailedStage = 4
		notifyStage(4, StageFailed, result.FailureReason)
		skipRemaining()
		return result
	}

	_, _, failedStgHTTP, reasonHTTP := validateGetResponse(httpGetRes, "HTTP", localPublicIP)
	if failedStgHTTP > 0 {
		result.FailureReason = reasonHTTP
		result.FailedStage = failedStgHTTP
		notifyStage(failedStgHTTP, StageFailed, reasonHTTP)
		skipRemaining()
		return result
	}

	notifyStage(4, StagePassed, "")
	notifyStage(2, StagePassed, "")

	if err := ctx.Err(); err != nil {
		result.FailureReason = fmt.Sprintf("Vetting canceled: %s", err.Error())
		skipRemaining()
		return result
	}

	// -------------------------------------------------------------
	// STAGE 5: Cookie & Header Integrity Check (HTTPS & HTTP)
	// -------------------------------------------------------------
	notifyStage(5, StageRunning, "")
	tokenBytes := make([]byte, 16)
	_, _ = cryptoRand.Read(tokenBytes)
	testCookieValue := hex.EncodeToString(tokenBytes)
	cookieHeader := fmt.Sprintf("session_test=%s", testCookieValue)

	// Test HTTPS Cookie Echo
	httpsCookieRes, err := DispatchSingleProxyRequestContext(ctx, candidate, vettingBaseHTTPSURL+"/cookies", RequestOptions{
		Timeout:          timeout,
		AllowRedirects:   false,
		TLSPolicy:        TLSStrict,
		ResolveRemoteDNS: true,
		RootCAs:          vettingTLSRootCAs,
		Headers:          map[string]string{"Cookie": cookieHeader},
	})
	if err != nil {
		result.FailureReason = fmt.Sprintf("Stage 5 (HTTPS Cookie Integrity) Failed: %s", err.Error())
		result.FailedStage = 5
		notifyStage(5, StageFailed, result.FailureReason)
		skipRemaining()
		return result
	}

	var httpsCookieJSON map[string]interface{}
	if err := httpsCookieRes.JSON(&httpsCookieJSON); err != nil {
		result.FailureReason = "Stage 5 (HTTPS Cookie Integrity) Failed: Malformed JSON on /cookies"
		result.FailedStage = 5
		notifyStage(5, StageFailed, result.FailureReason)
		skipRemaining()
		return result
	}

	echoedHTTPSCookies, ok := httpsCookieJSON["cookies"].(map[string]interface{})
	if !ok {
		result.FailureReason = "Stage 5 (HTTPS Cookie Integrity) Failed: Missing 'cookies' object in response"
		result.FailedStage = 5
		notifyStage(5, StageFailed, result.FailureReason)
		skipRemaining()
		return result
	}

	val, found := echoedHTTPSCookies["session_test"]
	if !found || fmt.Sprintf("%v", val) != testCookieValue {
		result.FailureReason = fmt.Sprintf("Stage 5 (HTTPS Cookie Integrity) Failed: Expected cookie '%s', got '%v'", testCookieValue, val)
		result.FailedStage = 5
		notifyStage(5, StageFailed, result.FailureReason)
		skipRemaining()
		return result
	}

	if len(echoedHTTPSCookies) != 1 {
		var extra []string
		for k := range echoedHTTPSCookies {
			if k != "session_test" {
				extra = append(extra, k)
			}
		}
		result.FailureReason = fmt.Sprintf("Stage 5 (HTTPS Cookie Integrity) Failed: Proxy injected tracking cookies: [%s]", strings.Join(extra, ", "))
		result.FailedStage = 5
		notifyStage(5, StageFailed, result.FailureReason)
		skipRemaining()
		return result
	}

	if err := ctx.Err(); err != nil {
		result.FailureReason = fmt.Sprintf("Vetting canceled: %s", err.Error())
		skipRemaining()
		return result
	}

	// Test HTTP Cookie Echo
	httpCookieRes, err := DispatchSingleProxyRequestContext(ctx, candidate, vettingBaseHTTPURL+"/cookies", RequestOptions{
		Timeout:          timeout,
		AllowRedirects:   false,
		ResolveRemoteDNS: true,
		Headers:          map[string]string{"Cookie": cookieHeader},
	})
	if err != nil {
		result.FailureReason = fmt.Sprintf("Stage 5 (HTTP Cookie Integrity) Failed: %s", err.Error())
		result.FailedStage = 5
		notifyStage(5, StageFailed, result.FailureReason)
		skipRemaining()
		return result
	}

	var httpCookieJSON map[string]interface{}
	if err := httpCookieRes.JSON(&httpCookieJSON); err != nil {
		result.FailureReason = "Stage 5 (HTTP Cookie Integrity) Failed: Malformed JSON on HTTP /cookies"
		result.FailedStage = 5
		notifyStage(5, StageFailed, result.FailureReason)
		skipRemaining()
		return result
	}

	echoedHTTPCookies, ok := httpCookieJSON["cookies"].(map[string]interface{})
	if !ok {
		result.FailureReason = "Stage 5 (HTTP Cookie Integrity) Failed: Missing 'cookies' object in HTTP response"
		result.FailedStage = 5
		notifyStage(5, StageFailed, result.FailureReason)
		skipRemaining()
		return result
	}

	valHTTP, foundHTTP := echoedHTTPCookies["session_test"]
	if !foundHTTP || fmt.Sprintf("%v", valHTTP) != testCookieValue {
		result.FailureReason = fmt.Sprintf("Stage 5 (HTTP Cookie Integrity) Failed: Expected HTTP cookie '%s', got '%v'", testCookieValue, valHTTP)
		result.FailedStage = 5
		notifyStage(5, StageFailed, result.FailureReason)
		skipRemaining()
		return result
	}

	if len(echoedHTTPCookies) != 1 {
		var extra []string
		for k := range echoedHTTPCookies {
			if k != "session_test" {
				extra = append(extra, k)
			}
		}
		result.FailureReason = fmt.Sprintf("Stage 5 (HTTP Cookie Integrity) Failed: Proxy injected tracking cookies on plain HTTP: [%s]", strings.Join(extra, ", "))
		result.FailedStage = 5
		notifyStage(5, StageFailed, result.FailureReason)
		skipRemaining()
		return result
	}

	notifyStage(5, StagePassed, "")
	result.Passed = true

	testedTimestamp := result.TestedAt
	if testedTimestamp == "" {
		testedTimestamp = time.Now().UTC().Format(time.RFC3339)
	}
	vettedItem := *candidate
	vettedItem.Anonymity = "elite"
	vettedItem.VettedAt = testedTimestamp
	vettedItem.LastChecked = testedTimestamp
	if vettedItem.Protocol == "" {
		vettedItem.Protocol = "socks5h"
	}
	if vettedItem.Proxy == "" {
		vettedItem.Proxy = result.Proxy
	}
	result.Item = &vettedItem
	return result
}

// PipelineOptions configures the SocksVettingPipeline
type PipelineOptions struct {
	BaseDir            string
	InputFile          string
	OutputFile         string
	ExportDir          string
	Concurrency        int
	Limit              int
	TargetPassed       int
	Timeout            time.Duration
	UpdatePolicy       UpdatePolicy
	ForceUpdate        bool
	NoUpdate           bool
	Verbose            bool
	SourceURL          string
	AutoSave           bool
	AutoSaveIncomplete bool
}

// SocksVettingPipeline orchestrates concurrent vetting across proxies
type SocksVettingPipeline struct {
	options            PipelineOptions
	pool               *ProxyPool
	localPublicIP      string
	vettedProxies      []*ProxyItem
	failedCount        int64
	completedCount     int64
	stageFailureCounts [6]int64
	mu                 sync.Mutex
}

// NewSocksVettingPipeline initializes a vetting pipeline
func NewSocksVettingPipeline(options PipelineOptions) *SocksVettingPipeline {
	if options.Concurrency <= 0 {
		options.Concurrency = DefaultConcurrency
	}
	if options.Timeout <= 0 {
		options.Timeout = DefaultBatchTimeout
	}
	if options.OutputFile == "" {
		options.OutputFile = DefaultOutputFile
	}
	if options.InputFile == "" {
		options.InputFile = ResolveDataFilePathWithBase(options.BaseDir, DefaultDataFileName)
	}

	return &SocksVettingPipeline{
		options: options,
	}
}

// Run executes the vetting pipeline with background context
func (p *SocksVettingPipeline) Run() ([]*ProxyItem, error) {
	return p.RunContext(context.Background(), nil)
}

// RunContext executes the vetting pipeline with context cancellation and event broadcasting
func (p *SocksVettingPipeline) RunContext(ctx context.Context, listener Listener) ([]*ProxyItem, error) {
	startTime := time.Now()

	var loggingDisabled atomic.Bool

	emitLog := func(level, msg string) {
		if loggingDisabled.Load() {
			return
		}
		if listener != nil {
			listener(Event{
				Kind:      EventLog,
				Timestamp: time.Now(),
				Level:     level,
				Message:   msg,
			})
		}
	}

	emitLog("info", "======================================================")
	emitLog("info", "      SOCKS5 Proxy Vetting Pipeline (5 Stages)        ")
	emitLog("info", "======================================================")

	forceUpdate := p.options.ForceUpdate || p.options.UpdatePolicy == UpdateForce
	noUpdate := p.options.NoUpdate || p.options.UpdatePolicy == UpdateNone

	isDefaultInput := p.options.InputFile == "" ||
		filepath.Base(p.options.InputFile) == DefaultDataFileName

	if !noUpdate && isDefaultInput {
		targetFile := p.options.InputFile
		if targetFile == "" {
			targetFile = ResolveDataFilePathWithBase(p.options.BaseDir, DefaultDataFileName)
		}
		updateResult, err := RefreshProxyDataIfNeededContext(ctx, RefreshOptions{
			BaseDir:     p.options.BaseDir,
			TargetFile:  targetFile,
			ForceUpdate: forceUpdate,
			NoUpdate:    noUpdate,
			Verbose:     p.options.Verbose,
			SourceURL:   p.options.SourceURL,
		}, listener)
		if err != nil {
			return nil, fmt.Errorf("failed upstream check: %w", err)
		}
		if updateResult != nil && updateResult.Updated {
			emitLog("info", "[Vetting Pipeline] Reloading proxy pool with fresh data...")
			p.options.InputFile = updateResult.TargetFilePath
		}
	}

	pool, err := NewProxyPoolWithBase(p.options.BaseDir, p.options.InputFile, false)
	if err != nil {
		return nil, fmt.Errorf("failed to load proxy pool from '%s': %w", p.options.InputFile, err)
	}
	p.pool = pool

	emitLog("info", "[Stage 1] Fetching host machine's real public IP...")
	localIP, err := FetchLocalPublicIPContext(ctx, p.options.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve host public IP: %w", err)
	}
	p.localPublicIP = localIP
	emitLog("info", fmt.Sprintf("[Stage 1] Host public IP recorded: %s", localIP))
	emitLog("info", fmt.Sprintf("Candidate proxies loaded: %d", pool.Count()))
	emitLog("info", fmt.Sprintf("Concurrency: %d workers", p.options.Concurrency))

	candidates := pool.Items()
	totalToTest := len(candidates)
	if p.options.Limit > 0 && p.options.Limit < totalToTest {
		totalToTest = p.options.Limit
	}

	var currentIndex int64
	var targetPassed int64 = int64(p.options.TargetPassed)
	if targetPassed <= 0 {
		targetPassed = int64(^uint(0) >> 1) // Max int
	}

	workerCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()
	var targetReached atomic.Bool

	if listener != nil {
		listener(Event{
			Kind:            EventBatchStarted,
			Timestamp:       time.Now(),
			ProgressCurrent: 0,
			ProgressTotal:   int64(totalToTest),
			Data: map[string]interface{}{
				"totalCandidates": totalToTest,
				"target":          p.options.TargetPassed,
				"localIP":         localIP,
			},
		})
	}

	var wg sync.WaitGroup
	wg.Add(p.options.Concurrency)

	for w := 0; w < p.options.Concurrency; w++ {
		go func() {
			defer wg.Done()

			for {
				if workerCtx.Err() != nil || targetReached.Load() {
					return
				}

				p.mu.Lock()
				if int64(len(p.vettedProxies)) >= targetPassed {
					p.mu.Unlock()
					return
				}
				p.mu.Unlock()

				idx := atomic.AddInt64(&currentIndex, 1) - 1
				if idx >= int64(totalToTest) {
					return
				}

				candidate := candidates[idx]

				if !targetReached.Load() && listener != nil {
					listener(Event{
						Kind:      EventCandidateStarted,
						Timestamp: time.Now(),
						Data: map[string]interface{}{
							"index": idx,
							"proxy": RedactSensitive(candidate.Proxy),
						},
					})
				}

				res := VetSingleProxyContext(workerCtx, candidate, p.localPublicIP, p.options.Timeout, func(stage int, state StageState, reason string) {
					if workerCtx.Err() != nil || targetReached.Load() {
						return
					}
					if listener != nil {
						listener(Event{
							Kind:      EventCandidateStage,
							Timestamp: time.Now(),
							Data: map[string]interface{}{
								"index":  idx,
								"proxy":  RedactSensitive(candidate.Proxy),
								"stage":  stage,
								"state":  state,
								"reason": reason,
							},
						})
					}
				})

				// If canceled or target reached while evaluating candidate, exit immediately without counting as failure
				if workerCtx.Err() != nil || targetReached.Load() {
					return
				}

				var progressPayload BatchProgressPayload
				var passedRecorded bool

				if res.Passed {
					vettedItem := res.Item
					if vettedItem == nil {
						testedTimestamp := res.TestedAt
						if testedTimestamp == "" {
							testedTimestamp = time.Now().UTC().Format(time.RFC3339)
						}
						cCopy := *candidate
						cCopy.Anonymity = "elite"
						cCopy.VettedAt = testedTimestamp
						cCopy.LastChecked = testedTimestamp
						if cCopy.Protocol == "" {
							cCopy.Protocol = "socks5h"
						}
						if cCopy.Proxy == "" {
							cCopy.Proxy = res.Proxy
						}
						vettedItem = &cCopy
					}

					var isFinalTarget bool
					p.mu.Lock()
					// Cap strictly at targetPassed to avoid concurrency overshoot
					if int64(len(p.vettedProxies)) < targetPassed {
						p.vettedProxies = append(p.vettedProxies, vettedItem)
						passedRecorded = true

						if p.options.TargetPassed > 0 && int64(len(p.vettedProxies)) >= targetPassed {
							targetReached.Store(true)
							cancelWorkers()
							isFinalTarget = true
						}
					}
					p.completedCount++
					progressPayload = BatchProgressPayload{
						TestedCount:        p.completedCount,
						TotalToTest:        int64(totalToTest),
						PassedCount:        int64(len(p.vettedProxies)),
						FailedCount:        p.failedCount,
						TargetPassed:       int64(p.options.TargetPassed),
						StageFailureCounts: p.stageFailureCounts,
						ElapsedTime:        time.Since(startTime),
					}
					p.mu.Unlock()

					if passedRecorded {
						emitLog("success", fmt.Sprintf("[PASS] #%d %s passed ALL 5 verification stages!", idx+1, RedactSensitive(res.Proxy)))

						if isFinalTarget {
							loggingDisabled.Store(true)
							if listener != nil {
								listener(Event{
									Kind:      EventTargetReached,
									Timestamp: time.Now(),
									Data: map[string]interface{}{
										"target": p.options.TargetPassed,
										"passed": int64(p.options.TargetPassed),
									},
								})
							}
						}

						if listener != nil {
							listener(Event{
								Kind:      EventCandidateCompleted,
								Timestamp: time.Now(),
								Level:     "success",
								Data: CandidateResultPayload{
									Index:  idx,
									Proxy:  RedactSensitive(res.Proxy),
									Passed: true,
									Result: res,
									Item:   vettedItem,
								},
							})
						}
					}
				} else {
					if workerCtx.Err() != nil || targetReached.Load() {
						return
					}

					p.mu.Lock()
					p.failedCount++

					stg := res.FailedStage
					if stg >= 1 && stg <= 5 {
						p.stageFailureCounts[stg]++
					} else if strings.Contains(res.FailureReason, "Stage 2") {
						p.stageFailureCounts[2]++
					} else if strings.Contains(res.FailureReason, "Stage 3") {
						p.stageFailureCounts[3]++
					} else if strings.Contains(res.FailureReason, "Stage 4") {
						p.stageFailureCounts[4]++
					} else if strings.Contains(res.FailureReason, "Stage 5") {
						p.stageFailureCounts[5]++
					} else {
						p.stageFailureCounts[1]++
					}

					p.completedCount++
					progressPayload = BatchProgressPayload{
						TestedCount:        p.completedCount,
						TotalToTest:        int64(totalToTest),
						PassedCount:        int64(len(p.vettedProxies)),
						FailedCount:        p.failedCount,
						TargetPassed:       int64(p.options.TargetPassed),
						StageFailureCounts: p.stageFailureCounts,
						ElapsedTime:        time.Since(startTime),
					}
					p.mu.Unlock()

					if p.options.Verbose {
						emitLog("warn", fmt.Sprintf("[FAIL] #%d %s -> %s", idx+1, RedactSensitive(res.Proxy), RedactSensitive(res.FailureReason)))
					}

					if listener != nil {
						listener(Event{
							Kind:      EventCandidateCompleted,
							Timestamp: time.Now(),
							Level:     "warn",
							Data: CandidateResultPayload{
								Index:         idx,
								Proxy:         RedactSensitive(res.Proxy),
								Passed:        false,
								FailureReason: res.FailureReason,
								FailedStage:   res.FailedStage,
								Result:        res,
							},
						})
					}
				}

				if listener != nil {
					listener(Event{
						Kind:            EventBatchProgress,
						Timestamp:       time.Now(),
						ProgressCurrent: progressPayload.TestedCount,
						ProgressTotal:   int64(totalToTest),
						Data:            progressPayload,
					})
				}
			}
		}()
	}

	wg.Wait()

	p.mu.Lock()
	vettedList := make([]*ProxyItem, len(p.vettedProxies))
	copy(vettedList, p.vettedProxies)
	p.mu.Unlock()

	var savedPaths []string
	isCanceled := ctx.Err() != nil

	shouldAutoSave := p.options.AutoSave && (!isCanceled || p.options.AutoSaveIncomplete)

	if shouldAutoSave {
		paths, err := SaveVettedResults(p.options.BaseDir, p.options.OutputFile, vettedList)
		if err != nil {
			emitLog("error", fmt.Sprintf("Failed to save vetted results: %s", err.Error()))
			return vettedList, fmt.Errorf("failed saving vetted results: %w", err)
		}
		savedPaths = append(savedPaths, paths...)
		for _, sp := range paths {
			emitLog("info", fmt.Sprintf("Vetting results saved to: %s", sp))
		}

		if p.options.ExportDir != "" {
			var exportPath string
			base := p.options.BaseDir
			if base == "" {
				base, _ = os.Getwd()
			}
			exportTarget := p.options.ExportDir
			if !filepath.IsAbs(exportTarget) {
				exportTarget = filepath.Join(base, exportTarget)
			}

			if strings.HasSuffix(strings.ToLower(exportTarget), ".json") {
				exportPath = exportTarget
			} else {
				exportPath = filepath.Join(exportTarget, DefaultVettedFileName)
			}

			if err := saveProxiesAtomically(exportPath, vettedList); err != nil {
				emitLog("error", fmt.Sprintf("Failed to export to %s: %s", exportPath, err.Error()))
				return vettedList, fmt.Errorf("failed exporting proxies: %w", err)
			}
			savedPaths = append(savedPaths, exportPath)
			emitLog("info", fmt.Sprintf("Exported to:     %s", exportPath))
		}
	}

	if isCanceled {
		if shouldAutoSave {
			emitLog("warn", "[Vetting Pipeline] Canceled by user. Incomplete scan results auto-saved.")
		} else {
			emitLog("warn", "[Vetting Pipeline] Canceled by user. Completed in-memory results retained.")
		}
	} else if !shouldAutoSave {
		emitLog("info", "[Vetting Pipeline] Auto-save results is disabled. Completed in-memory results retained.")
	}

	p.mu.Lock()
	processed := p.completedCount
	if processed > int64(totalToTest) {
		processed = int64(totalToTest)
	}
	p.mu.Unlock()

	emitLog("info", "======================================================")
	emitLog("info", "               Vetting Pipeline Summary               ")
	emitLog("info", "======================================================")
	emitLog("info", fmt.Sprintf("Total Candidates Processed: %d", processed))
	emitLog("info", fmt.Sprintf("Verified Elite Proxies:     %d", len(vettedList)))
	emitLog("info", fmt.Sprintf("Rejected Proxies:           %d", p.failedCount))
	emitLog("info", "Failure Breakdown by Stage:")
	emitLog("info", fmt.Sprintf("  - Stage 1 (Connectivity / SOCKS Handshake): %d", p.stageFailureCounts[1]))
	emitLog("info", fmt.Sprintf("  - Stage 2 (IP / Header Leaks):              %d", p.stageFailureCounts[2]))
	emitLog("info", fmt.Sprintf("  - Stage 3 (TLS / Anti-MITM):                %d", p.stageFailureCounts[3]))
	emitLog("info", fmt.Sprintf("  - Stage 4 (Anti-Rerouting / Poisoning):     %d", p.stageFailureCounts[4]))
	emitLog("info", fmt.Sprintf("  - Stage 5 (Cookie & Header Tampering):      %d", p.stageFailureCounts[5]))

	if listener != nil {
		listener(Event{
			Kind:      EventBatchCompleted,
			Timestamp: time.Now(),
			Data: BatchCompletePayload{
				TotalProcessed:     processed,
				PassedCount:        len(vettedList),
				FailedCount:        p.failedCount,
				StageFailureCounts: p.stageFailureCounts,
				SavedPaths:         savedPaths,
				VettedProxies:      vettedList,
				Canceled:           isCanceled,
				ElapsedTime:        time.Since(startTime),
			},
		})
	}

	return vettedList, nil
}

// SaveProxiesToFile writes proxy list formatted with 2-space indentation atomically
func SaveProxiesToFile(destPath string, proxies []*ProxyItem) error {
	return saveProxiesAtomically(destPath, proxies)
}

func saveProxiesAtomically(destPath string, proxies []*ProxyItem) error {
	if proxies == nil {
		proxies = []*ProxyItem{}
	}

	outData, err := json.MarshalIndent(proxies, "", "  ")
	if err != nil {
		return fmt.Errorf("failed serializing proxies: %w", err)
	}

	return ReplaceFileWithBytes(destPath, outData, 0644)
}

// ProxyKey generates a unique normalized key for a proxy (e.g. "ip:port" or canonical host:port)
func ProxyKey(item *ProxyItem) string {
	if item == nil {
		return ""
	}
	if item.IP != "" && item.Port > 0 {
		return fmt.Sprintf("%s:%d", strings.ToLower(strings.TrimSpace(item.IP)), item.Port)
	}
	if item.Host != "" && item.Port > 0 {
		return fmt.Sprintf("%s:%d", strings.ToLower(strings.TrimSpace(item.Host)), item.Port)
	}
	if item.Proxy != "" {
		if norm := NormalizeProxy(item.Proxy); norm != nil && norm.IP != "" && norm.Port > 0 {
			return fmt.Sprintf("%s:%d", strings.ToLower(strings.TrimSpace(norm.IP)), norm.Port)
		}
		return strings.ToLower(strings.TrimSpace(item.Proxy))
	}
	return ""
}

func withTimestamps(item *ProxyItem, nowISO string) *ProxyItem {
	if item == nil {
		return nil
	}
	c := *item
	if c.LastChecked == "" {
		if c.VettedAt != "" {
			c.LastChecked = c.VettedAt
		} else {
			c.LastChecked = nowISO
		}
	}
	if c.VettedAt == "" {
		c.VettedAt = c.LastChecked
	}
	return &c
}

// MergeVettedProxies merges newly vetted proxies into an existing master list.
// Proxies in newVetted are placed at the top of the list with updated last checked timestamps.
// Any proxy that already exists in the master list is moved to the top of the file (deduplicated).
// Every proxy in the resulting master list has its last checked timestamp listed.
func MergeVettedProxies(existing []*ProxyItem, newVetted []*ProxyItem) []*ProxyItem {
	nowISO := time.Now().UTC().Format(time.RFC3339)
	var merged []*ProxyItem
	seen := make(map[string]bool)

	// 1. Newly vetted proxies are placed at the top of the file
	for _, item := range newVetted {
		if item == nil {
			continue
		}
		key := ProxyKey(item)
		if key != "" {
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		merged = append(merged, withTimestamps(item, nowISO))
	}

	// 2. Existing proxies not in the newly vetted batch are preserved below
	for _, item := range existing {
		if item == nil {
			continue
		}
		key := ProxyKey(item)
		if key != "" && seen[key] {
			// Proxy was already placed at top from newVetted (move to top behavior)
			continue
		}
		if key != "" {
			seen[key] = true
		}
		merged = append(merged, withTimestamps(item, nowISO))
	}

	if merged == nil {
		merged = []*ProxyItem{}
	}
	return merged
}

// SaveVettedResults writes the vetted proxies according to storage rules:
// 1. Saves proxy results to ./elite_proxies (or configured target dir) instead of ./output.
// 2. Each vetting finish saves a new individual JSON file titled {number of elite proxies in the json}_{timestamp}.
// 3. Adds new data to the vetted_proxies.json master list, moving existing proxies to top
//    and ensuring last checked timestamps are set for all proxies.
func SaveVettedResults(baseDir, outputTarget string, newVetted []*ProxyItem) ([]string, error) {
	if baseDir == "" {
		baseDir, _ = os.Getwd()
	}

	var outDir string
	var masterPath string

	if outputTarget == "" {
		outDir = filepath.Join(baseDir, DefaultOutputDir)
		masterPath = filepath.Join(outDir, DefaultVettedFileName)
	} else {
		target := outputTarget
		if !filepath.IsAbs(target) {
			target = filepath.Join(baseDir, target)
		}
		if strings.HasSuffix(strings.ToLower(target), ".json") {
			masterPath = target
			outDir = filepath.Dir(target)
		} else {
			outDir = target
			masterPath = filepath.Join(outDir, DefaultVettedFileName)
		}
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, fmt.Errorf("failed creating output directory %s: %w", outDir, err)
	}

	// 1. Read and validate existing master (or legacy fallback) BEFORE publishing any files
	var existingProxies []*ProxyItem
	var srcToRead string

	info, err := os.Stat(masterPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed accessing master file %s: %w", masterPath, err)
		}
		// os.IsNotExist: master does not exist yet; check legacy fallback locations
		candidates := []string{
			filepath.Join(baseDir, "output", DefaultVettedFileName),
			filepath.Join(baseDir, "data", DefaultVettedFileName),
		}
		for _, c := range candidates {
			if cInfo, cErr := os.Stat(c); cErr == nil && !cInfo.IsDir() {
				srcToRead = c
				break
			} else if cErr != nil && !os.IsNotExist(cErr) {
				return nil, fmt.Errorf("failed accessing fallback master file %s: %w", c, cErr)
			}
		}
	} else if info.IsDir() {
		return nil, fmt.Errorf("master file path is a directory: %s", masterPath)
	} else {
		srcToRead = masterPath
	}

	if srcToRead != "" {
		data, err := os.ReadFile(srcToRead)
		if err != nil {
			return nil, fmt.Errorf("failed reading master file %s: %w", srcToRead, err)
		}
		trimmed := strings.TrimSpace(string(data))
		if len(trimmed) == 0 {
			return nil, fmt.Errorf("master file %s is empty", srcToRead)
		}
		if err := json.Unmarshal([]byte(trimmed), &existingProxies); err != nil {
			return nil, fmt.Errorf("failed parsing existing master file %s: %w", srcToRead, err)
		}
	}

	var savedPaths []string

	// Ensure timestamps on newVetted
	now := time.Now().UTC()
	nowISO := now.Format(time.RFC3339)
	sessionProxies := make([]*ProxyItem, 0, len(newVetted))
	for _, item := range newVetted {
		if item != nil {
			sessionProxies = append(sessionProxies, withTimestamps(item, nowISO))
		}
	}

	// 2. Save new individual JSON file: {number of elite proxies in the json}_{timestamp}.json
	sessionFileName := fmt.Sprintf("%d_%d.json", len(sessionProxies), now.Unix())
	sessionFilePath := filepath.Join(outDir, sessionFileName)

	if err := saveProxiesAtomically(sessionFilePath, sessionProxies); err != nil {
		return nil, fmt.Errorf("failed saving individual session file %s: %w", sessionFilePath, err)
	}
	savedPaths = append(savedPaths, sessionFilePath)

	// 3. Merge new data into master list (moving existing to top, updating timestamps)
	masterList := MergeVettedProxies(existingProxies, sessionProxies)

	if err := saveProxiesAtomically(masterPath, masterList); err != nil {
		return savedPaths, fmt.Errorf("failed saving master list %s: %w", masterPath, err)
	}
	savedPaths = append(savedPaths, masterPath)

	return savedPaths, nil
}
