package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/samuelkane526/socks5-sentinel/internal/proxycore"
)

func getArg(args []string, flag string, defVal string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == flag {
			if i+1 < len(args) {
				return args[i+1]
			}
			return defVal
		}
	}
	return defVal
}

func hasArg(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// PrintHelp outputs CLI instructions and available options
func PrintHelp() {
	helpText := `
Anonymous SOCKS5 Proxy Client & 5-Stage Vetting Pipeline (Go Edition)
====================================================================
Usage:
  socks5-vet --vet [options]
  socks5-vet --vet-single <IP:PORT>
  socks5-vet --url <URL> [options]
  socks5-vet --test [options]
  socks5-vet --update [options]

Vetting Pipeline Options:
  --vet                Run the 5-stage asynchronous vetting pipeline (auto-updates data by default)
  --target <n>         Stop once N proxies successfully pass (e.g. --target 10, 0 for unlimited)
  --export <dir>       Directory or JSON file path to export vetted proxies
  --concurrency <n>    Number of concurrent vetting workers (default: 100)
  --limit <n>          Maximum candidate proxies to test (default: all)
  --output <file>      File path to save vetted proxies (default: elite_proxies/vetted_proxies.json)

Proxy Data Update Options:
  --update             Check GitHub upstream for fresh proxy data and download if updated
  --force-update       Force re-download of proxy data even if up to date
  --no-update          Skip the automatic upstream update check

Client Request Options:
  --url <url>          Target URL to request (HTTP or HTTPS)
  --file <path>        Proxy list file (default: elite_proxies/vetted_proxies.json or data/socks5.txt)
  --retries <n>        Max retry attempts upon proxy failure (default: 5)
  --timeout <ms>       Total request timeout in ms (default: 10000)
  --strict-tls         Enforce strict certificate verification (anti-MITM, default: true)
  --allow-insecure     Allow self-signed TLS certificates (useful for IP scans)
  --verbose, -v        Display proxy rotation and failover logs
  --test               Run a quick test on the proxy list (3 sequential requests)

Examples:
  socks5-vet --vet --target 5
  socks5-vet --vet --target 10 --export ./exported_proxies
  socks5-vet --vet --force-update
  socks5-vet --vet --no-update
  socks5-vet --vet-single 183.106.215.208:1080
  socks5-vet --update --force-update
  socks5-vet --url https://httpbin.org/get --verbose
`
	fmt.Println(strings.TrimSpace(helpText))
}

// Run executes CLI argument parsing and dispatch, returning an exit code
func Run(args []string) int {
	if _, err := proxycore.EnsureDataDir(""); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to initialize data directory: %v\n", err)
	}

	if len(args) == 0 || hasArg(args, "--help") || hasArg(args, "-h") {
		PrintHelp()
		return 0
	}

	isVetMode := hasArg(args, "--vet")
	isUpdateMode := hasArg(args, "--update")
	forceUpdate := hasArg(args, "--force-update")
	noUpdate := hasArg(args, "--no-update")
	exportDir := getArg(args, "--export", "")
	vetSingleAddr := getArg(args, "--vet-single", "")
	isTestMode := hasArg(args, "--test")
	targetURL := getArg(args, "--url", "")
	proxyFile := getArg(args, "--file", "")
	verbose := hasArg(args, "--verbose") || hasArg(args, "-v")
	allowInsecure := hasArg(args, "--allow-insecure")
	strictTLSFlag := hasArg(args, "--strict-tls")
	outputFile := getArg(args, "--output", proxycore.DefaultOutputFile)

	// Validate conflicting flags
	if forceUpdate && noUpdate {
		fmt.Fprintln(os.Stderr, "Error: Conflicting update flags: cannot specify both --force-update and --no-update")
		return 1
	}

	if allowInsecure && strictTLSFlag {
		fmt.Fprintln(os.Stderr, "Error: Conflicting TLS flags: cannot specify both --strict-tls and --allow-insecure")
		return 1
	}

	tlsPolicy := proxycore.TLSStrict
	if allowInsecure {
		tlsPolicy = proxycore.TLSInsecure
	}

	retriesStr := getArg(args, "--retries", "5")
	retries, err := strconv.Atoi(retriesStr)
	if err != nil || retries < 1 {
		fmt.Fprintf(os.Stderr, "Error: Invalid --retries '%s': must be an integer >= 1\n", retriesStr)
		return 1
	}

	timeoutMsStr := getArg(args, "--timeout", "10000")
	timeoutMs, err := strconv.Atoi(timeoutMsStr)
	if err != nil || timeoutMs <= 0 {
		fmt.Fprintf(os.Stderr, "Error: Invalid --timeout '%s': must be a positive integer in milliseconds\n", timeoutMsStr)
		return 1
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	concurrencyStr := getArg(args, "--concurrency", strconv.Itoa(proxycore.DefaultConcurrency))
	concurrency, err := strconv.Atoi(concurrencyStr)
	if err != nil || concurrency < 1 {
		fmt.Fprintf(os.Stderr, "Error: Invalid --concurrency '%s': must be an integer >= 1\n", concurrencyStr)
		return 1
	}

	limitStr := getArg(args, "--limit", "0")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 0 {
		fmt.Fprintf(os.Stderr, "Error: Invalid --limit '%s': must be an integer >= 0\n", limitStr)
		return 1
	}

	targetStr := getArg(args, "--target", "0")
	targetPassed, err := strconv.Atoi(targetStr)
	if err != nil || targetPassed < 0 {
		fmt.Fprintf(os.Stderr, "Error: Invalid --target '%s': must be an integer >= 0\n", targetStr)
		return 1
	}

	// -------------------------------------------------------------
	// Standalone Upstream Update Mode
	// -------------------------------------------------------------
	if isUpdateMode {
		updateResult, err := proxycore.RefreshProxyDataIfNeeded(proxycore.RefreshOptions{
			TargetFile:  proxyFile,
			ForceUpdate: forceUpdate,
			NoUpdate:    noUpdate,
			Verbose:     verbose,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Update failed: %s\n", err.Error())
			return 1
		}
		if updateResult.Updated {
			fmt.Printf("Upstream proxy data updated successfully: %s\n", updateResult.TargetFilePath)
		} else {
			fmt.Printf("Proxy data is current (%s): %s\n", updateResult.Reason, updateResult.TargetFilePath)
		}
		return 0
	}

	// -------------------------------------------------------------
	// Single Proxy Vetting Mode
	// -------------------------------------------------------------
	if vetSingleAddr != "" {
		fmt.Println("[VET] Recording baseline host IP...")
		localIP, err := proxycore.FetchLocalPublicIP(proxycore.DefaultSingleTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Could not retrieve host public IP: %s\n", err.Error())
			return 1
		}
		fmt.Printf("[VET] Host Public IP: %s\n", localIP)

		candidate, valErr := proxycore.ValidateProxyAddress(vetSingleAddr)
		if valErr != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", valErr.Error())
			return 1
		}

		fmt.Printf("[VET] Testing candidate proxy: %s...\n", candidate.Scheme)
		res := proxycore.VetSingleProxy(candidate, localIP, proxycore.DefaultSingleTimeout)

		fmt.Println("\n--- 5-Stage Verification Results ---")
		for stg := 1; stg <= 5; stg++ {
			badge := "\x1b[31m[FAILED]\x1b[0m"
			if info, ok := res.Stages[stg]; ok && info.Passed {
				badge = "\x1b[32m[PASSED]\x1b[0m"
			}
			fmt.Printf("Stage %d: %-35s %s\n", stg, proxycore.StageNames[stg], badge)
		}

		if res.Passed {
			fmt.Println("\n\x1b[32m✔ SUCCESS: Candidate proxy passed ALL 5 verification stages!\x1b[0m")
			return 0
		}
		fmt.Printf("\n\x1b[31m✘ REJECTED: %s\x1b[0m\n", res.FailureReason)
		return 1
	}

	// -------------------------------------------------------------
	// Automated Vetting Pipeline Mode
	// -------------------------------------------------------------
	if isVetMode {
		pipeline := proxycore.NewSocksVettingPipeline(proxycore.PipelineOptions{
			InputFile:    proxyFile,
			OutputFile:   outputFile,
			ExportDir:    exportDir,
			Concurrency:  concurrency,
			Limit:        limit,
			TargetPassed: targetPassed,
			Timeout:      timeout,
			ForceUpdate:  forceUpdate,
			NoUpdate:     noUpdate,
			Verbose:      verbose,
			AutoSave:     true,
		})

		_, err := pipeline.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Pipeline failed: %s\n", err.Error())
			return 1
		}
		return 0
	}

	// -------------------------------------------------------------
	// Health Test Mode
	// -------------------------------------------------------------
	if isTestMode {
		fmt.Println("[TEST] Testing proxy client rotation and connectivity (3 consecutive requests)...")
		if proxyFile == "" {
			candidate := proxycore.ResolveProxyPathWithBase("", "")
			if _, err := os.Stat(candidate); os.IsNotExist(err) {
				if verbose {
					fmt.Printf("[Client] Proxy candidate file '%s' not found. Auto-fetching fresh socks5.txt from upstream...\n", candidate)
				}
				targetPath := proxycore.ResolveDataFilePathWithBase("", proxycore.DefaultDataFileName)
				updateRes, updateErr := proxycore.RefreshProxyDataIfNeeded(proxycore.RefreshOptions{
					TargetFile: targetPath,
					Verbose:    verbose,
				})
				if updateErr == nil && updateRes != nil && updateRes.Updated {
					proxyFile = updateRes.TargetFilePath
					if verbose {
						fmt.Printf("[Client] Successfully updated data folder with %s\n", updateRes.TargetFilePath)
					}
				}
			}
		}

		client, err := proxycore.NewSocksProxyClient(proxycore.ClientOptions{
			ProxyFile:          proxyFile,
			MaxRetries:         retries,
			Timeout:            timeout,
			TLSPolicy:          tlsPolicy,
			RejectUnauthorized: tlsPolicy == proxycore.TLSStrict,
			Verbose:            true,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing proxy client: %s\n", err.Error())
			return 1
		}

		for i := 1; i <= proxycore.HealthCheckRequestCount; i++ {
			fmt.Printf("\n--- Test Request #%d ---\n", i)
			res, err := client.Get(proxycore.HealthCheckEndpoint)
			if err != nil {
				fmt.Printf("[FAILURE] Test #%d failed: %s\n", i, err.Error())
				continue
			}

			fmt.Printf("[SUCCESS] Status: %d\n", res.Status)
			if res.ProxyUsed != nil {
				fmt.Printf("Proxy Used: %s\n", res.ProxyUsed.Scheme)
			}

			var bodyJSON map[string]interface{}
			if err := json.Unmarshal(res.RawBody, &bodyJSON); err == nil {
				if origin, ok := bodyJSON["origin"].(string); ok {
					fmt.Printf("Origin: %s\n", origin)
				}
			}
			fmt.Printf("Attempts required: %d\n", res.Attempts)
		}
		return 0
	}

	// -------------------------------------------------------------
	// Standard URL Request Mode
	// -------------------------------------------------------------
	if targetURL == "" {
		fmt.Fprintln(os.Stderr, "Error: --url parameter is required (or use --vet / --vet-single / --test / --update). Run with --help for details.")
		return 1
	}

	if _, err := proxycore.ValidateTargetURL(targetURL); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Invalid target URL '%s': %s\n", targetURL, err.Error())
		return 1
	}

	if proxyFile == "" {
		candidate := proxycore.ResolveProxyPathWithBase("", "")
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			if verbose {
				fmt.Printf("[Client] Proxy candidate file '%s' not found. Auto-fetching fresh socks5.txt from upstream...\n", candidate)
			}
			targetPath := proxycore.ResolveDataFilePathWithBase("", proxycore.DefaultDataFileName)
			updateRes, updateErr := proxycore.RefreshProxyDataIfNeeded(proxycore.RefreshOptions{
				TargetFile: targetPath,
				Verbose:    verbose,
			})
			if updateErr == nil && updateRes != nil && updateRes.Updated {
				proxyFile = updateRes.TargetFilePath
				if verbose {
					fmt.Printf("[Client] Successfully updated data folder with %s\n", updateRes.TargetFilePath)
				}
			}
		}
	}

	client, err := proxycore.NewSocksProxyClient(proxycore.ClientOptions{
		ProxyFile:          proxyFile,
		MaxRetries:         retries,
		Timeout:            timeout,
		TLSPolicy:          tlsPolicy,
		RejectUnauthorized: tlsPolicy == proxycore.TLSStrict,
		Verbose:            verbose,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing proxy client: %s\n", err.Error())
		return 1
	}

	res, err := client.Request(targetURL, proxycore.RequestOptions{
		TLSPolicy:          tlsPolicy,
		RejectUnauthorized: tlsPolicy == proxycore.TLSStrict,
		AllowInsecure:      tlsPolicy == proxycore.TLSInsecure,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[ERROR] Request failed: %s\n", err.Error())
		return 1
	}

	fmt.Printf("\n=== Response [Status %d %s] ===\n", res.Status, res.StatusText)
	if res.ProxyUsed != nil {
		fmt.Printf("Successful Proxy: %s\n", res.ProxyUsed.Scheme)
	}
	fmt.Printf("Attempts: %d\n", res.Attempts)
	fmt.Println("Headers:")
	for k, v := range res.Headers {
		fmt.Printf("  %s: %s\n", k, v)
	}
	fmt.Printf("\n=== Body ===\n%s\n", res.Text())
	return 0
}
