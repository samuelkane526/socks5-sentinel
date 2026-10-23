# Socks5 Vetter

Find working SOCKS5 proxies, check their behavior, and send HTTP requests through a rotating proxy pool. Socks5 Vetter lives in the `socks5-sentinel` repository and includes the `socks5-vet` Go command-line client and a Fyne desktop app backed by the same networking engine.

## Highlights

- **Five-stage vetting:** check connectivity, IP and header leaks, TLS certificates, HTTP responses, and cookie integrity.
- **Batch or single-proxy checks:** test candidates concurrently, set a passing-proxy target, and inspect failure reasons.
- **Automatic candidate updates:** download the upstream SOCKS5 list or bring your own text or JSON file.
- **Requests with failover:** rotate through proxies when requests fail, with configurable retries and timeouts.
- **Desktop workflow:** view progress, filter results, cancel jobs, inspect logs, and reuse saved results for requests.
- **Reusable results:** save a merged vetted list and timestamped session files.

## Getting started

This checkout contains source code. To create the CLI or desktop executable, follow [Build from source](#build-from-source). If you already have a built desktop executable, launch it and follow the workflow below; Go is only needed to build it.

Network operations require internet access. Automatic updates use Proxifly's free-proxy-list on GitHub; vetting uses public-IP lookup services and httpbin echo endpoints.

### Desktop

1. Open **Settings** and choose the working directory where proxy lists and results should live.
2. Open **Vetting**. Leave the source blank for upstream candidates, or select your own list. Choose **Local only** when using a local list without downloading updates.
3. Set a **Target**, such as `5`, and click **Start Vetting**. Inspect passing and rejected candidates as results arrive.
4. Choose **Use Results for Requests**, enter a target URL, and click **Send Request**.

The **Requests** screen also provides single-proxy verification and a three-request connectivity test. **Console** shows execution logs. Hover over control labels for contextual help.

After cancelling a batch, use **Save Partial Results** to keep collected passes before using them for requests. The desktop app runs one network job at a time.

### Command line

These examples use the Windows executable built below. On macOS or Linux, substitute `./socks5-vet` for `./socks5-vet.exe`. With the executable on your PATH, you can invoke it as `socks5-vet`.

Find five passing proxies, downloading candidates automatically:

```sh
./socks5-vet.exe --vet --target 5
```

Send a request using the saved list:

```sh
./socks5-vet.exe --url https://httpbin.org/get --file elite_proxies/vetted_proxies.json --verbose
```

Vet up to 100 candidates from your own file, with 20 workers and no upstream update:

```sh
./socks5-vet.exe --vet --file proxies.txt --no-update --limit 100 --concurrency 20
```

Other useful commands:

```sh
./socks5-vet.exe --update
./socks5-vet.exe --test --file elite_proxies/vetted_proxies.json
./socks5-vet.exe --vet --target 10 --export exported_proxies
./socks5-vet.exe --help
```

To check one proxy, use `--vet-single host:port`, replacing `host:port` with your endpoint. Authenticated SOCKS5 URLs are also accepted.

### Common options

| Option | Purpose | Default |
| --- | --- | --- |
| `--file <path>` | Candidate list for vetting or proxy pool for requests | Automatic selection |
| `--target <n>` | Stop after reaching a passing-proxy target | `0` (unlimited) |
| `--limit <n>` | Maximum candidates to test | `0` (all) |
| `--concurrency <n>` | Concurrent vetting workers | `100` |
| `--timeout <ms>` | Batch stage or request-attempt timeout | `10000` |
| `--retries <n>` | Additional request attempts after the first failure | `5` |
| `--output <path>` | Primary vetted JSON output | `elite_proxies/vetted_proxies.json` |
| `--export <path>` | Additional export directory or JSON file | None |
| `--no-update` | Skip automatic candidate updates | Updates enabled for batch vetting |
| `--force-update` | Download candidates even when unchanged | Off |
| `--verbose` / `-v` | Detailed request failover and pipeline logs | Off |

Single-proxy vetting uses a fixed five-second timeout per stage. Request retries can make the total operation longer than `--timeout`. Concurrent batch workers may finish after the passing target is reached.

## Proxy lists and saved data

Text lists accept one endpoint per line, with optional SOCKS5 credentials. Blank lines and lines beginning with `#` are ignored. For example, a local proxy list could contain:

```text
# Replace these with your own proxy endpoints
127.0.0.1:1080
socks5h://username:password@127.0.0.1:1081
```

JSON arrays of endpoint strings or supported proxy objects are also accepted, including the JSON produced by vetting.

| Path | Contents |
| --- | --- |
| `data/socks5.txt` | Downloaded candidate list |
| `data/last_pull_metadata.json` | Revision and download metadata for the default candidate file |
| `elite_proxies/vetted_proxies.json` | Merged saved results |
| `elite_proxies/<count>_<timestamp>.json` | Passing proxies from an individual saved session |

The CLI uses its current working directory; the desktop app uses the folder selected in **Settings**. Both create `data/` on startup. Output folders are created when results are saved.

With no explicit request source, the client prefers `elite_proxies/vetted_proxies.json`, then searches legacy vetted locations and raw candidate lists. Use `--file` to choose a specific list. A merged list can retain proxies from earlier runs; saving new results does not revalidate every older entry.

## What vetting checks

The five checks cover SOCKS5 connectivity, public-IP masking and identifying headers, trusted TLS certificates, HTTP response integrity, and cookie/header integrity. TLS verification runs before the IP-masking check.

A pass describes the observed behavior during that run, not a guarantee of anonymity or future availability. Echo-service outages can cause rejection. Saved authenticated proxy entries retain credentials, so treat those files as sensitive.

HTTPS requests verify certificates by default. `--allow-insecure` disables certificate verification for client requests; full proxy vetting keeps strict TLS verification.

## Build from source

Run these commands from the project root. The module declares Go `1.22.0`; use a Go toolchain compatible with the dependencies in [go.mod](go.mod).

### CLI

The CLI does not need the desktop graphics toolchain.

```sh
go build -o socks5-vet.exe .
./socks5-vet.exe --help
```

On macOS or Linux:

```sh
go build -o socks5-vet .
./socks5-vet --help
```

### Desktop app

The desktop entry point is [cmd/socks5-vetter](cmd/socks5-vetter/main.go). It uses Fyne and needs CGO, a C compiler, and the platform's graphics development dependencies. Build it on the target platform with its Fyne build prerequisites installed.

On Windows, build without a separate console window:

```sh
go build -ldflags "-H=windowsgui" -o socks5-vetter.exe ./cmd/socks5-vetter
```

On macOS or Linux:

```sh
go build -o socks5-vetter ./cmd/socks5-vetter
```

For development, launch directly with `go run ./cmd/socks5-vetter`.

## Development and feedback

The project separates its interfaces from the shared engine:

- [internal/proxycore](internal/proxycore): SOCKS5 transport, requests, vetting, updates, and persistence.
- [internal/cli](internal/cli): command-line arguments and operation dispatch.
- [internal/gui](internal/gui): desktop controller, preferences, views, and widgets.

Run the CLI and engine tests:

```sh
go test . ./internal/cli ./internal/proxycore
```

With the desktop build prerequisites available, run the full suite:

```sh
go test ./...
```

Bug reports are most useful with the operating system, command or desktop steps, expected result, and relevant logs. Remove proxy credentials and private response data before sharing. Include a focused test when contributing a behavior change.

## Credits and license

Socks5 Vetter uses Fyne for its desktop interface and Proxifly's free-proxy-list as its default candidate source. These are dependencies and data sources, not project authorship claims.

This checkout does not identify a project author or include a license file. No project license is specified here.
