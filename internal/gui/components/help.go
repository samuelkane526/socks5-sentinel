package components

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"strings"
)

// HelpText is the shared user-facing reference for controls throughout the app.
var HelpText = map[string]string{
	"Stage 1":                            "Establish the direct public IP baseline and test SOCKS5 connectivity with remote hostname resolution. A failure can indicate an unreachable endpoint, a failed handshake, or an unavailable baseline service.",
	"Stage 2":                            "Compare the proxy's echoed public IP with your direct public IP and inspect headers for identity leaks. The proxy must mask the baseline IP and pass the header checks.",
	"Stage 3":                            "Check HTTPS using trusted certificates and hostname verification to detect TLS interception. This check runs before Stage 2; invalid certificates cause rejection.",
	"Stage 4":                            "Request a plain HTTP echo response and check its status, content type and expected JSON structure for rerouting or altered responses. Plain HTTP itself is unencrypted.",
	"Stage 5":                            "Send a random session cookie and check the echoed cookie and headers for changes or injected tracking data. Passing only reflects what the test observed during this run.",
	"Local & Upstream Tracking Metadata": "Commit SHA identifies the downloaded upstream revision; Commit Message describes it. Upstream Date is the source revision time, Last Pulled is the local download time, and Local File Size describes the destination file. Missing metadata means no recorded download, not that proxies have passed verification.",
	"Documentation & Flag Reference":     "Reference for command-line equivalents and the five verification stages. Hover over control labels for usage details specific to each setting.",
	"Results (Request # | Status | Proxy Used | Origin IP | Attempts | Error)": "Each row is one of three health requests. Status is the returned HTTP status; Proxy Used is the selected endpoint; Origin IP is the address reported by the echo service; Attempts includes retries. Error describes a failed request. These connectivity checks do not replace full proxy vetting.",
	"Proxy Source":                          "Choose a .txt proxy list or supported proxy JSON file. Relative paths use the working directory in Settings. Leave blank to use automatic source selection; batch vetting uses the upstream candidate list, while requests prefer saved vetted proxies.",
	"Workers":                               "Number of proxies tested at the same time. Must be at least 1. More workers use more connections and bandwidth; reduce this if your network struggles.",
	"Workers (concurrency)":                 "Number of proxies tested at the same time. Must be at least 1. More workers use more connections and bandwidth; reduce this if your network struggles.",
	"Target":                                "Stop after finding this many passing proxies. Enter 0 to test without a passing-proxy target. Already running workers may finish as the target is reached.",
	"Target (0 = unlimited)":                "Stop after finding this many passing proxies. Enter 0 to test without a passing-proxy target. Already running workers may finish as the target is reached.",
	"Candidate Limit":                       "Maximum number of candidate proxies to test. Enter 0 to consider the full source list. This limits candidates, not successful results.",
	"Candidate Limit (0 = all)":             "Maximum number of candidate proxies to test. Enter 0 to consider the full source list. This limits candidates, not successful results.",
	"Tools":                                 "Toggle tools inspector for upstream candidate synchronization.",
	"Close Tools":                           "Close inspector tools and expand batch results table.",
	"View Headers":                          "Inspect HTTP response headers returned by the server.",
	"Use as Batch Source":                   "Set the current upstream destination file as the input source for batch vetting.",
	"Console":                               "Real-time diagnostic execution logs for vetting, HTTP requests, and upstream data synchronization.",
	"Primary Output JSON":                   "File where passing proxies are saved as JSON for later requests. Relative paths use the working directory. An existing output may be replaced.",
	"Update Policy":                         "Automatic checks upstream for changed proxy data. Force downloads a fresh copy even when unchanged. Local only skips upstream updates and requires an existing local list.",
	"Timeout (ms)":                          "Network timeout in milliseconds (1000 ms = 1 second). Must be greater than 0. Longer timeouts tolerate slow proxies but make failures take longer. Batch uses this for each verification stage; retries can make a whole request take longer.",
	"Additional Export Path":                "Optional extra destination for passing proxies, in addition to the primary JSON output. Browse chooses a folder; you can also type a file path. Leave blank to skip the extra export.",
	"Detailed proxy logs":                   "Include per-proxy diagnostic messages in Execution Logs. Useful for investigating failures; large batches produce more output.",
	"Detailed failover logs":                "Log each proxy attempt and failover so you can see why requests retry. Logs may include network addresses and response details.",
	"Start Vetting":                         "Test candidates through all five verification stages and save those that pass. Requires internet access, including the public IP and HTTP echo services. Only one network job can run at a time.",
	"Cancel":                                "Ask the active network operation to stop. Completed results remain visible; cancellation can take a moment while network work stops. For batch results, use Save Partial Results after cancellation.",
	"Actions":                               "Save Partial Results writes passing proxies collected so far; available after the job stops and at least one proxy passes. Use Results for Requests switches to Request with the primary output path; save partial results first if needed.",
	"Save Partial Results":                  "Save the passing proxies collected so far to the primary output JSON. Stop the active job first. Requires at least one passing proxy.",
	"Use Results for Requests":              "Open the Request screen using the primary output file as its proxy source. Ensure results have been saved to that file first.",
	"Filter":                                "Show all tested candidates, only those that passed, or only failures. Filtering changes the table display, not saved results.",
	"Auto-scroll to bottom":                 "Follow new results as they arrive. Turn off to inspect earlier rows without the table moving.",
	"Proxy Address ⇅":                       "Proxy endpoint tested. Click this heading to sort by address; click again to reverse the order.",
	"Status ⇅":                              "Whether the candidate passed all verification checks. Click to sort by status and again to reverse.",
	"Stage ⇅":                               "Verification stage associated with the result. Click to sort by stage and again to reverse. A failure identifies where testing stopped.",
	"Details / Reason ⇅":                    "Explanation of a pass or failure. Click to sort by this text and again to reverse.",
	"Configuration":                         "Configure a batch of SOCKS5 proxy verification tests. Progress shows candidates tested, passing and rejected counts, elapsed time, and failures by stage. Passing reflects these checks at test time; availability can change.",
	"Proxy Address (IP:PORT or socks5h://)": "Enter one SOCKS5 endpoint as host:port or socks5h://user:pass@host:port. Include credentials only when required. Single-proxy testing always verifies TLS and uses a fixed 5-second stage timeout.",
	"Final Verification Verdict":            "Summarizes whether this candidate passed all five checks. A pass describes this test run and does not guarantee future availability or safety.",
	"5-Stage Verification Protocol":         "Checks SOCKS connectivity, public IP masking and leaked headers, trusted TLS certificates, HTTP response integrity, and cookie/header integrity. Tests use external echo services; a service outage can also cause rejection. TLS is checked before the masking stage.",
	"Test Candidate Proxy":                  "Record your direct public IP, then run the five verification checks on the entered proxy. This test contacts external services and uses strict TLS with a 5-second timeout per stage.",
	"Target URL":                            "Full http:// or https:// address to fetch with an HTTP GET through a SOCKS5 proxy. Use HTTPS when sending sensitive data.",
	"Retries after first attempt":           "Additional proxy attempts after the first attempt fails. For example, 2 allows up to 3 total attempts, subject to available proxies. This screen currently requires at least 1 retry.",
	"TLS Security Policy":                   "Verify certificates checks the HTTPS server certificate and hostname. Allow invalid certificates skips that verification and can accept an impersonated server; use only for endpoints you intentionally trust. This setting does not encrypt plain HTTP.",
	"Send Request":                          "Send an HTTP GET to the target URL using the selected proxy pool. Failed proxy attempts can fail over up to the retry limit. Response status, proxy, attempts, headers and body appear below.",
	"Request Target & Options":              "Fetch a URL through a SOCKS5 proxy pool. Select a source or leave it automatic, then set retries, timeout and certificate verification.",
	"HTTP Response":                         "Shows the HTTP status, chosen proxy and attempt information. Response Body contains returned text; Headers contains server response headers. An HTTP response does not necessarily mean the server returned a successful status.",
	"Copy Body":                             "Copy the displayed response body to the clipboard. Treat returned content as potentially sensitive.",
	"Save Body to File":                     "Choose a file and write the displayed response body text to it. Fetch a response first; this is a text export of the displayed body.",
	"Run 3 Consecutive Requests":            "Send three sequential GET requests to https://httpbin.org/get through the proxy pool. Each request uses the retry and timeout settings. Results show status, proxy, echoed public IP, attempts and errors; this is a connectivity check, not the full vetting protocol.",
	"Destination Data File":                 "Where the downloaded upstream proxy list is stored. Relative paths use the working directory. Downloading updates this file; it does not verify the listed proxies. Run Batch Vetting before relying on candidates.",
	"Check & Update":                        "Contact GitHub for the upstream proxy list revision and download when needed. Requires internet access. The destination and nearby last_pull_metadata.json record the local copy and its revision.",
	"Force Download":                        "Download upstream data even if the recorded revision is unchanged. Replaces the destination list; useful when the local copy is missing or damaged.",
	"Working Directory (Relative paths resolve against this folder)": "Base folder for relative source, output and export paths. Changing it takes effect immediately and does not move existing files. If the saved folder no longer exists, the app uses its current directory.",
	"User Interface Theme":          "Choose Light, Dark, or the default system theme. Applies immediately and is saved for later launches.",
	"Default Workers":               "Initial worker count for Batch Vetting when the screen is created. Must be at least 1. Save Numeric Defaults, then restart to populate the screens with the new defaults.",
	"Default Retries":               "Initial additional retry count for Request and Health Test when their screens are created. Must be at least 1. Save and restart to use the new defaults in those screens.",
	"Default Timeout (ms)":          "Initial timeout for Batch, Request and Health Test in milliseconds. Must be greater than 0. Save and restart to populate those screens. Single Proxy keeps its fixed 5-second stage timeout.",
	"Save Numeric Defaults":         "Validate and save the worker, retry and timeout defaults for future screen creation. Restart to load them into the existing screens. Working directory and theme save immediately.",
	"Reset Preferences to Defaults": "After confirmation, restore the default working directory, theme and numeric defaults. Existing screen inputs may need a restart to reload. Proxy data and output files are not deleted.",
	"Execution Logs":                "Diagnostic messages from jobs. The log retains up to 5000 recent lines. Filter searches case-insensitively; Copy Logs copies all retained lines, including filtered-out lines; Clear removes the current log display and history.",
	"Autoscroll":                    "Follow the newest log messages. Turn off while inspecting earlier messages.",
	"Copy Logs":                     "Copy all retained log lines, including lines hidden by the filter. Review network addresses and response details before sharing.",
	"Clear":                         "Remove the retained execution logs and clear the display. This does not delete saved proxy files or cancel jobs.",
}

// AddHelp decorates visible controls once, preserving their original widget references.
func AddHelp(root fyne.CanvasObject, win fyne.Window) fyne.CanvasObject {
	var key string
	switch obj := root.(type) {
	case *StageList:
		AddHelp(obj.container, win)
	case *fyne.Container:
		originals := append([]fyne.CanvasObject(nil), obj.Objects...)
		changed := false
		for i, child := range obj.Objects {
			obj.Objects[i] = AddHelp(child, win)
			changed = changed || obj.Objects[i] != child
		}
		if changed && obj.Layout != nil {
			obj.Layout = &helpLayout{delegate: obj.Layout, originals: originals}
		}
	case *widget.Card:
		if obj.Content != nil {
			obj.SetContent(AddHelp(obj.Content, win))
		}
	case *container.Split:
		obj.Leading = AddHelp(obj.Leading, win)
		obj.Trailing = AddHelp(obj.Trailing, win)
	case *container.Scroll:
		obj.Content = AddHelp(obj.Content, win)
	case *container.AppTabs:
		for _, item := range obj.Items {
			item.Content = AddHelp(item.Content, win)
		}
	case *widget.Accordion:
		for _, item := range obj.Items {
			item.Detail = AddHelp(item.Detail, win)
		}
	case *widget.Label:
		key = obj.Text
	case *widget.Button:
		key = obj.Text
	case *widget.Check:
		key = obj.Text
	}
	key = strings.TrimSuffix(strings.TrimSpace(key), ":")
	if description := HelpText[key]; description != "" {
		return NewHoverTooltip(root, description, win)
	}
	return root
}

// Layouts such as Border retain references to their edge objects. Lay out those
// original objects, then transfer their geometry to the help wrappers.
type helpLayout struct {
	delegate  fyne.Layout
	originals []fyne.CanvasObject
}

func (l *helpLayout) MinSize(_ []fyne.CanvasObject) fyne.Size {
	return l.delegate.MinSize(l.originals)
}

func (l *helpLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	l.delegate.Layout(l.originals, size)
	for i, original := range l.originals {
		if objects[i] != original {
			pos, size := original.Position(), original.Size()
			objects[i].Move(pos)
			objects[i].Resize(size)
			original.Move(fyne.Position{})
		}
	}
}
