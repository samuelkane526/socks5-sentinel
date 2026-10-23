package views

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/samuelkane526/socks5-sentinel/internal/gui"
	"github.com/samuelkane526/socks5-sentinel/internal/gui/components"
	"github.com/samuelkane526/socks5-sentinel/internal/proxycore"
)

// HealthView executes the 3-request rotation health test
type HealthView struct {
	controller *gui.Controller
	window     fyne.Window
	content    *fyne.Container

	sourcePicker *components.PathPicker
	retriesEntry *widget.Entry
	timeoutEntry *widget.Entry
	tlsPolicySel *widget.RadioGroup

	runBtn    *widget.Button
	cancelBtn *widget.Button

	summaryLabel *widget.Label
	detailLabel  *widget.Label
	table        *widget.Table
	attempts     []proxycore.HealthAttemptPayload
	mu           sync.Mutex
}

// NewHealthView initializes HealthView
func NewHealthView(ctrl *gui.Controller, win fyne.Window) *HealthView {
	hv := &HealthView{
		controller: ctrl,
		window:     win,
		attempts:   make([]proxycore.HealthAttemptPayload, 0, 3),
	}

	hv.buildUI()
	return hv
}

func (hv *HealthView) buildUI() {
	hv.sourcePicker = components.NewPathPicker(hv.window, components.PickerModeOpenFile, "Automatic (elite_proxies/vetted_proxies.json or socks5.txt)", nil)

	hv.retriesEntry = widget.NewEntry()
	hv.retriesEntry.SetText(strconv.Itoa(hv.controller.Preferences().GetDefaultRetries()))

	hv.timeoutEntry = widget.NewEntry()
	hv.timeoutEntry.SetText(strconv.Itoa(hv.controller.Preferences().GetDefaultTimeoutMs()))

	hv.tlsPolicySel = widget.NewRadioGroup([]string{
		"Verify certificates (Strict anti-MITM, default)",
		"Allow invalid certificates (--allow-insecure)",
	}, nil)
	hv.tlsPolicySel.SetSelected("Verify certificates (Strict anti-MITM, default)")

	header := components.NewSectionHeader(
		"Health Test Configuration",
		"Parity Notice: Health Test mode performs 3 consecutive requests to https://httpbin.org/get with automatic proxy rotation and failover.",
		hv.window,
	)

	hv.runBtn = widget.NewButtonWithIcon("Run 3 Consecutive Requests", theme.MediaPlayIcon(), hv.onRunHealthTest)
	hv.runBtn.Importance = widget.HighImportance

	hv.cancelBtn = widget.NewButtonWithIcon("Cancel", theme.MediaStopIcon(), func() {
		hv.controller.CancelActiveJob()
	})
	hv.cancelBtn.Disable()

	inputCard := widget.NewCard("", "", container.NewVBox(
		header,
		widget.NewLabelWithStyle("Proxy Source:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		hv.sourcePicker,
		container.NewGridWithColumns(2,
			container.NewVBox(widget.NewLabelWithStyle("Retries after first attempt:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), hv.retriesEntry),
			container.NewVBox(widget.NewLabelWithStyle("Timeout (ms):", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), hv.timeoutEntry),
		),
		widget.NewLabelWithStyle("TLS Security Policy:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		hv.tlsPolicySel,
		container.NewHBox(hv.runBtn, hv.cancelBtn),
	))

	hv.summaryLabel = widget.NewLabel("No health test run yet.")
	hv.summaryLabel.TextStyle = fyne.TextStyle{Bold: true}

	hv.table = widget.NewTable(
		func() (int, int) {
			hv.mu.Lock()
			defer hv.mu.Unlock()
			return len(hv.attempts), 6
		},
		func() fyne.CanvasObject {
			lbl := widget.NewLabel("Template Result")
			lbl.TextStyle = fyne.TextStyle{Monospace: true}
			return lbl
		},
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			lbl := obj.(*widget.Label)
			hv.mu.Lock()
			if id.Row >= len(hv.attempts) {
				hv.mu.Unlock()
				lbl.SetText("")
				return
			}
			att := hv.attempts[id.Row]
			hv.mu.Unlock()

			switch id.Col {
			case 0:
				lbl.SetText(fmt.Sprintf("Request #%d", att.Attempt))
			case 1:
				if att.Status == 200 {
					lbl.SetText("✔ HTTP 200")
				} else if att.Status > 0 {
					lbl.SetText(fmt.Sprintf("HTTP %d", att.Status))
				} else {
					lbl.SetText("✘ FAILED")
				}
			case 2:
				lbl.SetText(att.ProxyUsed)
			case 3:
				lbl.SetText(att.Origin)
			case 4:
				lbl.SetText(fmt.Sprintf("%d attempt(s)", att.Attempts))
			case 5:
				lbl.SetText(att.Error)
			}
		},
	)
	hv.table.SetColumnWidth(0, 110)
	hv.table.SetColumnWidth(1, 110)
	hv.table.SetColumnWidth(2, 240)
	hv.table.SetColumnWidth(3, 140)
	hv.table.SetColumnWidth(4, 110)
	hv.table.SetColumnWidth(5, 300)

	hv.detailLabel = widget.NewLabel("Select a row above to view attempt details and long errors.")
	hv.detailLabel.Wrapping = fyne.TextWrapWord

	hv.table.OnSelected = func(id widget.TableCellID) {
		hv.mu.Lock()
		defer hv.mu.Unlock()
		if id.Row < len(hv.attempts) {
			att := hv.attempts[id.Row]
			errStr := att.Error
			if errStr == "" {
				errStr = "None"
			}
			hv.detailLabel.SetText(fmt.Sprintf("Request #%d: Status: %d | Proxy: %s | Origin: %s | Time: %s | Error: %s",
				att.Attempt, att.Status, att.ProxyUsed, att.Origin, att.Duration.Round(time.Millisecond), errStr))
		}
	}

	resultsHeader := components.NewSectionHeader("Results (Request # | Status | Proxy Used | Origin IP | Attempts | Error)", "", hv.window)
	resultsCard := widget.NewCard("", "", container.NewBorder(
		container.NewVBox(resultsHeader, hv.summaryLabel),
		hv.detailLabel, nil, nil,
		container.NewScroll(hv.table),
	))

	hv.content = container.NewBorder(inputCard, nil, nil, nil, resultsCard)

	components.AddHelp(hv.content, hv.window)
	hv.controller.AddStateListener(func(st gui.AppState) {
		switch st.Status {
		case gui.JobRunning:
			if st.ActiveJob == gui.JobHealthTest {
				hv.setFormEnabled(false)
				hv.runBtn.Disable()
				hv.cancelBtn.Enable()
			}
		default:
			hv.setFormEnabled(true)
			hv.runBtn.Enable()
			hv.cancelBtn.Disable()
		}
	})
}

func (hv *HealthView) setFormEnabled(enabled bool) {
	if enabled {
		hv.retriesEntry.Enable()
		hv.timeoutEntry.Enable()
	} else {
		hv.retriesEntry.Disable()
		hv.timeoutEntry.Disable()
	}
	hv.sourcePicker.SetEnabled(enabled)
}

func (hv *HealthView) onRunHealthTest() {
	retries, err := strconv.Atoi(hv.retriesEntry.Text)
	if err != nil || retries < 1 {
		dialog.ShowError(fmt.Errorf("invalid retries: %s (must be >= 1)", hv.retriesEntry.Text), hv.window)
		return
	}

	timeoutMs, err := strconv.Atoi(hv.timeoutEntry.Text)
	if err != nil || timeoutMs <= 0 {
		dialog.ShowError(fmt.Errorf("invalid timeout: %s (must be > 0 ms)", hv.timeoutEntry.Text), hv.window)
		return
	}

	tlsPolicy := proxycore.TLSStrict
	if strings.Contains(hv.tlsPolicySel.Selected, "allow-insecure") {
		tlsPolicy = proxycore.TLSInsecure
	}

	baseDir := hv.controller.Preferences().GetWorkingFolder()
	proxyFile := hv.sourcePicker.Path()

	hv.mu.Lock()
	hv.attempts = hv.attempts[:0]
	hv.mu.Unlock()
	hv.table.Refresh()
	hv.summaryLabel.SetText("Running 3 consecutive health check requests...")

	err = hv.controller.StartJob(gui.JobHealthTest, "Health Test (3 requests to https://httpbin.org/get)", func(ctx context.Context, emit func(proxycore.Event)) error {
		client, initErr := proxycore.NewSocksProxyClient(proxycore.ClientOptions{
			BaseDir:            baseDir,
			ProxyFile:          proxyFile,
			MaxRetries:         retries,
			Timeout:            time.Duration(timeoutMs) * time.Millisecond,
			TLSPolicy:          tlsPolicy,
			RejectUnauthorized: tlsPolicy == proxycore.TLSStrict,
			Verbose:            true,
		})
		if initErr != nil {
			emit(proxycore.NewLogEvent("error", fmt.Sprintf("Failed initializing client: %s", initErr.Error())))
			return initErr
		}

		successes := 0
		failures := 0

		for i := 1; i <= proxycore.HealthCheckRequestCount; i++ {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			start := time.Now()
			emit(proxycore.NewLogEvent("info", fmt.Sprintf("--- Test Request #%d ---", i)))

			res, reqErr := client.RequestWithContext(ctx, proxycore.HealthCheckEndpoint, func(e proxycore.Event) {
				emit(e)
			}, proxycore.RequestOptions{
				Method:             "GET",
				TLSPolicy:          tlsPolicy,
				RejectUnauthorized: tlsPolicy == proxycore.TLSStrict,
				AllowInsecure:      tlsPolicy == proxycore.TLSInsecure,
			})

			dur := time.Since(start)
			payload := proxycore.HealthAttemptPayload{
				Attempt:  i,
				Duration: dur,
			}

			if reqErr != nil {
				failures++
				payload.Error = reqErr.Error()
				emit(proxycore.NewLogEvent("error", fmt.Sprintf("[FAILURE] Test #%d failed: %s", i, reqErr.Error())))
			} else {
				successes++
				payload.Status = res.Status
				if res.ProxyUsed != nil {
					payload.ProxyUsed = res.ProxyUsed.Scheme
				}
				payload.Attempts = res.Attempts

				var bodyJSON map[string]interface{}
				if jsonErr := json.Unmarshal(res.RawBody, &bodyJSON); jsonErr == nil {
					if origin, ok := bodyJSON["origin"].(string); ok {
						payload.Origin = origin
					}
				}
				emit(proxycore.NewLogEvent("success", fmt.Sprintf("[SUCCESS] Status: %d, Origin: %s, Attempts: %d", res.Status, payload.Origin, res.Attempts)))
			}

			hv.mu.Lock()
			hv.attempts = append(hv.attempts, payload)
			hv.mu.Unlock()

			fyne.Do(func() {
				hv.table.Refresh()
				hv.summaryLabel.SetText(fmt.Sprintf("Progress: %d/3 completed | Successes: %d | Failures: %d", i, successes, failures))
			})
		}

		fyne.Do(func() {
			hv.summaryLabel.SetText(fmt.Sprintf("Summary: 3/3 Requests Complete | %d Passed | %d Failed", successes, failures))
		})

		return nil
	})

	if err != nil {
		dialog.ShowError(err, hv.window)
	}
}

// Content returns container
func (hv *HealthView) Content() fyne.CanvasObject {
	return hv.content
}
