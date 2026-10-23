package views

import (
	"context"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/samuelkane526/socks5-sentinel/internal/gui"
	"github.com/samuelkane526/socks5-sentinel/internal/gui/components"
	"github.com/samuelkane526/socks5-sentinel/internal/proxycore"
)

// RequestView handles custom HTTP/HTTPS proxied requests
type RequestView struct {
	controller *gui.Controller
	window     fyne.Window
	content    *fyne.Container

	urlEntry     *widget.Entry
	sourcePicker *components.PathPicker
	retriesEntry *widget.Entry
	timeoutEntry *widget.Entry
	tlsPolicySel *widget.RadioGroup
	verboseCheck *widget.Check

	sendBtn   *widget.Button
	cancelBtn *widget.Button

	tlsWarningLabel  *widget.Label
	viewHeadersBtn   *widget.Button
	optionsAccordion *widget.Accordion
	healthView       *HealthView
	singleView       *SingleView

	// Response widgets
	statusBadge  *canvas.Text
	metaLabel    *widget.Label
	headersBox   *widget.Entry
	bodyBox      *widget.Entry
	copyBodyBtn  *widget.Button
	saveBodyBtn  *widget.Button
	responseCard *widget.Card
}

// NewRequestView initializes RequestView
func NewRequestView(ctrl *gui.Controller, win fyne.Window) *RequestView {
	rv := &RequestView{
		controller: ctrl,
		window:     win,
		healthView: NewHealthView(ctrl, win),
		singleView: NewSingleView(ctrl, win),
	}

	rv.buildUI()
	return rv
}

func (rv *RequestView) buildUI() {
	rv.urlEntry = widget.NewEntry()
	rv.urlEntry.SetPlaceHolder("https://httpbin.org/get")
	rv.urlEntry.SetText("https://httpbin.org/get")

	rv.sourcePicker = components.NewPathPicker(rv.window, components.PickerModeOpenFile, "Automatic (elite_proxies/vetted_proxies.json or socks5.txt)", func(path string) {
		if rv.healthView != nil && rv.healthView.sourcePicker != nil {
			rv.healthView.sourcePicker.SetPath(path)
		}
	})

	rv.retriesEntry = widget.NewEntry()
	rv.retriesEntry.SetText(strconv.Itoa(rv.controller.Preferences().GetDefaultRetries()))

	rv.timeoutEntry = widget.NewEntry()
	rv.timeoutEntry.SetText(strconv.Itoa(rv.controller.Preferences().GetDefaultTimeoutMs()))

	rv.tlsWarningLabel = widget.NewLabel("⚠ TLS Verification Disabled (Strict anti-MITM protection is turned off)")
	rv.tlsWarningLabel.TextStyle = fyne.TextStyle{Bold: true}
	rv.tlsWarningLabel.Importance = widget.DangerImportance
	rv.tlsWarningLabel.Hide()

	rv.tlsPolicySel = widget.NewRadioGroup([]string{
		"Verify certificates (Strict anti-MITM, default)",
		"Allow invalid certificates (--allow-insecure)",
	}, func(sel string) {
		if strings.Contains(sel, "allow-insecure") {
			rv.tlsWarningLabel.Show()
		} else {
			rv.tlsWarningLabel.Hide()
		}
	})
	rv.tlsPolicySel.SetSelected("Verify certificates (Strict anti-MITM, default)")

	rv.verboseCheck = widget.NewCheck("Detailed failover logs", nil)

	rv.sendBtn = widget.NewButtonWithIcon("Send Request", theme.MailSendIcon(), rv.onSendRequest)
	rv.sendBtn.Importance = widget.HighImportance

	rv.cancelBtn = widget.NewButtonWithIcon("Cancel", theme.MediaStopIcon(), func() {
		rv.controller.CancelActiveJob()
	})
	rv.cancelBtn.Disable()

	header := components.NewSectionHeader("Request Target & Options", "", rv.window)

	urlRow := container.NewBorder(nil, nil,
		widget.NewLabelWithStyle("Target URL:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewHBox(rv.sendBtn, rv.cancelBtn),
		rv.urlEntry,
	)

	sourceRow := container.NewBorder(nil, nil,
		widget.NewLabelWithStyle("Proxy Source:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		nil,
		rv.sourcePicker,
	)

	advOptions := container.NewVBox(
		container.NewGridWithColumns(2,
			container.NewVBox(widget.NewLabelWithStyle("Retries after first attempt:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), rv.retriesEntry),
			container.NewVBox(widget.NewLabelWithStyle("Timeout (ms):", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), rv.timeoutEntry),
		),
		widget.NewLabelWithStyle("TLS Security Policy:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		rv.tlsPolicySel,
		rv.verboseCheck,
	)

	rv.optionsAccordion = widget.NewAccordion(
		widget.NewAccordionItem("Advanced Request Options (Retries, Timeout, TLS, Logs)", advOptions),
		widget.NewAccordionItem("Single Proxy Verification (5 Stages)", rv.singleView.Content()),
		widget.NewAccordionItem("Pool Health Check (Run 3 consecutive requests to echo service)", rv.healthView.Content()),
	)

	topCommandArea := container.NewVBox(
		header,
		urlRow,
		sourceRow,
		rv.tlsWarningLabel,
		rv.optionsAccordion,
	)

	// Response View
	rv.statusBadge = canvas.NewText("[ STATUS ]", color.RGBA{128, 128, 128, 255})
	rv.statusBadge.TextStyle = fyne.TextStyle{Bold: true}
	rv.statusBadge.TextSize = 14

	rv.metaLabel = widget.NewLabel("No response yet")
	rv.metaLabel.TextStyle = fyne.TextStyle{Italic: true}

	rv.headersBox = widget.NewMultiLineEntry()
	rv.headersBox.Disable()
	rv.headersBox.TextStyle = fyne.TextStyle{Monospace: true}

	rv.bodyBox = widget.NewMultiLineEntry()
	rv.bodyBox.Disable()
	rv.bodyBox.Wrapping = fyne.TextWrapWord
	rv.bodyBox.TextStyle = fyne.TextStyle{Monospace: true}

	rv.copyBodyBtn = widget.NewButtonWithIcon("Copy Body", theme.ContentCopyIcon(), func() {
		rv.window.Clipboard().SetContent(rv.bodyBox.Text)
	})

	rv.saveBodyBtn = widget.NewButtonWithIcon("Save Body to File", theme.DocumentSaveIcon(), func() {
		if rv.bodyBox.Text == "" {
			dialog.ShowInformation("Empty", "No response body to save.", rv.window)
			return
		}
		components.PromptSaveFilePath(rv.window, "response.txt", func(chosenPath string) {
			baseDir := rv.controller.Preferences().GetWorkingFolder()
			destPath := chosenPath
			if !filepath.IsAbs(destPath) && baseDir != "" {
				destPath = filepath.Join(baseDir, destPath)
			}
			doSave := func() {
				if err := proxycore.ReplaceFileWithBytes(destPath, []byte(rv.bodyBox.Text), 0644); err != nil {
					dialog.ShowError(err, rv.window)
				} else {
					dialog.ShowInformation("Saved", fmt.Sprintf("Successfully saved response body to %s", filepath.Base(destPath)), rv.window)
				}
			}
			if _, statErr := os.Stat(destPath); statErr == nil {
				dialog.ShowConfirm("Overwrite File?", fmt.Sprintf("File %s already exists. Overwrite it?", filepath.Base(destPath)), func(confirm bool) {
					if confirm {
						doSave()
					}
				}, rv.window)
			} else {
				doSave()
			}
		})
	})

	rv.viewHeadersBtn = widget.NewButtonWithIcon("View Headers", theme.InfoIcon(), func() {
		rv.showHeadersPopup()
	})

	bodyToolbar := container.NewHBox(rv.copyBodyBtn, rv.saveBodyBtn, rv.viewHeadersBtn)
	statusLine := container.NewBorder(nil, nil,
		container.NewHBox(rv.statusBadge, widget.NewSeparator(), rv.metaLabel),
		bodyToolbar,
	)

	respHeader := components.NewSectionHeader("HTTP Response", "", rv.window)
	rv.responseCard = widget.NewCard("", "", container.NewBorder(
		container.NewVBox(respHeader, statusLine, widget.NewSeparator()),
		nil, nil, nil,
		rv.bodyBox,
	))

	rv.content = container.NewBorder(topCommandArea, nil, nil, nil, rv.responseCard)

	components.AddHelp(rv.content, rv.window)
	rv.controller.AddStateListener(func(st gui.AppState) {
		switch st.Status {
		case gui.JobRunning:
			if st.ActiveJob == gui.JobRequest {
				rv.setFormEnabled(false)
				rv.sendBtn.Disable()
				rv.cancelBtn.Enable()
			}
		default:
			rv.setFormEnabled(true)
			rv.sendBtn.Enable()
			rv.cancelBtn.Disable()
		}
	})
}

func (rv *RequestView) showHeadersPopup() {
	if rv.window == nil || rv.window.Canvas() == nil {
		return
	}
	copyBtn := widget.NewButtonWithIcon("Copy Headers", theme.ContentCopyIcon(), func() {
		if rv.window != nil {
			rv.window.Clipboard().SetContent(rv.headersBox.Text)
		}
	})
	headerLabel := widget.NewLabelWithStyle("Response Headers", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	var pop *widget.PopUp
	closeBtn := widget.NewButtonWithIcon("Close", theme.CancelIcon(), func() {
		if pop != nil {
			pop.Hide()
		}
	})
	topBar := container.NewBorder(nil, nil, headerLabel, container.NewHBox(copyBtn, closeBtn))
	content := container.NewBorder(topBar, nil, nil, nil, rv.headersBox)
	popBox := components.PopupContent(content, rv.window.Canvas(), fyne.NewSize(640, 400))
	pop = widget.NewModalPopUp(popBox, rv.window.Canvas())
	pop.Show()
}

func (rv *RequestView) setFormEnabled(enabled bool) {
	if enabled {
		rv.urlEntry.Enable()
		rv.retriesEntry.Enable()
		rv.timeoutEntry.Enable()
		rv.verboseCheck.Enable()
	} else {
		rv.urlEntry.Disable()
		rv.retriesEntry.Disable()
		rv.timeoutEntry.Disable()
		rv.verboseCheck.Disable()
	}
	rv.sourcePicker.SetEnabled(enabled)
}

// SetSourcePath sets the proxy source entry (used by "Use Results for Requests")
func (rv *RequestView) SetSourcePath(path string) {
	rv.sourcePicker.SetPath(path)
	if rv.healthView != nil && rv.healthView.sourcePicker != nil {
		rv.healthView.sourcePicker.SetPath(path)
	}
}

func (rv *RequestView) onSendRequest() {
	rawURL := strings.TrimSpace(rv.urlEntry.Text)
	if _, err := proxycore.ValidateTargetURL(rawURL); err != nil {
		dialog.ShowError(err, rv.window)
		return
	}

	retries, err := strconv.Atoi(rv.retriesEntry.Text)
	if err != nil || retries < 1 {
		dialog.ShowError(fmt.Errorf("invalid retries: %s (must be >= 1)", rv.retriesEntry.Text), rv.window)
		return
	}

	timeoutMs, err := strconv.Atoi(rv.timeoutEntry.Text)
	if err != nil || timeoutMs <= 0 {
		dialog.ShowError(fmt.Errorf("invalid timeout: %s (must be > 0 ms)", rv.timeoutEntry.Text), rv.window)
		return
	}

	tlsPolicy := proxycore.TLSStrict
	if strings.Contains(rv.tlsPolicySel.Selected, "allow-insecure") {
		tlsPolicy = proxycore.TLSInsecure
	}

	baseDir := rv.controller.Preferences().GetWorkingFolder()
	proxyFile := rv.sourcePicker.Path()

	rv.statusBadge.Text = "[ SENDING... ]"
	rv.statusBadge.Color = color.RGBA{0, 122, 255, 255}
	rv.statusBadge.Refresh()
	rv.metaLabel.SetText("Dispatching through rotating proxy client...")
	rv.headersBox.SetText("")
	rv.bodyBox.SetText("")

	startTime := time.Now()

	err = rv.controller.StartJob(gui.JobRequest, fmt.Sprintf("GET %s", proxycore.RedactSensitive(rawURL)), func(ctx context.Context, emit func(proxycore.Event)) error {
		client, initErr := proxycore.NewSocksProxyClient(proxycore.ClientOptions{
			BaseDir:            baseDir,
			ProxyFile:          proxyFile,
			MaxRetries:         retries,
			Timeout:            time.Duration(timeoutMs) * time.Millisecond,
			TLSPolicy:          tlsPolicy,
			RejectUnauthorized: tlsPolicy == proxycore.TLSStrict,
			Verbose:            rv.verboseCheck.Checked,
		})
		if initErr != nil {
			emit(proxycore.NewLogEvent("error", fmt.Sprintf("Failed initializing client: %s", initErr.Error())))
			return initErr
		}

		res, reqErr := client.RequestWithContext(ctx, rawURL, func(e proxycore.Event) {
			emit(e)
		}, proxycore.RequestOptions{
			TLSPolicy:          tlsPolicy,
			RejectUnauthorized: tlsPolicy == proxycore.TLSStrict,
			AllowInsecure:      tlsPolicy == proxycore.TLSInsecure,
		})

		elapsed := time.Since(startTime).Round(time.Millisecond)

		if reqErr != nil {
			fyne.Do(func() {
				rv.statusBadge.Text = "[ FAILED ]"
				rv.statusBadge.Color = color.RGBA{218, 54, 51, 255}
				rv.statusBadge.Refresh()
				rv.metaLabel.SetText(fmt.Sprintf("Failed in %s", elapsed))
				rv.bodyBox.SetText(reqErr.Error())
			})
			return reqErr
		}

		var hdrLines []string
		for k, v := range res.Headers {
			hdrLines = append(hdrLines, fmt.Sprintf("%s: %s", k, v))
		}

		proxyStr := "Direct Connect"
		if res.ProxyUsed != nil {
			proxyStr = res.ProxyUsed.Scheme
		}

		fyne.Do(func() {
			if res.Status >= 200 && res.Status < 300 {
				rv.statusBadge.Text = fmt.Sprintf("[ %d %s ]", res.Status, res.StatusText)
				rv.statusBadge.Color = color.RGBA{46, 160, 67, 255}
			} else {
				rv.statusBadge.Text = fmt.Sprintf("[ %d %s ]", res.Status, res.StatusText)
				rv.statusBadge.Color = color.RGBA{220, 150, 0, 255}
			}
			rv.statusBadge.Refresh()

			rv.metaLabel.SetText(fmt.Sprintf("Proxy: %s | Attempts: %d | Time: %s", proxyStr, res.Attempts, elapsed))
			rv.headersBox.SetText(strings.Join(hdrLines, "\n"))
			rv.bodyBox.SetText(res.Text())
		})

		return nil
	})

	if err != nil {
		dialog.ShowError(err, rv.window)
	}
}

// Content returns container
func (rv *RequestView) Content() fyne.CanvasObject {
	return rv.content
}

// SingleView returns the underlying SingleView
func (rv *RequestView) SingleView() *SingleView {
	return rv.singleView
}

// HealthView returns the underlying HealthView
func (rv *RequestView) HealthView() *HealthView {
	return rv.healthView
}
