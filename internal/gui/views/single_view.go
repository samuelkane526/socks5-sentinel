package views

import (
	"context"
	"fmt"
	"image/color"
	"strings"

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

// SingleView renders the 5-stage single candidate evaluation screen
type SingleView struct {
	controller *gui.Controller
	window     fyne.Window
	content    *fyne.Container

	addrEntry  *widget.Entry
	baselineIP *widget.Label
	testBtn    *widget.Button
	cancelBtn  *widget.Button

	stageList   *components.StageList
	verdictCard *widget.Card
	verdictText *canvas.Text
	verdictDesc *widget.Label
}

// NewSingleView initializes SingleView
func NewSingleView(ctrl *gui.Controller, win fyne.Window) *SingleView {
	sv := &SingleView{
		controller: ctrl,
		window:     win,
		stageList:  components.NewStageList(),
	}

	sv.buildUI()
	return sv
}

func (sv *SingleView) buildUI() {
	sv.addrEntry = widget.NewEntry()
	sv.addrEntry.SetPlaceHolder("e.g. 183.106.215.208:1080 or socks5h://user:pass@host:port")

	sv.baselineIP = widget.NewLabel("Host Public IP: Not recorded yet")
	sv.baselineIP.TextStyle = fyne.TextStyle{Italic: true}

	header := components.NewSectionHeader(
		"Candidate Proxy Target",
		"Parity Notice: Single-proxy vetting executes with strict TLS anti-MITM verification and a fixed 5.0-second stage timeout.",
		sv.window,
	)

	sv.testBtn = widget.NewButtonWithIcon("Test Candidate Proxy", theme.MediaPlayIcon(), sv.onTestProxy)
	sv.testBtn.Importance = widget.HighImportance

	sv.cancelBtn = widget.NewButtonWithIcon("Cancel", theme.MediaStopIcon(), func() {
		sv.controller.CancelActiveJob()
	})
	sv.cancelBtn.Disable()

	inputCard := widget.NewCard("", "", container.NewVBox(
		header,
		widget.NewLabelWithStyle("Proxy Address (IP:PORT or socks5h://):", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		sv.addrEntry,
		sv.baselineIP,
		container.NewHBox(sv.testBtn, sv.cancelBtn),
	))

	// Verdict Banner
	sv.verdictText = canvas.NewText("", color.RGBA{128, 128, 128, 255})
	sv.verdictText.TextStyle = fyne.TextStyle{Bold: true}
	sv.verdictText.TextSize = 16

	sv.verdictDesc = widget.NewLabel("")
	sv.verdictDesc.Wrapping = fyne.TextWrapWord

	verdictHeader := components.NewSectionHeader("Final Verification Verdict", "", sv.window)
	sv.verdictCard = widget.NewCard("", "", container.NewVBox(
		verdictHeader,
		container.NewCenter(sv.verdictText),
		sv.verdictDesc,
	))
	sv.verdictCard.Hide()

	stageHeader := components.NewSectionHeader("5-Stage Verification Protocol", "", sv.window)
	stageCard := widget.NewCard("", "", container.NewBorder(stageHeader, nil, nil, nil, container.NewScroll(sv.stageList)))

	topArea := container.NewVBox(inputCard, sv.verdictCard)
	sv.content = container.NewBorder(topArea, nil, nil, nil, stageCard)

	components.AddHelp(sv.content, sv.window)
	sv.controller.AddStateListener(func(st gui.AppState) {
		switch st.Status {
		case gui.JobRunning:
			if st.ActiveJob == gui.JobSingleVet {
				sv.addrEntry.Disable()
				sv.testBtn.Disable()
				sv.cancelBtn.Enable()
			}
		default:
			sv.addrEntry.Enable()
			sv.testBtn.Enable()
			sv.cancelBtn.Disable()
		}
	})
}

func (sv *SingleView) onTestProxy() {
	addr := strings.TrimSpace(sv.addrEntry.Text)
	if addr == "" {
		dialog.ShowError(fmt.Errorf("please enter a proxy address"), sv.window)
		return
	}

	candidate, err := proxycore.ValidateProxyAddress(addr)
	if err != nil {
		dialog.ShowError(err, sv.window)
		return
	}

	sv.stageList.Reset()
	sv.verdictCard.Hide()
	sv.baselineIP.SetText("Host Public IP: Fetching baseline...")

	err = sv.controller.StartJob(gui.JobSingleVet, fmt.Sprintf("Testing single candidate: %s", candidate.Scheme), func(ctx context.Context, emit func(proxycore.Event)) error {
		emit(proxycore.NewLogEvent("info", "[VET] Fetching host machine baseline public IP..."))
		localIP, ipErr := proxycore.FetchLocalPublicIPContext(ctx, proxycore.DefaultSingleTimeout)
		if ipErr != nil {
			emit(proxycore.NewLogEvent("error", fmt.Sprintf("Could not retrieve host public IP: %s", ipErr.Error())))
			fyne.Do(func() {
				sv.baselineIP.SetText(fmt.Sprintf("Host Public IP: Failed (%s)", ipErr.Error()))
				sv.verdictText.Text = "✘ REJECTED: Could not obtain host baseline IP"
				sv.verdictText.Color = color.RGBA{218, 54, 51, 255}
				sv.verdictText.Refresh()
				sv.verdictDesc.SetText(ipErr.Error())
				sv.verdictCard.Show()
			})
			return ipErr
		}

		fyne.Do(func() {
			sv.baselineIP.SetText(fmt.Sprintf("Host Public IP Baseline: %s", localIP))
		})
		emit(proxycore.NewLogEvent("info", fmt.Sprintf("[VET] Host Public IP recorded: %s", localIP)))
		emit(proxycore.NewLogEvent("info", fmt.Sprintf("[VET] Running 5 stages against %s...", candidate.Scheme)))

		res := proxycore.VetSingleProxyContext(ctx, candidate, localIP, proxycore.DefaultSingleTimeout, func(stage int, state proxycore.StageState, reason string) {
			sv.stageList.UpdateStage(stage, state, reason)
		})

		fyne.Do(func() {
			if res.Passed {
				sv.verdictText.Text = "✔ SUCCESS: Passed ALL 5 Verification Stages!"
				sv.verdictText.Color = color.RGBA{46, 160, 67, 255}
				sv.verdictDesc.SetText(fmt.Sprintf("Candidate proxy %s is elite, verified, and safe for production routing.", res.Proxy))
			} else {
				sv.verdictText.Text = "✘ REJECTED: Failed Verification"
				sv.verdictText.Color = color.RGBA{218, 54, 51, 255}
				sv.verdictDesc.SetText(res.FailureReason)
			}
			sv.verdictText.Refresh()
			sv.verdictCard.Show()
		})

		return nil
	})

	if err != nil {
		dialog.ShowError(err, sv.window)
	}
}

// Content returns root object
func (sv *SingleView) Content() fyne.CanvasObject {
	return sv.content
}
