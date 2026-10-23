package views

import (
	"fmt"
	"strconv"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/samuelkane526/socks5-sentinel/internal/gui"
	"github.com/samuelkane526/socks5-sentinel/internal/gui/components"
)

// SettingsView provides configuration settings and application documentation
type SettingsView struct {
	controller *gui.Controller
	window     fyne.Window
	content    *fyne.Container

	folderPicker *components.PathPicker
	themeSelect  *widget.Select
	concEntry    *widget.Entry
	retryEntry   *widget.Entry
	timeoutEntry *widget.Entry

	OnWorkingFolderChanged func(string)
}

// NewSettingsView initializes SettingsView
func NewSettingsView(ctrl *gui.Controller, win fyne.Window) *SettingsView {
	sv := &SettingsView{
		controller: ctrl,
		window:     win,
	}

	sv.buildUI()
	return sv
}

func (sv *SettingsView) buildUI() {
	prefs := sv.controller.Preferences()

	// Working Folder
	sv.folderPicker = components.NewPathPicker(sv.window, components.PickerModeOpenFolder, "Select working folder", func(path string) {
		if path != "" {
			prefs.SetWorkingFolder(path)
			if sv.OnWorkingFolderChanged != nil {
				sv.OnWorkingFolderChanged(path)
			}
		}
	})
	sv.folderPicker.SetPath(prefs.GetWorkingFolder())

	// Theme
	sv.themeSelect = widget.NewSelect([]string{"System (OS Default)", "Light", "Dark"}, func(selected string) {
		switch selected {
		case "Light":
			prefs.SetTheme("light")
		case "Dark":
			prefs.SetTheme("dark")
		default:
			prefs.SetTheme("system")
		}
	})

	currentTheme := prefs.GetTheme()
	switch currentTheme {
	case "light":
		sv.themeSelect.SetSelected("Light")
	case "dark":
		sv.themeSelect.SetSelected("Dark")
	default:
		sv.themeSelect.SetSelected("System (OS Default)")
	}

	// Default numbers
	sv.concEntry = widget.NewEntry()
	sv.concEntry.SetText(strconv.Itoa(prefs.GetDefaultConcurrency()))

	sv.retryEntry = widget.NewEntry()
	sv.retryEntry.SetText(strconv.Itoa(prefs.GetDefaultRetries()))

	sv.timeoutEntry = widget.NewEntry()
	sv.timeoutEntry.SetText(strconv.Itoa(prefs.GetDefaultTimeoutMs()))

	saveDefaultsBtn := widget.NewButtonWithIcon("Save Numeric Defaults", theme.DocumentSaveIcon(), func() {
		conc, err1 := strconv.Atoi(sv.concEntry.Text)
		retries, err2 := strconv.Atoi(sv.retryEntry.Text)
		timeout, err3 := strconv.Atoi(sv.timeoutEntry.Text)
		if err1 != nil || conc < 1 || err2 != nil || retries < 1 || err3 != nil || timeout <= 0 {
			dialog.ShowError(fmt.Errorf("please provide valid numeric values (concurrency >= 1, retries >= 1, timeout > 0)"), sv.window)
			return
		}
		prefs.SaveNumericDefaults(conc, retries, timeout)
		dialog.ShowInformation("Saved", "Numeric defaults updated. Restart to load them into existing screens.", sv.window)
	})

	resetBtn := widget.NewButtonWithIcon("Reset Preferences to Defaults", theme.DeleteIcon(), func() {
		dialog.ShowConfirm("Reset Preferences", "Are you sure you want to restore default application settings?", func(confirm bool) {
			if confirm {
				prefs.ResetToDefaults()
				sv.folderPicker.SetPath(prefs.GetWorkingFolder())
				sv.themeSelect.SetSelected("System (OS Default)")
				sv.concEntry.SetText(strconv.Itoa(prefs.GetDefaultConcurrency()))
				sv.retryEntry.SetText(strconv.Itoa(prefs.GetDefaultRetries()))
				sv.timeoutEntry.SetText(strconv.Itoa(prefs.GetDefaultTimeoutMs()))
				if sv.OnWorkingFolderChanged != nil {
					sv.OnWorkingFolderChanged(prefs.GetWorkingFolder())
				}
				dialog.ShowInformation("Reset", "Application preferences restored to defaults.", sv.window)
			}
		}, sv.window)
	})

	generalHeader := components.NewSectionHeader("General Settings", "Environment and appearance settings take effect immediately.", sv.window)
	generalCard := widget.NewCard("", "", container.NewVBox(
		generalHeader,
		widget.NewLabelWithStyle("Working Directory (Relative paths resolve against this folder; saved immediately):", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		sv.folderPicker,
		widget.NewLabelWithStyle("User Interface Theme (Applies immediately):", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		sv.themeSelect,
	))

	// Documentation & Help text
	helpText := `Socks5 Vetter — Anonymous SOCKS5 Client & 5-Stage Vetting Pipeline
====================================================================

CLI Flags to Consolidated GUI Workspaces:
-----------------------------------------
• --vet                -> Vetting workspace ("Start Vetting")
• --vet-single <IP:P>  -> Vetting workspace -> Tools -> Single Proxy ("Test Candidate Proxy")
• --update             -> Vetting workspace -> Tools -> Sources ("Check & Update")
• --target <n>         -> Vetting "Target (0 = unlimited)"
• --concurrency <n>    -> Vetting Advanced "Workers (concurrency)"
• --limit <n>          -> Vetting Advanced "Candidate Limit (0 = all)"
• --output <file>      -> Vetting Advanced "Primary Output JSON"
• --export <path>      -> Vetting Advanced "Additional Export Path"
• --file <path>        -> Proxy Source in Vetting & Requests
• --force-update       -> Vetting Tools -> Sources "Force Download"
• --no-update          -> Vetting Advanced Update Policy "Use local data only"
• --url <URL>          -> Requests workspace ("Send Request")
• --test               -> Requests workspace -> Pool Health Check ("Run 3 requests")
• --retries <n>        -> Requests Advanced "Retries after first attempt"
• --timeout <ms>       -> Timeout entry (in milliseconds)
• --strict-tls         -> TLS Policy "Verify certificates" (Strict anti-MITM)
• --allow-insecure     -> TLS Policy "Allow invalid certificates"
• --verbose, -v        -> Detailed logs toggle (view real-time in Console)

5-Stage Vetting Protocol Architecture:
--------------------------------------
1. Stage 1: Baseline Setup & SOCKS Handshake
   Records host machine public IPv4 and performs RFC 1928 handshake with ATYP 0x03.
2. Stage 3: Strict TLS/SSL Anti-MITM Verification
   Validates standard trusted root certificates against https://httpbin.org/get.
3. Stage 2: IP Masking & Header Leak Verification
   Asserts echoed public origin differs from host IP and strips tracing headers (X-Forwarded-For, Via).
4. Stage 4: Anti-Rerouting & Plaintext DNS Poisoning Check
   Verifies status 200, Content-Type application/json, and schema integrity on plain HTTP.
5. Stage 5: Session Cookie & Header Integrity Verification
   Generates a cryptographically random session cookie and validates exact echo without injected tracking cookies.
`
	helpBox := widget.NewMultiLineEntry()
	helpBox.SetText(helpText)
	helpBox.Disable()
	helpBox.Wrapping = fyne.TextWrapWord
	helpBox.TextStyle = fyne.TextStyle{Monospace: true}

	defaultsForm := container.NewVBox(
		widget.NewLabel("These defaults are applied when initializing screens or on application restart:"),
		container.NewGridWithColumns(3,
			container.NewVBox(widget.NewLabelWithStyle("Default Workers:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), sv.concEntry),
			container.NewVBox(widget.NewLabelWithStyle("Default Retries:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), sv.retryEntry),
			container.NewVBox(widget.NewLabelWithStyle("Default Timeout (ms):", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), sv.timeoutEntry),
		),
		saveDefaultsBtn,
	)

	maintenanceBox := container.NewVBox(
		widget.NewLabel("Restore all application settings, theme, and numeric defaults back to factory defaults:"),
		resetBtn,
	)

	settingsAccordion := widget.NewAccordion(
		widget.NewAccordionItem("Advanced Defaults (Workers, Retries, Timeout)", defaultsForm),
		widget.NewAccordionItem("Preferences Maintenance", maintenanceBox),
		widget.NewAccordionItem("Documentation & Flag Reference", container.NewVBox(
			container.NewGridWrap(fyne.NewSize(600, 320), helpBox),
		)),
	)

	sv.content = container.NewVBox(generalCard, widget.NewSeparator(), settingsAccordion)
	components.AddHelp(sv.content, sv.window)
}

// Content returns root wrapped in a scroll container
func (sv *SettingsView) Content() fyne.CanvasObject {
	return container.NewScroll(sv.content)
}
