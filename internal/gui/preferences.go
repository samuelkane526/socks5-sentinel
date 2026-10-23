package gui

import (
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
	"github.com/samuelkane526/socks5-sentinel/internal/proxycore"
)

const (
	PrefKeyWorkingFolder = "working_folder"
	PrefKeyTheme         = "app_theme"
	PrefKeyConcurrency   = "default_concurrency"
	PrefKeyRetries       = "default_retries"
	PrefKeyTimeoutMs     = "default_timeout_ms"
)

// AppPreferences manages user settings and persistence
type AppPreferences struct {
	app fyne.App
}

// NewAppPreferences initializes preferences wrapper
func NewAppPreferences(a fyne.App) *AppPreferences {
	return &AppPreferences{app: a}
}

// GetWorkingFolder returns custom working folder or current directory
func (p *AppPreferences) GetWorkingFolder() string {
	folder := p.app.Preferences().StringWithFallback(PrefKeyWorkingFolder, "")
	if folder != "" {
		if info, err := os.Stat(folder); err == nil && info.IsDir() {
			return folder
		}
	}
	cwd, err := os.Getwd()
	if err == nil {
		// Build output lives one level below the application's working root.
		if strings.EqualFold(filepath.Base(cwd), "output") {
			return filepath.Dir(cwd)
		}
		return cwd
	}
	return ""
}

// SetWorkingFolder saves custom working folder
func (p *AppPreferences) SetWorkingFolder(folder string) {
	p.app.Preferences().SetString(PrefKeyWorkingFolder, folder)
}

// GetTheme returns "system", "light", or "dark"
func (p *AppPreferences) GetTheme() string {
	return p.app.Preferences().StringWithFallback(PrefKeyTheme, "system")
}

// SetTheme saves and applies theme
func (p *AppPreferences) SetTheme(themeName string) {
	p.app.Preferences().SetString(PrefKeyTheme, themeName)
	p.ApplyTheme(themeName)
}

// ApplyTheme configures Fyne runtime theme
func (p *AppPreferences) ApplyTheme(themeName string) {
	switch themeName {
	case "light":
		p.app.Settings().SetTheme(theme.LightTheme())
	case "dark":
		p.app.Settings().SetTheme(theme.DarkTheme())
	default:
		// Default / system follows OS
		p.app.Settings().SetTheme(theme.DefaultTheme())
	}
}

// GetDefaultConcurrency returns persisted or standard concurrency
func (p *AppPreferences) GetDefaultConcurrency() int {
	return p.app.Preferences().IntWithFallback(PrefKeyConcurrency, proxycore.DefaultConcurrency)
}

// GetDefaultRetries returns persisted or standard retries
func (p *AppPreferences) GetDefaultRetries() int {
	return p.app.Preferences().IntWithFallback(PrefKeyRetries, proxycore.DefaultRetries)
}

// GetDefaultTimeoutMs returns persisted or standard timeout in ms
func (p *AppPreferences) GetDefaultTimeoutMs() int {
	return p.app.Preferences().IntWithFallback(PrefKeyTimeoutMs, 10000)
}

// ResetToDefaults clears preferences back to initial values
func (p *AppPreferences) SaveNumericDefaults(workers, retries, timeoutMs int) {
	p.app.Preferences().SetInt(PrefKeyConcurrency, workers)
	p.app.Preferences().SetInt(PrefKeyRetries, retries)
	p.app.Preferences().SetInt(PrefKeyTimeoutMs, timeoutMs)
}

// ResetToDefaults clears preferences back to initial values
func (p *AppPreferences) ResetToDefaults() {
	p.app.Preferences().RemoveValue(PrefKeyWorkingFolder)
	p.app.Preferences().RemoveValue(PrefKeyTheme)
	p.app.Preferences().RemoveValue(PrefKeyConcurrency)
	p.app.Preferences().RemoveValue(PrefKeyRetries)
	p.app.Preferences().RemoveValue(PrefKeyTimeoutMs)
	p.ApplyTheme("system")
}
