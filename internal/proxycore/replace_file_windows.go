//go:build windows

package proxycore

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// replaceFileAtomic replaces destPath with tempPath atomically on Windows.
// It uses MoveFileEx with MOVEFILE_REPLACE_EXISTING and MOVEFILE_WRITE_THROUGH.
// destPath is never deleted beforehand, and tempPath is preserved if replacement fails.
func replaceFileAtomic(tempPath, destPath string) error {
	fromPtr, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return fmt.Errorf("invalid temp path: %w", err)
	}
	toPtr, err := windows.UTF16PtrFromString(destPath)
	if err != nil {
		return fmt.Errorf("invalid dest path: %w", err)
	}

	flags := uint32(windows.MOVEFILE_REPLACE_EXISTING | windows.MOVEFILE_WRITE_THROUGH)
	if err := windows.MoveFileEx(fromPtr, toPtr, flags); err != nil {
		return fmt.Errorf("MoveFileEx failed: %w", err)
	}
	return nil
}
