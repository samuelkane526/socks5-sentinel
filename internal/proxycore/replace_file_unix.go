//go:build !windows

package proxycore

import (
	"fmt"
	"os"
)

// replaceFileAtomic replaces destPath with tempPath on Unix using os.Rename.
// destPath is never deleted beforehand, and tempPath is preserved if replacement fails.
func replaceFileAtomic(tempPath, destPath string) error {
	if err := os.Rename(tempPath, destPath); err != nil {
		return fmt.Errorf("rename failed: %w", err)
	}
	return nil
}
