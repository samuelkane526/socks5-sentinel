package proxycore

import (
	"fmt"
	"os"
	"path/filepath"
)

// ReplaceFile atomically moves tempPath over destPath without deleting destPath first.
// If the replacement fails, tempPath is preserved for recovery and its path is included in the error.
func ReplaceFile(tempPath, destPath string) error {
	destDir := filepath.Dir(destPath)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed creating target directory %s: %w", destDir, err)
	}

	if err := replaceFileAtomic(tempPath, destPath); err != nil {
		// Retain tempPath for recovery, do not delete it, do not fall back to copying over destPath
		return fmt.Errorf("failed replacing %s with %s (recovery file retained at %s): %w", destPath, tempPath, tempPath, err)
	}
	return nil
}

// ReplaceFileWithBytes writes data to a unique temporary file in the destination directory,
// syncs, closes, and replaces destPath atomically.
// Incomplete temporary files are cleaned up on write/sync failure.
func ReplaceFileWithBytes(destPath string, data []byte, perm os.FileMode) error {
	destDir := filepath.Dir(destPath)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed creating destination directory %s: %w", destDir, err)
	}

	tmpFile, err := os.CreateTemp(destDir, ".tmp-atomic-*")
	if err != nil {
		return fmt.Errorf("failed creating temp file in %s: %w", destDir, err)
	}
	tempPath := tmpFile.Name()

	// Ensure cleanup if we exit before successful replacement
	cleanedUp := false
	defer func() {
		if !cleanedUp {
			_ = os.Remove(tempPath)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed writing data to temp file %s: %w", tempPath, err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed syncing temp file %s: %w", tempPath, err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed closing temp file %s: %w", tempPath, err)
	}

	if perm != 0 {
		_ = os.Chmod(tempPath, perm)
	}

	// From this point, if replacement fails, we want the temp file retained for recovery
	cleanedUp = true
	return ReplaceFile(tempPath, destPath)
}
