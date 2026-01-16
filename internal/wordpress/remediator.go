// Package wordpress provides WordPress remediation functionality
package wordpress

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/greysquirr3l/wordfence-go/internal/logging"
)

// RemediationSource provides correct file content for remediation
type RemediationSource interface {
	// GetCorrectContent retrieves the correct content for a file
	GetCorrectContent(ctx context.Context, identity *FileIdentity) ([]byte, error)
}

// RemediationResult represents the result of remediating a file
type RemediationResult struct {
	Path        string
	Identity    *FileIdentity
	Known       bool
	Remediated  bool
	BackupPath  string
	Error       error
	TargetPath  string
}

// Success returns true if remediation was successful
func (r *RemediationResult) Success() bool {
	return r.Remediated && r.Error == nil
}

// RemediatorConfig configures the Remediator
type RemediatorConfig struct {
	CreateBackup  bool
	BackupDir     string
	DryRun        bool
	FollowSymlinks bool
}

// Remediator remediates infected WordPress files
type Remediator struct {
	source     RemediationSource
	identifier *FileIdentifier
	config     *RemediatorConfig
	logger     *logging.Logger
}

// NewRemediator creates a new Remediator
func NewRemediator(source RemediationSource, config *RemediatorConfig) *Remediator {
	if config == nil {
		config = &RemediatorConfig{
			CreateBackup: true,
		}
	}
	return &Remediator{
		source:     source,
		identifier: NewFileIdentifier(),
		config:     config,
		logger:     logging.New(logging.LevelInfo),
	}
}

// SetLogger sets the logger for the remediator
func (r *Remediator) SetLogger(logger *logging.Logger) {
	r.logger = logger
}

// RemediateFile attempts to remediate a single file
func (r *Remediator) RemediateFile(ctx context.Context, path string) *RemediationResult {
	result := &RemediationResult{
		Path:       path,
		TargetPath: path,
	}

	// Identify the file
	identity, err := r.identifier.Identify(path)
	if err != nil {
		result.Error = fmt.Errorf("failed to identify file: %w", err)
		return result
	}
	result.Identity = identity

	if !identity.IsKnown() {
		r.logger.Warning("Unable to identify %s as a WordPress file", path)
		return result
	}
	result.Known = true

	r.logger.Debug("Identified %s as %s file", path, identity.Type)

	// Get the correct content
	correctContent, err := r.source.GetCorrectContent(ctx, identity)
	if err != nil {
		result.Error = fmt.Errorf("failed to get correct content: %w", err)
		r.logger.Warning("Unable to get correct content for %s: %v", path, err)
		return result
	}

	if correctContent == nil {
		result.Error = fmt.Errorf("no correct content available")
		r.logger.Warning("No correct content available for %s", path)
		return result
	}

	// Dry run - just log what would happen
	if r.config.DryRun {
		r.logger.Info("[DRY RUN] Would remediate %s", path)
		result.Remediated = true
		return result
	}

	// Create backup if configured
	if r.config.CreateBackup {
		backupPath, err := r.createBackup(path)
		if err != nil {
			result.Error = fmt.Errorf("failed to create backup: %w", err)
			r.logger.Error("Failed to create backup for %s: %v", path, err)
			return result
		}
		result.BackupPath = backupPath
		r.logger.Debug("Created backup at %s", backupPath)
	}

	// Write the correct content
	if err := os.WriteFile(path, correctContent, 0600); err != nil { //nolint:gosec // intentional file write for remediation
		result.Error = fmt.Errorf("failed to write file: %w", err)
		r.logger.Error("Failed to write remediated content to %s: %v", path, err)
		return result
	}

	result.Remediated = true
	r.logger.Info("Successfully remediated %s", path)
	return result
}

// createBackup creates a backup of the file
func (r *Remediator) createBackup(path string) (string, error) {
	// Read the original content
	content, err := os.ReadFile(path) //nolint:gosec // path is from internal directory walk
	if err != nil {
		return "", fmt.Errorf("reading original file: %w", err)
	}

	// Determine backup path
	var backupPath string
	if r.config.BackupDir != "" {
		// Create backup in specified directory
		if err := os.MkdirAll(r.config.BackupDir, 0750); err != nil {
			return "", fmt.Errorf("creating backup directory: %w", err)
		}
		timestamp := time.Now().Format("20060102-150405")
		baseName := filepath.Base(path)
		backupPath = filepath.Join(r.config.BackupDir, fmt.Sprintf("%s.%s.bak", baseName, timestamp))
	} else {
		// Create backup in same directory
		timestamp := time.Now().Format("20060102-150405")
		backupPath = fmt.Sprintf("%s.%s.bak", path, timestamp)
	}

	// Write backup
	if err := os.WriteFile(backupPath, content, 0600); err != nil {
		return "", fmt.Errorf("writing backup file: %w", err)
	}

	return backupPath, nil
}

// RemediateDirectory remediates all files in a directory
func (r *Remediator) RemediateDirectory(ctx context.Context, dir string) <-chan *RemediationResult {
	results := make(chan *RemediationResult, 100)

	go func() {
		defer close(results)

		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if err != nil {
				results <- &RemediationResult{
					Path:  path,
					Error: err,
				}
				return nil
			}

			// Skip directories
			if info.IsDir() {
				return nil
			}

			// Skip symlinks unless configured to follow
			if info.Mode()&os.ModeSymlink != 0 && !r.config.FollowSymlinks {
				return nil
			}

			result := r.RemediateFile(ctx, path)
			results <- result
			return nil
		})

		if err != nil && !errors.Is(err, context.Canceled) {
			r.logger.Warning("Error walking directory %s: %v", dir, err)
		}
	}()

	return results
}

// RemediationStats holds remediation statistics
type RemediationStats struct {
	Total        int
	Remediated   int
	Skipped      int
	Failed       int
	Unknown      int
}

// CollectResults collects results and computes statistics
func CollectResults(results <-chan *RemediationResult) ([]*RemediationResult, *RemediationStats) {
	var collected []*RemediationResult
	stats := &RemediationStats{}

	for result := range results {
		collected = append(collected, result)
		stats.Total++

		if result.Error != nil {
			stats.Failed++
		} else if !result.Known {
			stats.Unknown++
		} else if result.Remediated {
			stats.Remediated++
		} else {
			stats.Skipped++
		}
	}

	return collected, stats
}
