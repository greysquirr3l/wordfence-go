// Package wordpress provides WordPress identification and remediation
package wordpress

import (
	"fmt"
	"os"
	"path/filepath"
)

// FileType represents the type of WordPress file
type FileType string

const (
	// FileTypeCore represents a WordPress core file
	FileTypeCore FileType = "core"
	// FileTypePlugin represents a WordPress plugin file
	FileTypePlugin FileType = "plugin"
	// FileTypeTheme represents a WordPress theme file
	FileTypeTheme FileType = "theme"
	// FileTypeUnknown represents an unknown file type
	FileTypeUnknown FileType = "unknown"
)

// FileIdentity represents the identity of a WordPress file
type FileIdentity struct {
	Type        FileType
	LocalPath   string // Path relative to the component root
	Site        *Site
	Extension   interface{} // *Plugin or *Theme
	CoreVersion string
}

// IsKnown returns true if the file identity is known
func (fi *FileIdentity) IsKnown() bool {
	return fi.Type != FileTypeUnknown
}

// GetExtensionName returns the name of the extension (plugin or theme)
func (fi *FileIdentity) GetExtensionName() string {
	switch ext := fi.Extension.(type) {
	case *Plugin:
		return ext.Slug
	case *Theme:
		return ext.Slug
	default:
		return ""
	}
}

// GetExtensionVersion returns the version of the extension
func (fi *FileIdentity) GetExtensionVersion() string {
	switch ext := fi.Extension.(type) {
	case *Plugin:
		return ext.Version
	case *Theme:
		return ext.Version
	default:
		return ""
	}
}

// FileIdentifier identifies WordPress files
type FileIdentifier struct {
	knownSites map[string]*Site
}

// NewFileIdentifier creates a new FileIdentifier
func NewFileIdentifier() *FileIdentifier {
	return &FileIdentifier{
		knownSites: make(map[string]*Site),
	}
}

// Identify identifies a file and returns its identity
func (fi *FileIdentifier) Identify(path string) (*FileIdentity, error) {
	// Resolve to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving absolute path: %w", err)
	}

	// Check if file exists
	if _, err := os.Stat(absPath); err != nil {
		return nil, fmt.Errorf("checking file: %w", err)
	}

	// Try to find the WordPress site this file belongs to
	site, localPath, fileType, extension := fi.findSiteForPath(absPath)
	if site == nil {
		return &FileIdentity{Type: FileTypeUnknown}, nil
	}

	return &FileIdentity{
		Type:        fileType,
		LocalPath:   localPath,
		Site:        site,
		Extension:   extension,
		CoreVersion: site.Version,
	}, nil
}

// findSiteForPath finds the WordPress site that contains the given path
func (fi *FileIdentifier) findSiteForPath(absPath string) (*Site, string, FileType, interface{}) {
	// Walk up the directory tree to find a WordPress installation
	dir := filepath.Dir(absPath)
	for {
		// Check if we've already cached this site
		if site, ok := fi.knownSites[dir]; ok {
			return fi.identifyWithinSite(absPath, site)
		}

		// Check if this looks like a WordPress installation
		if isWordPressRoot(dir) {
			site, err := Detect(dir)
			if err == nil && site != nil {
				fi.knownSites[dir] = site
				return fi.identifyWithinSite(absPath, site)
			}
		}

		// Move up one directory
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root
			break
		}
		dir = parent
	}

	return nil, "", FileTypeUnknown, nil
}

// identifyWithinSite identifies a file within a known WordPress site
func (fi *FileIdentifier) identifyWithinSite(absPath string, site *Site) (*Site, string, FileType, interface{}) {
	// Get relative path from site root
	relPath, err := filepath.Rel(site.Path, absPath)
	if err != nil {
		return nil, "", FileTypeUnknown, nil
	}

	// Check if it's in wp-content/plugins
	pluginsDir := filepath.Join(site.Path, "wp-content", "plugins")
	if isUnderDir(absPath, pluginsDir) {
		for _, plugin := range site.Plugins {
			if isUnderDir(absPath, plugin.Path) {
				localPath, _ := filepath.Rel(plugin.Path, absPath)
				return site, localPath, FileTypePlugin, plugin
			}
		}
		// Unknown plugin
		return nil, "", FileTypeUnknown, nil
	}

	// Check if it's in wp-content/themes
	themesDir := filepath.Join(site.Path, "wp-content", "themes")
	if isUnderDir(absPath, themesDir) {
		for _, theme := range site.Themes {
			if isUnderDir(absPath, theme.Path) {
				localPath, _ := filepath.Rel(theme.Path, absPath)
				return site, localPath, FileTypeTheme, theme
			}
		}
		// Unknown theme
		return nil, "", FileTypeUnknown, nil
	}

	// Check if it's a core file (not in wp-content or is wp-content itself)
	wpContentDir := filepath.Join(site.Path, "wp-content")
	if !isUnderDir(absPath, wpContentDir) || absPath == wpContentDir {
		// It's a core file
		return site, relPath, FileTypeCore, nil
	}

	// Unknown file in wp-content (uploads, etc.)
	return nil, "", FileTypeUnknown, nil
}

// isUnderDir checks if path is under or equal to dir
func isUnderDir(path, dir string) bool {
	relPath, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	// Check if it doesn't start with ".."
	return len(relPath) > 0 && relPath[0] != '.'
}

// isWordPressRoot checks if a directory looks like a WordPress root
func isWordPressRoot(dir string) bool {
	// Check for key WordPress files
	markers := []string{
		"wp-config.php",
		"wp-load.php",
		"wp-blog-header.php",
	}

	for _, marker := range markers {
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			return true
		}
	}

	return false
}
