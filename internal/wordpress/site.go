// Package wordpress provides WordPress site detection and parsing
package wordpress

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Expected files and directories for WordPress core
var (
	ExpectedCoreFiles = []string{
		"wp-blog-header.php",
		"wp-load.php",
	}
	ExpectedCoreDirs = []string{
		"wp-admin",
		"wp-includes",
	}
)

// Site represents a WordPress installation
type Site struct {
	Path        string
	CorePath    string
	ContentPath string
	Version     string
	Plugins     []*Plugin
	Themes      []*Theme
}

// SiteOption configures a Site
type SiteOption func(*siteConfig)

type siteConfig struct {
	allowIOErrors bool
}

// WithAllowIOErrors sets whether to continue on IO errors
func WithAllowIOErrors(allow bool) SiteOption {
	return func(c *siteConfig) {
		c.allowIOErrors = allow
	}
}

// Detect detects a WordPress installation at the given path
func Detect(path string) (*Site, error) {
	return DetectWithOptions(path)
}

// DetectWithOptions detects a WordPress installation with options
func DetectWithOptions(path string, opts ...SiteOption) (*Site, error) {
	cfg := &siteConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	// Check if this is a WordPress core directory
	if !isCoreDirectory(path) {
		return nil, fmt.Errorf("not a WordPress installation: %s", path)
	}

	site := &Site{
		Path:     path,
		CorePath: path,
	}

	// Determine content path
	site.ContentPath = filepath.Join(path, "wp-content")
	if _, err := os.Stat(site.ContentPath); os.IsNotExist(err) {
		// Try alternate content paths
		for _, alt := range []string{"../app", "../content"} {
			altPath := filepath.Join(path, alt)
			if _, err := os.Stat(altPath); err == nil {
				site.ContentPath = altPath
				break
			}
		}
	}

	// Get WordPress version
	version, err := parseWordPressVersion(path)
	if err == nil {
		site.Version = version
	}

	// Load plugins
	pluginsDir := filepath.Join(site.ContentPath, "plugins")
	if _, err := os.Stat(pluginsDir); err == nil {
		loader := NewPluginLoader(pluginsDir)
		site.Plugins, _ = loader.LoadAll()
	}

	// Load themes
	themesDir := filepath.Join(site.ContentPath, "themes")
	if _, err := os.Stat(themesDir); err == nil {
		loader := NewThemeLoader(themesDir)
		site.Themes, _ = loader.LoadAll()
	}

	return site, nil
}

// isCoreDirectory checks if the path contains WordPress core files
func isCoreDirectory(path string) bool {
	// Check for expected files
	for _, file := range ExpectedCoreFiles {
		filePath := filepath.Join(path, file)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return false
		}
	}

	// Check for expected directories
	for _, dir := range ExpectedCoreDirs {
		dirPath := filepath.Join(path, dir)
		info, err := os.Stat(dirPath)
		if err != nil || !info.IsDir() {
			return false
		}
	}

	return true
}

// parseWordPressVersion extracts the WordPress version from version.php
func parseWordPressVersion(corePath string) (string, error) {
	versionFile := filepath.Join(corePath, "wp-includes", "version.php")

	file, err := os.Open(versionFile) // #nosec G304 -- versionFile is constructed from corePath
	if err != nil {
		return "", fmt.Errorf("failed to open version.php: %w", err)
	}
	defer func() { _ = file.Close() }()

	// Look for: $wp_version = 'X.Y.Z';
	versionRegex := regexp.MustCompile(`\$wp_version\s*=\s*['"]([^'"]+)['"]`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := versionRegex.FindStringSubmatch(line)
		if len(matches) >= 2 {
			return matches[1], nil
		}
	}

	return "", fmt.Errorf("version not found in version.php")
}

// Locator finds WordPress installations in a directory tree
type Locator struct {
	allowNested   bool
	allowIOErrors bool
}

// LocatorOption configures a Locator
type LocatorOption func(*Locator)

// WithAllowNested allows finding nested WordPress installations
func WithAllowNested(allow bool) LocatorOption {
	return func(l *Locator) {
		l.allowNested = allow
	}
}

// WithLocatorAllowIOErrors sets whether to continue on IO errors
func WithLocatorAllowIOErrors(allow bool) LocatorOption {
	return func(l *Locator) {
		l.allowIOErrors = allow
	}
}

// NewLocator creates a new WordPress locator
func NewLocator(opts ...LocatorOption) *Locator {
	l := &Locator{
		allowNested:   true,
		allowIOErrors: false,
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// Locate finds all WordPress installations under the given path
func (l *Locator) Locate(path string) ([]*Site, error) {
	var sites []*Site
	visited := make(map[string]bool)

	err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if l.allowIOErrors {
				return nil
			}
			return err
		}

		if !d.IsDir() {
			return nil
		}

		// Skip already visited
		absPath, _ := filepath.Abs(p)
		if visited[absPath] {
			return filepath.SkipDir
		}
		visited[absPath] = true

		// Check if this is a WordPress installation
		if isCoreDirectory(p) {
			site, err := DetectWithOptions(p, WithAllowIOErrors(l.allowIOErrors))
			if err == nil {
				sites = append(sites, site)
				if !l.allowNested {
					return filepath.SkipDir
				}
			}
		}

		return nil
	})

	if err != nil {
		return sites, fmt.Errorf("walking directory: %w", err)
	}
	return sites, nil
}

// Extension represents a WordPress extension (plugin or theme)
type Extension struct {
	Slug    string
	Name    string
	Version string
	Path    string
	Header  map[string]string
}

// GetHeader returns a header value
func (e *Extension) GetHeader(key string) string {
	if e.Header == nil {
		return ""
	}
	return e.Header[key]
}

// parseHeader parses WordPress-style file headers
func parseHeader(content string, fields map[string]string) map[string]string {
	result := make(map[string]string)

	for key, headerName := range fields {
		// Look for "Header Name: value" pattern
		pattern := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(headerName) + `\s*:\s*(.+)`)
		matches := pattern.FindStringSubmatch(content)
		if len(matches) >= 2 {
			result[key] = strings.TrimSpace(matches[1])
		}
	}

	return result
}

// readFileHeader reads the first N bytes of a file for header parsing
func readFileHeader(path string, maxBytes int) (string, error) {
	file, err := os.Open(path) // #nosec G304 -- path is derived from directory listing
	if err != nil {
		return "", fmt.Errorf("opening file: %w", err)
	}
	defer func() { _ = file.Close() }()

	buf := make([]byte, maxBytes)
	n, err := file.Read(buf)
	if err != nil {
		return "", fmt.Errorf("reading file: %w", err)
	}

	return string(buf[:n]), nil
}
