// Package wordpress provides theme detection and parsing
package wordpress

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ThemeHeaderFields defines the WordPress theme header field mappings (parsed from style.css)
var ThemeHeaderFields = map[string]string{
	"Name":        "Theme Name",
	"ThemeURI":    "Theme URI",
	"Version":     "Version",
	"Description": "Description",
	"Author":      "Author",
	"AuthorURI":   "Author URI",
	"Template":    "Template",
	"TextDomain":  "Text Domain",
	"DomainPath":  "Domain Path",
	"RequiresWP":  "Requires at least",
	"RequiresPHP": "Requires PHP",
}

// Theme represents a WordPress theme
type Theme struct {
	Extension
	Template string // Parent theme slug (for child themes)
}

// IsChildTheme returns true if this is a child theme
func (t *Theme) IsChildTheme() bool {
	return t.Template != ""
}

// ThemeLoader loads themes from a directory
type ThemeLoader struct {
	directory string
}

// NewThemeLoader creates a new theme loader
func NewThemeLoader(directory string) *ThemeLoader {
	return &ThemeLoader{
		directory: directory,
	}
}

// LoadAll loads all themes from the themes directory
func (l *ThemeLoader) LoadAll() ([]*Theme, error) {
	var themes []*Theme

	entries, err := os.ReadDir(l.directory)
	if err != nil {
		return nil, fmt.Errorf("reading themes directory: %w", err)
	}

	for _, entry := range entries {
		// Skip hidden files and non-directories
		if strings.HasPrefix(entry.Name(), ".") || !entry.IsDir() {
			continue
		}

		theme := l.loadFromDirectory(entry.Name(), filepath.Join(l.directory, entry.Name()))
		if theme != nil {
			themes = append(themes, theme)
		}
	}

	return themes, nil
}

// loadFromDirectory loads a theme from a directory
func (l *ThemeLoader) loadFromDirectory(slug string, dirPath string) *Theme {
	// Themes must have a style.css file
	stylePath := filepath.Join(dirPath, "style.css")
	if _, err := os.Stat(stylePath); os.IsNotExist(err) {
		return nil
	}

	content, err := readFileHeader(stylePath, 8192)
	if err != nil {
		return nil
	}

	header := parseHeader(content, ThemeHeaderFields)

	// Must have a theme name to be valid
	name := header["Name"]
	if name == "" {
		return nil
	}

	version := header["Version"]
	template := header["Template"]

	return &Theme{
		Extension: Extension{
			Slug:    slug,
			Name:    name,
			Version: version,
			Path:    dirPath,
			Header:  header,
		},
		Template: template,
	}
}
