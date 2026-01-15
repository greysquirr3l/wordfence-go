// Package scanner provides file filtering for malware scanning
package scanner

import (
	"path/filepath"
	"regexp"
	"strings"
)

// FilterCondition represents a condition in a file filter
type FilterCondition struct {
	Test  func(path string) bool
	Allow bool
}

// FileFilter filters files based on conditions
type FileFilter struct {
	conditions []*FilterCondition
}

// NewFileFilter creates a new FileFilter
func NewFileFilter() *FileFilter {
	return &FileFilter{
		conditions: make([]*FilterCondition, 0),
	}
}

// AddCondition adds a filter condition
func (f *FileFilter) AddCondition(cond *FilterCondition) {
	f.conditions = append(f.conditions, cond)
}

// Add adds a condition with the given test and allow flag
func (f *FileFilter) Add(test func(path string) bool, allow bool) {
	f.AddCondition(&FilterCondition{
		Test:  test,
		Allow: allow,
	})
}

// Allow adds an allow condition
func (f *FileFilter) Allow(test func(path string) bool) {
	f.Add(test, true)
}

// Deny adds a deny condition
func (f *FileFilter) Deny(test func(path string) bool) {
	f.Add(test, false)
}

// Filter returns true if the path should be included (not filtered out)
func (f *FileFilter) Filter(path string) bool {
	allowed := false

	for _, cond := range f.conditions {
		if cond.Allow && allowed {
			continue // Only a single allow condition needs to match
		}

		matched := cond.Test(path)
		if matched {
			if cond.Allow {
				allowed = true
			} else {
				return false // Any disallowed condition takes precedence
			}
		}
	}

	return allowed
}

// Default file extension patterns (case-insensitive)
var (
	PatternPHP    = regexp.MustCompile(`(?i)\.(?:php(?:\d+)?|phtml)(\.|$)`)
	PatternHTML   = regexp.MustCompile(`(?i)\.(?:html?)(\.|$)`)
	PatternJS     = regexp.MustCompile(`(?i)\.(?:js|svg)(\.|$)`)
	PatternImages = regexp.MustCompile(`(?i)\.(?:jpg|jpeg|mp3|avi|m4v|mov|mp4|gif|png|tiff?|svg|sql|js|tbz2?|bz2?|xz|zip|tgz|gz|tar|log|err\d+)(\.|$)`)
)

// FilterPHP returns true if the path matches PHP file extensions
func FilterPHP(path string) bool {
	return PatternPHP.MatchString(path)
}

// FilterHTML returns true if the path matches HTML file extensions
func FilterHTML(path string) bool {
	return PatternHTML.MatchString(path)
}

// FilterJS returns true if the path matches JS/SVG file extensions
func FilterJS(path string) bool {
	return PatternJS.MatchString(path)
}

// FilterImages returns true if the path matches common media/archive extensions
func FilterImages(path string) bool {
	return PatternImages.MatchString(path)
}

// FilterAny always returns true
func FilterAny(path string) bool {
	return true
}

// FilterFilename creates a filter that matches a specific filename
func FilterFilename(filename string) func(string) bool {
	return func(path string) bool {
		return filepath.Base(path) == filename
	}
}

// FilterPattern creates a filter from a regex pattern
func FilterPattern(pattern string) (func(string) bool, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return func(path string) bool {
		return re.MatchString(path)
	}, nil
}

// FilterExtension creates a filter for a specific file extension
func FilterExtension(ext string) func(string) bool {
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	ext = strings.ToLower(ext)
	return func(path string) bool {
		return strings.ToLower(filepath.Ext(path)) == ext
	}
}

// FilterExtensions creates a filter for multiple file extensions
func FilterExtensions(exts ...string) func(string) bool {
	extMap := make(map[string]bool)
	for _, ext := range exts {
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		extMap[strings.ToLower(ext)] = true
	}
	return func(path string) bool {
		return extMap[strings.ToLower(filepath.Ext(path))]
	}
}

// DefaultFilter creates the default file filter for malware scanning
func DefaultFilter() *FileFilter {
	f := NewFileFilter()

	// Allow PHP, HTML, and JS files by default
	f.Allow(FilterPHP)
	f.Allow(FilterHTML)
	f.Allow(FilterJS)

	return f
}

// AllFilesFilter creates a filter that allows all files
func AllFilesFilter() *FileFilter {
	f := NewFileFilter()
	f.Allow(FilterAny)
	return f
}

// CustomFilter creates a filter with custom include/exclude patterns
type FilterConfig struct {
	IncludeFiles    []string // Specific filenames to include
	IncludePatterns []string // Regex patterns to include
	ExcludeFiles    []string // Specific filenames to exclude
	ExcludePatterns []string // Regex patterns to exclude
	IncludeAll      bool     // Include all files
}

// NewFilterFromConfig creates a filter from a configuration
func NewFilterFromConfig(cfg *FilterConfig) (*FileFilter, error) {
	f := NewFileFilter()

	// Start with default includes unless IncludeAll is set
	if cfg.IncludeAll {
		f.Allow(FilterAny)
	} else {
		// Default file types
		f.Allow(FilterPHP)
		f.Allow(FilterHTML)
		f.Allow(FilterJS)

		// Additional include files
		for _, filename := range cfg.IncludeFiles {
			f.Allow(FilterFilename(filename))
		}

		// Additional include patterns
		for _, pattern := range cfg.IncludePatterns {
			fn, err := FilterPattern(pattern)
			if err != nil {
				return nil, err
			}
			f.Allow(fn)
		}
	}

	// Exclude files
	for _, filename := range cfg.ExcludeFiles {
		f.Deny(FilterFilename(filename))
	}

	// Exclude patterns
	for _, pattern := range cfg.ExcludePatterns {
		fn, err := FilterPattern(pattern)
		if err != nil {
			return nil, err
		}
		f.Deny(fn)
	}

	return f, nil
}
