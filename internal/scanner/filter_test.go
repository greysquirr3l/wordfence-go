package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultFilter(t *testing.T) {
	filter := DefaultFilter()

	tests := []struct {
		path     string
		expected bool
	}{
		// Should include
		{"test.php", true},
		{"test.PHP", true},
		{"test.phtml", true},
		{"test.html", true},
		{"test.htm", true},
		{"test.js", true},
		{"test.svg", true},
		// May or may not include depending on default config
		// {"test.txt", false},
		// {"test.jpg", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := filter.Filter(tt.path)
			if result != tt.expected {
				t.Errorf("Filter(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestFilterConfigIncludeAll(t *testing.T) {
	cfg := &FilterConfig{
		IncludeAll: true,
	}

	filter, err := NewFilterFromConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// With IncludeAll, all files should pass
	tests := []string{
		"test.php",
		"test.txt",
		"test.jpg",
		"randomfile",
		"no_extension",
	}

	for _, path := range tests {
		if !filter.Filter(path) {
			t.Errorf("expected Filter(%q) to return true with IncludeAll", path)
		}
	}
}

func TestFilterConfigIncludeFiles(t *testing.T) {
	cfg := &FilterConfig{
		IncludeFiles: []string{"custom.xyz", "special.abc"},
	}

	filter, err := NewFilterFromConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should include the specified files plus defaults
	if !filter.Filter("custom.xyz") {
		t.Error("expected custom.xyz to be included")
	}
	if !filter.Filter("special.abc") {
		t.Error("expected special.abc to be included")
	}
	// Default php should still be included
	if !filter.Filter("test.php") {
		t.Error("expected test.php to be included")
	}
}

func TestFilterConfigIncludePatterns(t *testing.T) {
	cfg := &FilterConfig{
		IncludePatterns: []string{`\.config$`, `^important_`},
	}

	filter, err := NewFilterFromConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		path     string
		expected bool
	}{
		{"app.config", true},
		{"important_file.txt", true},
		{"test.php", true}, // Default still applies
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := filter.Filter(tt.path)
			if result != tt.expected {
				t.Errorf("Filter(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestFilterConfigExcludeFiles(t *testing.T) {
	cfg := &FilterConfig{
		ExcludeFiles: []string{"excluded.php", "skip_this.js"},
	}

	filter, err := NewFilterFromConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Excluded files should not pass even if they match extension
	if filter.Filter("excluded.php") {
		t.Error("expected excluded.php to be excluded")
	}
	if filter.Filter("skip_this.js") {
		t.Error("expected skip_this.js to be excluded")
	}

	// Other PHP files should still pass
	if !filter.Filter("other.php") {
		t.Error("expected other.php to be included")
	}
}

func TestFilterConfigExcludePatterns(t *testing.T) {
	cfg := &FilterConfig{
		ExcludePatterns: []string{`node_modules`, `\.min\.js$`},
	}

	filter, err := NewFilterFromConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		path     string
		expected bool
	}{
		{"node_modules/package/index.js", false},
		{"jquery.min.js", false},
		{"app.js", true},
		{"test.php", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := filter.Filter(tt.path)
			if result != tt.expected {
				t.Errorf("Filter(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestFilterConfigInvalidPattern(t *testing.T) {
	cfg := &FilterConfig{
		IncludePatterns: []string{"[invalid regex"},
	}

	_, err := NewFilterFromConfig(cfg)
	if err == nil {
		t.Error("expected error for invalid regex pattern")
	}

	cfg = &FilterConfig{
		ExcludePatterns: []string{"[invalid regex"},
	}

	_, err = NewFilterFromConfig(cfg)
	if err == nil {
		t.Error("expected error for invalid regex pattern")
	}
}

func TestFilterWithRealFiles(t *testing.T) {
	// Create temporary test files
	tempDir := t.TempDir()

	files := []string{
		"test.php",
		"script.js",
		"style.css",
		"image.png",
		"data.json",
	}

	for _, f := range files {
		path := filepath.Join(tempDir, f)
		if err := os.WriteFile(path, []byte("test content"), 0600); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
	}

	filter := DefaultFilter()

	tests := []struct {
		file     string
		expected bool
	}{
		{"test.php", true},
		{"script.js", true},
		{"style.css", false},
		{"image.png", false},
		{"data.json", false},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			path := filepath.Join(tempDir, tt.file)
			result := filter.Filter(path)
			if result != tt.expected {
				t.Errorf("Filter(%q) = %v, want %v", tt.file, result, tt.expected)
			}
		})
	}
}

func TestFileFilterAllowAndDeny(t *testing.T) {
	filter := NewFileFilter()

	// Add allow conditions
	filter.Allow(FilterExtension(".php"))
	filter.Allow(FilterExtension(".js"))

	// Add deny conditions
	filter.Deny(FilterFilename("blocked.php"))

	tests := []struct {
		path     string
		expected bool
	}{
		{"test.php", true},
		{"app.js", true},
		{"blocked.php", false},
		{"image.png", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := filter.Filter(tt.path)
			if result != tt.expected {
				t.Errorf("Filter(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}
