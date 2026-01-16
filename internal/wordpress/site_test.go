package wordpress

import (
	"os"
	"path/filepath"
	"testing"
)

//nolint:gosec // test file using temp directories with standard permissions
func createMockWordPressSite(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	// Create core files
	coreFiles := []string{
		"wp-blog-header.php",
		"wp-load.php",
		"wp-config.php",
	}

	for _, f := range coreFiles {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("<?php // "+f), 0600); err != nil {
			t.Fatalf("failed to create %s: %v", f, err)
		}
	}

	// Create core directories
	coreDirs := []string{
		"wp-admin",
		"wp-includes",
		"wp-content",
		"wp-content/plugins",
		"wp-content/themes",
	}

	for _, d := range coreDirs {
		if err := os.MkdirAll(filepath.Join(dir, d), 0750); err != nil {
			t.Fatalf("failed to create directory %s: %v", d, err)
		}
	}

	// Create version.php
	versionContent := `<?php
$wp_version = '6.4.2';
$wp_db_version = 56657;
$tinymce_version = '49110-20201110';
$required_php_version = '7.0.0';
$required_mysql_version = '5.0';
`
	versionDir := filepath.Join(dir, "wp-includes")
	if err := os.WriteFile(filepath.Join(versionDir, "version.php"), []byte(versionContent), 0600); err != nil {
		t.Fatalf("failed to create version.php: %v", err)
	}

	// Create a sample plugin
	pluginDir := filepath.Join(dir, "wp-content", "plugins", "hello-dolly")
	if err := os.MkdirAll(pluginDir, 0750); err != nil {
		t.Fatalf("failed to create plugin directory: %v", err)
	}

	pluginContent := `<?php
/**
 * Plugin Name: Hello Dolly
 * Version: 1.7.2
 * Author: Matt Mullenweg
 */
echo "Hello, Dolly!";
`
	if err := os.WriteFile(filepath.Join(pluginDir, "hello.php"), []byte(pluginContent), 0600); err != nil {
		t.Fatalf("failed to create plugin file: %v", err)
	}

	// Create a sample theme
	themeDir := filepath.Join(dir, "wp-content", "themes", "twentytwentyfour")
	if err := os.MkdirAll(themeDir, 0750); err != nil {
		t.Fatalf("failed to create theme directory: %v", err)
	}

	themeContent := `/*
Theme Name: Twenty Twenty-Four
Version: 1.0
Author: WordPress.org
*/
`
	if err := os.WriteFile(filepath.Join(themeDir, "style.css"), []byte(themeContent), 0600); err != nil {
		t.Fatalf("failed to create theme file: %v", err)
	}

	return dir
}

func TestDetectWordPress(t *testing.T) {
	wpDir := createMockWordPressSite(t)

	site, err := Detect(wpDir)
	if err != nil {
		t.Fatalf("failed to detect WordPress: %v", err)
	}

	if site == nil {
		t.Fatal("expected site to be detected")
	}

	// Check path
	if site.Path != wpDir {
		t.Errorf("expected path %s, got %s", wpDir, site.Path)
	}

	// Check version
	if site.Version != "6.4.2" {
		t.Errorf("expected version 6.4.2, got %s", site.Version)
	}

	// Check plugins were loaded
	if len(site.Plugins) == 0 {
		t.Error("expected at least one plugin")
	}

	// Check themes were loaded
	if len(site.Themes) == 0 {
		t.Error("expected at least one theme")
	}
}

func TestDetectWordPressNotFound(t *testing.T) {
	dir := t.TempDir()

	_, err := Detect(dir)
	if err == nil {
		t.Error("expected error for non-WordPress directory")
	}
}

func TestLocator(t *testing.T) {
	wpDir := createMockWordPressSite(t)

	locator := NewLocator()
	sites, err := locator.Locate(wpDir)
	if err != nil {
		t.Fatalf("failed to locate WordPress: %v", err)
	}

	if len(sites) != 1 {
		t.Errorf("expected 1 site, got %d", len(sites))
	}
}

//nolint:gosec // test file using temp directories
func TestLocatorNestedSites(t *testing.T) {
	// Create parent directory
	parentDir := t.TempDir()

	// Create two nested WordPress sites
	site1 := filepath.Join(parentDir, "site1")
	site2 := filepath.Join(parentDir, "site2")

	for _, dir := range []string{site1, site2} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			t.Fatalf("failed to create directory: %v", err)
		}

		// Create minimal WordPress structure
		coreFiles := []string{"wp-blog-header.php", "wp-load.php"}
		for _, f := range coreFiles {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("<?php"), 0600); err != nil {
				t.Fatalf("failed to create file: %v", err)
			}
		}

		coreDirs := []string{"wp-admin", "wp-includes"}
		for _, d := range coreDirs {
			if err := os.MkdirAll(filepath.Join(dir, d), 0750); err != nil {
				t.Fatalf("failed to create directory: %v", err)
			}
		}
	}

	locator := NewLocator(WithAllowNested(true))
	sites, err := locator.Locate(parentDir)
	if err != nil {
		t.Fatalf("failed to locate WordPress: %v", err)
	}

	if len(sites) != 2 {
		t.Errorf("expected 2 sites, got %d", len(sites))
	}
}

func TestPluginLoader(t *testing.T) {
	wpDir := createMockWordPressSite(t)
	pluginsDir := filepath.Join(wpDir, "wp-content", "plugins")

	loader := NewPluginLoader(pluginsDir)
	plugins, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("failed to load plugins: %v", err)
	}

	if len(plugins) == 0 {
		t.Fatal("expected at least one plugin")
	}

	// Find hello-dolly plugin
	var helloDolly *Plugin
	for _, p := range plugins {
		if p.Slug == "hello-dolly" {
			helloDolly = p
			break
		}
	}

	if helloDolly == nil {
		t.Fatal("expected to find hello-dolly plugin")
	}

	if helloDolly.Name != "Hello Dolly" {
		t.Errorf("expected plugin name 'Hello Dolly', got '%s'", helloDolly.Name)
	}

	if helloDolly.Version != "1.7.2" {
		t.Errorf("expected version '1.7.2', got '%s'", helloDolly.Version)
	}
}

func TestThemeLoader(t *testing.T) {
	wpDir := createMockWordPressSite(t)
	themesDir := filepath.Join(wpDir, "wp-content", "themes")

	loader := NewThemeLoader(themesDir)
	themes, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("failed to load themes: %v", err)
	}

	if len(themes) == 0 {
		t.Fatal("expected at least one theme")
	}

	// Find twentytwentyfour theme
	var theme2024 *Theme
	for _, th := range themes {
		if th.Slug == "twentytwentyfour" {
			theme2024 = th
			break
		}
	}

	if theme2024 == nil {
		t.Fatal("expected to find twentytwentyfour theme")
	}

	if theme2024.Name != "Twenty Twenty-Four" {
		t.Errorf("expected theme name 'Twenty Twenty-Four', got '%s'", theme2024.Name)
	}

	if theme2024.Version != "1.0" {
		t.Errorf("expected version '1.0', got '%s'", theme2024.Version)
	}
}

func TestIsCoreDirectory(t *testing.T) {
	wpDir := createMockWordPressSite(t)

	if !isCoreDirectory(wpDir) {
		t.Error("expected WordPress directory to be recognized as core directory")
	}

	nonWpDir := t.TempDir()
	if isCoreDirectory(nonWpDir) {
		t.Error("expected non-WordPress directory to not be recognized as core directory")
	}
}

func TestParseWordPressVersion(t *testing.T) {
	wpDir := createMockWordPressSite(t)

	version, err := parseWordPressVersion(wpDir)
	if err != nil {
		t.Fatalf("failed to parse version: %v", err)
	}

	if version != "6.4.2" {
		t.Errorf("expected version 6.4.2, got %s", version)
	}
}

func TestParseWordPressVersionNotFound(t *testing.T) {
	dir := t.TempDir()

	_, err := parseWordPressVersion(dir)
	if err == nil {
		t.Error("expected error when version.php doesn't exist")
	}
}
