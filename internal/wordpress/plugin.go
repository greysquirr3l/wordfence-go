// Package wordpress provides plugin detection and parsing
package wordpress

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PluginHeaderFields defines the WordPress plugin header field mappings
var PluginHeaderFields = map[string]string{
	"Name":        "Plugin Name",
	"PluginURI":   "Plugin URI",
	"Version":     "Version",
	"Description": "Description",
	"Author":      "Author",
	"AuthorURI":   "Author URI",
	"TextDomain":  "Text Domain",
	"DomainPath":  "Domain Path",
	"Network":     "Network",
	"RequiresWP":  "Requires at least",
	"RequiresPHP": "Requires PHP",
}

// Plugin represents a WordPress plugin
type Plugin struct {
	Extension
}

// PluginLoader loads plugins from a directory
type PluginLoader struct {
	directory string
}

// NewPluginLoader creates a new plugin loader
func NewPluginLoader(directory string) *PluginLoader {
	return &PluginLoader{
		directory: directory,
	}
}

// LoadAll loads all plugins from the plugins directory
func (l *PluginLoader) LoadAll() ([]*Plugin, error) {
	var plugins []*Plugin

	entries, err := os.ReadDir(l.directory)
	if err != nil {
		return nil, fmt.Errorf("reading plugins directory: %w", err)
	}

	for _, entry := range entries {
		// Skip hidden files
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		plugin := l.processEntry(entry)
		if plugin != nil {
			plugins = append(plugins, plugin)
		}
	}

	return plugins, nil
}

// processEntry processes a directory entry and returns a plugin if found
func (l *PluginLoader) processEntry(entry os.DirEntry) *Plugin {
	entryPath := filepath.Join(l.directory, entry.Name())

	if entry.IsDir() {
		// Look for PHP files in the plugin directory
		return l.loadFromDirectory(entry.Name(), entryPath)
	}

	// Single-file plugin
	if strings.HasSuffix(strings.ToLower(entry.Name()), ".php") {
		return l.loadFromFile(strings.TrimSuffix(entry.Name(), ".php"), entryPath)
	}

	return nil
}

// loadFromDirectory loads a plugin from a directory
func (l *PluginLoader) loadFromDirectory(slug string, dirPath string) *Plugin {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil
	}

	// Look for main plugin file (usually slug.php or any PHP with plugin header)
	mainFile := filepath.Join(dirPath, slug+".php")
	if _, err := os.Stat(mainFile); err == nil {
		plugin := l.loadFromFile(slug, mainFile)
		if plugin != nil {
			plugin.Path = dirPath
			return plugin
		}
	}

	// Try other PHP files
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(entry.Name()), ".php") {
			filePath := filepath.Join(dirPath, entry.Name())
			plugin := l.loadFromFile(slug, filePath)
			if plugin != nil {
				plugin.Path = dirPath
				return plugin
			}
		}
	}

	return nil
}

// loadFromFile loads a plugin from a PHP file
func (l *PluginLoader) loadFromFile(slug string, filePath string) *Plugin {
	content, err := readFileHeader(filePath, 8192)
	if err != nil {
		return nil
	}

	header := parseHeader(content, PluginHeaderFields)

	// Must have a plugin name to be valid
	name := header["Name"]
	if name == "" {
		return nil
	}

	version := header["Version"]

	return &Plugin{
		Extension: Extension{
			Slug:    slug,
			Name:    name,
			Version: version,
			Path:    filePath,
			Header:  header,
		},
	}
}
