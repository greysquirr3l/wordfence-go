// Package config provides configuration management for the CLI.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Config holds the global configuration.
type Config struct {
	// License is the Wordfence CLI license key.
	License string `mapstructure:"license"`

	// CacheDirectory is the path to the cache directory.
	CacheDirectory string `mapstructure:"cache_directory"`

	// CacheEnabled enables or disables caching.
	CacheEnabled bool `mapstructure:"cache"`

	// Debug enables debug output.
	Debug bool `mapstructure:"debug"`

	// Verbose enables verbose output.
	Verbose bool `mapstructure:"verbose"`

	// Quiet suppresses non-error output.
	Quiet bool `mapstructure:"quiet"`

	// NoColor disables colored output.
	NoColor bool `mapstructure:"no_color"`

	// ConfigFile is the path to the configuration file (set at runtime).
	ConfigFile string `mapstructure:"-"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	cacheDir := filepath.Join(homeDir, ".cache", "wordfence")

	return &Config{
		CacheDirectory: cacheDir,
		CacheEnabled:   true,
		Debug:          false,
		Verbose:        false,
		Quiet:          false,
		NoColor:        false,
	}
}

// DefaultConfigPath returns the default configuration file path.
func DefaultConfigPath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".config", "wordfence", "wordfence-cli.ini")
}

// Load loads configuration from all sources in priority order:
// 1. Command-line flags (handled by cobra)
// 2. Environment variables (WORDFENCE_CLI_*)
// 3. Config file
// 4. Defaults
func Load(configFile string) (*Config, error) {
	v := viper.New()

	// Set defaults
	defaults := DefaultConfig()
	v.SetDefault("license", defaults.License)
	v.SetDefault("cache_directory", defaults.CacheDirectory)
	v.SetDefault("cache", defaults.CacheEnabled)
	v.SetDefault("debug", defaults.Debug)
	v.SetDefault("verbose", defaults.Verbose)
	v.SetDefault("quiet", defaults.Quiet)
	v.SetDefault("no_color", defaults.NoColor)

	// Environment variables
	v.SetEnvPrefix("WORDFENCE_CLI")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.AutomaticEnv()

	// Check NO_COLOR environment variable (standard)
	if os.Getenv("NO_COLOR") != "" {
		v.Set("no_color", true)
	}

	// Config file
	if configFile != "" {
		v.SetConfigFile(configFile)
	} else {
		// Try default locations
		homeDir, _ := os.UserHomeDir()
		v.AddConfigPath(filepath.Join(homeDir, ".config", "wordfence"))
		v.AddConfigPath(".")
		v.SetConfigName("wordfence-cli")
		v.SetConfigType("ini")
	}

	// Read config file (ignore if not found)
	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			// Only return error if it's not a "file not found" error
			if configFile != "" {
				return nil, fmt.Errorf("reading config: %w", err)
			}
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	cfg.ConfigFile = v.ConfigFileUsed()

	return &cfg, nil
}

// ExpandPath expands ~ in paths to the user's home directory.
func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		homeDir, _ := os.UserHomeDir()
		return filepath.Join(homeDir, path[2:])
	}
	return path
}
