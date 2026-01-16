// Package config provides configuration management for the CLI.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-viper/encoding/ini"
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
	// Create codec registry and register INI support
	codecRegistry := viper.NewCodecRegistry()
	if err := codecRegistry.RegisterCodec("ini", ini.Codec{}); err != nil {
		return nil, fmt.Errorf("registering INI codec: %w", err)
	}

	v := viper.NewWithOptions(
		viper.WithCodecRegistry(codecRegistry),
	)

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

	// Debug: print config file info (without sensitive values)
	if os.Getenv("WORDFENCE_DEBUG_CONFIG") != "" {
		fmt.Fprintf(os.Stderr, "[DEBUG] Config file used: %s\n", v.ConfigFileUsed())
		fmt.Fprintf(os.Stderr, "[DEBUG] All keys: %v\n", v.AllKeys())
		// Don't print license values for security
		settings := v.AllSettings()
		if _, exists := settings["license"]; exists {
			settings["license"] = "[REDACTED]"
		}
		if _, exists := settings["DEFAULT.license"]; exists {
			settings["DEFAULT.license"] = "[REDACTED]"
		}
		fmt.Fprintf(os.Stderr, "[DEBUG] All settings: %v\n", settings)

		hasLicense := v.GetString("license") != ""
		fmt.Fprintf(os.Stderr, "[DEBUG] license configured: %v\n", hasLicense)
	}

	// Handle INI section prefixes - Viper reads [DEFAULT] section as "DEFAULT.key"
	// Check for DEFAULT.license if license is not set directly
	if v.GetString("license") == "" && v.GetString("DEFAULT.license") != "" {
		v.Set("license", v.GetString("DEFAULT.license"))
		if os.Getenv("WORDFENCE_DEBUG_CONFIG") != "" {
			fmt.Fprintf(os.Stderr, "[DEBUG] Set license from DEFAULT section\n")
		}
	}

	// Fallback: manually parse INI file if Viper failed to read license
	if v.GetString("license") == "" && v.ConfigFileUsed() != "" {
		if manualLicense, err := parseINILicense(v.ConfigFileUsed()); err == nil && manualLicense != "" {
			v.Set("license", manualLicense)
			if os.Getenv("WORDFENCE_DEBUG_CONFIG") != "" {
				fmt.Fprintf(os.Stderr, "[DEBUG] Set license from manual INI parsing\n")
			}
		}
	}
	if v.GetString("cache_directory") == "" && v.GetString("DEFAULT.cache_directory") != "" {
		v.Set("cache_directory", v.GetString("DEFAULT.cache_directory"))
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

// parseINILicense manually parses an INI file to extract the license value.
// This is a fallback when Viper fails to parse the INI properly.
func parseINILicense(configFile string) (string, error) {
	file, err := os.Open(configFile) //nolint:gosec // configFile is from trusted Viper config path
	if err != nil {
		return "", fmt.Errorf("opening config file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			// Log error but don't fail parsing
			fmt.Fprintf(os.Stderr, "Warning: failed to close config file: %v\n", closeErr)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Skip section headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			continue
		}

		// Look for license = value
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				// Remove quotes if present
				if (strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`)) ||
					(strings.HasPrefix(value, `'`) && strings.HasSuffix(value, `'`)) {
					value = value[1 : len(value)-1]
				}

				if key == "license" && value != "" {
					return value, nil
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scanning config file: %w", err)
	}
	return "", nil
}
