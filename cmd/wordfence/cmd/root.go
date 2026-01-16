// Package cmd contains the CLI commands.
package cmd

import (
	"fmt"
	"os"

	"github.com/greysquirr3l/wordfence-go/internal/config"
	"github.com/greysquirr3l/wordfence-go/internal/logging"
	"github.com/spf13/cobra"
)

var (
	cfgFile      string
	cfg          *config.Config
	debugFlag    bool
	verboseFlag  bool
	quietFlag    bool
	noColorFlag  bool
	licenseFlag  string
	cacheDirFlag string
	noCacheFlag  bool
)

// rootCmd represents the base command.
var rootCmd = &cobra.Command{
	Use:   "wordfence",
	Short: "Wordfence CLI - Security scanner for WordPress",
	Long: `Wordfence CLI is a high performance security scanner that detects
PHP/other malware and WordPress vulnerabilities.

It can scan filesystems for malware signatures and check WordPress
installations for known vulnerabilities in core, plugins, and themes.`,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		// Skip config loading for version and help commands
		if cmd.Name() == "version" || cmd.Name() == "help" {
			return nil
		}

		// Load configuration
		var err error
		cfg, err = config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Override with command-line flags
		if cmd.Flags().Changed("debug") {
			cfg.Debug = debugFlag
		}
		if cmd.Flags().Changed("verbose") {
			cfg.Verbose = verboseFlag
		}
		if cmd.Flags().Changed("quiet") {
			cfg.Quiet = quietFlag
		}
		if cmd.Flags().Changed("no-color") {
			cfg.NoColor = noColorFlag
		}
		if cmd.Flags().Changed("license") {
			if licenseFlag == "" {
				return fmt.Errorf("--license flag cannot be empty")
			}
			cfg.License = licenseFlag
		}
		if cmd.Flags().Changed("cache-dir") {
			cfg.CacheDirectory = cacheDirFlag
		}
		if cmd.Flags().Changed("no-cache") {
			cfg.CacheEnabled = !noCacheFlag
		}

		// Configure logging based on flags
		configureLogging(cfg)

		return nil
	},
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ~/.config/wordfence/wordfence-cli.ini)")
	rootCmd.PersistentFlags().StringVar(&licenseFlag, "license", "", "Wordfence CLI license key")
	rootCmd.PersistentFlags().StringVar(&cacheDirFlag, "cache-dir", "", "cache directory (default: ~/.cache/wordfence)")
	rootCmd.PersistentFlags().BoolVar(&noCacheFlag, "no-cache", false, "disable caching")
	rootCmd.PersistentFlags().BoolVar(&debugFlag, "debug", false, "enable debug output")
	rootCmd.PersistentFlags().BoolVar(&verboseFlag, "verbose", false, "enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&quietFlag, "quiet", false, "suppress non-error output")
	rootCmd.PersistentFlags().BoolVar(&noColorFlag, "no-color", false, "disable colored output")
}

func configureLogging(cfg *config.Config) {
	// Set log level based on flags
	var level logging.Level
	if cfg.Quiet {
		level = logging.LevelCritical
	} else if cfg.Debug {
		level = logging.LevelDebug
	} else if cfg.Verbose {
		level = logging.LevelVerbose
	} else {
		level = logging.LevelInfo
	}
	logging.SetDefaultLevel(level)

	// Configure colored output
	logging.SetDefaultColored(!cfg.NoColor)
}

// GetConfig returns the loaded configuration.
func GetConfig() *config.Config {
	return cfg
}
