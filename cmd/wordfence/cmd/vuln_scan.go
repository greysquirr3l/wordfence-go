package cmd

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/greysquirr3l/wordfence-go/internal/api"
	"github.com/greysquirr3l/wordfence-go/internal/cache"
	"github.com/greysquirr3l/wordfence-go/internal/intel"
	"github.com/greysquirr3l/wordfence-go/internal/logging"
	"github.com/greysquirr3l/wordfence-go/internal/scanner"
	"github.com/greysquirr3l/wordfence-go/internal/wordpress"
)

var (
	vulnScanOutput        string
	vulnScanOutputFormat  string
	vulnScanCheckCore     bool
	vulnScanCheckPlugins  bool
	vulnScanCheckThemes   bool
	vulnScanInformational bool
)

var vulnScanCmd = &cobra.Command{
	Use:   "vuln-scan [paths...]",
	Short: "Scan WordPress for vulnerabilities",
	Long: `Scan WordPress installations for known vulnerabilities.

The scanner will detect WordPress core, plugins, and themes at the
specified paths and check them against the Wordfence vulnerability
database.`,
	Example: `  # Scan a single WordPress installation
  wordfence vuln-scan /var/www/wordpress

  # Scan multiple installations
  wordfence vuln-scan /var/www/site1 /var/www/site2

  # Scan with CSV output
  wordfence vuln-scan --output-format csv --output vulns.csv /var/www`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runVulnScan(args)
	},
}

func init() {
	vulnScanCmd.Flags().StringVarP(&vulnScanOutput, "output", "o", "", "output file (default: stdout)")
	vulnScanCmd.Flags().StringVar(&vulnScanOutputFormat, "output-format", "human", "output format: csv, tsv, json, human")
	vulnScanCmd.Flags().BoolVar(&vulnScanCheckCore, "check-core", true, "check WordPress core")
	vulnScanCmd.Flags().BoolVar(&vulnScanCheckPlugins, "check-plugins", true, "check plugins")
	vulnScanCmd.Flags().BoolVar(&vulnScanCheckThemes, "check-themes", true, "check themes")
	vulnScanCmd.Flags().BoolVar(&vulnScanInformational, "informational", false, "include informational vulnerabilities")

	rootCmd.AddCommand(vulnScanCmd)
}

func runVulnScan(paths []string) error {
	ctx := context.Background()
	cfg := GetConfig()
	if cfg == nil {
		return fmt.Errorf("configuration not loaded")
	}

	// Check for license
	if cfg.License == "" {
		logging.Error("No license key configured. Set WORDFENCE_CLI_LICENSE or use --license flag.")
		logging.Info("Visit https://www.wordfence.com/products/wordfence-cli/ to obtain a license.")
		os.Exit(1)
	}

	logging.Info("Starting vulnerability scan...")
	startTime := time.Now()

	// Set up cache
	var c cache.Cache
	if cfg.CacheEnabled && cfg.CacheDirectory != "" {
		fileCache, err := cache.NewFileCache(cfg.CacheDirectory)
		if err != nil {
			logging.Warning("Failed to initialize cache: %v (continuing without cache)", err)
			c = cache.NewNoOpCache()
		} else {
			c = fileCache
		}
	} else {
		c = cache.NewNoOpCache()
	}

	// Create license
	license := &api.License{
		Key: cfg.License,
	}

	// Create Intelligence API client
	intelClient := api.NewIntelligenceClient(
		api.WithIntelligenceLicense(license),
	)

	// Load vulnerability index
	logging.Verbose("Loading vulnerability database...")
	vulnIndex, err := loadVulnerabilityIndex(ctx, c, intelClient)
	if err != nil {
		return fmt.Errorf("failed to load vulnerability database: %w", err)
	}
	logging.Debug("Loaded %d vulnerabilities", vulnIndex.Count())

	// Create scanner
	vulnScanner := scanner.NewVulnScanner(vulnIndex,
		scanner.WithVulnCheckCore(vulnScanCheckCore),
		scanner.WithVulnCheckPlugins(vulnScanCheckPlugins),
		scanner.WithVulnCheckThemes(vulnScanCheckThemes),
		scanner.WithVulnInformational(vulnScanInformational),
	)

	// Detect WordPress sites
	logging.Verbose("Detecting WordPress installations...")
	locator := wordpress.NewLocator()
	var sites []*wordpress.Site

	for _, path := range paths {
		foundSites, err := locator.Locate(path)
		if err != nil {
			logging.Warning("Error scanning path %s: %v", path, err)
			continue
		}
		sites = append(sites, foundSites...)
	}

	if len(sites) == 0 {
		logging.Warning("No WordPress installations found")
		return nil
	}

	logging.Info("Found %d WordPress installation(s)", len(sites))

	// Scan each site
	var allMatches []*scanner.VulnMatch
	for _, site := range sites {
		logging.Verbose("Scanning %s (WordPress %s)", site.Path, site.Version)
		logging.Debug("  Plugins: %d, Themes: %d", len(site.Plugins), len(site.Themes))

		result := vulnScanner.ScanSite(ctx, site)
		if result.Error != nil {
			logging.Warning("Error scanning site %s: %v", site.Path, result.Error)
			continue
		}

		allMatches = append(allMatches, result.Vulnerabilities...)
	}

	// Output results
	if err := outputVulnResults(allMatches, sites); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	elapsed := time.Since(startTime)
	logging.Info("Scan complete: %d vulnerabilities found in %s", len(allMatches), elapsed.Round(time.Millisecond))

	return nil
}

// loadVulnerabilityIndex loads vulnerability data from cache or API
func loadVulnerabilityIndex(ctx context.Context, c cache.Cache, client *api.IntelligenceClient) (*intel.VulnerabilityIndex, error) {
	cacheKey := "vulnerability_index_scanner"
	cacheMaxAge := 24 * time.Hour

	// Try to load from cache
	data, err := c.Get(cacheKey, cacheMaxAge)
	if err == nil {
		index, err := intel.ParseVulnerabilityIndex(data)
		if err == nil {
			logging.Debug("Loaded vulnerabilities from cache")
			return index, nil
		}
		logging.Debug("Failed to parse cached vulnerabilities: %v", err)
	}

	// Fetch from API
	logging.Verbose("Fetching vulnerability database from Wordfence...")
	index, err := client.GetScannerVulnerabilities(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching vulnerabilities: %w", err)
	}

	// Cache the data
	indexData, err := json.Marshal(index)
	if err != nil {
		logging.Warning("Failed to marshal vulnerabilities for cache: %v", err)
	} else {
		if err := c.Put(cacheKey, indexData); err != nil {
			logging.Warning("Failed to cache vulnerabilities: %v", err)
		}
	}

	return index, nil
}

// outputVulnResults outputs the vulnerability scan results
func outputVulnResults(matches []*scanner.VulnMatch, sites []*wordpress.Site) error {
	// Determine output writer
	var out *os.File
	var err error

	if vulnScanOutput != "" && vulnScanOutput != "-" {
		out, err = os.Create(vulnScanOutput) //nolint:gosec // user-specified output file
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer func() { _ = out.Close() }()
	} else {
		out = os.Stdout
	}

	switch strings.ToLower(vulnScanOutputFormat) {
	case formatJSON:
		return outputVulnJSON(out, matches)
	case formatCSV:
		return outputVulnCSV(out, matches, ',')
	case formatTSV:
		return outputVulnCSV(out, matches, '\t')
	default:
		return outputVulnHuman(out, matches, sites)
	}
}

// outputVulnJSON outputs results as JSON
func outputVulnJSON(out *os.File, matches []*scanner.VulnMatch) error {
	type vulnOutput struct {
		SoftwareType string  `json:"software_type"`
		Slug         string  `json:"slug"`
		Name         string  `json:"name"`
		Version      string  `json:"version"`
		VulnID       string  `json:"vulnerability_id"`
		Title        string  `json:"title"`
		CVE          string  `json:"cve,omitempty"`
		CVSS         float64 `json:"cvss_score,omitempty"`
		Link         string  `json:"link"`
		Path         string  `json:"path"`
	}

	results := make([]vulnOutput, 0, len(matches))
	for _, m := range matches {
		vo := vulnOutput{
			SoftwareType: string(m.SoftwareType),
			Slug:         m.Slug,
			Name:         m.Name,
			Version:      m.Version,
			VulnID:       m.Vulnerability.ID,
			Title:        m.Vulnerability.Title,
			CVE:          m.Vulnerability.CVE,
			Link:         fmt.Sprintf("https://www.wordfence.com/threat-intel/vulnerabilities/id/%s", m.Vulnerability.ID),
			Path:         m.Path,
		}
		if m.Vulnerability.CVSS != nil {
			vo.CVSS = m.Vulnerability.CVSS.Score
		}
		results = append(results, vo)
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("json encode error: %w", err)
	}
	return nil
}

// outputVulnCSV outputs results as CSV/TSV
func outputVulnCSV(out *os.File, matches []*scanner.VulnMatch, sep rune) error {
	w := csv.NewWriter(out)
	w.Comma = sep

	// Write header
	header := []string{"software_type", "slug", "name", "version", "vulnerability_id", "title", "cve", "cvss_score", "link", "path"}
	if err := w.Write(header); err != nil {
		return fmt.Errorf("csv write error: %w", err)
	}

	// Write rows
	for _, m := range matches {
		cvss := ""
		if m.Vulnerability.CVSS != nil {
			cvss = fmt.Sprintf("%.1f", m.Vulnerability.CVSS.Score)
		}

		row := []string{
			string(m.SoftwareType),
			m.Slug,
			m.Name,
			m.Version,
			m.Vulnerability.ID,
			m.Vulnerability.Title,
			m.Vulnerability.CVE,
			cvss,
			fmt.Sprintf("https://www.wordfence.com/threat-intel/vulnerabilities/id/%s", m.Vulnerability.ID),
			m.Path,
		}
		if err := w.Write(row); err != nil {
			return fmt.Errorf("csv write error: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("csv writer error: %w", err)
	}
	return nil
}

// outputVulnHuman outputs results in human-readable format
//
//nolint:unparam // error return kept for interface consistency with other output functions
func outputVulnHuman(out *os.File, matches []*scanner.VulnMatch, _ []*wordpress.Site) error {
	if len(matches) == 0 {
		_, _ = fmt.Fprintln(out, color.GreenString("✓ No vulnerabilities found"))
		return nil
	}

	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan)
	bold := color.New(color.Bold)

	// Group by severity
	var critical, high, medium, low []*scanner.VulnMatch
	for _, m := range matches {
		if m.Vulnerability.CVSS == nil {
			low = append(low, m)
			continue
		}
		switch {
		case m.Vulnerability.CVSS.Score >= 9.0:
			critical = append(critical, m)
		case m.Vulnerability.CVSS.Score >= 7.0:
			high = append(high, m)
		case m.Vulnerability.CVSS.Score >= 4.0:
			medium = append(medium, m)
		default:
			low = append(low, m)
		}
	}

	// Print summary
	_, _ = fmt.Fprintln(out)
	_, _ = red.Fprintf(out, "⚠ Found %d vulnerabilities\n", len(matches))
	if len(critical) > 0 {
		_, _ = fmt.Fprintf(out, "  Critical: %d\n", len(critical))
	}
	if len(high) > 0 {
		_, _ = fmt.Fprintf(out, "  High: %d\n", len(high))
	}
	if len(medium) > 0 {
		_, _ = fmt.Fprintf(out, "  Medium: %d\n", len(medium))
	}
	if len(low) > 0 {
		_, _ = fmt.Fprintf(out, "  Low/Unknown: %d\n", len(low))
	}
	_, _ = fmt.Fprintln(out)

	// Print each vulnerability
	printVulnGroup := func(title string, matches []*scanner.VulnMatch) {
		if len(matches) == 0 {
			return
		}
		_, _ = bold.Fprintf(out, "=== %s ===\n", title)
		for _, m := range matches {
			// Capitalize first letter of software type
			typeLabel := string(m.SoftwareType)
			if len(typeLabel) > 0 {
				typeLabel = strings.ToUpper(typeLabel[:1]) + typeLabel[1:]
			}
			_, _ = cyan.Fprintf(out, "\n[%s] %s v%s\n", typeLabel, m.Name, m.Version)
			_, _ = bold.Fprintf(out, "  %s\n", m.Vulnerability.Title)

			if m.Vulnerability.CVE != "" {
				_, _ = fmt.Fprintf(out, "  CVE: %s\n", m.Vulnerability.CVE)
			}
			if m.Vulnerability.CVSS != nil {
				severityColor := yellow
				if m.Vulnerability.CVSS.Score >= 9.0 {
					severityColor = red
				}
				_, _ = severityColor.Fprintf(out, "  CVSS: %.1f\n", m.Vulnerability.CVSS.Score)
			}
			_, _ = fmt.Fprintf(out, "  Path: %s\n", m.Path)
			_, _ = fmt.Fprintf(out, "  Link: https://www.wordfence.com/threat-intel/vulnerabilities/id/%s\n", m.Vulnerability.ID)
		}
		_, _ = fmt.Fprintln(out)
	}

	printVulnGroup("CRITICAL", critical)
	printVulnGroup("HIGH", high)
	printVulnGroup("MEDIUM", medium)
	printVulnGroup("LOW/UNKNOWN", low)

	return nil
}
