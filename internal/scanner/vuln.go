// Package scanner provides vulnerability scanning for WordPress
package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/greysquirr3l/wordfence-go/internal/intel"
	"github.com/greysquirr3l/wordfence-go/internal/logging"
	"github.com/greysquirr3l/wordfence-go/internal/wordpress"
)

// VulnScanResult represents the result of a vulnerability scan
type VulnScanResult struct {
	Site            *wordpress.Site
	Vulnerabilities []*VulnMatch
	Error           error
	ScanDuration    time.Duration
}

// VulnMatch represents a matched vulnerability
type VulnMatch struct {
	Vulnerability *intel.Vulnerability
	Software      *intel.Software
	SoftwareType  intel.SoftwareType
	Slug          string
	Name          string
	Version       string
	Path          string
}

// VulnScanOptions configures the vulnerability scanner
type VulnScanOptions struct {
	CheckCore      bool
	CheckPlugins   bool
	CheckThemes    bool
	Informational  bool
	IncludeVulnIDs []string
	ExcludeVulnIDs []string
}

// VulnScanner scans WordPress sites for vulnerabilities
type VulnScanner struct {
	index   *intel.VulnerabilityIndex
	options *VulnScanOptions
	logger  *logging.Logger
}

// VulnScannerOption configures a VulnScanner
type VulnScannerOption func(*VulnScanner)

// WithVulnCheckCore sets whether to check core
func WithVulnCheckCore(check bool) VulnScannerOption {
	return func(s *VulnScanner) {
		s.options.CheckCore = check
	}
}

// WithVulnCheckPlugins sets whether to check plugins
func WithVulnCheckPlugins(check bool) VulnScannerOption {
	return func(s *VulnScanner) {
		s.options.CheckPlugins = check
	}
}

// WithVulnCheckThemes sets whether to check themes
func WithVulnCheckThemes(check bool) VulnScannerOption {
	return func(s *VulnScanner) {
		s.options.CheckThemes = check
	}
}

// WithVulnInformational sets whether to include informational vulnerabilities
func WithVulnInformational(include bool) VulnScannerOption {
	return func(s *VulnScanner) {
		s.options.Informational = include
	}
}

// WithVulnLogger sets the logger
func WithVulnLogger(logger *logging.Logger) VulnScannerOption {
	return func(s *VulnScanner) {
		s.logger = logger
	}
}

// NewVulnScanner creates a new vulnerability scanner
func NewVulnScanner(index *intel.VulnerabilityIndex, opts ...VulnScannerOption) *VulnScanner {
	s := &VulnScanner{
		index: index,
		options: &VulnScanOptions{
			CheckCore:    true,
			CheckPlugins: true,
			CheckThemes:  true,
		},
		logger: logging.New(logging.LevelInfo),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// ScanSite scans a WordPress site for vulnerabilities
func (s *VulnScanner) ScanSite(_ context.Context, site *wordpress.Site) *VulnScanResult {
	start := time.Now()
	result := &VulnScanResult{
		Site: site,
	}

	// Check WordPress core
	if s.options.CheckCore && site.Version != "" {
		vulns := s.index.GetVulnerabilities(intel.SoftwareTypeCore, "wordpress", site.Version)
		for _, vuln := range vulns {
			if s.shouldInclude(vuln) {
				sw := vuln.IsAffected(intel.SoftwareTypeCore, "wordpress", site.Version)
				match := &VulnMatch{
					Vulnerability: vuln,
					Software:      sw,
					SoftwareType:  intel.SoftwareTypeCore,
					Slug:          "wordpress",
					Name:          "WordPress",
					Version:       site.Version,
					Path:          site.CorePath,
				}
				result.Vulnerabilities = append(result.Vulnerabilities, match)
			}
		}
	}

	// Check plugins
	if s.options.CheckPlugins {
		for _, plugin := range site.Plugins {
			if plugin.Version == "" {
				continue
			}

			vulns := s.index.GetVulnerabilities(intel.SoftwareTypePlugin, plugin.Slug, plugin.Version)
			for _, vuln := range vulns {
				if s.shouldInclude(vuln) {
					sw := vuln.IsAffected(intel.SoftwareTypePlugin, plugin.Slug, plugin.Version)
					match := &VulnMatch{
						Vulnerability: vuln,
						Software:      sw,
						SoftwareType:  intel.SoftwareTypePlugin,
						Slug:          plugin.Slug,
						Name:          plugin.Name,
						Version:       plugin.Version,
						Path:          plugin.Path,
					}
					result.Vulnerabilities = append(result.Vulnerabilities, match)
				}
			}
		}
	}

	// Check themes
	if s.options.CheckThemes {
		for _, theme := range site.Themes {
			if theme.Version == "" {
				continue
			}

			vulns := s.index.GetVulnerabilities(intel.SoftwareTypeTheme, theme.Slug, theme.Version)
			for _, vuln := range vulns {
				if s.shouldInclude(vuln) {
					sw := vuln.IsAffected(intel.SoftwareTypeTheme, theme.Slug, theme.Version)
					match := &VulnMatch{
						Vulnerability: vuln,
						Software:      sw,
						SoftwareType:  intel.SoftwareTypeTheme,
						Slug:          theme.Slug,
						Name:          theme.Name,
						Version:       theme.Version,
						Path:          theme.Path,
					}
					result.Vulnerabilities = append(result.Vulnerabilities, match)
				}
			}
		}
	}

	result.ScanDuration = time.Since(start)
	return result
}

// shouldInclude checks if a vulnerability should be included in results
func (s *VulnScanner) shouldInclude(vuln *intel.Vulnerability) bool {
	// Check informational filter
	if vuln.Informational && !s.options.Informational {
		return false
	}

	// Check include list
	if len(s.options.IncludeVulnIDs) > 0 {
		found := false
		for _, id := range s.options.IncludeVulnIDs {
			if id == vuln.ID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check exclude list
	for _, id := range s.options.ExcludeVulnIDs {
		if id == vuln.ID {
			return false
		}
	}

	return true
}

// ScanPath scans a path for WordPress installations and vulnerabilities
func (s *VulnScanner) ScanPath(ctx context.Context, path string) ([]*VulnScanResult, error) {
	locator := wordpress.NewLocator()
	sites, err := locator.Locate(path)
	if err != nil {
		return nil, fmt.Errorf("locating sites: %w", err)
	}

	var results []*VulnScanResult
	for _, site := range sites {
		select {
		case <-ctx.Done():
			return results, fmt.Errorf("context cancelled: %w", ctx.Err())
		default:
		}

		result := s.ScanSite(ctx, site)
		results = append(results, result)
	}

	return results, nil
}
