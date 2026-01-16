// Package wordpress provides NOC1-based remediation source
package wordpress

import (
	"context"
	"fmt"

	"github.com/greysquirr3l/wordfence-go/internal/api"
)

// NOC1RemediationSource fetches correct file content from the Wordfence NOC1 API
type NOC1RemediationSource struct {
	client *api.NOC1Client
}

// NewNOC1RemediationSource creates a new NOC1RemediationSource
func NewNOC1RemediationSource(client *api.NOC1Client) *NOC1RemediationSource {
	return &NOC1RemediationSource{
		client: client,
	}
}

// GetCorrectContent retrieves the correct content for a file from the NOC1 API
func (s *NOC1RemediationSource) GetCorrectContent(ctx context.Context, identity *FileIdentity) ([]byte, error) {
	if identity == nil || !identity.IsKnown() {
		return nil, fmt.Errorf("unknown file identity")
	}

	// Validate required fields for core files
	if identity.Type == FileTypeCore && identity.CoreVersion == "" {
		return nil, fmt.Errorf("WordPress version not detected - ensure wp-includes/version.php exists and is readable")
	}

	var extensionName, extensionVersion string

	switch identity.Type {
	case FileTypeCore:
		// Core file - no extension info needed
	case FileTypePlugin:
		extensionName = identity.GetExtensionName()
		extensionVersion = identity.GetExtensionVersion()
		if extensionName == "" || extensionVersion == "" {
			return nil, fmt.Errorf("plugin name or version not detected")
		}
	case FileTypeTheme:
		extensionName = identity.GetExtensionName()
		extensionVersion = identity.GetExtensionVersion()
		if extensionName == "" || extensionVersion == "" {
			return nil, fmt.Errorf("theme name or version not detected")
		}
	default:
		return nil, fmt.Errorf("unsupported file type: %s", identity.Type)
	}

	content, err := s.client.GetWPFileContent(
		ctx,
		string(identity.Type),
		identity.LocalPath,
		identity.CoreVersion,
		extensionName,
		extensionVersion,
	)
	if err != nil {
		return nil, fmt.Errorf("getting file content from NOC1: %w", err)
	}
	return content, nil
}
