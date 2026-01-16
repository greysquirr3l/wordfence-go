#!/bin/bash
# Fetch signature rules from Wordfence API and save for embedding
#
# Usage: ./scripts/fetch-rules.sh <license_key>
#
# This script fetches the latest malware signatures from the Wordfence API
# and saves them in a format suitable for embedding into the binary.

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <license_key>"
    echo ""
    echo "Environment variables:"
    echo "  WORDFENCE_LICENSE_KEY - Alternative to passing license key as argument"
    exit 1
fi

LICENSE_KEY="${1:-$WORDFENCE_LICENSE_KEY}"
API_URL="https://noc1.wordfence.com/v2.27/"
OUTPUT_DIR="internal/intel/rules"
OUTPUT_FILE="${OUTPUT_DIR}/signatures.json"

mkdir -p "$OUTPUT_DIR"

echo "Fetching malware signatures from Wordfence API..."

# Fetch patterns from NOC1 API (using query string like the Go client does)
RESPONSE=$(curl -sS "${API_URL}?action=get_patterns&k=${LICENSE_KEY}&cli=1&s=%7B%7D")

# Check for error response
if echo "$RESPONSE" | grep -q '"errorMsg"'; then
    echo "Error from API:"
    echo "$RESPONSE" | jq .
    exit 1
fi

# Save the raw response - the Go code will parse it
# The response format has:
#   rules: array of [id, timestamp, rule, description, scope, enabled, category, name, commonStrings[]]
#   commonStrings: array of strings
#   signatureUpdateTime: timestamp
echo "$RESPONSE" > "$OUTPUT_FILE"

# Get stats
RULE_COUNT=$(echo "$RESPONSE" | jq '.rules | length')
COMMON_COUNT=$(echo "$RESPONSE" | jq '.commonStrings | length')

echo "Saved ${RULE_COUNT} rules and ${COMMON_COUNT} common strings to ${OUTPUT_FILE}"
echo ""
echo "To build with embedded rules:"
echo "  make build-embedded"
