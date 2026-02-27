package parser_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Zubimendi/solsec/internal/parser"
)

// This is a minimal but realistic Slither JSON output.
var sampleSlitherOutput = []byte(`{
  "success": true,
  "error": null,
  "results": {
    "detectors": [
      {
        "check": "reentrancy-eth",
        "impact": "High",
        "confidence": "Medium",
        "description": "EtherStore.withdraw() (EtherStore.sol#10-14) sends eth to arbitrary user\n\tDangerous calls:\n\t- (success) = msg.sender.call{value: amount}() (EtherStore.sol#12)",
        "elements": [
          {
            "type": "function",
            "name": "withdraw",
            "source_mapping": {
              "start": 200,
              "length": 120,
              "filename_absolute": "/contracts/EtherStore.sol",
              "lines": [10, 11, 12, 13, 14]
            },
            "type_specific_fields": {
              "parent": { "type": "contract", "name": "EtherStore" }
            }
          }
        ],
        "id": "abc123",
        "markdown": ""
      },
      {
        "check": "tx-origin",
        "impact": "Medium",
        "confidence": "High",
        "description": "Wallet.transfer() (Wallet.sol#8) uses tx.origin for authorization.",
        "elements": [
          {
            "type": "function",
            "name": "transfer",
            "source_mapping": {
              "start": 100,
              "length": 60,
              "filename_absolute": "/contracts/Wallet.sol",
              "lines": [8]
            },
            "type_specific_fields": {}
          }
        ],
        "id": "def456",
        "markdown": ""
      }
    ]
  }
}`)

var failedSlitherOutput = []byte(`{
  "success": false,
  "error": "crytic-compile failed: No such file or directory",
  "results": { "detectors": [] }
}`)

var emptySlitherOutput = []byte(`{
  "success": true,
  "error": null,
  "results": { "detectors": [] }
}`)

func TestParseBytes_HappyPath(t *testing.T) {
	findings, err := parser.ParseBytes(sampleSlitherOutput)
	require.NoError(t, err)
	assert.Len(t, findings, 2)
}

func TestParseBytes_FirstFindingIsReentrancy(t *testing.T) {
	findings, err := parser.ParseBytes(sampleSlitherOutput)
	require.NoError(t, err)

	f := findings[0]
	assert.Equal(t, "slither", f.Source)
	assert.Equal(t, "reentrancy-eth", f.Check)
	assert.Equal(t, parser.SeverityHigh, f.Severity)
	assert.Equal(t, "Medium", f.Confidence)
	assert.Equal(t, "/contracts/EtherStore.sol", f.File)
	assert.Equal(t, []int{10, 11, 12, 13, 14}, f.Lines)
}

func TestParseBytes_RemediationPopulated(t *testing.T) {
	findings, err := parser.ParseBytes(sampleSlitherOutput)
	require.NoError(t, err)

	// Reentrancy finding should have remediation guidance
	assert.Contains(t, findings[0].Remediation, "checks-effects-interactions")
}

func TestParseBytes_SWCRefPopulated(t *testing.T) {
	findings, err := parser.ParseBytes(sampleSlitherOutput)
	require.NoError(t, err)

	assert.Equal(t, "SWC-107", findings[0].SWCRef)
	assert.Equal(t, "SWC-115", findings[1].SWCRef) // tx-origin
}

func TestParseBytes_ReferencesContainSlitherDocs(t *testing.T) {
	findings, err := parser.ParseBytes(sampleSlitherOutput)
	require.NoError(t, err)

	refs := findings[0].References
	assert.NotEmpty(t, refs)
	assert.Contains(t, refs[0], "slither/wiki")
}

func TestParseBytes_FailedSlitherOutput(t *testing.T) {
	_, err := parser.ParseBytes(failedSlitherOutput)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "slither analysis failed")
}

func TestParseBytes_EmptyFindings(t *testing.T) {
	findings, err := parser.ParseBytes(emptySlitherOutput)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestParseBytes_TitleFormatting(t *testing.T) {
	findings, err := parser.ParseBytes(sampleSlitherOutput)
	require.NoError(t, err)

	// "reentrancy-eth" → "Reentrancy Eth"
	assert.Equal(t, "Reentrancy Eth", findings[0].Title)
}

func TestSeverityRank_Order(t *testing.T) {
	assert.Less(t, parser.SeverityRank(parser.SeverityCritical), parser.SeverityRank(parser.SeverityHigh))
	assert.Less(t, parser.SeverityRank(parser.SeverityHigh), parser.SeverityRank(parser.SeverityMedium))
	assert.Less(t, parser.SeverityRank(parser.SeverityMedium), parser.SeverityRank(parser.SeverityLow))
}