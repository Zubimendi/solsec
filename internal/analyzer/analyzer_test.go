package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Zubimendi/solsec/internal/parser"
)

func TestAnalyze(t *testing.T) {
	content := `
pragma solidity 0.7.0;
contract X {
    function mint() public {}
}
`
	tmpDir, err := os.MkdirTemp("", "solsec-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	tmpFile := filepath.Join(tmpDir, "test.sol")
	err = os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	slitherFindings := []parser.Finding{
		{
			ID: "OLD-1",
			Check: "slither-check",
			Severity: parser.SeverityLow,
			File: tmpFile,
			Lines: []int{1},
			SWCRef: "SWC-999",
		},
	}

	report, err := Analyze(tmpFile, slitherFindings)
	require.NoError(t, err)

	assert.NotNil(t, report)
	assert.Equal(t, tmpFile, report.Target)
	// Should have at least the slither finding + custom access control finding for mint()
	assert.GreaterOrEqual(t, len(report.Findings), 2)
}
