package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckIntegerOverflow_OldSolidity(t *testing.T) {
	content := `
pragma solidity 0.7.0;

contract Old {
    function add(uint256 a, uint256 b) public {
        uint256 c = a + b;
    }
}
`
	tmpDir, err := os.MkdirTemp("", "solsec-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	tmpFile := filepath.Join(tmpDir, "old.sol")
	err = os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	findings, err := CheckIntegerOverflow(tmpFile)
	require.NoError(t, err)

	assert.Len(t, findings, 1)
	assert.Equal(t, "custom-integer-overflow", findings[0].Check)
}

func TestCheckIntegerOverflow_NewSolidity_Unchecked(t *testing.T) {
	content := `
pragma solidity ^0.8.0;

contract New {
    function sub(uint256 a, uint256 b) public {
        unchecked {
            uint256 c = a - b;
        }
    }
}
`
	tmpDir, err := os.MkdirTemp("", "solsec-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	tmpFile := filepath.Join(tmpDir, "new.sol")
	err = os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	findings, err := CheckIntegerOverflow(tmpFile)
	require.NoError(t, err)

	assert.Len(t, findings, 1)
	assert.Equal(t, "custom-unchecked-arithmetic", findings[0].Check)
}
