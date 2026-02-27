package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckAccessControl(t *testing.T) {
	content := `
contract Improper {
    function mint(address to, uint256 amount) public {
        // missing onlyOwner!
    }

    function safeMint(address to, uint256 amount) public internal {
        // internal is safe
    }

    function burn(uint256 amount) public onlyOwner {
        // has onlyOwner, safe
    }
}
`
	tmpDir, err := os.MkdirTemp("", "solsec-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	tmpFile := filepath.Join(tmpDir, "access.sol")
	err = os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	findings, err := CheckAccessControl(tmpFile)
	require.NoError(t, err)

	assert.Len(t, findings, 1)
	assert.Equal(t, "custom-missing-access-control", findings[0].Check)
	assert.Contains(t, findings[0].Title, "mint")
}
