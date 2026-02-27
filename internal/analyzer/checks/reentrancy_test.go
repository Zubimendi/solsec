package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckReentrancy(t *testing.T) {
	// Create a temporary Solidity file with a reentrancy vulnerability
	content := `
package main

contract Vulnerable {
    mapping(address => uint256) public balances;

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0);

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);

        balances[msg.sender] = 0;
    }
}
`
	tmpDir, err := os.MkdirTemp("", "solsec-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	tmpFile := filepath.Join(tmpDir, "vulnerable.sol")
	err = os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	findings, err := CheckReentrancy(tmpFile)
	require.NoError(t, err)

	assert.Len(t, findings, 1)
	assert.Equal(t, "custom-reentrancy-ordering", findings[0].Check)
	assert.Equal(t, tmpFile, findings[0].File)
	// Lines: call is at 10 (counting from 1), state change at 13
	// Wait, let's recount:
	// 1: 
	// 2: package main (not valid solidity but scanner doesn't care)
	// 3: 
	// 4: contract Vulnerable {
	// 5:     mapping(address => uint256) public balances;
	// 6: 
	// 7:     function withdraw() public {
	// 8:         uint256 amount = balances[msg.sender];
	// 9:         require(amount > 0);
	// 10: 
	// 11:         (bool success, ) = msg.sender.call{value: amount}("");
	// 12:         require(success);
	// 13: 
	// 14:         balances[msg.sender] = 0;
	// 15:     }
	// 16: }
	// Call at 11, change at 14.
	assert.Contains(t, findings[0].Lines, 11)
	assert.Contains(t, findings[0].Lines, 14)
}

func TestCheckReentrancy_WithGuard(t *testing.T) {
	content := `
contract Safe {
    bool private locked;
    modifier nonReentrant() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }

    mapping(address => uint256) public balances;

    function withdraw() public nonReentrant {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
`
	tmpDir, err := os.MkdirTemp("", "solsec-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	tmpFile := filepath.Join(tmpDir, "safe.sol")
	err = os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	findings, err := CheckReentrancy(tmpFile)
	require.NoError(t, err)

	assert.Empty(t, findings)
}
