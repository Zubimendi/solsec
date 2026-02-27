package runner

import (
	"fmt"
	"os/exec"
	"strings"
)

// Environment holds detected versions of required tools.
type Environment struct {
	PythonPath  string
	PythonVersion string
	SlitherPath string
	SlitherVersion string
}

// DetectEnvironment checks whether Python and Slither are available on PATH.
// Returns a descriptive error if either is missing, with install instructions.
func DetectEnvironment() (*Environment, error) {
	env := &Environment{}

	// Detect Python — try python3 first, fall back to python
	for _, name := range []string{"python3", "python"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		out, err := exec.Command(path, "--version").Output()
		if err != nil {
			continue
		}
		version := strings.TrimSpace(string(out))
		// Require Python 3.8+
		if strings.HasPrefix(version, "Python 3.") {
			env.PythonPath = path
			env.PythonVersion = version
			break
		}
	}

	if env.PythonPath == "" {
		return nil, fmt.Errorf(
			"Python 3.8+ not found on PATH\n\n" +
			"Install instructions:\n" +
			"  Ubuntu/Debian: sudo apt install python3 python3-pip\n" +
			"  macOS:         brew install python3\n" +
			"  Windows:       https://python.org/downloads",
		)
	}

	// Detect Slither
	slitherPath, err := exec.LookPath("slither")
	if err != nil {
		return nil, fmt.Errorf(
			"Slither not found on PATH\n\n" +
			"Install instructions:\n" +
			"  pip3 install slither-analyzer\n\n" +
			"If pip3 is not available:\n" +
			"  %s -m pip install slither-analyzer", env.PythonPath,
		)
	}

	out, err := exec.Command(slitherPath, "--version").Output()
	if err == nil {
		env.SlitherVersion = strings.TrimSpace(string(out))
	}
	env.SlitherPath = slitherPath

	return env, nil
}