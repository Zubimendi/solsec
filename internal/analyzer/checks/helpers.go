package checks

import (
	"os"
	"path/filepath"
)

// solidityFiles returns all .sol files at the given path.
// If path is a file, returns [path]. If a directory, walks it recursively.
func solidityFiles(target string) ([]string, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return []string{target}, nil
	}

	var files []string
	err = filepath.Walk(target, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !fi.IsDir() && filepath.Ext(path) == ".sol" {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}