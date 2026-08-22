package report

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// WriteFileAtomically renders through write into path, via a temporary file in
// the same directory that is renamed into place.
//
// os.Create truncates and then fills, so two runs sharing an output directory
// interleave and leave a file that is neither one's output: observed as a
// report.json that no longer parses. A rename is atomic on the same
// filesystem, so a concurrent reader sees either the old file or the new one
// and never a half-written mixture. The last writer wins, which is the right
// outcome for two runs told to write the same path.
func WriteFileAtomically(path string, write func(io.Writer) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	if err := write(tmp); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpName, path, err)
	}
	return nil
}
