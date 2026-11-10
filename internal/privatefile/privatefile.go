// Package privatefile creates and tightens files that other local users must
// not read, such as the SQLite databases the daemons and the HTTP API server
// keep session state and keys in.
//
// SQLite creates a missing database file honoring the process umask (0644
// under condor_master's umask of 022), and creates its -wal, -shm and -journal
// sidecars with the database file's own permissions. Creating the file with
// the wanted mode before SQLite opens it therefore covers the sidecars it
// creates later too.
package privatefile

import (
	"errors"
	"os"
)

// sqliteSidecars are the suffixes of the files SQLite keeps beside a
// database: the write-ahead log and its shared-memory index (WAL mode), and
// the rollback journal (the default journal mode).
var sqliteSidecars = []string{"-wal", "-shm", "-journal"}

// SQLiteFiles returns the database path followed by the paths of its
// possible sidecar files. The sidecars need not exist.
func SQLiteFiles(path string) []string {
	files := []string{path}
	for _, suffix := range sqliteSidecars {
		files = append(files, path+suffix)
	}
	return files
}

// Ensure makes path exist with exactly mode, creating it if absent and
// tightening it if it already exists with looser bits.
func Ensure(path string, mode os.FileMode) error {
	// path is an operator-configured database location, not attacker-controlled.
	f, err := os.OpenFile(path, os.O_CREATE, mode) //nolint:gosec // G304: path is operator-configured
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// O_CREATE's mode applies only on creation; chmod covers a pre-existing file
	// (and corrects for the umask, which masks the create mode too).
	return os.Chmod(path, mode)
}

// EnsureSQLite applies Ensure to the database at path, then sets mode on each
// of its sidecar files that already exists. A sidecar left by an earlier run
// is reused as it is, so its mode does not follow a database file tightened
// after the fact. It attempts every file and returns the errors joined.
func EnsureSQLite(path string, mode os.FileMode) error {
	errs := []error{Ensure(path, mode)}
	for _, p := range SQLiteFiles(path)[1:] {
		if err := os.Chmod(p, mode); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
