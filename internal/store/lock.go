package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrStoreInUse reports that another process already holds the state directory.
//
// Two processes appending one file is not two writers sharing a log. Each opens
// its own handle with its own offset, so the second writer's records land on top
// of the first writer's, and every record it overwrites was already framed with
// a correct length and a correct CRC. A replay cannot tell that damage from a
// healthy file: it trusts the bytes it walks and finds nothing to complain about,
// while the acknowledged messages of one of the two processes are simply gone.
// Measured, on this very format: 47 valid records, no discard warning, and 20 of
// 60 offline messages missing. So the refusal belongs at open, not in recovery.
var ErrStoreInUse = errors.New("store: the state directory is already open by another process")

// lockFileName sits beside state.log and is never read. It exists to be held.
//
// The state file itself cannot carry the lock: compaction closes its handle and
// reopens the replacement, which would drop the guard at exactly the moment a
// second writer could slip in.
const lockFileName = "state.lock"

// dirLock is the held lock. Releasing it is closing the handle, which the
// operating system also does on its own if the process dies: a killed broker
// costs its successor nothing, and no stale-lock file can wedge a restart.
type dirLock struct {
	f *os.File
}

// lockDir takes the directory's lock or reports ErrStoreInUse. It never blocks:
// a broker that cannot have the state directory should exit with an explanation
// rather than sit waiting for one it was never meant to share.
func lockDir(dir string) (*dirLock, error) {
	path := filepath.Join(dir, lockFileName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o640)
	if err != nil {
		return nil, err
	}
	held, err := tryLock(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !held {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %s", ErrStoreInUse, dir)
	}
	return &dirLock{f: f}, nil
}

// close is a no-op on an already released lock, so the three paths that can end
// a store - a failed open, a clean Close and a test's simulated crash - need not
// agree about which one runs.
func (d *dirLock) close() {
	if d == nil || d.f == nil {
		return
	}
	_ = d.f.Close()
	d.f = nil
}
