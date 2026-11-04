//go:build unix

package store

import (
	"errors"
	"os"
	"syscall"
)

// tryLock takes an exclusive, non-blocking flock on the lock file's descriptor.
// A lock taken this way belongs to the descriptor rather than to the process, so
// it survives no longer than the handle: another flock from a second descriptor
// in this same process is refused too, which is what the store's own tests need.
func tryLock(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, syscall.EWOULDBLOCK), errors.Is(err, syscall.EAGAIN),
		errors.Is(err, syscall.EACCES):
		return false, nil
	default:
		return false, err
	}
}
