//go:build windows

package store

import (
	"os"
	"syscall"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	// LockFile has no wait form, which is exactly the non-blocking behaviour the
	// store wants: a held lock fails at once instead of hanging the startup.
	procLockFile = kernel32.NewProc("LockFile")
)

const (
	// Lock the whole possible range rather than the file's current length: the
	// lock file is empty, and a range lock still conflicts with another
	// process's overlapping range at offset 0.
	lockAllLow  = 0xFFFFFFFF
	lockAllHigh = 0xFFFFFFFF

	errorLockViolation    syscall.Errno = 33
	errorSharingViolation syscall.Errno = 32
)

// tryLock asks kernel32 to lock the lock file's byte range. The lock is owned by
// the handle, so a killed process drops it with its descriptors and a stale file
// can never block the next start.
func tryLock(f *os.File) (bool, error) {
	r, _, err := procLockFile.Call(
		uintptr(syscall.Handle(f.Fd())),
		0, 0,
		uintptr(lockAllLow), uintptr(lockAllHigh),
	)
	if r != 0 {
		return true, nil
	}
	if errno, ok := err.(syscall.Errno); ok && (errno == errorLockViolation || errno == errorSharingViolation) {
		return false, nil
	}
	return false, err
}
