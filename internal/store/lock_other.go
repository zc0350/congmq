//go:build !unix && !windows

package store

import "os"

// tryLock has nothing to lock with on this platform, so the guard reports success
// and the single-writer rule falls back to the operator. Every GOOS congmq is
// shipped for (linux, darwin, windows) has a real lock; the builds left here are
// ones that cannot serve a TCP listener either.
func tryLock(*os.File) (bool, error) { return true, nil }
