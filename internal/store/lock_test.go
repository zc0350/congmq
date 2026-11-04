//go:build unix || windows

package store

import (
	"errors"
	"testing"
)

// The shape of this test is the shape of the mistake: bring the new broker up
// before the old one is stopped, or point two instances at one mounted volume.
// Both leave two processes appending one file, each from its own offset, so the
// later write lands on top of the earlier one's records - and every record it
// overwrote was framed and CRC-correct, so no replay can tell. See ErrStoreInUse.
func TestFileStoreRefusesASecondWriter(t *testing.T) {
	dir := t.TempDir()
	fs := openStore(t, dir, nil)
	if err := fs.Put(sampleSession("first")); err != nil {
		t.Fatalf("put: %v", err)
	}
	settle(fs)

	_, err := NewFileStore(FileStoreOptions{Dir: dir})
	if !errors.Is(err, ErrStoreInUse) {
		t.Fatalf("a second open of one directory = %v, want ErrStoreInUse", err)
	}
	if _, ok := fs.Get("first"); !ok {
		t.Fatal("the refused open took the session away from the store holding it")
	}
	if err := fs.Put(sampleSession("still-writing")); err != nil {
		t.Fatalf("put after a refused open: %v", err)
	}

	// A second directory is a second store: the guard must not become a global
	// lock that stops a machine from running two brokers side by side.
	neighbour := openStore(t, t.TempDir(), nil)
	if err := neighbour.Put(sampleSession("next-door")); err != nil {
		t.Fatalf("a store in its own directory was refused: %v", err)
	}

	// Letting go is the restart path: the holder closed, so the next process is
	// admitted and finds everything the first one wrote.
	if err := fs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	taken := openStore(t, dir, nil)
	if _, ok := taken.Get("first"); !ok {
		t.Fatal("the takeover lost the session the closed store had written")
	}
}

// Compaction closes the state file's handle and reopens the replacement, which is
// exactly when a lock bound to that handle would vanish and let a second writer
// in mid-rewrite. The lock lives in its own file for that reason.
func TestFileStoreKeepsItsLockAcrossCompaction(t *testing.T) {
	dir := t.TempDir()
	fs := openStore(t, dir, func(o *FileStoreOptions) { o.CompactAfter = 1 << 10 })
	for i := 0; i < 20; i++ {
		s := sampleSession("busy")
		s.Queued = append(s.Queued, Message{Topic: "c/#", Payload: []byte("more"), QoS: 1, PacketID: uint16(i)})
		if err := fs.Put(s); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
		settle(fs)
	}
	if _, err := NewFileStore(FileStoreOptions{Dir: dir}); !errors.Is(err, ErrStoreInUse) {
		t.Fatalf("after a compaction the directory was open to a second writer: %v", err)
	}
}

// A killed process leaves no lock behind, because a lock belongs to a handle and
// the operating system closes the handles of a dead process. crash() is that
// inside one test binary: the file is let go with no Close, so the next start
// must be admitted rather than wedged by a lock nobody holds.
func TestFileStoreLockDiesWithTheProcessThatHeldIt(t *testing.T) {
	dir := t.TempDir()
	fs := openStore(t, dir, nil)
	if err := fs.Put(sampleSession("owed")); err != nil {
		t.Fatalf("put: %v", err)
	}
	settle(fs)
	fs.crash()

	taken := openStore(t, dir, nil)
	if _, ok := taken.Get("owed"); !ok {
		t.Fatal("the session did not survive the simulated crash")
	}
}
