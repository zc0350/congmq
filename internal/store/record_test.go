package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// logPath is the file a test drives, inside a directory Go removes afterwards.
func logPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "records.log")
}

// openLog opens a log and makes sure the test lets go of it, because Windows
// will not delete a directory holding a file another handle has open, and a
// leaked handle fails the suite for a reason that has nothing to do with it.
func openLog(t *testing.T, path string, header []byte) (*recordLog, LogOpen, error) {
	t.Helper()
	l, opened, err := openRecordLog(path, header)
	if l != nil {
		t.Cleanup(func() { _ = l.close(false) })
	}
	return l, opened, err
}

// writeRaw appends bytes behind the log's back, which is how a half-written
// record from a killed process is simulated without killing anything.
func writeRaw(t *testing.T, path string, b ...byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		t.Fatalf("open for raw append: %v", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		t.Fatalf("raw append: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close raw append: %v", err)
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	return info.Size()
}

// frameLen is how many bytes one payload occupies on disk, length header and
// checksum included, which is all the offset arithmetic below needs.
func frameLen(payload string) int { return 4 + len(payload) + 4 }

func TestRecordLogRoundTrip(t *testing.T) {
	path := logPath(t)
	hdr := headerRecord()

	l, opened, err := openLog(t, path, hdr)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if len(opened.Records) != 0 || opened.Discarded != 0 {
		t.Fatalf("a new log replayed %d records and %d discarded bytes", len(opened.Records), opened.Discarded)
	}
	for _, payload := range []string{"one", "two", "three"} {
		if err := l.append([]byte(payload)); err != nil {
			t.Fatalf("append %q: %v", payload, err)
		}
	}
	if err := l.close(true); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, opened, err = openLog(t, path, hdr)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	// The header is a record like any other, so it comes back first.
	want := append([]string{string(hdr)}, "one", "two", "three")
	if len(opened.Records) != len(want) {
		t.Fatalf("replayed %d records, want %d", len(opened.Records), len(want))
	}
	for i, w := range want {
		if string(opened.Records[i]) != w {
			t.Errorf("record %d = %q, want %q", i, opened.Records[i], w)
		}
	}
}

func TestRecordLogTornTailIsCutAndReported(t *testing.T) {
	path := logPath(t)
	hdr := headerRecord()

	l, _, err := openLog(t, path, hdr)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := l.append([]byte("kept")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := l.flush(true); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := l.close(false); err != nil {
		t.Fatalf("close: %v", err)
	}

	// A length header that stops mid-field, plus a body that never arrived:
	// exactly what SIGKILL leaves behind.
	torn := append([]byte{0x00, 0x00, 0x10}, make([]byte, 999)...)
	writeRaw(t, path, torn...)

	l, opened, err := openLog(t, path, hdr)
	if err != nil {
		t.Fatalf("open after a torn tail: %v", err)
	}
	if opened.Discarded != int64(len(torn)) {
		t.Errorf("discarded %d bytes, want the %d that were never a record", opened.Discarded, len(torn))
	}
	if got := frameLen("kept") + frameLen(string(hdr)); fileSize(t, path) != int64(got) {
		t.Errorf("file is %d bytes after truncation, want %d", fileSize(t, path), got)
	}
	if len(opened.Records) != 2 || string(opened.Records[1]) != "kept" {
		t.Fatalf("replayed %q, want the header and the one intact record", opened.Records)
	}
	// The tail has to be gone from the file itself, or the next append would sit
	// behind bytes a later replay reads as corruption.
	if err := l.append([]byte("after")); err != nil {
		t.Fatalf("append after recovery: %v", err)
	}
	if err := l.close(true); err != nil {
		t.Fatalf("close: %v", err)
	}
	want := int64(frameLen(string(hdr)) + frameLen("kept") + frameLen("after"))
	if got := fileSize(t, path); got != want {
		t.Errorf("after appending over a recovered file the size is %d, want %d: no orphan bytes may survive", got, want)
	}
	_, opened, err = openLog(t, path, hdr)
	if err != nil {
		t.Fatalf("third open: %v", err)
	}
	if len(opened.Records) != 3 || string(opened.Records[2]) != "after" {
		t.Errorf("recovered log replayed %q, want three records ending in 'after'", opened.Records)
	}
}

func TestRecordLogStopsAtBadChecksum(t *testing.T) {
	path := logPath(t)
	hdr := headerRecord()

	l, _, err := openLog(t, path, hdr)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := l.append([]byte("first")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := l.append([]byte("second")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := l.flush(true); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := l.close(false); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Flip one byte of the last record's CRC. A checksum that disagrees means
	// payload and tail cannot be trusted together, so replay ends there with
	// everything before it intact.
	off := int64(frameLen(string(hdr)) + frameLen("first") + 4 + len("second"))
	f, err := os.OpenFile(path, os.O_RDWR, 0o640)
	if err != nil {
		t.Fatalf("open to corrupt: %v", err)
	}
	crc := make([]byte, 4)
	if _, err := f.ReadAt(crc, off); err != nil {
		_ = f.Close()
		t.Fatalf("read crc: %v", err)
	}
	binary.BigEndian.PutUint32(crc, binary.BigEndian.Uint32(crc)^0xFFFF)
	if _, err := f.WriteAt(crc, off); err != nil {
		_ = f.Close()
		t.Fatalf("write crc: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close after corrupting: %v", err)
	}

	_, opened, err := openLog(t, path, hdr)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(opened.Records) != 2 || string(opened.Records[1]) != "first" {
		t.Fatalf("replayed %q, want the header and 'first' only", opened.Records)
	}
	if opened.Discarded != int64(frameLen("second")) {
		t.Errorf("discarded %d bytes, want the whole of the 'second' frame (%d)", opened.Discarded, frameLen("second"))
	}
}

func TestRecordLogRefusesAForeignFile(t *testing.T) {
	hdr := headerRecord()

	t.Run("framed but not ours", func(t *testing.T) {
		path := logPath(t)
		foreign := []byte(`{"op":"session"}`)
		// A well-formed frame whose payload is not the header: a store file from a
		// different format, or one whose front has been edited.
		if err := os.WriteFile(path, frame(foreign), 0o640); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, _, err := openLog(t, path, hdr); !errors.Is(err, ErrBadStore) {
			t.Fatalf("open error = %v, want ErrBadStore", err)
		}
		if b, err := os.ReadFile(path); err != nil || !bytes.Equal(b, frame(foreign)) {
			t.Errorf("a refused file must be left exactly as it was: %q (err %v)", b, err)
		}
	})

	t.Run("not framed at all", func(t *testing.T) {
		path := logPath(t)
		const foreign = "this is somebody else's file"
		if err := os.WriteFile(path, []byte(foreign), 0o640); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, _, err := openLog(t, path, hdr); !errors.Is(err, ErrBadStore) {
			t.Fatalf("open error = %v, want ErrBadStore", err)
		}
		b, err := os.ReadFile(path)
		if err != nil || string(b) != foreign {
			t.Errorf("refusing must not rewrite the file: %q (err %v)", b, err)
		}
	})
}

func TestRecordLogRefusesAnAbsurdLength(t *testing.T) {
	path := logPath(t)
	hdr := headerRecord()

	// The header, then a frame claiming more than recordMax. Nothing is
	// allocated for it, and replay ends before it rather than trusting it.
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, uint32(recordMax)+1)
	oversized := append(body, make([]byte, 8)...)
	seed := append(frame(hdr), oversized...)
	if err := os.WriteFile(path, seed, 0o640); err != nil {
		t.Fatalf("seed: %v", err)
	}
	l, opened, err := openLog(t, path, hdr)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(opened.Records) != 1 {
		t.Fatalf("replayed %d records, want only the header", len(opened.Records))
	}
	if opened.Discarded != int64(len(oversized)) {
		t.Errorf("discarded %d bytes, want the whole oversized frame (%d)", opened.Discarded, len(oversized))
	}
	if err := l.close(false); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestRecordLogCompactReplacesAndKeepsAppending(t *testing.T) {
	path := logPath(t)
	hdr := headerRecord()

	l, _, err := openLog(t, path, hdr)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < 50; i++ {
		if err := l.append([]byte(fmt.Sprintf("churn %d", i))); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := l.flush(true); err != nil {
		t.Fatalf("flush: %v", err)
	}
	before := fileSize(t, path)

	replacement := [][]byte{hdr, []byte("kept")}
	if err := l.compact(replacement); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if l.sinceLastCompact() != 0 {
		t.Errorf("bytes since compaction = %d, want the counter to start over", l.sinceLastCompact())
	}
	if err := l.append([]byte("appended after")); err != nil {
		t.Fatalf("append after compaction: %v", err)
	}
	if err := l.close(true); err != nil {
		t.Fatalf("close: %v", err)
	}
	// The replacement file must be the only thing left: a stray .compact beside
	// it would outlive every log entry it held.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("store directory holds %v, want only the log", names(entries))
	}

	_, opened, err := openLog(t, path, hdr)
	if err != nil {
		t.Fatalf("reopen after compaction: %v", err)
	}
	want := []string{string(hdr), "kept", "appended after"}
	if len(opened.Records) != len(want) {
		t.Fatalf("replayed %q, want %q", opened.Records, want)
	}
	for i, w := range want {
		if string(opened.Records[i]) != w {
			t.Errorf("record %d = %q, want %q", i, opened.Records[i], w)
		}
	}
	if after := fileSize(t, path); after >= before {
		t.Errorf("compaction left %d bytes, which is not smaller than the %d it replaced", after, before)
	}
}

func names(entries []os.DirEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func TestRecordLogUnflushedBytesAreNotReplayed(t *testing.T) {
	path := logPath(t)
	hdr := headerRecord()

	l, _, err := openLog(t, path, hdr)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := l.append([]byte("still buffered")); err != nil {
		t.Fatalf("append: %v", err)
	}
	// Abandon the handle without flushing, which is what a panic looks like: the
	// bytes never left the process, so nothing of the record may survive on disk.
	if err := l.f.Close(); err != nil {
		t.Fatalf("close without flush: %v", err)
	}

	_, opened, err := openLog(t, path, hdr)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if len(opened.Records) != 1 || string(opened.Records[0]) != string(hdr) {
		t.Fatalf("replayed %q, want only the header", opened.Records)
	}
	if opened.Discarded != 0 {
		t.Errorf("discarded %d bytes, want none: the buffered record was never written", opened.Discarded)
	}
}

// recordMax is not only a bound on what replay will read. A longer record stops
// the replay there and everything after it is counted as a torn tail, so writing
// one would silently delete the sessions that follow. Both paths that put bytes
// in the file have to refuse instead.
func TestRecordLogRefusesARecordReplayWouldLose(t *testing.T) {
	path := logPath(t)
	hdr := headerRecord()

	l, _, err := openLog(t, path, hdr)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	before := fileSize(t, path)
	big := bytes.Repeat([]byte("q"), recordMax+1)

	if err := l.append(big); !errors.Is(err, ErrBadStore) {
		t.Fatalf("append of an oversized record = %v, want ErrBadStore", err)
	}
	if got := fileSize(t, path); got != before {
		t.Fatalf("a refused append grew the file to %d bytes, was %d", got, before)
	}
	// Refusing one record is not the log giving up.
	if err := l.append([]byte("after")); err != nil {
		t.Fatalf("append after a refusal: %v", err)
	}
	if err := l.flush(false); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if err := l.compact([][]byte{hdr, big}); !errors.Is(err, ErrBadStore) {
		t.Fatalf("compact over an oversized record = %v, want ErrBadStore", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("store directory holds %v, want only the log", names(entries))
	}
	if got := fileSize(t, path); got <= before {
		t.Fatalf("the log is %d bytes after a refused compaction, want the records it already held", got)
	}

	if err := l.close(false); err != nil {
		t.Fatalf("close: %v", err)
	}
	_, opened, err := openLog(t, path, hdr)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if len(opened.Records) != 2 || string(opened.Records[1]) != "after" {
		t.Fatalf("replayed %q, want the header and the record that fit", opened.Records)
	}
	if opened.Discarded != 0 {
		t.Errorf("discarded %d bytes, want none", opened.Discarded)
	}
}
