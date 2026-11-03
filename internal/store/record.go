package store

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// The log format, in one sentence: a header record naming the format, then
// records appended in order, each one a 4-byte big-endian length, that many
// payload bytes, and a 4-byte CRC-32 of the payload. Nothing else is on the
// file, so a crash leaves at most one half-written record at the end and the
// fix is to stop reading there.
//
// A format that replays without a schema migration is worth more here than a
// compact one: these files outlive the build that wrote them.
const logVersion = "congmq-store-v1"

// recordMax bounds one record on read. A session holding the default
// 1000-message queue stays far below it, so a longer value means the file is
// not one this program wrote, rather than that it is merely large.
const recordMax = 64 << 20

// ErrBadStore reports a file that is not a store log, or is too damaged to
// guess at. The broker refuses to start rather than write over it: moving a
// file aside is always recoverable, silently losing every offline message is
// not.
var ErrBadStore = errors.New("congmq: unusable store file")

// LogOpen is what replaying a log produced.
type LogOpen struct {
	// Records are the payloads, oldest first. A later record for the same key
	// replaces an earlier one; that is the caller's business, not the log's.
	Records [][]byte
	// Discarded counts trailing bytes cut off because they did not form a whole
	// record, which is what a hard kill looks like on disk.
	Discarded int64
}

// recordLog is an append-only file of framed records, safe for concurrent use.
// It knows nothing about sessions: it stores bytes and hands them back in order.
type recordLog struct {
	path string
	f    *os.File
	w    *bufio.Writer

	mu           sync.Mutex
	pending      int64 // queued and not yet written to the file
	sinceCompact int64 // bytes appended since the file was last rewritten whole
}

// openRecordLog reads the log at path and returns it ready for appending. A
// missing or empty file is created and given header as its first record.
func openRecordLog(path string, header []byte) (*recordLog, LogOpen, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o640)
	if err != nil {
		return nil, LogOpen{}, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, LogOpen{}, err
	}
	l := &recordLog{path: path, f: f, w: bufio.NewWriterSize(f, 32<<10)}

	recs, discarded, err := replay(f, header)
	if err != nil {
		_ = f.Close()
		return nil, LogOpen{}, err
	}
	if len(recs) == 0 && info.Size() > 0 {
		// Bytes that will not frame into even one record are not a store log,
		// however they got there. Refusing is recoverable - an operator can move
		// the file aside - erasing somebody's data because it looked odd is not.
		_ = f.Close()
		return nil, LogOpen{}, fmt.Errorf("%w: %s holds %d bytes that are not records",
			ErrBadStore, path, info.Size())
	}
	if discarded > 0 {
		// Cut the torn tail off the file, so the next append does not sit behind
		// bytes a later replay would read as corruption.
		if err := f.Truncate(info.Size() - discarded); err != nil {
			_ = f.Close()
			return nil, LogOpen{}, err
		}
	}
	if len(recs) == 0 {
		// A brand new file. The header goes down before any payload can queue
		// behind it, because it is what tells this log from an unrelated file that
		// happens to share the name.
		if err := l.append(header); err != nil {
			_ = f.Close()
			return nil, LogOpen{}, err
		}
		if err := l.flush(true); err != nil {
			_ = f.Close()
			return nil, LogOpen{}, err
		}
		return l, LogOpen{}, nil
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return nil, LogOpen{}, err
	}
	return l, LogOpen{Records: recs, Discarded: discarded}, nil
}

// replay walks the file from the front and stops at the first record it cannot
// trust. Everything before that point is kept.
func replay(f *os.File, header []byte) ([][]byte, int64, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, 0, err
	}
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, 0, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, 0, err
	}

	var (
		recs   [][]byte
		pos    int64
		length = make([]byte, 4)
	)
	for pos < size {
		n, err := readAtLeast(f, length)
		if err != nil {
			// A partial length field is a crash mid-append. Whatever sits behind
			// an incomplete header cannot be told from garbage, so it goes.
			return recs, size - pos, nil
		}
		hdr := int64(n)
		body := int64(binary.BigEndian.Uint32(length))
		if body == 0 || pos+hdr+body+4 > size || body > recordMax {
			return recs, size - pos, nil
		}
		buf := make([]byte, body+4)
		if _, err := io.ReadFull(f, buf); err != nil {
			return recs, size - pos, nil
		}
		payload := buf[:body]
		if crc32.ChecksumIEEE(payload) != binary.BigEndian.Uint32(buf[body:]) {
			return recs, size - pos, nil
		}
		if len(recs) == 0 && !bytes.Equal(payload, header) {
			return nil, 0, fmt.Errorf("%w: %s does not start with %q", ErrBadStore, f.Name(), logVersion)
		}
		recs = append(recs, payload)
		pos += hdr + body + 4
	}
	return recs, 0, nil
}

// readAtLeast fills buf fully, reporting io.EOF only when nothing at all could
// be read, so a half-written header at the tail is not mistaken for a clean end.
func readAtLeast(f *os.File, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := f.Read(buf[total:])
		total += n
		if err != nil {
			if total == 0 && errors.Is(err, io.EOF) {
				return 0, io.EOF
			}
			return total, err
		}
	}
	return total, nil
}

// frame returns the on-disk form of one record.
func frame(payload []byte) []byte {
	buf := make([]byte, 4, 8+len(payload))
	binary.BigEndian.PutUint32(buf, uint32(len(payload)))
	buf = append(buf, payload...)
	return binary.BigEndian.AppendUint32(buf, crc32.ChecksumIEEE(payload))
}

// checkRecord refuses a payload that replay would not read back. A record
// longer than recordMax ends the log at that point and everything after it is
// counted as a torn tail, so writing one would quietly delete later sessions'
// state. The caller keeps that state in memory and is told why it will not go.
func checkRecord(payload []byte) error {
	if len(payload) > recordMax {
		return fmt.Errorf("%w: a %d byte record exceeds the %d byte limit",
			ErrBadStore, len(payload), recordMax)
	}
	return nil
}

// append queues one record. It reaches the file at the next flush, so a caller
// that must not lose it has to flush with sync.
func (l *recordLog) append(payload []byte) error {
	if err := checkRecord(payload); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := frame(payload)
	if _, err := l.w.Write(b); err != nil {
		return err
	}
	l.pending += int64(len(b))
	l.sinceCompact += int64(len(b))
	return nil
}

// flush writes queued records out, and to the platters when sync is set. The
// difference matters: without sync a process crash still preserves the bytes,
// because they reached the operating system, while a machine crash may not.
func (l *recordLog) flush(sync bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.flushLocked(sync)
}

func (l *recordLog) flushLocked(sync bool) error {
	if err := l.w.Flush(); err != nil {
		return err
	}
	l.pending = 0
	if sync {
		return l.f.Sync()
	}
	return nil
}

// compact rewrites the file so it holds exactly recs, then keeps appending to
// the new file. The old contents stay intact until the replacement is already
// on disk, so a crash during compaction costs the work and nothing else.
func (l *recordLog) compact(recs [][]byte) error {
	// Checked before the replacement file is opened: a record that will not fit
	// has to leave the live log exactly as it was, not half-rewritten.
	for _, r := range recs {
		if err := checkRecord(r); err != nil {
			return err
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	tmp := l.path + ".compact"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	for _, r := range recs {
		if _, err := out.Write(frame(r)); err != nil {
			_ = out.Close()
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}

	// The live handle has to let go before the replacement: Windows will not
	// rename over an open file. Nothing is appended between the close and the
	// reopen, because this method holds the log's mutex throughout.
	if err := l.flushLocked(false); err != nil {
		return err
	}
	if err := l.f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, l.path); err != nil {
		return fmt.Errorf("replace %s: %w", l.path, err)
	}
	f, err := os.OpenFile(l.path, os.O_RDWR|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	// Fields, not *l = recordLog{...}: the mutex is held right now, and
	// overwriting it with a zero value would make the deferred Unlock panic.
	l.f = f
	l.w = bufio.NewWriterSize(f, 32<<10)
	l.pending = 0
	l.sinceCompact = 0

	// A rename is only durable if the directory is flushed too. On Windows a
	// directory cannot be opened for this, and the error is ignored rather than
	// fatal, because the rename itself did happen.
	if dir, err := os.Open(filepath.Dir(l.path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// sinceLastCompact reports how many bytes have been appended since the file was
// last rewritten whole, which is what a compaction threshold is compared to.
func (l *recordLog) sinceLastCompact() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sinceCompact
}

func (l *recordLog) close(sync bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.flushLocked(sync); err != nil {
		_ = l.f.Close()
		return err
	}
	return l.f.Close()
}
