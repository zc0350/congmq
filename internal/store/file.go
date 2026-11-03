package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// SyncMode is the bargain the store strikes with the disk. There is no fourth
// option that costs nothing: either a write waits for the platters, or a crash
// can undo writes the broker already took responsibility for.
type SyncMode string

const (
	// SyncEverysec coalesces snapshots and flushes at most once a second,
	// losing at most a second of offline queue while keeping throughput off the
	// back of one fsync per message.
	SyncEverysec SyncMode = "everysec"
	// SyncAlways holds Put until its record has reached the disk. A crash then
	// loses nothing the broker had acknowledged, and every queued message pays
	// for an fsync.
	SyncAlways SyncMode = "always"
	// SyncNever flushes but never fsyncs. A killed process still leaves its
	// bytes with the operating system; a machine that loses power may not.
	SyncNever SyncMode = "never"
)

// Will is a last will waiting out its Will Delay Interval. It belongs to no
// session, so it needs a durable home of its own: a broker that restarts inside
// the delay window still owes the world that message.
type Will struct {
	ClientID string
	Msg      Message
	FireAt   time.Time
}

// Durable is the part of a broker's state that belongs to no session: the
// retained message of a topic, and a will waiting out its delay. Sessions have
// Store; without this, both of these die with the process.
//
// Every method reports its failure rather than swallowing it. A store that will
// not write must not disconnect publishers, but it must not be quiet either.
type Durable interface {
	// LoadRetained returns the retained messages left on disk, ordered by topic
	// so a restart replays them the same way every time.
	LoadRetained() []Message
	Retain(m Message) error
	ForgetRetained(topic string) error
	// LoadWills returns the delayed wills still owed, due first.
	LoadWills() []Will
	DeferWill(w Will) error
	ForgetWill(clientID string) error
}

// FileStoreOptions configures a FileStore.
type FileStoreOptions struct {
	// Dir holds the state file. It is created if missing.
	Dir string
	// Sync is the durability bargain; empty means SyncEverysec.
	Sync SyncMode
	// CompactAfter rewrites the file once this many bytes have been appended
	// since the last rewrite. Zero means the default of 32MB.
	CompactAfter int64
	// FlushInterval bounds how long a coalesced snapshot waits on the writer.
	// Zero means one second.
	FlushInterval time.Duration
	// OnError receives the failures a background flush cannot hand back to a
	// caller. The broker wires it to its log; a store that will not write must
	// not disconnect publishers, but it must not be quiet either.
	OnError func(error)
}

func (o *FileStoreOptions) withDefaults() {
	if o.Sync == "" {
		o.Sync = SyncEverysec
	}
	if o.CompactAfter <= 0 {
		o.CompactAfter = 32 << 20
	}
	if o.FlushInterval <= 0 {
		o.FlushInterval = time.Second
	}
}

// stateFileName is the one file a FileStore owns inside its directory.
const stateFileName = "state.log"

// record is one entry of the state log. The op says which map to touch; a later
// record for the same key replaces an earlier one, and a delete is a tombstone
// rather than an absent record, because absence cannot be replayed.
type record struct {
	Op       string   `json:"op"`
	ClientID string   `json:"client,omitempty"`
	Topic    string   `json:"topic,omitempty"`
	Session  *Session `json:"session,omitempty"`
	Message  *Message `json:"msg,omitempty"`
	Will     *Will    `json:"will,omitempty"`
}

const (
	opHeader      = "header"
	opSession     = "session"
	opSessionGone = "session-deleted"
	opRetain      = "retain"
	opRetainGone  = "retain-deleted"
	opWill        = "will"
	opWillGone    = "will-deleted"
)

// headerRecord names the format. It is compared byte for byte when a file is
// opened, which is what tells this file from an unrelated one that happens to
// share the name.
func headerRecord() []byte {
	b, err := json.Marshal(record{Op: opHeader, ClientID: logVersion})
	if err != nil {
		// A struct of strings cannot fail to marshal, and a store that cannot
		// name its own format is not worth opening.
		panic("store: header does not marshal: " + err.Error())
	}
	return b
}

// FileStore keeps the broker's durable state in one append-only file: offline
// sessions, retained messages and delayed wills. It satisfies Store, so the
// broker's session handling is unchanged, and Durable for the other two.
//
// Sessions are the only large and hot part of it, so their snapshots are
// coalesced in memory and written by one background writer. Retained messages
// and wills are small and rare enough to be appended as they happen.
type FileStore struct {
	opt  FileStoreOptions
	path string
	log  *recordLog

	mu       sync.Mutex
	sessions map[string]*Session
	retained map[string]Message
	wills    map[string]Will

	// dirty holds the newest snapshot per client since the last write, so a
	// session whose queue grew a hundred times in one second is written once.
	dirty map[string]*Session
	// gone lists clients whose session was deleted and still needs a tombstone.
	gone map[string]bool

	// Discarded counts the trailing bytes cut off at open, so an operator can be
	// told that the crash cost something instead of being reassured for free.
	Discarded int64

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// interface documentation: FileStore is both the session store and the durable
// home of everything else.
var (
	_ Store   = (*FileStore)(nil)
	_ Durable = (*FileStore)(nil)
)

// NewFileStore opens, or creates, the store in opt.Dir and replays what is
// already there.
func NewFileStore(opt FileStoreOptions) (*FileStore, error) {
	opt.withDefaults()
	if opt.Dir == "" {
		return nil, errors.New("store: FileStore needs a directory")
	}
	switch opt.Sync {
	case SyncEverysec, SyncAlways, SyncNever:
	default:
		return nil, fmt.Errorf("store: unknown sync mode %q", opt.Sync)
	}
	if err := os.MkdirAll(opt.Dir, 0o750); err != nil {
		return nil, err
	}

	path := filepath.Join(opt.Dir, stateFileName)
	lg, opened, err := openRecordLog(path, headerRecord())
	if err != nil {
		return nil, err
	}

	fs := &FileStore{
		opt:       opt,
		path:      path,
		log:       lg,
		sessions:  make(map[string]*Session),
		retained:  make(map[string]Message),
		wills:     make(map[string]Will),
		dirty:     make(map[string]*Session),
		gone:      make(map[string]bool),
		Discarded: opened.Discarded,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	if err := fs.apply(opened.Records); err != nil {
		_ = lg.close(false)
		return nil, err
	}
	go fs.writer()
	return fs, nil
}

// apply folds the log into the in-memory maps, oldest first.
func (fs *FileStore) apply(recs [][]byte) error {
	for _, raw := range recs {
		var r record
		if err := json.Unmarshal(raw, &r); err != nil {
			return fmt.Errorf("%w: %v", ErrBadStore, err)
		}
		switch r.Op {
		case opHeader:
			continue
		case opSession:
			if r.Session == nil || r.Session.ClientID == "" {
				return fmt.Errorf("%w: session record has no identifier", ErrBadStore)
			}
			fs.sessions[r.Session.ClientID] = r.Session
		case opSessionGone:
			delete(fs.sessions, r.ClientID)
		case opRetain:
			if r.Message == nil {
				return fmt.Errorf("%w: retain record has no message", ErrBadStore)
			}
			// An empty payload is how a retained message is deleted, so the rule
			// that applies it lives here too, not only in the broker.
			if len(r.Message.Payload) == 0 {
				delete(fs.retained, r.Message.Topic)
				continue
			}
			msg := r.Message.Clone()
			fs.retained[msg.Topic] = msg
		case opRetainGone:
			delete(fs.retained, r.Topic)
		case opWill:
			if r.Will == nil || r.Will.ClientID == "" {
				return fmt.Errorf("%w: will record has no client", ErrBadStore)
			}
			w := *r.Will
			w.Msg = w.Msg.Clone()
			fs.wills[w.ClientID] = w
		case opWillGone:
			delete(fs.wills, r.ClientID)
		default:
			return fmt.Errorf("%w: unknown op %q", ErrBadStore, r.Op)
		}
	}
	return nil
}

// Path is the state file this store appends to. It is read-only information for
// whoever started the broker: a log line naming the exact file beats one naming
// the directory the operator then has to guess inside.
func (fs *FileStore) Path() string { return fs.path }

// Get returns a detached copy of a stored session.
func (fs *FileStore) Get(clientID string) (*Session, bool) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	s, ok := fs.sessions[clientID]
	if !ok {
		return nil, false
	}
	return s.clone(), true
}

// Put replaces a session. Under SyncAlways this call is the durable one; under
// the other modes the newest snapshot is written by the next flush, which is why
// the in-memory map is updated before anything is queued.
func (fs *FileStore) Put(s *Session) error {
	if s == nil || s.ClientID == "" {
		return errors.New("store: session needs a client identifier")
	}
	c := s.clone()
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.sessions[c.ClientID] = c
	fs.dirty[c.ClientID] = c
	delete(fs.gone, c.ClientID)
	return fs.applyPolicyLocked()
}

// Delete forgets a session, discarding its queued messages.
func (fs *FileStore) Delete(clientID string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	delete(fs.sessions, clientID)
	delete(fs.dirty, clientID)
	fs.gone[clientID] = true
	return fs.applyPolicyLocked()
}

// applyPolicyLocked writes and syncs whatever is pending if the mode says a
// caller may not proceed until it is on disk. The caller holds fs.mu.
func (fs *FileStore) applyPolicyLocked() error {
	if fs.opt.Sync != SyncAlways {
		return nil
	}
	if err := fs.queueLocked(); err != nil {
		return err
	}
	return fs.log.flush(true)
}

// queueLocked appends a record for every dirty session and every pending
// deletion. Sessions are written as whole snapshots, so a record that fails to
// marshal loses only its own client's queue; the broker is told, and the next
// snapshot carries the same state again.
func (fs *FileStore) queueLocked() error {
	var firstErr error
	for id, s := range fs.dirty {
		raw, err := json.Marshal(record{Op: opSession, Session: s})
		if err != nil {
			delete(fs.dirty, id)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := fs.log.append(raw); err != nil {
			return err
		}
		delete(fs.dirty, id)
	}
	for id := range fs.gone {
		raw, err := json.Marshal(record{Op: opSessionGone, ClientID: id})
		if err != nil {
			delete(fs.gone, id)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := fs.log.append(raw); err != nil {
			return err
		}
		delete(fs.gone, id)
	}
	return firstErr
}

// Sessions lists every stored session, detached.
func (fs *FileStore) Sessions() []*Session {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	out := make([]*Session, 0, len(fs.sessions))
	for _, s := range fs.sessions {
		out = append(out, s.clone())
	}
	return out
}

// LoadRetained returns the retained messages left on disk, by topic.
func (fs *FileStore) LoadRetained() []Message {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	out := make([]Message, 0, len(fs.retained))
	for _, m := range fs.retained {
		out = append(out, m.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Topic < out[j].Topic })
	return out
}

// Retain records m as the retained message of its topic, or clears the topic
// when the payload is empty, which is how a publisher deletes one.
func (fs *FileStore) Retain(m Message) error {
	c := m.Clone()
	r := record{Op: opRetain, Topic: c.Topic, Message: &c}
	if len(c.Payload) == 0 {
		r = record{Op: opRetainGone, Topic: c.Topic}
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(c.Payload) == 0 {
		delete(fs.retained, c.Topic)
	} else {
		c.Retain = true
		fs.retained[c.Topic] = c
	}
	return fs.appendNowLocked(r)
}

// ForgetRetained drops a topic's retained message, which is what the expiry
// reaper does when one ages out.
func (fs *FileStore) ForgetRetained(topic string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	delete(fs.retained, topic)
	return fs.appendNowLocked(record{Op: opRetainGone, Topic: topic})
}

// LoadWills returns the delayed wills still owed, due first.
func (fs *FileStore) LoadWills() []Will {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	out := make([]Will, 0, len(fs.wills))
	for _, w := range fs.wills {
		c := w
		c.Msg = w.Msg.Clone()
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FireAt.Before(out[j].FireAt) })
	return out
}

// DeferWill records a will waiting out its delay.
func (fs *FileStore) DeferWill(w Will) error {
	c := w
	c.Msg = w.Msg.Clone()
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.wills[c.ClientID] = c
	return fs.appendNowLocked(record{Op: opWill, ClientID: c.ClientID, Will: &c})
}

// ForgetWill drops a client's pending will once it has fired or been withdrawn.
func (fs *FileStore) ForgetWill(clientID string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	delete(fs.wills, clientID)
	return fs.appendNowLocked(record{Op: opWillGone, ClientID: clientID})
}

// appendNowLocked writes one small record. Retained messages and wills are not
// coalesced because they are neither large nor hot; the sync policy still
// decides whether the write is on disk before the caller is told it succeeded.
func (fs *FileStore) appendNowLocked(r record) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := fs.log.append(raw); err != nil {
		return err
	}
	if fs.opt.Sync == SyncAlways {
		return fs.log.flush(true)
	}
	return nil
}

// writer is the only goroutine that flushes outside a synchronous caller, which
// is what keeps one append order across coalesced snapshots and inline records.
func (fs *FileStore) writer() {
	defer close(fs.done)
	tick := time.NewTicker(fs.opt.FlushInterval)
	defer tick.Stop()
	for {
		select {
		case <-fs.stop:
			return
		case <-tick.C:
			fs.mu.Lock()
			err := fs.queueLocked()
			if err == nil {
				err = fs.log.flush(fs.opt.Sync != SyncNever)
			}
			grown := fs.log.sinceLastCompact() > fs.opt.CompactAfter
			fs.mu.Unlock()
			if err != nil {
				fs.report(err)
			}
			if grown {
				if err := fs.Compact(); err != nil {
					fs.report(err)
				}
			}
		}
	}
}

// report hands an error to the callback the broker installed. Nothing here
// retries: the next flush carries the same state again, because dirty is only
// cleared once the bytes are queued.
func (fs *FileStore) report(err error) {
	if fs.opt.OnError != nil {
		fs.opt.OnError(err)
	}
}

// Compact rewrites the file down to live state, so a long-lived broker's store
// stays the size of what it still holds rather than of everything it ever saw.
func (fs *FileStore) Compact() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	recs := [][]byte{headerRecord()}
	for _, s := range fs.sessions {
		if err := fs.appendRecLocked(&recs, record{Op: opSession, Session: s}); err != nil {
			return err
		}
	}
	for _, m := range fs.retained {
		msg := m
		if err := fs.appendRecLocked(&recs, record{Op: opRetain, Topic: msg.Topic, Message: &msg}); err != nil {
			return err
		}
	}
	for _, w := range fs.wills {
		will := w
		if err := fs.appendRecLocked(&recs, record{Op: opWill, ClientID: will.ClientID, Will: &will}); err != nil {
			return err
		}
	}
	// Sessions are snapshotted from fs.sessions, which Put updates before it
	// queues, and deletions are already folded in, so the pending sets are
	// redundant here and the rewrite below discards whatever they had queued.
	fs.dirty = make(map[string]*Session)
	fs.gone = make(map[string]bool)
	return fs.log.compact(recs)
}

// appendRecLocked marshals one record for the compaction list. A state that
// cannot marshal aborts the rewrite: a half-written replacement would drop it.
func (fs *FileStore) appendRecLocked(dst *[][]byte, r record) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	*dst = append(*dst, raw)
	return nil
}

// Close stops the writer, writes what is still dirty and rewrites the file, so
// a clean shutdown leaves a small log rather than a growing one. Closing twice
// is safe and returns the first result, because a broker under construction may
// reach it from more than one teardown path.
func (fs *FileStore) Close() error {
	fs.closeOnce.Do(fs.closeLocked)
	return fs.closeErr
}

func (fs *FileStore) closeLocked() {
	close(fs.stop)
	<-fs.done
	if err := fs.Compact(); err != nil {
		fs.mu.Lock()
		_ = fs.log.close(false)
		fs.mu.Unlock()
		fs.closeErr = err
		return
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.closeErr = fs.log.close(fs.opt.Sync != SyncNever)
}

// crash stops the writer and lets go of the file without the clean-shutdown
// rewrite. It exists so a test can ask what a killed process leaves behind; a
// later Close is a no-op.
func (fs *FileStore) crash() {
	fs.closeOnce.Do(func() {
		close(fs.stop)
		<-fs.done
		_ = fs.log.f.Close()
	})
}
