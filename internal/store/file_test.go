package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zc0350/congmq/internal/packets"
)

// openStore opens the store in dir and arranges for it to be closed, so a test
// that gives up partway still leaves Windows a deletable temp directory.
func openStore(t *testing.T, dir string, tweak func(*FileStoreOptions)) *FileStore {
	t.Helper()
	opt := FileStoreOptions{Dir: dir, FlushInterval: 20 * time.Millisecond}
	if tweak != nil {
		tweak(&opt)
	}
	fs, err := NewFileStore(opt)
	if err != nil {
		t.Fatalf("open store in %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = fs.Close() })
	return fs
}

// settle lets the background writer take at least one tick.
func settle(fs *FileStore) {
	time.Sleep(6 * fs.opt.FlushInterval)
}

// The session below is built from fixed instants, so two calls to sampleSession
// compare equal: what a test reloads must be byte-identical to what it stored,
// with no "close enough" allowed for the clocks.
var (
	storedSessionExpiry = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	storedMessageExpiry = time.Date(2026, 11, 3, 11, 30, 0, 0, time.UTC)
)

func sampleSession(id string) *Session {
	props := &packets.Properties{}
	props.SetContentType("application/json")
	props.AddUser("device", "a1")

	q := &packets.Properties{}
	q.SetMessageExpiry(0) // present and zero: the case a reflected encoding loses

	return &Session{
		ClientID:     id,
		Username:     "tester",
		RemoteIP:     "10.0.0.8",
		NextPacketID: 77,
		Proto:        packets.V5,
		Expiry:       storedSessionExpiry,
		Subscriptions: map[string]Sub{
			"a/b":           {QoS: 2, NoLocal: true, RetainAsPublished: true, RetainHandling: 1, ID: 5},
			"c/#":           {QoS: 1},
			"$share/g1/a/b": {QoS: 0},
		},
		Inflight: []Message{{
			Topic: "a/b", Payload: []byte("unacked"), QoS: 1, PacketID: 12,
			Dir: Outbound, Stage: StageAwaitPubRel, Attempts: 2, Props: props,
			Expires: storedMessageExpiry,
		}},
		Queued: []Message{{
			Topic: "c/#", Payload: []byte("queued"), QoS: 2, PacketID: 13,
			Dir: Outbound, Stage: StageAwaitPubRec, Props: q,
		}},
	}
}

func sameSession(t *testing.T, got, want *Session) {
	t.Helper()
	if got == nil {
		t.Fatal("session is missing from the store")
	}
	if got.ClientID != want.ClientID || got.Username != want.Username || got.RemoteIP != want.RemoteIP {
		t.Errorf("identity = %q/%q/%q, want %q/%q/%q", got.ClientID, got.Username, got.RemoteIP,
			want.ClientID, want.Username, want.RemoteIP)
	}
	if got.NextPacketID != want.NextPacketID {
		t.Errorf("next packet id = %d, want %d: restarting it would duplicate deliveries", got.NextPacketID, want.NextPacketID)
	}
	if got.Proto != want.Proto {
		t.Errorf("protocol = %d, want %d: a restored 5.0 session must still write property areas", got.Proto, want.Proto)
	}
	if !got.Expiry.Equal(want.Expiry) {
		t.Errorf("expiry = %v, want %v", got.Expiry, want.Expiry)
	}
	if len(got.Subscriptions) != len(want.Subscriptions) {
		t.Fatalf("replayed %d subscriptions, want %d", len(got.Subscriptions), len(want.Subscriptions))
	}
	for f, w := range want.Subscriptions {
		g, ok := got.Subscriptions[f]
		if !ok {
			t.Errorf("subscription %q was not restored", f)
			continue
		}
		if g != w {
			t.Errorf("subscription %q = %+v, want %+v", f, g, w)
		}
	}
	if len(got.Inflight) != len(want.Inflight) {
		t.Fatalf("inflight = %d messages, want %d", len(got.Inflight), len(want.Inflight))
	}
	if len(got.Queued) != len(want.Queued) {
		t.Fatalf("queued = %d messages, want %d", len(got.Queued), len(want.Queued))
	}
	for i, w := range want.Inflight {
		sameMessage(t, got.Inflight[i], w, "inflight")
	}
	for i, w := range want.Queued {
		sameMessage(t, got.Queued[i], w, "queued")
	}
}

func sameMessage(t *testing.T, got, want Message, what string) {
	t.Helper()
	if got.Topic != want.Topic || !bytes.Equal(got.Payload, want.Payload) {
		t.Errorf("%s message = %q/%q, want %q/%q", what, got.Topic, got.Payload, want.Topic, want.Payload)
	}
	if got.QoS != want.QoS || got.Retain != want.Retain || got.Dup != want.Dup {
		t.Errorf("%s message flags = qos %d retain %v dup %v, want qos %d retain %v dup %v",
			what, got.QoS, got.Retain, got.Dup, want.QoS, want.Retain, want.Dup)
	}
	if got.PacketID != want.PacketID || got.Dir != want.Dir || got.Stage != want.Stage || got.Attempts != want.Attempts {
		t.Errorf("%s message handoff = id %d dir %d stage %d attempts %d, want id %d dir %d stage %d attempts %d",
			what, got.PacketID, got.Dir, got.Stage, got.Attempts, want.PacketID, want.Dir, want.Stage, want.Attempts)
	}
	if !got.Expires.Equal(want.Expires) {
		t.Errorf("%s message expiry = %v, want %v", what, got.Expires, want.Expires)
	}
	if (got.Props == nil) != (want.Props == nil) {
		t.Fatalf("%s message properties = %v, want presence to match", what, got.Props)
	}
	if got.Props == nil {
		return
	}
	// The binary form is the wire form, so an identical encoding proves the
	// presence mask as well as the values came back.
	gb, err := got.Props.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal restored properties: %v", err)
	}
	wb, err := want.Props.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal expected properties: %v", err)
	}
	if !bytes.Equal(gb, wb) {
		t.Errorf("%s message properties = %x, want %x", what, gb, wb)
	}
}

func TestFileStoreSessionSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	fs := openStore(t, dir, nil)

	want := sampleSession("persist-me")
	if err := fs.Put(want); err != nil {
		t.Fatalf("put: %v", err)
	}
	// A caller that keeps editing the session it handed over must not be able to
	// change what the store holds.
	want.Queued[0].Payload[0] = 'X'
	want.Subscriptions["late"] = Sub{QoS: 1}

	if err := fs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	fs = openStore(t, dir, nil)
	got, ok := fs.Get("persist-me")
	if !ok {
		t.Fatal("the session was not replayed")
	}
	sameSession(t, got, sampleSession("persist-me"))

	// Mutating the copy must not reach the stored state either.
	got.NextPacketID = 1
	if again, _ := fs.Get("persist-me"); again.NextPacketID != 77 {
		t.Error("Get handed back the stored session itself, not a copy")
	}
}

// TestFileStoreKeepsPropertyPresence is the reason the property area is stored
// as its wire form: a reflected encoding drops the mask, and then a publisher
// that said "expire this message in zero seconds" comes back as one that said
// nothing at all - the opposite instruction.
func TestFileStoreKeepsPropertyPresence(t *testing.T) {
	dir := t.TempDir()
	fs := openStore(t, dir, nil)

	zero := &packets.Properties{}
	zero.SetMessageExpiry(0)
	zero.SetPayloadFormat(0)
	zero.SetContentType("")
	zero.AddUser("empty", "")

	silent := &packets.Properties{}
	silent.AddUser("only", "this")

	s := &Session{
		ClientID: "props",
		Queued: []Message{
			{Topic: "a", Payload: []byte("zero"), QoS: 1, Props: zero},
			{Topic: "b", Payload: []byte("silent"), QoS: 1, Props: silent},
			{Topic: "c", Payload: []byte("v311"), QoS: 0},
		},
	}
	if err := fs.Put(s); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	fs = openStore(t, dir, nil)
	got, ok := fs.Get("props")
	if !ok {
		t.Fatal("the session was not replayed")
	}
	if len(got.Queued) != 3 {
		t.Fatalf("replayed %d messages, want 3", len(got.Queued))
	}
	first := got.Queued[0].Props
	if first == nil {
		t.Fatal("the properties of the first message vanished")
	}
	for _, id := range []byte{packets.PropMessageExpiry, packets.PropPayloadFormat, packets.PropContentType} {
		if !first.Has(id) {
			t.Errorf("property %#02x was present and zero on disk, and is now absent", id)
		}
	}
	if _, ok := first.UserValue("empty"); !ok {
		t.Error("a user property with an empty value was dropped")
	}
	if got.Queued[2].Props != nil {
		t.Errorf("a 3.1.1 message came back with properties: %v", got.Queued[2].Props)
	}
}

func TestFileStoreSessionDeletionOutlivesTheRestart(t *testing.T) {
	dir := t.TempDir()
	fs := openStore(t, dir, nil)

	if err := fs.Put(&Session{ClientID: "gone", Queued: []Message{{Topic: "a", Payload: []byte("x"), QoS: 1}}}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := fs.Delete("gone"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := fs.Get("gone"); ok {
		t.Fatal("the session is still readable in the store that deleted it")
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	fs = openStore(t, dir, nil)
	if _, ok := fs.Get("gone"); ok {
		t.Fatal("a deleted session came back after the restart: the tombstone was not written")
	}
	if got := fs.Sessions(); len(got) != 0 {
		t.Fatalf("replayed sessions %v, want none", got)
	}
}

// putOne writes a few sessions and then crashes instead of closing, so the
// caller sees exactly what the mode had made durable at that instant. wait lets
// the background writer take its ticks first; with the writer's interval set to
// an hour there are no ticks to wait for, and the test finishes on the spot.
func putOne(t *testing.T, mode SyncMode, interval time.Duration, flushes int, wait bool) string {
	t.Helper()
	dir := t.TempDir()
	fs := openStore(t, dir, func(o *FileStoreOptions) {
		o.Sync = mode
		o.FlushInterval = interval
	})
	for i := 0; i < flushes; i++ {
		s := &Session{ClientID: "slow", Queued: []Message{{Topic: "a", Payload: []byte(strings.Repeat("m", i+1)), QoS: 1}}}
		if err := fs.Put(s); err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	if wait {
		settle(fs)
	}
	fs.crash()
	return dir
}

// TestFileStoreSyncModes pins the bargain each mode strikes: always loses
// nothing the broker already took responsibility for, everysec loses whatever
// had not reached its next flush, and never is the same again after a process
// crash because the bytes did reach the operating system.
func TestFileStoreSyncModes(t *testing.T) {
	t.Run("always is durable on the call", func(t *testing.T) {
		dir := putOne(t, SyncAlways, time.Hour, 1, false)
		fs := openStore(t, dir, nil)
		s, ok := fs.Get("slow")
		if !ok || len(s.Queued) != 1 || string(s.Queued[0].Payload) != "m" {
			t.Fatalf("after a crash the store holds %v, want the one message Put reported", s)
		}
	})

	t.Run("everysec loses what had not been flushed", func(t *testing.T) {
		// The writer never got a tick, so nothing left the process. This is the
		// loss window the mode buys throughput with, and it is worth pinning
		// rather than explaining.
		dir := putOne(t, SyncEverysec, time.Hour, 1, false)
		fs := openStore(t, dir, nil)
		if _, ok := fs.Get("slow"); ok {
			t.Fatal("everysec promised to wait for the next flush, and did not")
		}
	})

	t.Run("everysec keeps the newest snapshot once the writer runs", func(t *testing.T) {
		dir := t.TempDir()
		fs := openStore(t, dir, func(o *FileStoreOptions) { o.Sync = SyncEverysec })
		for i := 1; i <= 20; i++ {
			s := &Session{ClientID: "chatty", Queued: []Message{{Topic: "a", Payload: []byte(strings.Repeat("m", i)), QoS: 1}}}
			if err := fs.Put(s); err != nil {
				t.Fatalf("put: %v", err)
			}
		}
		settle(fs)
		// Crash rather than Close: a clean shutdown compacts, and compaction would
		// rewrite the very evidence this checks. Twenty Puts must still be sitting
		// on disk as one snapshot, which is what keeps the file from growing by
		// the queue depth.
		fs.crash()
		l, opened, err := openRecordLog(filepath.Join(dir, stateFileName), headerRecord())
		if err != nil {
			t.Fatalf("read the log behind the store: %v", err)
		}
		_ = l.close(false)
		if len(opened.Records) != 2 {
			t.Errorf("the log holds %d records, want the header plus one coalesced snapshot", len(opened.Records))
		}

		fs = openStore(t, dir, nil)
		s, ok := fs.Get("chatty")
		if !ok {
			t.Fatal("the session was not replayed")
		}
		if len(s.Queued) != 1 {
			t.Fatalf("replayed %d queued messages, want one coalesced snapshot", len(s.Queued))
		}
		if len(s.Queued[0].Payload) != 20 {
			t.Errorf("replayed a queue holding %d bytes, want the newest snapshot of 20", len(s.Queued[0].Payload))
		}
	})

	t.Run("never survives a process crash but not a power loss", func(t *testing.T) {
		dir := putOne(t, SyncNever, 10*time.Millisecond, 1, true)
		// The writer flushed without fsyncing. A killed process still had its
		// bytes with the operating system, so a restart finds them; only a
		// machine crash can take them back, which no test here can simulate.
		fs := openStore(t, dir, nil)
		if s, ok := fs.Get("slow"); !ok || len(s.Queued) != 1 {
			t.Fatalf("after a process crash the store holds %v, want the flushed message", s)
		}
	})
}

func TestFileStoreCrashLeavesATornTailAndReportsIt(t *testing.T) {
	dir := t.TempDir()
	fs := openStore(t, dir, func(o *FileStoreOptions) { o.Sync = SyncAlways })
	want := sampleSession("torn")
	if err := fs.Put(want); err != nil {
		t.Fatalf("put: %v", err)
	}
	path := filepath.Join(dir, stateFileName)
	clean := fileSize(t, path)
	// The bytes a kill catches mid-append: a length header and part of a body.
	writeRaw(t, path, 0x00, 0x00, 0x20, 0x00, 0x11, 0x22)
	if grew := fileSize(t, path); grew != clean+6 {
		t.Fatalf("the torn bytes did not reach the file: %d, was %d", grew, clean)
	}
	fs.crash()

	fs = openStore(t, dir, nil)
	if fs.Discarded != 6 {
		t.Errorf("discarded %d bytes, want the 6 that were never a record", fs.Discarded)
	}
	if after := fileSize(t, path); after != clean {
		t.Errorf("the file is %d bytes after recovery, want the %d an intact session took: orphan bytes would be read as corruption on the next restart", after, clean)
	}
	got, ok := fs.Get("torn")
	if !ok {
		t.Fatal("the session that was already on disk did not come back")
	}
	sameSession(t, got, want)
	// And the store must still be writable after recovering from a torn tail.
	if err := fs.Put(sampleSession("after-torn")); err != nil {
		t.Fatalf("put after recovery: %v", err)
	}
}

func TestFileStoreRefusesAFileItDidNotWrite(t *testing.T) {
	hdr := string(headerRecord())

	t.Run("unknown op", func(t *testing.T) {
		dir := t.TempDir()
		raw := bytes.Join([][]byte{frame([]byte(hdr)), frame([]byte(`{"op":"teleport"}`))}, nil)
		if err := os.WriteFile(filepath.Join(dir, stateFileName), raw, 0o640); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, err := NewFileStore(FileStoreOptions{Dir: dir}); !errors.Is(err, ErrBadStore) {
			t.Fatalf("open error = %v, want ErrBadStore", err)
		}
	})

	t.Run("session without an identifier", func(t *testing.T) {
		dir := t.TempDir()
		raw := bytes.Join([][]byte{frame([]byte(hdr)), frame([]byte(`{"op":"session","session":{}}`))}, nil)
		if err := os.WriteFile(filepath.Join(dir, stateFileName), raw, 0o640); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, err := NewFileStore(FileStoreOptions{Dir: dir}); !errors.Is(err, ErrBadStore) {
			t.Fatalf("open error = %v, want ErrBadStore", err)
		}
	})

	t.Run("junk where the header should be", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, stateFileName), []byte("not a store"), 0o640); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, err := NewFileStore(FileStoreOptions{Dir: dir}); !errors.Is(err, ErrBadStore) {
			t.Fatalf("open error = %v, want ErrBadStore", err)
		}
	})

	t.Run("no directory", func(t *testing.T) {
		if _, err := NewFileStore(FileStoreOptions{}); err == nil {
			t.Fatal("a FileStore with nowhere to put its file was accepted")
		}
	})

	t.Run("unknown sync mode", func(t *testing.T) {
		// A typo in -store-sync must be a refusal to start, not a silent
		// downgrade to the default bargain.
		if _, err := NewFileStore(FileStoreOptions{Dir: t.TempDir(), Sync: SyncMode("durable-ish")}); err == nil {
			t.Fatal("an unknown sync mode was accepted")
		} else if !strings.Contains(err.Error(), "durable-ish") {
			t.Errorf("open error = %v, want it to name the mode it rejected", err)
		}
	})
}

func TestFileStoreRetainedMessagesComeBack(t *testing.T) {
	dir := t.TempDir()
	fs := openStore(t, dir, nil)

	for _, topic := range []string{"b/sensor", "a/sensor", "c/gone"} {
		m := Message{Topic: topic, QoS: 1, Retain: true, Payload: []byte("v-" + topic)}
		if topic == "c/gone" {
			m.Payload = nil // an empty payload is how a retained message is deleted
		}
		if err := fs.Retain(m); err != nil {
			t.Fatalf("retain %s: %v", topic, err)
		}
	}
	props := &packets.Properties{}
	props.SetContentType("text/plain")
	if err := fs.Retain(Message{Topic: "d/props", QoS: 2, Retain: true, Payload: []byte("hello"), Props: props}); err != nil {
		t.Fatalf("retain with properties: %v", err)
	}
	// Deleting through the explicit path must work too, and be durable.
	if err := fs.Retain(Message{Topic: "a/sensor", Payload: []byte("v-a/sensor")}); err != nil {
		t.Fatalf("retain again: %v", err)
	}
	if err := fs.ForgetRetained("b/sensor"); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	fs = openStore(t, dir, nil)
	got := fs.LoadRetained()
	var topics []string
	for _, m := range got {
		topics = append(topics, m.Topic)
	}
	// a/sensor came back because a retain without the flag still replaces the
	// topic's message; b/sensor was forgotten; c/gone was never stored.
	want := []string{"a/sensor", "d/props"}
	if strings.Join(topics, ",") != strings.Join(want, ",") {
		t.Fatalf("reloaded %v, want %v in topic order", topics, want)
	}
	if got[0].Retain != true {
		t.Error("a reloaded retained message lost its RETAIN flag")
	}
	if !got[1].Props.Has(packets.PropContentType) || got[1].Props.ContentType != "text/plain" {
		t.Errorf("reloaded properties = %v, want the content type back", got[1].Props)
	}
}

func TestFileStoreDeferredWillsComeBack(t *testing.T) {
	dir := t.TempDir()
	fs := openStore(t, dir, nil)

	due := time.Now().Add(2 * time.Minute).UTC()
	if err := fs.DeferWill(Will{ClientID: "late", Msg: Message{Topic: "w/late", QoS: 1, Payload: []byte("bye")}, FireAt: due.Add(time.Minute)}); err != nil {
		t.Fatalf("defer: %v", err)
	}
	if err := fs.DeferWill(Will{ClientID: "sooner", Msg: Message{Topic: "w/sooner", QoS: 0, Payload: []byte("bye sooner")}, FireAt: due}); err != nil {
		t.Fatalf("defer: %v", err)
	}
	if err := fs.DeferWill(Will{ClientID: "withdrawn", Msg: Message{Topic: "w/gone", Payload: []byte("never")}, FireAt: due}); err != nil {
		t.Fatalf("defer: %v", err)
	}
	if err := fs.ForgetWill("withdrawn"); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	fs = openStore(t, dir, nil)
	got := fs.LoadWills()
	if len(got) != 2 {
		t.Fatalf("reloaded %d wills, want the two that were still owed", len(got))
	}
	if got[0].ClientID != "sooner" || got[1].ClientID != "late" {
		t.Errorf("wills came back in order %q, %q, want due first", got[0].ClientID, got[1].ClientID)
	}
	if !got[1].FireAt.Equal(due.Add(time.Minute)) {
		t.Errorf("will delay = %v, want the interval to survive the restart", got[1].FireAt)
	}
	if string(got[0].Msg.Payload) != "bye sooner" || got[0].Msg.QoS != 0 {
		t.Errorf("reloaded will = %+v, want the message the client registered", got[0].Msg)
	}
}

func TestFileStoreCompactionKeepsTheFileBounded(t *testing.T) {
	dir := t.TempDir()
	fs := openStore(t, dir, func(o *FileStoreOptions) {
		o.Sync = SyncAlways
		o.CompactAfter = 8 << 10
	})

	big := bytes.Repeat([]byte("p"), 512)
	for i := 0; i < 40; i++ {
		s := &Session{ClientID: "grows", Queued: []Message{{Topic: "a", Payload: big, QoS: 1, PacketID: uint16(i)}}}
		if err := fs.Put(s); err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	settle(fs)
	size := fileSize(t, filepath.Join(dir, stateFileName))
	if size > 8<<10 {
		t.Errorf("the store file grew to %d bytes with an 8KB compaction threshold", size)
	}
	// store_bytes is the same number an operator would get from ls, and it is the
	// only way to tell a file compaction is holding down from one that stopped.
	if got := fs.DiskBytes(); got != size {
		t.Errorf("DiskBytes = %d, want the %d bytes the file actually holds", got, size)
	}
	// The log and the lock handle are the only two files allowed here: a leftover
	// state.log.compact would mean the rename never finished.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 2 || entries[0].Name() != lockFileName || entries[1].Name() != stateFileName {
		t.Fatalf("store directory holds %v, want %s and %s", names(entries), lockFileName, stateFileName)
	}

	if err := fs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	fs = openStore(t, dir, nil)
	s, ok := fs.Get("grows")
	if !ok {
		t.Fatal("compaction lost the session")
	}
	if len(s.Queued) != 1 || s.Queued[0].PacketID != 39 {
		t.Errorf("replayed queue %+v, want the newest snapshot", s.Queued)
	}
}

// TestFileStoreReportsAFailedFlush covers the one failure a background writer
// has no caller to hand back to: without the callback the broker would be
// silently unpersisted.
func TestFileStoreReportsAFailedFlush(t *testing.T) {
	dir := t.TempDir()
	fs := openStore(t, dir, func(o *FileStoreOptions) {
		o.Sync = SyncEverysec
		o.FlushInterval = 10 * time.Millisecond
	})
	// A closed handle is the store having nowhere to write.
	if err := fs.log.f.Close(); err != nil {
		t.Fatalf("close the handle behind the store: %v", err)
	}
	seen := make(chan error, 4)
	fs.opt.OnError = func(err error) { seen <- err }
	if err := fs.Put(&Session{ClientID: "unwritten"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	select {
	case err := <-seen:
		if err == nil {
			t.Fatal("the writer reported a nil failure")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a flush that could not write stayed quiet")
	}
}

// A record written while its client was still connected carries two facts the
// broker needs after it dies: that the session was live, so its expiry had not
// started counting, and what the client had asked for as that expiry. Both are
// ordinary struct fields, so what is worth proving is that the file carries them
// through a crash.
func TestFileStoreRemembersALiveSession(t *testing.T) {
	dir := t.TempDir()
	fs := openStore(t, dir, nil)
	if err := fs.Put(&Session{
		ClientID:       "live",
		Live:           true,
		ExpiryInterval: 90 * time.Second,
		Subscriptions:  map[string]Sub{"dev/#": {QoS: 1}},
		Proto:          packets.V5,
	}); err != nil {
		t.Fatalf("put: %v", err)
	}
	settle(fs)
	fs.crash()

	again := openStore(t, dir, nil)
	got, ok := again.Get("live")
	if !ok {
		t.Fatal("the live session did not survive the crash")
	}
	if !got.Live {
		t.Error("the record came back without its live marker, so the reaper will treat it as already offline")
	}
	if got.ExpiryInterval != 90*time.Second {
		t.Errorf("ExpiryInterval = %s, want 1m30s", got.ExpiryInterval)
	}
	if !got.Expiry.IsZero() {
		t.Errorf("Expiry = %s, want the zero time: the clock had not started", got.Expiry)
	}
	if len(got.Subscriptions) != 1 {
		t.Errorf("the session came back with %d subscriptions, want the one it had", len(got.Subscriptions))
	}
}

// TestExpiredAndStatsReadTheStoreWithoutDetachingIt pins the two methods the
// reaper and store_bytes rely on. Expired must answer with identifiers alone:
// the reaper asks once a tick, and a scan that deep-copied every queued message
// of every offline client would cost more than the deliveries it is tidying up.
func TestExpiredAndStatsReadTheStoreWithoutDetachingIt(t *testing.T) {
	ranOut := time.Now().Add(-time.Second)
	stores := []struct {
		name string
		open func(t *testing.T) Store
	}{
		{"memory", func(*testing.T) Store { return NewMemoryStore() }},
		{"file", func(t *testing.T) Store { return openStore(t, t.TempDir(), nil) }},
	}
	queue := []Message{
		{Topic: "a", Payload: []byte("one"), QoS: 1},
		{Topic: "a", Payload: []byte("two"), QoS: 1},
	}

	for _, tc := range stores {
		t.Run(tc.name, func(t *testing.T) {
			st := tc.open(t)
			mustPut(t, st, &Session{ClientID: "gone", Queued: queue, Expiry: ranOut})
			mustPut(t, st, &Session{ClientID: "kept", Queued: queue[:1], Expiry: time.Now().Add(time.Hour)})
			// A 3.1.1 session carries no expiry at all and must never be reaped.
			mustPut(t, st, &Session{ClientID: "forever", Queued: queue})

			if got := st.Expired(time.Now()); len(got) != 1 || got[0] != "gone" {
				t.Errorf("Expired = %v, want only the session whose clock ran out", got)
			}
			if s := st.Stats(); s.Sessions != 3 || s.Queued != 5 {
				t.Errorf("Stats = %+v, want 3 sessions holding 5 queued messages", s)
			}

			// Naming the dead ones is the store's job; ending them is the
			// broker's, and the residency has to follow the delete.
			if err := st.Delete("gone"); err != nil {
				t.Fatalf("delete: %v", err)
			}
			if s := st.Stats(); s.Sessions != 2 || s.Queued != 3 {
				t.Errorf("Stats = %+v after the reap, want the gone session's queue dropped", s)
			}
			if n := len(st.Expired(time.Now())); n != 0 {
				t.Errorf("Expired still reports %d sessions after the delete", n)
			}
		})
	}
}

func mustPut(t *testing.T, st Store, s *Session) {
	t.Helper()
	if err := st.Put(s); err != nil {
		t.Fatalf("put %s: %v", s.ClientID, err)
	}
}
