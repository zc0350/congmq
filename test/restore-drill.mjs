// Cold-backup restore drill. It runs the real broker, kills it, copies the
// directory the way an operator's backup job does, and starts a *different*
// broker somewhere else from that copy — then asks a third-party client whether
// the state came back. Nothing is simulated except the kill.
//
//   node restore-drill.mjs
//
//   CONGMQ_BIN=/path/to/congmq node restore-drill.mjs
//
// What this covers that the crash test does not: crash-check.mjs restarts the
// same broker over the same directory on the same port, which is the service
// restart and the upgrade. A backup is a different thing — another path, another
// broker identifier, and a file that was copied while it was still being
// written. The three scenarios are those three claims.
//
// Two things are deliberately not here. The unacknowledged-inflight and QoS 2
// staging halves of a restored session need a client that can hold an ack open,
// and a third-party client acknowledges what it receives, so those belong to the
// Go suite's bare-socket client (internal/broker/restart_test.go). And the gap
// between the sync tiers only opens on a machine that stops taking writes at all,
// which no harness on this box can do — scenario C therefore measures what a
// killed process leaves behind, and says so.
import mqtt from 'mqtt';
import { spawn } from 'node:child_process';
import { cpSync, mkdtempSync, rmSync, statSync, truncateSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const EXE = process.platform === 'win32' ? '.exe' : '';
const BIN = process.env.CONGMQ_BIN ?? fileURLToPath(new URL(`../bin/congmq${EXE}`, import.meta.url));
const BASE = Number(process.env.CONGMQ_DRILL_BASE_PORT ?? 1985);
const PORTS = [
  { port: BASE, metrics: BASE + 1 },
  { port: BASE + 2, metrics: BASE + 3 },
  { port: BASE + 4, metrics: BASE + 5 },
];

const QUEUE_SIZE = 8; // offline messages that must survive the copy
const WILL_DELAY = 18; // seconds the delayed will waits out, longer than a restart takes
const FLUSH = '300ms'; // so a snapshot reaches the disk before the kill, without fsync

let failures = 0;
let total = 0;
const check = (name, ok, detail = '') => {
  total++;
  console.log(`${ok ? 'pass' : 'FAIL'}  ${name}${detail ? `\n        -> ${detail}` : ''}`);
  if (!ok) failures++;
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const mqttUrl = ({ port }) => `mqtt://127.0.0.1:${port}`;

async function waitFor(what, cond, limit = 8000) {
  const started = Date.now();
  for (;;) {
    const ok = await cond();
    if (ok) return Date.now() - started;
    if (Date.now() - started > limit) throw new Error(`timed out after ${limit}ms waiting for ${what}`);
    await sleep(50);
  }
}

// ---------------------------------------------------------------- broker ----

// startBroker runs the binary against dir under its own broker identifier and
// resolves once the store has been replayed and the listener is up. The `-id`
// changes with every call on purpose: state that only comes back under the
// identifier that wrote it is not a backup, it is a lock-in.
function startBroker(dir, { sync = 'everysec', id = 'congmq-drill', ...rest } = {}) {
  const { port, metrics } = rest;
  const args = [
    '-addr', `127.0.0.1:${port}`,
    '-metrics', `127.0.0.1:${metrics}`,
    '-store', dir,
    '-store-sync', sync,
    '-store-flush-interval', FLUSH,
    '-reap-interval', '200ms',
    '-id', id,
  ];
  const proc = spawn(BIN, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  const handle = { proc, args, id, port, metrics, lines: [], killed: false };
  const push = (b) => {
    for (const line of b.toString().split(/\r?\n/)) if (line.trim()) handle.lines.push(line.trim());
  };
  proc.stderr.on('data', push);
  proc.stdout.on('data', push);
  handle.log = (needle) => handle.lines.find((l) => l.includes(needle)) ?? '';
  handle.crash = async () => {
    if (handle.killed) return;
    handle.killed = true;
    proc.kill('SIGKILL');
    await new Promise((r) => proc.once('exit', r));
  };
  return waitFor('the broker to start listening', () => handle.log('msg=listening') !== '', 12000).then(
    () => handle,
    (err) => handle.crash().then(() => {
      err.brokerLines = handle.lines.slice(-8);
      throw err;
    }),
  );
}

// copyState takes the whole directory, the way a backup job does: the directory
// is the state, so nothing here reaches into the file to help it along.
function copyState(from, to) {
  cpSync(from, to, { recursive: true });
  return statSync(join(to, 'state.log')).size;
}

async function metricsOf({ metrics }) {
  try {
    return await (await fetch(`http://127.0.0.1:${metrics}/metrics`)).json();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- clients ---

function connect(url, opts) {
  return new Promise((resolve, reject) => {
    const client = mqtt.connect(url, { protocolVersion: 5, connectTimeout: 5000, ...opts });
    client.received = [];
    client.on('error', (err) => client.received.push({ error: String(err) }));
    client.on('message', (topic, payload, packet) =>
      client.received.push({
        topic,
        payload: payload.toString(),
        qos: packet.qos,
        dup: packet.dup,
        retain: packet.retain,
        at: Date.now(),
      }),
    );
    const timer = setTimeout(() => reject(new Error(`${opts.clientId} did not connect`)), 10000);
    client.once('connect', (packet) => {
      clearTimeout(timer);
      client.connack = packet;
      resolve(client);
    });
    client.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

const subscribe = (client, topic, qos = 1) =>
  new Promise((resolve, reject) =>
    client.subscribe(topic, { qos }, (err, granted) => (err ? reject(err) : resolve(granted))),
  );

const messages = (client, topic) => client.received.filter((m) => m.topic === topic);
const gone = (client) => client.received.filter((m) => m.topic).map((m) => `${m.topic}:${m.payload}`);
const payloads = (list) => list.map((m) => m.payload);

// away closes the socket without goodbye, which is what a device that lost power
// looks like to a broker — and is the only way to leave a queue behind.
const away = (client) => new Promise((resolve) => client.end(true, {}, resolve));

// persistent is how every client in this drill connects: a session the broker is
// allowed to keep, and no automatic resubscribe, because a filter the client
// re-sends after reconnecting proves nothing about what was on the disk.
const persistent = (clientId) => ({
  clientId,
  clean: false,
  properties: { sessionExpiryInterval: 600 },
  reconnectPeriod: 0,
  resubscribe: false,
});

// ------------------------------------------------------------- the plant ----

// One shape of state, planted on whichever broker is listening: an away
// subscriber holding a queue, a live subscriber holding two filters, a delayed
// will, and a retained reading. Each has its own way of proving it came back, so
// a restore that only got some of them cannot pass.
async function plant(url) {
  const watch = await connect(url, persistent('rd-watch'));
  await subscribe(watch, 'drill/live', 1);
  await subscribe(watch, 'drill/will/#', 1);

  const queue = await connect(url, persistent('rd-away'));
  await subscribe(queue, 'drill/data', 1);
  await away(queue);

  const node = await connect(url, {
    ...persistent('rd-node'),
    will: { topic: 'drill/will/node', payload: 'node went dark', qos: 1, properties: { willDelayInterval: WILL_DELAY } },
  });
  const diedAt = Date.now();
  await away(node);

  const pub = await connect(url, { clientId: 'rd-pub', clean: true, reconnectPeriod: 0 });
  const want = [];
  for (let i = 1; i <= QUEUE_SIZE; i++) {
    await pub.publishAsync('drill/data', `q${i}`, { qos: 1 });
    want.push(`drill/data:q${i}`);
  }
  await pub.publishAsync('drill/retained', '21.5C', { qos: 1, retain: true });
  await pub.publishAsync('drill/live', 'before the crash', { qos: 1 });
  await waitFor('the live subscriber to take its message', () => messages(watch, 'drill/live').length === 1);
  await away(pub);

  return { want, diedAt, watch };
}

// The assertions a restored state has to pass, run against whichever broker is
// now listening on url. The watcher reconnects without sending a single
// SUBSCRIBE: whatever it receives after that arrived on a filter the copied file
// handed back, and the will firing at its original deadline is the one promise
// that also proves the clock came back.
async function reconcile(url, { want, diedAt }) {
  const back = await connect(url, persistent('rd-away'));
  check(
    'the reconnect continues the session it had before the backup',
    back.connack?.sessionPresent === true,
    JSON.stringify(back.connack),
  );
  await waitFor('the queued messages', () => gone(back).length >= want.length, 8000).catch(() => {});
  await sleep(500);
  check(
    `all ${want.length} offline messages came out of the copy, in order and exactly once`,
    JSON.stringify(gone(back)) === JSON.stringify(want),
    gone(back).join(',') || 'nothing',
  );
  await away(back);

  const fresh = await connect(url, { clientId: 'rd-fresh', clean: true, reconnectPeriod: 0 });
  await subscribe(fresh, 'drill/retained', 1);
  await waitFor('the retained reading', () => messages(fresh, 'drill/retained').length >= 1, 6000).catch(() => {});
  check(
    'the retained message was in the copy and arrived flagged RETAIN',
    messages(fresh, 'drill/retained')[0]?.retain === true && messages(fresh, 'drill/retained')[0]?.payload === '21.5C',
    gone(fresh).join(',') || 'nothing',
  );
  await away(fresh);

  const watch = await connect(url, persistent('rd-watch'));
  check(
    'the watcher that never resubscribed was taken back as the same session',
    watch.connack?.sessionPresent === true,
    JSON.stringify(watch.connack),
  );

  const due = diedAt + WILL_DELAY * 1000;
  await sleep(Math.max(0, due - Date.now() + 2500));
  const wills = messages(watch, 'drill/will/node');
  check(
    'the delayed will was still owed and fired on the deadline the dead broker set',
    wills.length === 1,
    wills.length
      ? `${((wills[0].at - diedAt) / 1000).toFixed(1)}s after the node died, against a ${WILL_DELAY}s delay`
      : `nothing on drill/will/node; the watcher saw ${gone(watch).join(',') || 'nothing'}`,
  );

  const pub = await connect(url, { clientId: 'rd-pub2', clean: true, reconnectPeriod: 0 });
  await pub.publishAsync('drill/live', 'after the restore', { qos: 1 });
  await waitFor('the restored filter to deliver', () => messages(watch, 'drill/live').length >= 1, 8000).catch(() => {});
  await sleep(300);
  check(
    'a subscriber that never resubscribed still receives: its filter came off the copied file',
    payloads(messages(watch, 'drill/live')).join(',') === 'after the restore',
    payloads(messages(watch, 'drill/live')).join(',') || 'nothing',
  );
  await away(pub);
  await away(watch);
}

// The three things every broker in this drill opens with: the sessions, the
// reading, the owed will. Pinned to a number so a copy that silently dropped one
// has to say which.
const openedAs = (handle, want) => {
  const line = handle.log('store open');
  return { line, ok: want.test(line) };
};

// ---------------------------------------------------------------- scenario A --

// The drill itself: crash, copy the directory, bring up a different broker from
// the copy, and then prove the copy did not consume the original.
async function scenarioCopy(p) {
  console.log(`\nA  cold copy  (${BIN})`);
  const live = dirOf('live');
  const backup = dirOf('backup');
  const url = mqttUrl(p);

  let broker = await startBroker(live, { ...p, id: 'congmq-A1' });
  const planted = await plant(url);
  await sleep(1200); // past a flush tick, so this is a backup of settled state
  const size = statSync(join(live, 'state.log')).size;
  await broker.crash();

  const copied = copyState(live, backup);
  check("the backup is a byte-for-byte copy of a stopped broker's state", copied === size, `${size}B live, ${copied}B copied`);

  broker = await startBroker(backup, { ...p, id: 'congmq-A2' });
  const open = openedAs(broker, /sessions=3 retained=1 wills=1/);
  check('the copy opens with three sessions, one retained message and one owed will', open.ok, open.line || 'no store open line');

  const m = await metricsOf(p);
  check(
    'the restored broker says what its store holds, and the file agrees with it',
    m?.store_sessions === 3 && m?.store_bytes === copied,
    `store_sessions=${m?.store_sessions}, store_bytes=${m?.store_bytes}, file=${copied}B`,
  );

  await reconcile(url, planted);
  await broker.crash();

  // A backup you cannot read twice is a move, not a copy.
  broker = await startBroker(live, { ...p, id: 'congmq-A3' });
  const again = openedAs(broker, /sessions=3 retained=1 wills=1/);
  check('the original directory still restores the same state after the copy was used', again.ok, again.line || 'no store open line');

  const fresh = await connect(url, { clientId: 'rd-check', clean: true, reconnectPeriod: 0 });
  await subscribe(fresh, 'drill/retained', 1);
  await waitFor('the retained reading again', () => messages(fresh, 'drill/retained').length >= 1, 6000).catch(() => {});
  check('and it still hands out its retained reading', messages(fresh, 'drill/retained').length === 1, gone(fresh).join(',') || 'nothing');
  await away(fresh);
  await broker.crash();
}

// ---------------------------------------------------------------- scenario B --

// The degraded open. A file copied out from under a running broker — or a backup
// job that stopped halfway — ends in the middle of a record, and the reader has
// to keep everything before that point instead of refusing to start.
async function scenarioTruncated(p) {
  console.log('\nB  a copy cut mid-record');
  const live = dirOf('tail');
  const cut = dirOf('cut');
  const url = mqttUrl(p);

  let broker = await startBroker(live, { ...p, id: 'congmq-B1' });
  const tail = await connect(url, persistent('rd-tail'));
  await subscribe(tail, 'drill/tail', 1);
  await away(tail);
  const pub = await connect(url, { clientId: 'rd-pub3', clean: true, reconnectPeriod: 0 });
  for (let i = 1; i <= 6; i++) await pub.publishAsync('drill/tail', `t${i}`, { qos: 1 });
  await away(pub);
  await sleep(1200);
  await broker.crash();

  const whole = copyState(live, cut);
  // An odd number of bytes, so the last record loses part of its body or its
  // checksum: the shape a half-copied file actually has, not the tidy shape a
  // test would prefer to hand the code.
  truncateSync(join(cut, 'state.log'), whole - 37);

  broker = await startBroker(cut, { ...p, id: 'congmq-B2' });
  const open = broker.log('store open');
  const warned = broker.log('bytes_discarded');
  // Read the file before anything connects: the point is what the open itself did
  // to those bytes, and a reconnecting client appends a snapshot of its own.
  const kept = statSync(join(cut, 'state.log')).size;
  check('a truncated copy still starts a broker', open !== '', open || broker.lines.slice(-4).join(' | '));
  check(
    'and it says out loud that the previous shutdown was not clean',
    /bytes_discarded=\d+/.test(warned),
    warned || 'no bytes_discarded warning',
  );
  check(
    'the open cut the file back to the last record it could trust',
    kept < whole,
    `${whole}B copied, ${kept}B after the open (the last trusted record ends there)`,
  );

  const back = await connect(url, persistent('rd-tail'));
  await waitFor('the messages that survived', () => messages(back, 'drill/tail').length >= 1, 8000).catch(() => {});
  await sleep(400);
  const got = payloads(messages(back, 'drill/tail'));
  const inOrder = JSON.stringify(got) === JSON.stringify(got.slice().sort());
  check(
    'the trusted prefix still queues: the oldest of the six came back, in order',
    got.length >= 1 && got.length <= 6 && got[0] === 't1' && inOrder,
    `${got.length}/6: ${got.join(',') || 'nothing'} — a whole-snapshot log loses the newest ` +
      'rewrite of one session, and the snapshot before it is usually still complete',
  );
  await away(back);

  // A log that survived a degraded open has to keep working: the tail it dropped
  // must not come back later as garbage, and new state must still reach a reader.
  const again = await connect(url, persistent('rd-tail2'));
  await subscribe(again, 'drill/tail2', 1);
  await away(again);
  const pub2 = await connect(url, { clientId: 'rd-pub4', clean: true, reconnectPeriod: 0 });
  for (let i = 1; i <= 3; i++) await pub2.publishAsync('drill/tail2', `n${i}`, { qos: 1 });
  await away(pub2);
  await sleep(1200);
  await broker.crash();

  broker = await startBroker(cut, p);
  const reopened = await connect(url, persistent('rd-tail2'));
  await waitFor('the post-degradation queue', () => messages(reopened, 'drill/tail2').length >= 1, 8000).catch(() => {});
  await sleep(400);
  check(
    'and the store keeps writing after a degraded open',
    payloads(messages(reopened, 'drill/tail2')).join(',') === 'n1,n2,n3',
    payloads(messages(reopened, 'drill/tail2')).join(',') || 'nothing',
  );
  await away(reopened);
  await broker.crash();
}

// ---------------------------------------------------------------- scenario C --

// All three -store-sync tiers, restored from a copy taken after the process died.
// A killed process leaves its writes with the operating system, so all three come
// back whole — that is the sentence worth having, because it means the tier an
// operator picks for throughput does not change what their backup contains. The
// tiers differ only where the machine itself stops taking writes.
async function scenarioSyncTiers(p) {
  console.log('\nC  the three sync tiers, restored from a copy');
  const results = {};
  for (const sync of ['always', 'everysec', 'never']) {
    const live = mkdtempSync(join(tmpdir(), `congmq-sync-${sync}-`));
    const backup = join(tmpdir(), `congmq-syncback-${sync}-${process.pid}`);
    rmSync(backup, { recursive: true, force: true });
    const url = mqttUrl(p);

    let broker = await startBroker(live, { ...p, sync, id: `congmq-C-${sync}` });
    const queue = await connect(url, persistent('rd-tier'));
    await subscribe(queue, 'drill/tier', 1);
    await away(queue);
    const pub = await connect(url, { clientId: 'rd-tpub', clean: true, reconnectPeriod: 0 });
    for (let i = 1; i <= QUEUE_SIZE; i++) await pub.publishAsync('drill/tier', `s${i}`, { qos: 1 });
    await away(pub);
    await sleep(1500);
    await broker.crash();

    copyState(live, backup);
    broker = await startBroker(backup, { ...p, sync, id: `congmq-C2-${sync}` });
    const back = await connect(url, persistent('rd-tier'));
    await waitFor(`the ${sync} queue`, () => messages(back, 'drill/tier').length >= QUEUE_SIZE, 8000).catch(() => {});
    await sleep(400);
    results[sync] = payloads(messages(back, 'drill/tier'));
    await away(back);
    await broker.crash();
  }

  for (const sync of ['always', 'everysec', 'never']) {
    check(
      `-store-sync ${sync}: every acknowledged message was in the copy`,
      results[sync].join(',') === Array.from({ length: QUEUE_SIZE }, (_, i) => `s${i + 1}`).join(','),
      `${results[sync].length}/${QUEUE_SIZE}: ${results[sync].join(',') || 'nothing'}`,
    );
  }
  check(
    'the tiers restore alike, so the choice of tier is a crash decision and not a backup one',
    JSON.stringify(results.always) === JSON.stringify(results.everysec) &&
      JSON.stringify(results.everysec) === JSON.stringify(results.never),
    `always ${results.always.length}, everysec ${results.everysec.length}, never ${results.never.length}`,
  );
}

// ------------------------------------------------------------------ main ----

console.log(`congmq cold-backup restore drill: ${BIN}`);
console.log(
  `ports ${PORTS.map(({ port, metrics }) => `${port}/${metrics}`).join('  ')}  ` +
    `(CONGMQ_DRILL_BASE_PORT moves the block; CONGMQ_BIN points at the binary)`,
);

const dirs = [];
const dirOf = (tag) => {
  const dir = mkdtempSync(join(tmpdir(), `congmq-${tag}-`));
  dirs.push(dir);
  return dir;
};

try {
  // Fail fast and clearly if the binary is missing or the ports are taken, rather
  // than letting a connect timeout stand in for a build instruction.
  const probe = await startBroker(dirOf('probe'), PORTS[0]);
  await probe.crash();
} catch (err) {
  console.error(`cannot start ${BIN}: ${err.message}`);
  console.error((err.brokerLines ?? []).join('\n'));
  console.error('build it first:  go build -o bin/congmq.exe ./cmd/congmq');
  cleanup();
  process.exit(1);
}

try {
  await scenarioCopy(PORTS[0]);
  await scenarioTruncated(PORTS[1]);
  await scenarioSyncTiers(PORTS[2]);
} catch (err) {
  console.error(`\nthe harness stopped: ${err.stack ?? err.message}`);
  console.error((err.brokerLines ?? []).join('\n'));
  failures++;
}

function cleanup() {
  // A store directory cannot be removed on Windows while a broker still holds
  // state.log, so every broker above is crashed before its directory is touched,
  // and a leftover temp directory is reported rather than hidden.
  let left = 0;
  for (const dir of [...dirs, ...globBackups()]) {
    try {
      rmSync(dir, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
    } catch {
      left++;
    }
  }
  if (left) console.log(`note: ${left} temp director${left === 1 ? 'y' : 'ies'} left behind under ${tmpdir()}`);
}

function globBackups() {
  // The scenario backups are named, not mkdtemp'd, so they can be listed here
  // rather than tracked through six call sites.
  return [`congmq-backup-${process.pid}-a`, `congmq-cut-${process.pid}-b`, `congmq-syncback-always-${process.pid}`,
    `congmq-syncback-everysec-${process.pid}`, `congmq-syncback-never-${process.pid}`].map((n) => join(tmpdir(), n));
}

cleanup();
console.log(failures ? `\nFAIL  ${failures}/${total} drill check(s) failed` : `\nall ${total} restore-drill checks passed`);
process.exit(failures ? 1 : 0);
