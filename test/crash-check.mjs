// Crash recovery harness. It runs the real broker binary, kills it with the
// signal a power loss leaves behind, and asks a third-party client (mqtt.js)
// whether the state came back. Nothing here is simulated: the bytes go to a
// file, the process dies mid-connection, and a second process reads them.
//
//   node crash-check.mjs
//
//   CONGMQ_BIN=/path/to/congmq node crash-check.mjs
//
// It needs a binary built with `go build -o bin/congmq.exe ./cmd/congmq` and two
// free ports. Phase one runs -store-sync always, which promises nothing back;
// phase two runs everysec and measures the window it does give up.
import mqtt from 'mqtt';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const BIN =
  process.env.CONGMQ_BIN ??
  fileURLToPath(new URL(`../bin/congmq${process.platform === 'win32' ? '.exe' : ''}`, import.meta.url));
const PORT = Number(process.env.CONGMQ_PORT ?? 1887);
const METRICS_PORT = Number(process.env.CONGMQ_METRICS_PORT ?? 1889);
const BROKER_URL = `mqtt://127.0.0.1:${PORT}`;

const WILL_DELAY = 12; // seconds the delayed will waits out
const QUEUE_SIZE = 10; // offline messages that must come back
const BURST = 100; // messages per half of the everysec measurement

let failures = 0;
let total = 0;
const check = (name, ok, detail = '') => {
  total++;
  console.log(`${ok ? 'pass' : 'FAIL'}  ${name}${detail ? `\n        -> ${detail}` : ''}`);
  if (!ok) failures++;
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// waitFor polls a condition until it holds, and reports the time it took rather
// than a bare timeout, so a slow pass and a lucky pass look different in the log.
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

// startBroker spawns the binary against dir and resolves once its own log says
// it is listening, which is also when the store has been replayed: Serve restores
// durable state and sessions before it accepts a single connection.
function startBroker(dir, sync, extra = []) {
  const args = [
    '-addr', `127.0.0.1:${PORT}`,
    '-metrics', `127.0.0.1:${METRICS_PORT}`,
    '-store', dir,
    '-store-sync', sync,
    '-reap-interval', '200ms',
    ...extra,
  ];
  const proc = spawn(BIN, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  const handle = { proc, args, lines: [], killed: false };
  proc.stderr.on('data', (b) => {
    for (const line of b.toString().split(/\r?\n/)) if (line.trim()) handle.lines.push(line.trim());
  });
  proc.stdout.on('data', (b) => handle.lines.push(b.toString().trim()));
  handle.log = (needle) => handle.lines.find((l) => l.includes(needle)) ?? '';
  handle.crash = async () => {
    handle.killed = true;
    proc.kill('SIGKILL');
    await new Promise((r) => proc.once('exit', r));
  };
  const ready = waitFor('the broker to start listening', () => handle.log('msg=listening') !== '', 10000);
  return ready.then(() => handle);
}

// killBroker ends a broker. The last one in a run is killed rather than drained,
// because the graceful path is what the Go suite covers and this file is about
// the other one.
async function killBroker(handle) {
  if (handle.killed) return;
  handle.killed = true;
  handle.proc.kill('SIGKILL');
  await new Promise((r) => handle.proc.once('exit', r));
}

async function metrics() {
  try {
    const res = await fetch(`http://127.0.0.1:${METRICS_PORT}/metrics`);
    return await res.json();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- clients ---

// connect opens a client and hands back the CONNACK it was answered with, so a
// test can read Session Present instead of inferring it from what arrives.
function connect(opts) {
  return new Promise((resolve, reject) => {
    const client = mqtt.connect(BROKER_URL, { protocolVersion: 5, connectTimeout: 5000, ...opts });
    client.received = [];
    // A reconnect attempt that fails emits error, and an error event with no
    // listener ends the process: the harness is not allowed to die that way.
    client.on('error', (err) => client.received.push({ error: String(err) }));
    client.on('message', (topic, payload, packet) =>
      client.received.push({ topic, payload: payload.toString(), qos: packet.qos, retain: packet.retain, at: Date.now() }),
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

const gone = (client) =>
  client.received.filter((m) => m.topic).map((m) => `${m.topic}:${m.payload}${m.retain ? ':retain' : ''}`);

// away closes the socket without saying goodbye, which is what a device that
// loses power looks like to the broker.
const away = (client) => new Promise((resolve) => client.end(true, {}, resolve));

// ------------------------------------------------------------------ phase 1 --

// The promise of -store-sync always: a message the broker acknowledged is on the
// disk, and a kill in the middle of a connection costs nothing that was already
// promised. It also proves the two halves a restart owes: the session a client
// was holding, and the state that belongs to no session.
async function phaseAlways() {
  console.log(`\nphase 1  -store-sync always  (${BIN})`);
  const dir = mkdtempSync(join(tmpdir(), 'congmq-always-'));
  let broker = await startBroker(dir, 'always');
  console.log(`  broker pid ${broker.proc.pid}`);

  // The watcher stays connected across the crash and never resubscribes: if it
  // still gets the will, the subscription came off the disk.
  const watch = await connect({
    clientId: 'cc-watch',
    clean: false,
    properties: { sessionExpiryInterval: 600 },
    reconnectPeriod: 500,
    resubscribe: false,
  });
  await subscribe(watch, 'will/state', 1);

  // A persistent subscriber that is away when the messages arrive.
  const queue = await connect({
    clientId: 'cc-queue',
    clean: false,
    properties: { sessionExpiryInterval: 600 },
    reconnectPeriod: 0,
    resubscribe: false,
  });
  await subscribe(queue, 'dev/data', 1);
  await away(queue);

  // A device with a delayed will, dying without goodbye.
  const node = await connect({
    clientId: 'cc-node',
    clean: false,
    properties: { sessionExpiryInterval: 600 },
    reconnectPeriod: 0,
    will: { topic: 'will/state', payload: 'node went dark', qos: 1, properties: { willDelayInterval: WILL_DELAY } },
  });
  const t0 = Date.now();
  await away(node);

  const pub = await connect({ clientId: 'cc-pub', clean: true, reconnectPeriod: 0 });
  for (let i = 1; i <= QUEUE_SIZE; i++) await pub.publishAsync('dev/data', `q${i}`, { qos: 1 });
  await pub.publishAsync('sensor/temp', '21.5C', { qos: 1, retain: true });

  const before = await metrics();
  check(
    'before the crash the broker had taken the publishes and held the reading',
    before && before.messages_in >= QUEUE_SIZE + 1 && before.retained_messages === 1,
    `messages_in=${before?.messages_in} retained=${before?.retained_messages}`,
  );

  await away(pub);
  await broker.crash();
  console.log(`  killed pid ${broker.proc.pid} ${((Date.now() - t0) / 1000).toFixed(1)}s after the node died`);

  broker = await startBroker(dir, 'always');
  const open = broker.log('store open');
  check(
    'the restart reports three sessions, one retained message and one owed will',
    /sessions=3 retained=1 wills=1/.test(open),
    open || 'no store open line',
  );

  // The offline queue: the client comes back and expects what it missed.
  const back = await connect({
    clientId: 'cc-queue',
    clean: false,
    properties: { sessionExpiryInterval: 600 },
    reconnectPeriod: 0,
    resubscribe: false,
  });
  check('the reconnect continues the session', back.connack?.sessionPresent === true, JSON.stringify(back.connack));
  await waitFor('the queued messages', () => gone(back).length >= QUEUE_SIZE, 6000);
  await sleep(400);
  const want = Array.from({ length: QUEUE_SIZE }, (_, i) => `dev/data:q${i + 1}`);
  check(
    `all ${QUEUE_SIZE} offline messages came back, in order and exactly once`,
    JSON.stringify(gone(back)) === JSON.stringify(want),
    gone(back).join(','),
  );

  // The retained reading belongs to the topic, not to a session.
  const fresh = await connect({ clientId: 'cc-fresh', clean: true, reconnectPeriod: 0 });
  await subscribe(fresh, 'sensor/temp', 1);
  await waitFor('the retained message', () => gone(fresh).length >= 1, 4000);
  check(
    'the retained message was still on disk and arrived with its RETAIN flag',
    gone(fresh)[0] === 'sensor/temp:21.5C:retain',
    String(gone(fresh)),
  );

  // The delayed will is the one promise that outlives the process on a clock: it
  // was owed WILL_DELAY seconds after the node died, and the restart must not
  // have started that timer again.
  const due = t0 + WILL_DELAY * 1000;
  await sleep(Math.max(0, due - Date.now() + 2500));
  const arrived = watch.received.filter((m) => m.topic === 'will/state');
  check('the watcher that never resubscribed was still subscribed', arrived.length === 1, gone(watch).join(','));
  if (arrived.length) {
    const offset = (arrived[0].at - t0) / 1000;
    check(
      `the will fired ${offset.toFixed(1)}s after the node died, on the original deadline`,
      offset >= WILL_DELAY - 0.5 && offset <= WILL_DELAY + 3,
      `expected ${WILL_DELAY}s, got ${offset.toFixed(1)}s`,
    );
    check('the will arrived at the QoS it was written with', arrived[0].qos === 1, `qos ${arrived[0].qos}`);
  }
  const after = await metrics();
  check('the restarted broker counts the restored retained message', after?.retained_messages === 1, `retained=${after?.retained_messages}`);

  await killBroker(broker);
  rmSync(dir, { recursive: true, force: true });
}

// ------------------------------------------------------------------ phase 2 --

// What everysec actually gives up, measured rather than asserted. One hundred
// messages go in and get a flush tick to reach the operating system; another
// hundred go in and the process is killed inside the next interval. After the
// restart the first hundred must all be there, and whatever is missing from the
// second hundred is exactly the window the mode promises to lose.
async function phaseEverysec() {
  console.log('\nphase 2  -store-sync everysec  (flush interval 1s)');
  const dir = mkdtempSync(join(tmpdir(), 'congmq-everysec-'));
  let broker = await startBroker(dir, 'everysec');

  const sub = await connect({
    clientId: 'es-queue',
    clean: false,
    properties: { sessionExpiryInterval: 600 },
    reconnectPeriod: 0,
    resubscribe: false,
  });
  await subscribe(sub, 'dev/data', 1);
  await away(sub);

  const send = async (from, count) => {
    const pub = await connect({ clientId: `es-pub-${from}`, clean: true, reconnectPeriod: 0 });
    for (let i = from; i < from + count; i++) await pub.publishAsync('dev/data', `m${i}`, { qos: 1 });
    await away(pub);
  };

  await send(1, BURST);
  await sleep(1400); // past a tick, so the first burst is the disk's problem now
  await send(BURST + 1, BURST);
  const acked = Date.now();
  await broker.crash();
  console.log(`  killed ${Date.now() - acked}ms after the last PUBACK of the newest burst`);

  broker = await startBroker(dir, 'everysec');
  const back = await connect({
    clientId: 'es-queue',
    clean: false,
    properties: { sessionExpiryInterval: 600 },
    reconnectPeriod: 0,
    resubscribe: false,
  });
  let first = 0;
  let second = 0;
  const tally = () => {
    const ids = back.received.filter((m) => m.topic).map((m) => Number(m.payload.slice(1)));
    first = ids.filter((n) => n <= BURST).length;
    second = ids.filter((n) => n > BURST).length;
    return first === BURST;
  };
  try {
    await waitFor(`all ${BURST} ticked messages`, tally, 10000);
  } catch {
    // Reported by the check below rather than by a stack trace.
  }
  await sleep(600);
  tally();
  check(
    `every message that had passed a flush tick came back, and only the newest ones could be missing`,
    first === BURST,
    `older burst ${first}/${BURST}, newer burst ${second}/${BURST}`,
  );
  console.log(
    `  measured window: ${second}/${BURST} of the newest burst survived the kill, ` +
      `so ${BURST - second} acknowledged messages were the sub-second everysec agreed to give up`,
  );

  await away(back);
  await killBroker(broker);
  rmSync(dir, { recursive: true, force: true });
}

console.log(`congmq crash recovery: ${BROKER_URL} metrics 127.0.0.1:${METRICS_PORT}`);
const probeDir = mkdtempSync(join(tmpdir(), 'congmq-probe-'));
try {
  // Fail fast and clearly if the binary is missing or the port is taken, rather
  // than letting a connect timeout stand in for a build instruction.
  const probe = await startBroker(probeDir, 'everysec');
  await killBroker(probe);
} catch (err) {
  rmSync(probeDir, { recursive: true, force: true });
  console.error(`cannot start ${BIN}: ${err.message}`);
  console.error('build it first:  go build -o bin/congmq.exe ./cmd/congmq');
  process.exit(1);
}

try {
  await phaseAlways();
  await phaseEverysec();
} catch (err) {
  console.error(`\nthe harness stopped: ${err.stack ?? err.message}`);
  failures++;
}

console.log(failures ? `\nFAIL  ${failures}/${total} check(s) failed` : `\nall ${total} crash recovery checks passed`);
process.exit(failures ? 1 : 0);
