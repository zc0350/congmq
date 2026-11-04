// Rolling upgrade across two real builds, under load.
//
//   node rolling-upgrade.mjs
//
//   CONGMQ_BIN=... CONGMQ_OLD_BIN=... node rolling-upgrade.mjs
//
// Both binaries run against the same -store directory and the same port, one
// after the other, while clients keep publishing and reconnecting through the
// swap. That is what an upgrade actually is: the old process stops in the middle
// of live connections and a different build inherits its files. So this asks,
// with a third-party client, whether the takeover holds — in both directions,
// because a bad upgrade has to be rolled back the same way it was upgraded.
//
// The old build is a tag, not a reconstruction, which is the only version worth
// testing against: it is what an existing deployment is already running and
// already wrote to disk.
//
//   go build -o .tmp/congmq.exe ./cmd/congmq
//   git archive v1.0.0 | tar -x -C .tmp/v1000
//   (cd .tmp/v1000 && go build -o ../congmq-v1000.exe ./cmd/congmq)
//
// Leg 3 covers the mistake an upgrade tempts people into: starting the new
// broker before the old one has stopped. Two processes append one file, each
// from its own offset, so the later write lands on top of the earlier one's
// records — and every record it overwrites is framed and CRC-correct, so a
// replay cannot see the damage. The store now refuses the second process; this
// leg proves the refusal, and that a killed holder cannot wedge its successor.
import mqtt from 'mqtt';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const EXE = process.platform === 'win32' ? '.exe' : '';
const NEW = process.env.CONGMQ_BIN ?? fileURLToPath(new URL(`../bin/congmq${EXE}`, import.meta.url));
const OLD = process.env.CONGMQ_OLD_BIN ?? fileURLToPath(new URL(`../.tmp/congmq-v1000${EXE}`, import.meta.url));
const BASE = Number(process.env.CONGMQ_UPGRADE_BASE_PORT ?? 1940);
const PORTS = {
  upgrade: { port: BASE + 1, metrics: BASE + 2 },
  rollback: { port: BASE + 3, metrics: BASE + 4 },
  holder: { port: BASE + 5, metrics: BASE + 6 },
  // The refused process never binds this pair, and each later user of it waits
  // for the previous one to exit, so one pair serves all three.
  rival: { port: BASE + 7, metrics: BASE + 8 },
};

const QUEUE_SIZE = 6; // offline messages planted before the load starts
const WILL_DELAY = 15; // longer than a swap takes, shorter than this harness
const GAP = 60; // ms between published messages: a steady load, not a burst
// The live handoff is the one path that is not durable: the router puts a message
// in the subscriber's mailbox and acknowledges the publisher, so whatever has not
// reached the socket when the process dies is gone. Measured rather than assumed,
// and bounded by nothing except how fast a subscriber reads.
const LIVE_LOSS_LIMIT = 5;

let failures = 0;
let total = 0;
const check = (name, ok, detail = '') => {
  total++;
  console.log(`${ok ? 'pass' : 'FAIL'}  ${name}${detail ? `\n        -> ${detail}` : ''}`);
  if (!ok) failures++;
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const url = ({ port }) => `mqtt://127.0.0.1:${port}`;
const seqOf = (payload) => Number(payload.slice(1));

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

// startBroker spawns one build against dir and resolves when its own log says it
// is listening — which is after the store has been replayed. A broker that exits
// before that line is reported with its exit code and its own log, because a
// refused start is a result this harness asks for on purpose.
function startBroker(bin, { dir, ports, id, extra = [] }) {
  const args = [
    '-addr', `127.0.0.1:${ports.port}`,
    '-metrics', `127.0.0.1:${ports.metrics}`,
    '-store', dir,
    '-store-sync', 'always',
    '-reap-interval', '200ms',
    '-id', id,
    ...extra,
  ];
  const proc = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  const handle = { proc, bin, args, lines: [], exit: null };
  proc.stderr.on('data', (b) => {
    for (const line of b.toString().split(/\r?\n/)) if (line.trim()) handle.lines.push(line.trim());
  });
  proc.stdout.on('data', (b) => {
    for (const line of b.toString().split(/\r?\n/)) if (line.trim()) handle.lines.push(line.trim());
  });
  proc.on('exit', (code, signal) => {
    handle.exit = { code, signal };
  });
  handle.log = (needle) => handle.lines.find((l) => l.includes(needle)) ?? '';
  handle.counts = () => {
    const m = handle.log('store open').match(/sessions=(\d+) retained=(\d+) wills=(\d+)/);
    return m ? { sessions: +m[1], retained: +m[2], wills: +m[3] } : null;
  };
  handle.crash = async () => {
    // A hard kill on purpose: Windows cannot be handed a SIGTERM, and a machine
    // that stops taking writes is the worse case an upgrade has to survive.
    if (!handle.exit) proc.kill('SIGKILL');
    await waitFor('the broker to exit', () => handle.exit !== null, 10000);
    return handle.exit;
  };
  return waitFor('the broker to start listening', () => {
    if (handle.exit) {
      const err = new Error(`${bin} exited with code ${handle.exit.code} before listening`);
      err.brokerLines = handle.lines;
      err.exit = handle.exit;
      throw err;
    }
    return handle.log('msg=listening') !== '';
  })
    .then(() => handle)
    .catch((err) => {
      if (!err.brokerLines) err.brokerLines = handle.lines;
      return handle.crash().then(() => Promise.reject(err));
    });
}

// ---------------------------------------------------------------- clients ---

// connect keeps every CONNACK, not just the first: a takeover is read from the
// one that arrives after the swap, and a client that rebuilt its session from
// scratch answers Session Present = false there.
function connect(brokerUrl, opts) {
  return new Promise((resolve, reject) => {
    const client = mqtt.connect(brokerUrl, { protocolVersion: 5, connectTimeout: 5000, ...opts });
    client.seen = [];
    client.connacks = [];
    client.problems = [];
    client.on('error', (err) => client.problems.push(String(err).slice(0, 80)));
    client.on('message', (topic, payload) => client.seen.push({ topic, payload: payload.toString(), at: Date.now() }));
    let settled = false;
    const timer = setTimeout(() => reject(new Error(`${opts.clientId} did not connect`)), 12000);
    client.on('connect', (packet) => {
      client.connacks.push(packet);
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(client);
    });
    client.once('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
  });
}

const persistent = (clientId) => ({
  clientId,
  clean: false,
  properties: { sessionExpiryInterval: 600 },
  reconnectPeriod: 300,
  // Not resubscribing is the point: a subscription that still works after the
  // swap came off the disk the other build wrote.
  resubscribe: false,
});

const subscribe = (client, topic, qos = 1) =>
  new Promise((resolve, reject) =>
    client.subscribe(topic, { qos }, (err, granted) => (err ? reject(err) : resolve(granted))),
  );

const on = (client, topic) => client.seen.filter((m) => m.topic === topic);
const away = (client) => new Promise((resolve) => client.end(true, {}, resolve));

// ------------------------------------------------------------------ load ----

// One publisher, both paths per tick: ru/live for the subscriber that is
// connected, ru/queue for the session that is not. Each path records its own
// ack, because the two of them owe different promises.
function makeLoad(brokerUrl) {
  const log = { sent: [], refused: [], connacks: [], stop: false, done: false, seq: 0 };
  const api = {
    log,
    async start() {
      const pub = await connect(brokerUrl, { clientId: 'ru-pub', clean: true, reconnectPeriod: 300 });
      pub.on('connect', (p) => log.connacks.push(p));
      api.pub = pub;
      api.loop = (async () => {
        while (!log.stop) {
          const n = ++log.seq;
          const body = `s${n}`;
          const rec = { n, live: 0, queue: 0, failed: 0 };
          for (const [topic, key] of [['ru/live', 'live'], ['ru/queue', 'queue']]) {
            try {
              await pub.publishAsync(topic, body, { qos: 1 });
              rec[key] = Date.now();
            } catch (err) {
              rec.failed++;
              log.refused.push(`${topic} ${body}: ${String(err).slice(0, 60)}`);
            }
          }
          if (rec.live || rec.queue) log.sent.push(rec);
          await sleep(GAP);
        }
        log.done = true;
      })();
      return pub;
    },
    async stop() {
      log.stop = true;
      await api.loop;
      await away(api.pub);
    },
    // The sequence numbers one path was held to, acked between two instants
    // (to = 0 means as far as the run goes).
    ackedBy(key, from, to) {
      return log.sent
        .filter((r) => r[key] && r[key] >= from && (to === 0 || r[key] < to))
        .map((r) => r.n);
    },
  };
  return api;
}

// -------------------------------------------------------------- scenarios ---

const dirs = [];
const procs = [];
const dirOf = (tag) => {
  const dir = mkdtempSync(join(tmpdir(), `congmq-up-${tag}-${process.pid}-`));
  dirs.push(dir);
  return dir;
};
const track = (h) => {
  procs.push(h);
  return h;
};

// Plant the four kinds of state an upgrade has to carry: an offline queue, a live
// session with its subscription, a retained reading, and a delayed will the next
// process owes on a clock it did not start.
async function plant(brokerUrl) {
  const planted = { sessions: 0, retained: 0, wills: 0 };

  const queue = await connect(brokerUrl, persistent('ru-queue'));
  await subscribe(queue, 'ru/queue', 1);
  await away(queue);
  planted.sessions++;

  const live = await connect(brokerUrl, persistent('ru-live'));
  await subscribe(live, 'ru/live', 1);
  planted.sessions++;

  const watch = await connect(brokerUrl, persistent('ru-watch'));
  await subscribe(watch, 'ru/will', 1);
  planted.sessions++;

  const node = await connect(
    brokerUrl,
    Object.assign(persistent('ru-node'), {
      will: { topic: 'ru/will', payload: 'node went dark', qos: 1, properties: { willDelayInterval: WILL_DELAY } },
    }),
  );
  planted.sessions++;
  planted.wills++;

  const pub = await connect(brokerUrl, { clientId: 'ru-plant', clean: true, reconnectPeriod: 0 });
  for (let i = 1; i <= QUEUE_SIZE; i++) await pub.publishAsync('ru/queue', `p${i}`, { qos: 1 });
  await pub.publishAsync('ru/temp', '21.5C', { qos: 1, retain: true });
  planted.retained++;
  await away(pub);

  const diedAt = Date.now();
  // Closes without a DISCONNECT, which is what a dead device looks like, and is
  // what arms the delayed will.
  await away(node);

  const load = makeLoad(brokerUrl);
  await load.start();
  // Let the queue settle and the will's delay run partway before the swap.
  await sleep(2500);
  return { live, watch, load, diedAt, planted };
}

// What a takeover owes, checked against whichever build now holds the port.
async function reconcile(state, next, brokerUrl, { who, other }) {
  const { live, watch, load, diedAt, planted } = state;

  const counts = next.counts();
  check(
    `${other} read the state ${who} wrote: ${planted.sessions} sessions, ${planted.retained} retained, ${planted.wills} owed will`,
    counts && counts.sessions === planted.sessions && counts.retained === planted.retained && counts.wills === planted.wills,
    `its own log says ${JSON.stringify(counts)}`,
  );

  const refusedConnack = [...live.connacks, ...watch.connacks, ...load.log.connacks].filter((c) => {
    const code = c?.reasonCode ?? c?.returnCode;
    return code !== 0;
  });
  check(
    'the two builds never disagreed about a client: every CONNACK was accepted',
    refusedConnack.length === 0,
    refusedConnack.length ? JSON.stringify(refusedConnack.slice(0, 3)) : `${live.connacks.length + watch.connacks.length + load.log.connacks.length} accepted`,
  );

  // The live path first, while the load is still running: what the new build
  // delivers from here on is the point of a takeover.
  await waitFor(`${other} to hand the live session back`, () => live.connacks.length >= 2, 12000).catch(() => {});
  const rejoin = live.connacks.slice(1).find((c) => c.sessionPresent === true);
  check(
    `the live session was continued by ${other}, not rebuilt`,
    !!rejoin,
    `after the swap: ${live.connacks.slice(1).map((c) => `sessionPresent=${c.sessionPresent}`).join(', ') || 'no reconnect'}`,
  );
  const afterSwap = on(live, 'ru/live').filter((m) => m.at > state.startedNext);
  await waitFor('the live subscriber to keep receiving', () => on(live, 'ru/live').some((m) => m.at > state.startedNext + 1500), 10000)
    .catch(() => {});
  await sleep(400);
  const carried = on(live, 'ru/live').filter((m) => m.at > state.startedNext);
  check(
    `the subscription ${who} wrote still delivers under ${other}, with the client never resubscribing`,
    carried.length >= 5,
    `${carried.length} message(s) delivered after the takeover (${afterSwap.length} of them before it had been up 1.5s)`,
  );

  // Quiesce before draining the queue: a message that arrives live while the
  // replay is running would overtake an older queued one, which is the mailbox
  // racing itself, not the file being wrong.
  await load.stop();
  const back = await connect(brokerUrl, persistent('ru-queue'));
  const want = [
    ...Array.from({ length: QUEUE_SIZE }, (_, i) => `p${i + 1}`),
    ...load.log.sent.filter((r) => r.queue).map((r) => `s${r.n}`),
  ];
  await waitFor('the offline queue to come back', () => on(back, 'ru/queue').length >= want.length, 12000).catch(() => {});
  await sleep(600);
  const got = on(back, 'ru/queue').map((m) => m.payload);
  const uniq = [...new Set(got)];
  const dupes = got.filter((v, i) => got.indexOf(v) !== i);
  const missing = want.filter((w) => !uniq.includes(w));
  const bySeq = (a, b) => (a[0] === b[0] ? Number(a.slice(1)) - Number(b.slice(1)) : a[0] === 'p' ? -1 : 1);
  check(
    `every message the queue was given a PUBACK for across both builds came back, none missing`,
    missing.length === 0,
    missing.length ? `missing ${missing.length}: ${missing.slice(0, 8).join(',')}` : `${uniq.length} of ${want.length}`,
  );
  check(
    `the ${uniq.length}-message queue spans the version boundary in the order it was written`,
    JSON.stringify(uniq) === JSON.stringify(uniq.slice().sort(bySeq)),
    `${uniq.slice(0, 4).join(',')} … ${uniq.slice(-3).join(',')}`,
  );
  // A duplicate whose publish was reported as failed is the client resending a
  // message it never got a PUBACK for: QoS 1 is at-least-once, and the publisher
  // owns that. A duplicate of anything else came from the broker.
  check(
    'nothing arrived twice except a publish the client had to resend',
    dupes.every((d) => load.log.refused.some((r) => r.includes(` ${d}:`))),
    `${dupes.length} duplicate(s) of ${got.length}, ${load.log.refused.length} failed publish attempt(s)`,
  );
  await away(back);

  // What the kill costs on the in-memory path, measured against the acks.
  const beforeKill = load.ackedBy('live', 0, state.killedAt);
  const delivered = new Set(on(live, 'ru/live').map((m) => seqOf(m.payload)));
  const lost = beforeKill.filter((n) => !delivered.has(n));
  check(
    `the live handoff gave up at most ${LIVE_LOSS_LIMIT} messages it had acknowledged: the rest were delivered`,
    lost.length <= LIVE_LOSS_LIMIT,
    `${lost.length} of ${beforeKill.length} acknowledged before the swap never arrived (still in the mailbox, never on disk)`,
  );

  const fresh = await connect(brokerUrl, { clientId: 'ru-fresh', clean: true, reconnectPeriod: 0 });
  await subscribe(fresh, 'ru/temp', 1);
  await waitFor('the retained reading', () => on(fresh, 'ru/temp').length >= 1, 6000).catch(() => {});
  const r = on(fresh, 'ru/temp')[0];
  check(
    `the retained message ${who} wrote is still on the topic under ${other}`,
    !!r && r.payload === '21.5C',
    r ? r.payload : 'nothing arrived',
  );
  await away(fresh);

  // The delayed will is a promise on a clock one process inherited from another.
  const due = diedAt + WILL_DELAY * 1000;
  await sleep(Math.max(0, due - Date.now() + 2000));
  const will = on(watch, 'ru/will');
  check(
    `the will ${who} owed fired under ${other}, exactly once`,
    will.length === 1,
    `${will.length} will message(s): ${will.map((m) => m.payload).join(',')}`,
  );
  if (will.length === 1) {
    const offset = (will[0].at - diedAt) / 1000;
    check(
      `it fired ${offset.toFixed(1)}s after the node died, on the ${WILL_DELAY}s deadline the dead process was given`,
      offset >= WILL_DELAY - 0.5 && offset <= WILL_DELAY + 5,
      `expected ${WILL_DELAY}s, got ${offset.toFixed(1)}s`,
    );
  }
  check(
    'and the watcher that never resubscribed was still subscribed',
    will.length === 1 && watch.connacks.length >= 2,
    `connacks: ${watch.connacks.length}`,
  );
  await away(live);
  await away(watch);
  return { lost: lost.length, ackedBefore: beforeKill.length, queued: uniq.length, delivered: on(live, 'ru/live').length };
}

// Swap one build out for the other while the load runs through it.
async function swap(state, from, to, ports, { who, other }) {
  state.killedAt = Date.now();
  await from.crash();
  // The successor binds the same port, so the old process has to be gone first —
  // and its store file has to be let go, which is the same wait the lock needs.
  const next = track(await startBroker(to, { dir: state.dir, ports, id: `${other.split(' ')[0]}-takeover` }));
  state.startedNext = Date.now();
  const out = await reconcile(state, next, url(ports), { who, other });
  await next.crash();
  return out;
}

async function scenarioUpgrade(ports) {
  console.log(`\nleg 1  v1.0.0 -> current, under load  (port ${ports.port})`);
  const dir = dirOf('up');
  const from = track(await startBroker(OLD, { dir, ports, id: 'v1000-running' }));
  const state = await plant(url(ports));
  state.dir = dir;
  await sleep(2000);
  return swap(state, from, NEW, ports, { who: 'v1.0.0', other: 'the current build' });
}

async function scenarioRollback(ports) {
  console.log(`\nleg 2  current -> v1.0.0, under load  (port ${ports.port})`);
  const dir = dirOf('rb');
  const from = track(await startBroker(NEW, { dir, ports, id: 'current-running' }));
  const state = await plant(url(ports));
  state.dir = dir;
  await sleep(2000);
  return swap(state, from, OLD, ports, { who: 'the current build', other: 'v1.0.0' });
}

// The upgrade mistake, and the guard that stops it.
async function scenarioSecondWriter(ports) {
  console.log(`\nleg 3  two brokers against one -store directory  (port ${ports.port})`);
  const dir = dirOf('lock');
  const holder = track(await startBroker(NEW, { dir, ports, id: 'holder' }));

  const sub = await connect(url(ports), persistent('lk-queue'));
  await subscribe(sub, 'lk/data', 1);
  await away(sub);
  const pub = await connect(url(ports), { clientId: 'lk-pub', clean: true, reconnectPeriod: 0 });
  for (let i = 1; i <= 4; i++) await pub.publishAsync('lk/data', `k${i}`, { qos: 1 });
  await pub.publishAsync('lk/temp', '12.0C', { qos: 1, retain: true });
  const bytes = statSync(join(dir, 'state.log')).size;
  await away(pub);

  let refusal = '';
  let exitCode = null;
  try {
    const rival = await startBroker(NEW, { dir, ports: PORTS.rival, id: 'rival' });
    refusal = rival.lines.join('\n');
    await rival.crash();
    check('a second broker on one store directory was allowed to start', false, refusal.slice(0, 200));
  } catch (err) {
    refusal = `${err.message}\n${(err.brokerLines ?? []).join('\n')}`;
    exitCode = err.exit?.code;
  }
  check(
    'the second process is refused instead of overwriting records it does not own',
    /already open by another process/.test(refusal),
    (refusal.split(/\r?\n/).find((l) => l.includes('store')) ?? refusal).slice(0, 180),
  );
  check(
    'and it exits non-zero, so systemd, docker and a script all see the failure',
    exitCode !== null && exitCode !== 0,
    `exit code ${exitCode}`,
  );

  const back = await connect(url(ports), persistent('lk-queue'));
  await waitFor('the queue to survive the refused start', () => on(back, 'lk/data').length >= 4, 8000).catch(() => {});
  await sleep(400);
  const got = on(back, 'lk/data').map((m) => m.payload);
  check(
    'the holder was untouched: still writing, still holding everything it was given',
    got.join(',') === 'k1,k2,k3,k4' && statSync(join(dir, 'state.log')).size >= bytes,
    `${got.length}/4: ${got.join(',') || 'nothing'} (file ${bytes}B at the refused start)`,
  );
  await away(back);
  await away(sub);

  // A second batch, left in the queue on purpose: the session above was drained,
  // so only a backlog nobody has read yet can show what the successor inherits.
  const more = await connect(url(ports), { clientId: 'lk-pub2', clean: true, reconnectPeriod: 0 });
  for (let i = 5; i <= 8; i++) await more.publishAsync('lk/data', `k${i}`, { qos: 1 });
  await away(more);

  // A lock that outlived its holder would wedge every restart after a crash, so
  // the point of it being a file handle is that the next process gets in.
  await holder.crash();
  const successor = track(await startBroker(NEW, { dir, ports: PORTS.rival, id: 'successor' }));
  check(
    'a killed holder leaves no lock behind: the successor starts and replays the state',
    /sessions=1 retained=1/.test(successor.log('store open')),
    successor.log('store open') || 'no store open line',
  );
  const reborn = await connect(url(PORTS.rival), persistent('lk-queue'));
  await waitFor('the replayed queue', () => on(reborn, 'lk/data').length >= 4, 8000).catch(() => {});
  await sleep(300);
  check(
    'and the backlog the refused process never got to write is intact',
    on(reborn, 'lk/data').map((m) => m.payload).join(',') === 'k5,k6,k7,k8',
    on(reborn, 'lk/data').map((m) => m.payload).join(',') || 'nothing arrived',
  );
  const keep = await connect(url(PORTS.rival), { clientId: 'lk-fresh', clean: true, reconnectPeriod: 0 });
  await subscribe(keep, 'lk/temp', 1);
  await waitFor('the retained reading', () => on(keep, 'lk/temp').length >= 1, 6000).catch(() => {});
  check(
    'the retained message survived the refusal and the restart',
    on(keep, 'lk/temp')[0]?.payload === '12.0C',
    String(on(keep, 'lk/temp').map((m) => m.payload).join(',')),
  );
  await away(keep);
  await away(reborn);
  await successor.crash();

  // What the guard cannot do: v1.0.0 has no lock code, so a rollback started
  // while the current build still holds the directory is not stopped by it.
  // Reported, because that half is carried by the procedure, not the binary.
  const keeper = track(await startBroker(NEW, { dir, ports, id: 'keeper' }));
  const old = spawn(OLD, ['-addr', `127.0.0.1:${PORTS.rival.port}`, '-store', dir, '-store-sync', 'always', '-id', 'old-unaware'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const lines = [];
  old.stderr.on('data', (b) => lines.push(b.toString().trim()));
  await sleep(3000);
  const startedAnyway = lines.some((l) => l.includes('msg=listening'));
  console.log(
    `  measured: v1.0.0 against a directory the current build holds ${startedAnyway ? 'STARTED anyway (no lock code in it)' : 'is stopped'}` +
      ` — so a rollback has to confirm the old process is fully gone before it starts`,
  );
  if (startedAnyway) old.kill('SIGKILL');
  await new Promise((r) => (old.exitCode === null && old.signalCode === null ? old.once('exit', r) : r()));
  await keeper.crash();
  return { startedAnyway };
}

// ------------------------------------------------------------------ main ----

console.log(`congmq rolling upgrade: ${url(PORTS.upgrade)} .. ${url(PORTS.holder)}`);
for (const [label, bin] of [['the build being upgraded from', OLD], ['the current build', NEW]]) {
  try {
    console.log(`  ${label}: ${bin} (${(statSync(bin).size / 1048576).toFixed(1)} MB)`);
  } catch {
    console.error(`cannot read ${label}: ${bin}`);
    console.error('build them first:');
    console.error('  go build -o .tmp/congmq.exe ./cmd/congmq');
    console.error('  mkdir -p .tmp/v1000 && git archive v1.0.0 | tar -x -C .tmp/v1000');
    console.error('  (cd .tmp/v1000 && go build -o ../congmq-v1000.exe ./cmd/congmq)');
    process.exit(1);
  }
}

const probe = dirOf('probe');
try {
  const h = await startBroker(NEW, { dir: probe, ports: PORTS.upgrade, id: 'probe' });
  await h.crash();
} catch (err) {
  console.error(`cannot start ${NEW}: ${err.message}`);
  console.error((err.brokerLines ?? []).join('\n'));
  cleanup();
  process.exit(1);
}

const results = [];
try {
  results.push(['v1.0.0 -> current', await scenarioUpgrade(PORTS.upgrade)]);
  results.push(['current -> v1.0.0', await scenarioRollback(PORTS.rollback)]);
  await scenarioSecondWriter(PORTS.holder);
} catch (err) {
  console.error(`\nthe harness stopped: ${err.stack ?? err.message}`);
  console.error((err.brokerLines ?? []).join('\n'));
  failures++;
}

function cleanup() {
  // Every broker is killed before its directory is touched, because Windows will
  // not remove a file a process that has not been waited for still holds.
  for (const h of procs) h.crash().catch(() => {});
  let left = 0;
  for (const dir of dirs) {
    try {
      rmSync(dir, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
    } catch {
      left++;
    }
  }
  if (left) console.log(`note: ${left} temp director${left === 1 ? 'y' : 'ies'} left behind under ${tmpdir()}`);
}

console.log('\nwhat the swap cost, measured');
for (const [name, r] of results) {
  console.log(
    `  ${name.padEnd(18)} queue across the boundary: ${r.queued} message(s) | ` +
      `live acks before the kill: ${r.ackedBefore}, of which ${r.lost} never arrived | ` +
      `delivered to the live subscriber: ${r.delivered}`,
  );
}
console.log(
  '  The offline queue is the durable path, so every message acknowledged on it is owed back across\n' +
  '  the boundary. The live path is not: the router hands a message to a subscriber from memory, so a\n' +
  '  kill costs whatever had not left the mailbox. That is a small, named number, not a mystery.',
);

cleanup();
console.log(failures ? `\nFAIL  ${failures}/${total} upgrade check(s) failed` : `\nall ${total} rolling-upgrade checks passed`);
process.exit(failures ? 1 : 0);
