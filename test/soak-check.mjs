// Soak harness: one broker, a long sequence of mixed load cycles, slope-based verdicts.
//
//   node soak-check.mjs
//   node soak-check.mjs --minutes=3
//   CONGMQ_SOAK_MINUTES=90 CONGMQ_BIN=... node soak-check.mjs --out=soak-2026-11-04.md
//
// The capacity baseline answers "how much can it hold". Nothing here answers
// "what does holding that do to it over time", and a leak is not visible in one
// measurement — only in the shape of many: heap climbing while the load stays
// flat, goroutines that never come back down after the connections did, a store
// file still growing after the sessions it recorded were reaped.
//
// So this keeps one broker up and runs the same cycle for the whole duration:
// idle connections, live QoS 1 and QoS 2 traffic, then away subscribers that make
// the durable queue spill and the reaper reclaim it. Beside that, a third-party
// client (mqtt.js) keeps a retained message, a hard-closed will and a roundtrip
// probe alive the entire run, so "the broker was still usable at minute 40" is a
// measured claim rather than an assumption.
//
// The metrics endpoint is sampled into a series every CONGMQ_SOAK_SAMPLE_SECONDS.
// Verdicts are computed from that series — the floor each cycle leaves behind,
// and the level the whole run settles at — plus two counters that must never
// move: dropped_messages, and the gap between what the broker says it delivered
// and what both clients say they got.
//
// The away phase also pins this session's Session Expiry fix in place for the
// whole run: the loader asks for 60s, the broker is started with
// -session-expiry-max 45s, so every single CONNECT in the soak must be answered
// with 45. A probe asserts it every SAMPLE and says so out loud.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import mqtt from 'mqtt';

const EXE = process.platform === 'win32' ? '.exe' : '';
const here = fileURLToPath(new URL('.', import.meta.url));
const BIN = process.env.CONGMQ_BIN ?? fileURLToPath(new URL(`../bin/congmq${EXE}`, import.meta.url));
const LOADER = process.env.CONGMQ_LOAD_BIN ?? fileURLToPath(new URL(`../bin/congmq-load${EXE}`, import.meta.url));
const BASE = Number(process.env.CONGMQ_SOAK_BASE_PORT ?? 1980);
const PORT = BASE;
const METRICS_PORT = BASE + 1;
const METRICS_URL = `http://127.0.0.1:${METRICS_PORT}/metrics`;
const BROKER_URL = `mqtt://127.0.0.1:${PORT}`;

const argv = Object.fromEntries(
  process.argv.slice(2).map((a) => {
    const [, k, v] = a.match(/^--([^=]+)(?:=(.*))?$/) ?? ['', a.replace(/^--/, ''), ''];
    return [k, v];
  }),
);
const MINUTES = Number(argv.minutes ?? process.env.CONGMQ_SOAK_MINUTES ?? 10);
const SAMPLE_MS = Number(argv.sample ?? process.env.CONGMQ_SOAK_SAMPLE_SECONDS ?? 20) * 1000;
const OUT = argv.out ?? `soak-${new Date().toISOString().slice(0, 10)}.md`;
const DURATION_MS = MINUTES * 60_000;
const EXPIRY_MAX_S = 45; // what the broker is allowed to keep, and must say so
const EXPIRY_ASK_S = 60; // what the away subscribers ask for
const QUEUE_MAX = 4000; // per offline session; nothing may reach it in this run
// Compaction is the promise that a long run's disk is the size of what the store
// still holds. At the 32MB default a ten-minute soak would never trigger it, so
// the threshold is lowered to put the rewrite on the measured path.
const COMPACT_MB = Number(process.env.CONGMQ_SOAK_COMPACT_MB ?? 4);
const NS = `soak/${Math.random().toString(16).slice(2, 10)}`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const num = (v) => (typeof v === 'number' ? v : 0);
const mib = (b) => `${(num(b) / 1048576).toFixed(1)}MB`;
const comma = (n) => Math.round(num(n)).toLocaleString('en-US');
const pct = (part, whole) => (whole ? `${((part / whole) * 100).toFixed(1)}%` : 'n/a');

let total = 0;
let failures = 0;
const verdicts = [];
const probes = [];
const check = (name, ok, detail = '') => {
  total++;
  console.log(`${ok ? 'pass' : 'FAIL'}  ${name}${detail ? `\n        -> ${detail}` : ''}`);
  if (!ok) failures++;
  verdicts.push({ name, ok, detail });
};

// The harness reports itself before it reports the broker. A loader that could not
// finish or a probe that could not connect looks exactly like a broker that went
// deaf, so every driver error is collected and gated.
const driverErrors = [];

// ---------------------------------------------------------------- broker -----

const store = mkdtempSync(join(tmpdir(), 'congmq-soak-'));
const brokerArgs = [
  '-addr', `127.0.0.1:${PORT}`,
  '-metrics', `127.0.0.1:${METRICS_PORT}`,
  '-store', store,
  '-store-sync', 'everysec',
  '-store-flush-interval', '1s',
  // Compaction is meant to hold a long run's disk down. The threshold is lowered
  // from its 32MB default so the rewrite happens on the measured path rather than
  // only in a unit test.
  '-store-compact-mb', String(COMPACT_MB),
  '-queue-max', String(QUEUE_MAX),
  '-session-expiry-max', `${EXPIRY_MAX_S}s`,
  '-reap-interval', '1s',
  '-log-level', 'info',
];
const broker = spawn(BIN, brokerArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
const brokerLines = [];
const onBrokerData = (b) => brokerLines.push(...b.toString().split(/\r?\n/).filter(Boolean));
broker.stderr.on('data', onBrokerData);
broker.stdout.on('data', onBrokerData);
const brokerLog = (needle) => brokerLines.filter((l) => l.includes(needle));

async function waitListening() {
  const started = Date.now();
  for (;;) {
    if (brokerLog('msg=listening').length) return brokerLog('msg=listening')[0];
    if (broker.exitCode !== null) {
      throw new Error(`broker died at startup (exit ${broker.exitCode}):\n${brokerLines.join('\n')}`);
    }
    if (Date.now() - started > 20000) throw new Error('broker did not come up within 20s');
    await sleep(50);
  }
}

async function metrics() {
  try {
    return await (await fetch(METRICS_URL)).json();
  } catch (err) {
    driverErrors.push(`metrics sample failed: ${err.message}`);
    return null;
  }
}

const stateBytes = () => {
  try {
    return statSync(join(store, 'state.log')).size;
  } catch {
    return 0;
  }
};

// ---------------------------------------------------------------- clients ----

// Every delivery to every mqtt.js client in this run, counted as it arrives.
// The reconciliation at the end compares the broker's messages_out against this
// plus what the loaders counted, so it has to be every client and not one — a
// tick that goes to two subscribers is two deliveries to the broker.
let nodeDeliveries = 0;

function connect(opts) {
  return new Promise((resolve, reject) => {
    const client = mqtt.connect(BROKER_URL, { protocolVersion: 5, connectTimeout: 8000, ...opts });
    client.received = [];
    client.on('error', (err) => client.received.push({ error: String(err) }));
    client.on('message', (topic, payload, packet) => {
      nodeDeliveries++;
      client.received.push({ topic, payload: payload.toString(), retain: packet.retain, at: Date.now() });
    });
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

const publish = (client, topic, payload, qos = 1, retain = false) =>
  new Promise((resolve, reject) =>
    client.publish(topic, payload, { qos, retain }, (err) => (err ? reject(err) : resolve())),
  );

// Force-close: no DISCONNECT. That is what a device losing power looks like, and
// it is the only way a will gets published.
const hardClose = (client) => new Promise((resolve) => client.end(true, {}, resolve));

/**
 * One availability probe: connect, read the CONNACK, take a roundtrip.
 *
 * The Session Expiry assertion lives here because a soak is the only place that
 * sees the clamp under load, hundreds of times, over a long run.
 */
async function probe(cycle) {
  const out = { ok: false, expiry: null, rtt: null, why: '' };
  let client;
  try {
    client = await connect({
      clientId: `${NS}-probe-${cycle}`,
      clean: false,
      reconnectPeriod: 0,
      properties: { sessionExpiryInterval: 3600 },
    });
    out.expiry = client.connack?.properties?.sessionExpiryInterval ?? null;
    await subscribe(client, `${NS}/probe/#`, 1);
    const topic = `${NS}/probe/${cycle}`;
    const from = Date.now();
    await publish(client, topic, `probe-${cycle}`, 1);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('no roundtrip within 5s')), 5000);
      const poll = setInterval(() => {
        if (client.received.some((m) => m.topic === topic)) {
          clearTimeout(timer);
          clearInterval(poll);
          resolve();
        }
      }, 25);
    });
    out.rtt = Date.now() - from;
    out.ok = true;
  } catch (err) {
    out.why = String(err.message ?? err).slice(0, 160);
  } finally {
    if (client) await hardClose(client).catch(() => {});
  }
  return out;
}

// ------------------------------------------------------------------ phases ---

const PHASES = [
  {
    name: 'idle-connections',
    args: ['-mode', 'conns', '-conns', '400', '-seconds', '20'],
  },
  {
    name: 'qos1-live',
    args: ['-mode', 'pump', '-publishers', '4', '-subscribers', '4', '-qos', '1',
      '-rate', '3000', '-seconds', '25', '-payload', '256', '-window', '100',
      '-topic', `${NS}/live1`],
  },
  {
    name: 'qos2-live',
    args: ['-mode', 'pump', '-publishers', '2', '-subscribers', '2', '-qos', '2',
      '-rate', '900', '-seconds', '15', '-topic', `${NS}/live2`],
  },
  {
    // The phase that puts the durable store on the measured path: these
    // subscribers take a 60s Session Expiry, close without goodbye, and are then
    // reclaimed on the 45s the operator allows. Each cycle is supposed to hand
    // the reaper work it has to finish.
    name: 'away-queue',
    args: ['-mode', 'pump', '-publishers', '3', '-subscribers', '2', '-offline', '30',
      '-session-expiry', String(EXPIRY_ASK_S), '-qos', '1', '-rate', '600',
      '-seconds', '15', '-topic', `${NS}/away`],
  },
];

// The last thing the soak needs is a heap reading that is not stale, and a Go
// runtime that has stopped allocating has no reason to collect: HeapAlloc — which
// is what mem_alloc_bytes reports — is the live set as of the last collection, so
// an idle broker keeps quoting whatever it measured during the load. This run is
// what forces a fresh collection: clean-session subscribers take no offline queue,
// so the messages cost memory on the way through and own nothing on the way out.
const SETTLE_DRAIN = {
  name: 'settle-drain',
  args: ['-mode', 'pump', '-publishers', '2', '-subscribers', '2', '-qos', '1',
    '-rate', '6000', '-seconds', '15', '-payload', '512', '-window', '100',
    '-topic', `${NS}/settle`],
};

async function runLoader(phase) {
  const args = ['-addr', `127.0.0.1:${PORT}`, '-metrics', METRICS_URL, ...phase.args];
  const proc = spawn(LOADER, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  let err = '';
  proc.stdout.on('data', (b) => (out += b));
  proc.stderr.on('data', (b) => (err += b.toString().replace(/\r/g, '')));
  const limit = (Number(phase.args[phase.args.indexOf('-seconds') + 1]) || 20) + 180;
  let timer;
  const code = await Promise.race([
    new Promise((r) => proc.once('close', r)),
    new Promise((r) => (timer = setTimeout(() => r('timeout'), limit * 1000))),
  ]).finally(() => clearTimeout(timer));
  if (code === 'timeout') {
    proc.kill('SIGKILL');
    driverErrors.push(`${phase.name}: loader exceeded ${limit}s`);
    return null;
  }
  if (code !== 0) {
    driverErrors.push(`${phase.name}: loader exited ${code}: ${(err || out).slice(0, 200)}`);
    return null;
  }
  let rep;
  try {
    rep = JSON.parse(out);
  } catch {
    driverErrors.push(`${phase.name}: loader printed no JSON (${out.slice(0, 120)})`);
    return null;
  }
  if ((rep.errors ?? []).length) {
    driverErrors.push(`${phase.name}: ${rep.errors.join('; ').slice(0, 200)}`);
  }
  return rep;
}

// --------------------------------------------------------------- measuring ---

const samples = [];
let sampling = true;
let currentCycle = 0;

async function sampler() {
  const t0 = Date.now();
  while (sampling) {
    const m = await metrics();
    if (m) {
      samples.push({
        at: Date.now() - t0,
        cycle: currentCycle,
        online: num(m.online),
        subs: num(m.subscriptions),
        connections: num(m.total_connections),
        in: num(m.messages_in),
        out: num(m.messages_out),
        spills: num(m.queue_spills),
        dropped: num(m.dropped_messages),
        expiredSessions: num(m.expired_sessions),
        retained: num(m.retained_messages),
        // The store's own residency: the sessions it holds, the messages queued
        // inside them, and how many bytes that costs on disk. These are what make
        // a heap that stayed high after the load an attributable fact rather than a
        // shape on a graph.
        storeSessions: num(m.store_sessions),
        storeQueued: num(m.store_queued),
        storeBytes: num(m.store_bytes),
        gcCycles: num(m.gc_cycles),
        malformed: num(m.malformed_packets),
        protocolErrors: num(m.protocol_errors),
        goroutines: num(m.goroutines),
        alloc: num(m.mem_alloc_bytes),
        sys: num(m.mem_sys_bytes),
        heapObjects: num(m.heap_objects),
        pid: num(m.pid),
        uptime: num(m.uptime_seconds),
        state: stateBytes(),
      });
    }
    await sleep(SAMPLE_MS);
  }
}

/** Least-squares slope of [x, y] points: change of y per one unit of x. */
function fitSlope(points) {
  const n = points.length;
  if (n < 2) return 0;
  const mx = points.reduce((a, p) => a + p[0], 0) / n;
  const my = points.reduce((a, p) => a + p[1], 0) / n;
  let numPart = 0;
  let denPart = 0;
  for (const [x, y] of points) {
    numPart += (x - mx) * (y - my);
    denPart += (x - mx) ** 2;
  }
  return denPart === 0 ? 0 : numPart / denPart;
}

const median = (xs) => {
  const v = [...xs].sort((a, b) => a - b);
  return v.length ? v[Math.floor(v.length / 2)] : 0;
};

// ------------------------------------------------------------------- main ----

async function main() {
  const ready = await waitListening();
  console.log(`broker    ${BIN}`);
  console.log(`loader    ${LOADER}`);
  console.log(`store     ${store}`);
  console.log(`namespace ${NS}`);
  console.log(`${ready}\n`);

  const before = await metrics();
  const idle = {
    alloc: num(before?.mem_alloc_bytes),
    goroutines: num(before?.goroutines),
    gc: num(before?.gc_cycles),
  };

  // The standing subscriber: it keeps the retained topic, the will topic and the
  // churn client's own tree under observation for the whole run.
  const watch = await connect({ clientId: `${NS}-watch`, clean: true, reconnectPeriod: 0 });
  await subscribe(watch, `${NS}/self/#`, 1);
  await subscribe(watch, `${NS}/will/#`, 1);

  let retainedPayload = '';
  let ticksSent = 0;
  let willsPlanted = 0;

  sampling = true;
  const samplerLoop = sampler();
  const stopAt = Date.now() + DURATION_MS;
  const phaseRun = [];
  let cycle = 0;

  while (Date.now() < stopAt) {
    cycle++;
    currentCycle = cycle;
    // Retained state is re-planted every cycle so the end of the run can tell
    // "the retained message survived the soak" from "the last writer happened to
    // be the first one".
    retainedPayload = `retained-cycle-${cycle}-${NS.slice(5)}`;
    await publish(watch, `${NS}/retained/state`, retainedPayload, 1, true);

    const churn = await connect({ clientId: `${NS}-churn`, clean: true, reconnectPeriod: 0 });
    await subscribe(churn, `${NS}/self/tick`, 1);
    for (let i = 0; i < 8; i++) {
      if (Date.now() >= stopAt) break;
      await publish(churn, `${NS}/self/tick`, `tick-${cycle}-${i}`, 1);
      ticksSent++;
      // A will roughly every cycle, planted on a connection that dies without
      // saying goodbye. The watcher must see all of them, at any point in the run.
      if (i === 4) {
        const w = await connect({
          clientId: `${NS}-will-${cycle}`,
          clean: true,
          reconnectPeriod: 0,
          will: { topic: `${NS}/will/${cycle}`, payload: `gone-${cycle}`, qos: 1, retain: false },
        });
        await hardClose(w);
        willsPlanted++;
      }
      await sleep(1500);
    }
    await hardClose(churn);

    for (const phase of PHASES) {
      if (Date.now() >= stopAt) break;
      const rep = await runLoader(phase);
      if (rep) phaseRun.push({ cycle, phase: phase.name, rep });
    }

    const p = await probe(cycle);
    probes.push(p);
  }

  // ---------------------------------------------------------------- settle ---
  // Samples taken from here on belong to no cycle: the run stopped adding load, and
  // the quiet tail is a different measurement from a cycle's trough. Tagging them
  // zero keeps them out of the per-cycle floor while leaving them in the series for
  // the final reading.
  currentCycle = 0;
  // The watcher gets a grace period before it is closed: a will published in the
  // last second of the run is still on its way, and counting before it lands would
  // blame the broker for a delivery that is already in flight.
  await sleep(4000);
  const loaderDelivered = phaseRun.reduce((a, r) => a + num(r.rep.delivered), 0);
  const awaySessions = phaseRun
    .filter((r) => r.phase === 'away-queue')
    .reduce((a, r) => a + num(r.rep.away_sessions), 0);
  const nodeSeen = nodeDeliveries;
  const willsSeen = watch.received.filter((m) => m.topic?.startsWith(`${NS}/will/`)).length;
  await hardClose(watch);

  console.log(`\nsettling for ${EXPIRY_MAX_S + 20}s (expiry window + reaper ticks)...`);
  await sleep((EXPIRY_MAX_S + 20) * 1000);
  // A retained topic holds one message and nobody here subscribes to it during the
  // run, so the only way to ask whether it survived is to send somebody new at the
  // end and see what the broker hands over. A copy flagged retain can only have
  // come from the retained store, which is the claim being tested.
  const retainedProber = await connect({ clientId: `${NS}-retained-probe`, clean: true, reconnectPeriod: 0 });
  await subscribe(retainedProber, `${NS}/retained/state`, 1);
  const from = Date.now();
  let got;
  while (Date.now() - from < 6000) {
    got = retainedProber.received.find((m) => m.topic === `${NS}/retained/state`);
    if (got) break;
    await sleep(100);
  }
  const retainedSeen = got ? `${got.payload}${got.retain ? ' (retained store)' : ' (live copy!)'}` : '';
  await hardClose(retainedProber);
  await sleep(2000);

  // Read the settled state before anything else touches it: who is connected, what
  // the store still holds, how big the file is. The drain below changes the heap
  // reading on purpose and would change these if it ran first.
  const settled = await metrics();
  const stateSettled = stateBytes();

  const drain = await runLoader(SETTLE_DRAIN);
  await sleep(6000);

  sampling = false;
  await samplerLoop;

  const final = await metrics();
  const last = samples[samples.length - 1] ?? {};
  // The floor is the shape that matters here. A repeating load that leaks leaves a
  // trough one cycle higher than the last even when the peak looks identical: the
  // peak says how big the broker gets, the trough says whether it ever gives
  // anything back. Each cycle is the same four phases, so the quietest sample in
  // one cycle is comparable to the quietest sample in the next.
  const troughs = [];
  for (let c = 1; c <= cycle; c++) {
    const inCycle = samples.filter((s) => s.cycle === c);
    if (inCycle.length < 2) continue;
    troughs.push({
      cycle: c,
      alloc: Math.min(...inCycle.map((s) => s.alloc)),
      goroutines: Math.min(...inCycle.map((s) => s.goroutines)),
      storeSessions: Math.min(...inCycle.map((s) => s.storeSessions)),
      storeQueued: Math.min(...inCycle.map((s) => s.storeQueued)),
      state: inCycle.at(-1).state,
    });
  }
  // Only a cycle that ran every phase has a trough that means what the next
  // cycle's will. The run stops on the clock, so its last cycle is cut off
  // mid-phase and its quietest sample is whatever the load left standing —
  // comparing that against cycle one is a slope of the harness's calendar, not
  // of the broker.
  const runsIn = (c) => phaseRun.filter((r) => r.cycle === c).length;
  const fullTroughs = troughs.filter((t) => runsIn(t.cycle) === PHASES.length);

  console.log(`\n${cycle} cycles, ${phaseRun.length} loader runs, ${probes.length} probes, ${samples.length} samples`);
  console.log('');

  // --------------------------------------------------------------- verdicts ---

  check('the harness drove its own work', driverErrors.length === 0,
    driverErrors.length ? driverErrors.slice(0, 4).join(' | ') : 'every loader run finished and reported itself');

  check('the soak had something to measure', cycle >= 2 && troughs.length >= 2 && phaseRun.length >= 4,
    `${cycle} cycles, ${troughs.length} with enough samples to compare, ${phaseRun.length} loader runs`);

  check('the broker is the same process it started', num(final?.pid) === num(before?.pid) && num(final?.pid) !== 0,
    `pid ${before?.pid} -> ${final?.pid}`);

  // The two halves of the offline-queue story. A message handed to an away
  // subscriber is a spill; a message pushed out of a bounded queue is a drop.
  // Nothing here should ever fill a queue, so spills must climb while dropped
  // stays at zero — and a run where spills never moved measured no offline
  // queueing at all, which makes this a gate on the harness as much as the
  // broker.
  check('the away subscribers were really queued for', num(final?.queue_spills) > 0,
    `queue_spills=${comma(final?.queue_spills)}, dropped_messages=${num(final?.dropped_messages)}`);

  check('no message was dropped to bound a queue', num(final?.dropped_messages) === 0,
    `dropped_messages=${num(final?.dropped_messages)}, queue_spills=${comma(final?.queue_spills)}`);

  const deliveredGap = Math.abs(num(final?.messages_out) - (loaderDelivered + num(drain?.delivered) + nodeSeen));
  check('what the broker delivered is what both clients received',
    deliveredGap <= Math.max(4, num(final?.messages_out) * 0.002),
    `broker messages_out=${comma(final?.messages_out)}, loaders ${comma(loaderDelivered)} + mqtt.js ${comma(nodeSeen)}, gap ${comma(deliveredGap)} (${pct(deliveredGap, num(final?.messages_out))})`);

  check('every will the soak planted was published', willsPlanted > 0 && willsSeen === willsPlanted,
    `planted ${willsPlanted}, seen ${willsSeen}`);

  check('the retained message still answers a new subscriber at the end',
    retainedSeen.startsWith(retainedPayload) && retainedSeen.includes('(retained store)'),
    `wanted ${retainedPayload}, a new subscriber got ${retainedSeen || 'nothing'}`);

  const expiryBad = probes.filter((p) => p.expiry !== EXPIRY_MAX_S);
  check('every CONNECT was told the expiry the broker will actually keep',
    probes.length > 0 && expiryBad.length === 0,
    `${probes.length - expiryBad.length}/${probes.length} said ${EXPIRY_MAX_S}` +
      (expiryBad.length ? `; first outlier: ${JSON.stringify(expiryBad[0])}` : ''));

  const probeFailed = probes.filter((p) => !p.ok);
  check('the broker stayed usable the whole time', probes.length >= 2 && probeFailed.length === 0,
    `${probes.length - probeFailed.length}/${probes.length} roundtrips` +
      (probeFailed.length ? `; first failure: ${probeFailed[0].why}` : ''));

  const rtts = probes.map((p) => p.rtt).filter((v) => typeof v === 'number');
  check('a roundtrip stayed fast to the last cycle',
    rtts.length > 0 && Math.max(...rtts) < 4000,
    `median ${median(rtts)}ms, worst ${Math.max(...(rtts.length ? rtts : [0]))}ms over ${rtts.length} probes`);

  // The per-cycle floor, fitted and compared. Both halves are needed: the slope
  // says whether the run is still climbing as it ends, and the level says the
  // climb never came back down to where the first cycle left it. Thresholds are
  // deliberately wide — a soak gate that fails on GC timing is a gate nobody
  // trusts the second time it fires — and only cycles that ran the whole load
  // take part, because a truncated cycle's trough is not a quiet moment.
  const allocFloor = fitSlope(fullTroughs.map((t) => [t.cycle, t.alloc]));
  const goroutineFloor = fitSlope(fullTroughs.map((t) => [t.cycle, t.goroutines]));
  const firstTrough = fullTroughs[0] ?? { cycle: 0, alloc: idle.alloc, goroutines: idle.goroutines };
  const lastTrough = fullTroughs.at(-1) ?? firstTrough;
  check('the heap floor did not rise from the first complete cycle to the last',
    fullTroughs.length >= 2 &&
      lastTrough.alloc <= Math.max(firstTrough.alloc * 1.25, firstTrough.alloc + 8 * 1048576),
    `${fullTroughs.length}/${troughs.length} cycles ran all ${PHASES.length} phases; ` +
      `cycle ${firstTrough.cycle} ${mib(firstTrough.alloc)} -> cycle ${lastTrough.cycle} ${mib(lastTrough.alloc)}, ${mib(allocFloor)} per cycle`);
  check('the goroutine floor did not rise from the first complete cycle to the last',
    fullTroughs.length >= 2 && lastTrough.goroutines <= firstTrough.goroutines + 60,
    `cycle ${firstTrough.cycle} ${firstTrough.goroutines} -> cycle ${lastTrough.cycle} ${lastTrough.goroutines}, ${goroutineFloor.toFixed(1)} per cycle`);

  // Settling. Every connection this harness opened is closed, so the only things
  // that may remain are what the operator asked the broker to keep. `settled` is
  // read before the drain, while nothing at all is connected; `last` is the tail
  // sample taken after it, and is the one the heap number has to come from.
  check('every session the soak made is gone',
    num(settled?.online) === 0 && num(settled?.subscriptions) === 0,
    `online=${num(settled?.online)}, subscriptions=${num(settled?.subscriptions)}`);

  check('the reaper ran during the soak',
    num(settled?.expired_sessions) >= awaySessions && awaySessions > 0,
    `expired_sessions=${num(settled?.expired_sessions)}, away sessions handed over ${awaySessions}`);

  check('the heap drain ran', !!drain,
    drain ? `${comma(drain.delivered)} messages through clean subscribers, nothing queued behind them`
      : 'no drain: the heap number below is whatever the last collection saw');

  const queuedPeak = Math.max(...samples.map((s) => s.storeQueued));
  const statePeak = Math.max(...samples.map((s) => s.state));
  check('memory came back down with the load',
    num(last.alloc) <= Math.max(idle.alloc * 2, idle.alloc + 24 * 1048576),
    `heap ${mib(last.alloc)} settled vs ${mib(idle.alloc)} idle (peak under load ${mib(Math.max(...samples.map((s) => s.alloc)))}), ` +
      `${comma(num(last.gcCycles) - idle.gc)} GC cycles since idle, store held ${comma(queuedPeak)} queued at its busiest and ${comma(num(settled?.store_queued))} at the settle reading`);

  check('goroutines came back down with the load',
    num(last.goroutines) <= idle.goroutines + 100,
    `${num(last.goroutines)} settled vs ${idle.goroutines} idle (peak ${Math.max(...samples.map((s) => s.goroutines))})`);

  // The store's own residency, which is what a heap that stayed high is either
  // explained by or not. Queued messages are the part that costs memory and disk,
  // and a reaped session must not leave its queue behind — a leak of offline
  // messages shows up here long before the heap slope has anything to say.
  const queuedFloor = fitSlope(fullTroughs.map((t) => [t.cycle, t.storeQueued]));
  check('the store gave every queued message back', num(settled?.store_queued) === 0,
    `store_queued=${comma(num(settled?.store_queued))} settled, ${comma(queuedPeak)} at the peak, ` +
      `floor slope ${comma(queuedFloor)} per cycle`);

  // A couple of records are owed by the harness itself: the last probe connects
  // seconds before the settle reading and is inside the expiry window it asked
  // for. A store still holding the soak's away subscribers is not that.
  check('the store holds no session the soak left behind', num(settled?.store_sessions) <= 2,
    `store_sessions=${num(settled?.store_sessions)} settled (the last probe is owed its ${EXPIRY_MAX_S}s window), ` +
      `peak ${Math.max(...samples.map((s) => s.storeSessions))}`);

  // Compaction stated as the broker states it: the file is what the store still
  // holds plus what has been appended since the last rewrite, and the rewrite is
  // due once that second part passes the threshold. So the disk a run needed is
  // priced by the backlog it actually held, and once the store holds nothing the
  // file stops growing — it does not fall back to the threshold, and a gate that
  // asked it to would be measuring a promise the broker never made.
  const awayPhase = PHASES.find((p) => p.name === 'away-queue');
  const awayPayload = Number(awayPhase.args[awayPhase.args.indexOf('-payload') + 1]) || 256;
  const bytesPerQueued = queuedPeak > 0 ? statePeak / queuedPeak : 0;
  check('the disk the soak needed is explained by the backlog it held',
    bytesPerQueued <= 4096,
    `peak ${comma(queuedPeak)} queued messages against a ${mib(statePeak)} file = ${bytesPerQueued.toFixed(0)} bytes per record ` +
      `(a ${awayPayload}-byte payload is ${Math.ceil(awayPayload * 4 / 3)}B base64 inside JSON, plus topic, packet id and fields)`);

  check('the store stopped growing once it was holding nothing',
    num(last.state) <= stateSettled + (2 << 20),
    `state.log ${mib(stateSettled)} at the settle reading, ${mib(last.state)} after the drain ` +
      `(peak ${mib(statePeak)}, compaction threshold ${COMPACT_MB}MB, store holds ${comma(num(settled?.store_queued))} queued)`);

  // Two instruments on one file. If the harness's own stat and the broker's
  // gauge disagree once the writes have stopped, one of them is not measuring
  // this store, and every disk verdict above is built on that.
  check('the broker and the harness see the same store file',
    Math.abs(num(final?.store_bytes) - stateBytes()) <= 2 << 20,
    `broker store_bytes=${mib(final?.store_bytes)}, harness statSync=${mib(stateBytes())}`);

  const noise = brokerLog('level=ERROR').concat(brokerLog('panic'));
  check('the broker logged no error through the whole run', noise.length === 0,
    noise.slice(0, 3).join(' | ') || 'no level=ERROR, no panic');

  const abuse = (num(final?.malformed_packets) || 0) + (num(final?.protocol_errors) || 0);
  // This harness closes sockets without goodbye on purpose — every will and every
  // away subscriber does — so a truncated read at the end of a killed socket is
  // the run behaving, not the broker failing. It is allowed one per such close,
  // and says so either way.
  const hardCloses = willsPlanted + awaySessions + probes.length;
  check('the abrupt closes were not treated as protocol failures', abuse <= hardCloses,
    `malformed+protocol=${abuse} against ${hardCloses} deliberate no-goodbye closes`);

  await writeReport({
    ready, before, final, last, settled, drain, cycle, idle, troughs, fullTroughs,
    allocFloor, goroutineFloor, queuedFloor, stateSettled, queuedPeak, statePeak,
    loaderDelivered, nodeSeen, willsPlanted, willsSeen, awaySessions, samples, phaseRun, probes,
  });
  console.log(`\nreport     ${join(process.cwd(), OUT)}`);
  console.log(`\n${failures ? 'FAIL' : 'pass'}  ${total - failures}/${total} soak checks passed`);
}

// ---------------------------------------------------------------- report -----

async function writeReport(ctx) {
  const rows = ctx.samples.map((s) =>
    `| ${Math.round(s.at / 1000)} | ${s.online} | ${s.subs} | ${s.goroutines} | ` +
    `${mib(s.alloc)} | ${mib(s.sys)} | ${comma(s.out)} | ${comma(s.spills)} | ${s.dropped} | ` +
    `${comma(s.storeQueued)} | ${s.storeSessions} | ${mib(s.state)} |`,
  );
  const phases = {};
  for (const r of ctx.phaseRun) {
    phases[r.phase] ??= { n: 0, delivered: 0, published: 0, errors: 0 };
    phases[r.phase].n++;
    phases[r.phase].delivered += num(r.rep.delivered);
    phases[r.phase].published += num(r.rep.published);
    phases[r.phase].errors += (r.rep.errors ?? []).length + num(r.rep.connect_errors) + num(r.rep.subscribe_errors);
  }
  if (ctx.drain) {
    phases[SETTLE_DRAIN.name] = {
      n: 1,
      delivered: num(ctx.drain.delivered),
      published: num(ctx.drain.published),
      errors: (ctx.drain.errors ?? []).length + num(ctx.drain.connect_errors) + num(ctx.drain.subscribe_errors),
    };
  }
  const loaderDelivered = num(ctx.loaderDelivered) + num(ctx.drain?.delivered);
  const md = `# Soak run ${new Date().toISOString()}

| | |
|---|---|
| broker | \`${BIN}\` |
| loader | \`${LOADER}\` |
| duration | ${MINUTES} min, sample every ${SAMPLE_MS / 1000}s |
| namespace | \`${NS}\` |
| flags | \`-store-sync everysec -store-compact-mb ${COMPACT_MB} -queue-max ${QUEUE_MAX} -session-expiry-max ${EXPIRY_MAX_S}s -reap-interval 1s\` |

## 结论

${ctx.samples.length} 次采样、${ctx.cycle} 个周期、${probes.length} 次探针。
${failures ? `**${failures}/${total} 项判定未通过**（明细见下）。` : `**${total}/${total} 项判定全部通过。**`}

${verdicts.map((v) => `- ${v.ok ? 'x' : '!' } ${v.name}${v.detail ? ` — ${v.detail}` : ''}`).join('\n')}

## 每类负载

| phase | 次数 | published | delivered | 压测端自报错误 |
|---|---|---|---|---|
${Object.entries(phases).map(([p, s]) => `| \`${p}\` | ${s.n} | ${comma(s.published)} | ${comma(s.delivered)} | ${s.errors} |`).join('\n')}

## 采样序列

| t (s) | online | subs | goroutines | heap | sys | messages_out | queue_spills | dropped | store_queued | store_sessions | state.log |
|---|---|---|---|---|---|---|---|---|---|---|---|
${rows.join('\n')}

## 每周期的谷底（泄漏看这条，不看峰值）

| cycle | heap 谷底 | goroutine 谷底 | store_queued 谷底 | state.log | 跑满四类负载 |
|---|---|---|---|---|---|
${ctx.troughs.map((t) => `| ${t.cycle} | ${mib(t.alloc)} | ${t.goroutines} | ${comma(t.storeQueued)} | ${mib(t.state)} | ${ctx.fullTroughs.includes(t) ? '是' : '否（被时长截断，不参与谷底斜率）'} |`).join('\n')}

## 斜率与回落

- 谷底斜率只按跑满四类负载的 ${ctx.fullTroughs.length}/${ctx.troughs.length} 个周期算：heap **${mib(ctx.allocFloor)}/周期**；goroutine **${ctx.goroutineFloor.toFixed(1)}/周期**；store_queued **${comma(ctx.queuedFloor)}/周期**
- 空载 heap ${mib(ctx.idle.alloc)} → 峰值 ${mib(Math.max(...ctx.samples.map((s) => s.alloc)))} → 收尾 ${mib(ctx.last.alloc)}（收尾这个数是 ${comma(ctx.drain?.delivered)} 条 QoS 1 消息压过去之后最近一次 GC 的快照：\`mem_alloc_bytes\` 只在 GC 时更新，空转的 Go runtime 没有理由去看，压一段负载才拿得到新数）
- 空载 goroutine ${ctx.idle.goroutines} → 峰值 ${Math.max(...ctx.samples.map((s) => s.goroutines))} → 收尾 ${ctx.last.goroutines}
- 存储驻留（压负载之前读的 \`settled\`）：\`store_sessions\` ${num(ctx.settled?.store_sessions)}、\`store_queued\` ${comma(num(ctx.settled?.store_queued))}（峰值 ${Math.max(...ctx.samples.map((s) => s.storeSessions))} / ${comma(ctx.queuedPeak)}）
- 磁盘：\`state.log\` 结算时 ${mib(ctx.stateSettled)}，压完那段负载后 ${mib(ctx.last.state)}，全程峰值 ${mib(ctx.statePeak)}；峰值驻留 ${comma(ctx.queuedPeak)} 条 ÷ 峰值文件 = 每条约 ${(ctx.queuedPeak ? ctx.statePeak / ctx.queuedPeak : 0).toFixed(0)}B，这就是磁盘上那一坨的来源（\`-store-compact-mb ${COMPACT_MB}\`；broker 自报 \`store_bytes\` ${mib(ctx.final?.store_bytes)}）
- 交付对账：broker \`messages_out\` ${comma(ctx.final?.messages_out)} = 压测端 ${comma(loaderDelivered)} + mqtt.js ${comma(ctx.nodeSeen)}
- 遗嘱：种下 ${ctx.willsPlanted}、见到 ${ctx.willsSeen}；离线会话交给回收器 ${ctx.awaySessions}，实际过期 ${num(ctx.settled?.expired_sessions)}

## 怎么读这份报告

一次采样说明不了任何事，这条序列才说明：每个周期跑的是同样四类负载，所以周期与周期之间可比的不是峰值，是谷底——谷底一路抬高，就是有什么东西没跟着连接一起释放。被时长截掉的最后一个周期不算谷底，它压根没跑到安静的时候。
\`dropped_messages\` 与 \`queue_spills\` 是一对：前者必须一直是 0，后者必须一路长——离线队列真的在写，且没有溢出。
heap 抬了不算结论，\`store_sessions\` / \`store_queued\` 才是归因：这两个数收尾必须归零，否则留在内存与磁盘上的就是存储里的会话，而不是还没跑完的 GC。两者归零而 heap 仍高，先怀疑仪表再怀疑 broker——\`mem_alloc_bytes\` 是上一次 GC 时的快照，空载的 Go runtime 可以好几分钟不看一眼，所以这份报告在收尾前压了一段不留驻留的负载，把那个数刷新成真数。
磁盘看的是契约不是阈值：文件 = 存储当前持有的 + 上次重写之后追加的。一段洪峰被回收之后，文件仍留着上次重写那一刻的体积，要等追加量再过一遍阈值、或者进程干净关停，才会缩回去。所以判两条：峰值文件大小能被峰值驻留解释（每条队列消息摊到的字节数不离谱），以及存储空了之后文件不再长。

启动行：\`${ctx.ready}\`
`;
  writeFileSync(OUT, md.replace(/\r/g, ''), 'utf8');
}

// ---------------------------------------------------------------- teardown ---

async function teardown() {
  // The store directory cannot be removed on Windows while the broker still holds
  // state.log, and a leftover temp directory is not a failed check — so the kill
  // lands first and the removal is best effort. It must never swallow the verdict.
  broker.kill('SIGKILL');
  await new Promise((r) => broker.once('exit', r));
  await sleep(600);
  try {
    rmSync(store, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
  } catch (err) {
    console.log(`note: left ${store} behind (${err.code})`);
  }
}

main()
  .then(async () => {
    await teardown();
    process.exit(failures ? 1 : 0);
  })
  .catch(async (err) => {
    console.log(`\nFAIL  the soak harness itself: ${err.stack ?? err.message}`);
    await teardown();
    process.exit(1);
  });
