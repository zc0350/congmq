// Third-party-client checks for the anti-abuse limits: an unarmed broker that
// nobody has to think about, and four armed ones that refuse connections,
// connection churn, subscriptions and credentials — each proved through mqtt.js,
// a raw socket and the same /metrics an operator graphs.
//
//	node test/abuse-check.mjs
//
// The Go suite owns the boundaries that need a clock it controls (token refill,
// lockout arithmetic, IPv6 /64 keying) and the per-address isolation that needs a
// socket bound to 127.0.0.2. What is worth re-proving here is that a real client
// library sees the same verdicts, and that the limits never touch the message
// path: every broker below still carries an ordinary session afterwards.
//
// Four brokers, because one limit at a time is the only way to tell which one
// answered. CONGMQ_BIN and CONGMQ_ABUSE_BASE_PORT point this at another build or
// another port block; the defaults sit above the 1883/1884 a dev box is holding.
import mqtt from 'mqtt';
import crypto from 'node:crypto';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const BIN =
  process.env.CONGMQ_BIN ??
  fileURLToPath(new URL(`../bin/congmq${process.platform === 'win32' ? '.exe' : ''}`, import.meta.url));

const BASE_PORT = Number(process.env.CONGMQ_ABUSE_BASE_PORT ?? 1920);
const OFF = { port: BASE_PORT, metrics: BASE_PORT + 1 };
const CONN = { port: BASE_PORT + 2, metrics: BASE_PORT + 3 };
const RATE = { port: BASE_PORT + 4, metrics: BASE_PORT + 5 };
const POLICY = { port: BASE_PORT + 6, metrics: BASE_PORT + 7 };

const url = (p) => `mqtt://127.0.0.1:${p}`;
const base = (p) => `http://127.0.0.1:${p}`;

const hex = (alg, s) => crypto.createHash(alg).update(s, 'utf8').digest('hex');
// {"username":"ops","salt":"x","alg":"md5","scheme":"username+salt"}
const OPS_PASSWORD = hex('md5', 'ops' + 'x');
const WRONG_PASSWORD = 'deadbeef';

let failures = 0;
let total = 0;
const check = (name, ok, detail = '') => {
  total++;
  console.log(`${ok ? 'pass' : 'FAIL'}  ${name}${detail ? `\n        -> ${detail}` : ''}`);
  if (!ok) failures++;
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(what, cond, limit = 15000) {
  const started = Date.now();
  for (;;) {
    const ok = await cond();
    if (ok) return Date.now() - started;
    if (Date.now() - started > limit) throw new Error(`timed out after ${limit}ms waiting for ${what}`);
    await sleep(50);
  }
}

// ------------------------------------------------------------------ brokers ----

function startBroker(port, metricsPort, args) {
  const proc = spawn(BIN, ['-addr', `127.0.0.1:${port}`, '-metrics', `127.0.0.1:${metricsPort}`,
    '-log-level', 'info', ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  const handle = { proc, lines: [], killed: false, metrics: base(metricsPort) };
  proc.stderr.on('data', (b) => {
    for (const line of b.toString().split(/\r?\n/)) if (line.trim()) handle.lines.push(line.trim());
  });
  proc.stdout.on('data', (b) => handle.lines.push(b.toString().trim()));
  proc.once('exit', (code) => handle.lines.push(`exit=${code}`));
  proc.on('error', (err) => handle.lines.push(`spawn error: ${err.message}`));
  handle.log = (needle) => handle.lines.find((l) => l.includes(needle)) ?? '';
  handle.count = (needle) => handle.lines.filter((l) => l.includes(needle)).length;
  return handle;
}

const waitListening = (h) => waitFor(`${h.metrics} to listen`, () => h.log('msg=listening') !== '');

async function killAndWait(h) {
  if (h.killed) return true;
  h.killed = true;
  h.proc.kill('SIGKILL');
  for (let i = 0; i < 100; i++) {
    if (h.lines.some((l) => l.startsWith('exit='))) return true;
    await sleep(50);
  }
  return false;
}

async function metrics(h) {
  return (await fetch(`${h.metrics}/metrics`)).json();
}

async function metricsText(h) {
  const res = await fetch(`${h.metrics}/metrics.txt`);
  return { type: res.headers.get('content-type') ?? '', text: await res.text() };
}

function promParse(text) {
  const values = {};
  const types = {};
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    if (line.startsWith('# TYPE ')) {
      const [name, type] = line.replace('# TYPE ', '').split(' ');
      types[name] = type;
    } else if (!line.startsWith('#')) {
      const [name, value] = line.split(' ');
      values[name] = value;
    }
  }
  return { values, types };
}

async function waitForMetric(h, what, cond, limit = 15000) {
  const started = Date.now();
  for (;;) {
    const m = await metrics(h);
    if (cond(m)) return m;
    if (Date.now() - started > limit) throw new Error(`timed out after ${limit}ms waiting for ${what} (last: ${JSON.stringify(m)})`);
    await sleep(50);
  }
}

// -------------------------------------------------------------- raw sockets ----

// silentSocket opens a TCP connection and sends nothing at all — the load a limit
// checked at CONNECT cannot see, which is the reason the gate sits at accept.
// A refusal arrives afterwards as `closed`: the broker hangs up without reading a
// byte, and the peer is told nothing that would let it tell a gate refusal from a
// device fault.
function silentSocket(port) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ port, host: '127.0.0.1' });
    const state = { sock: s, closed: false };
    let settled = false;
    let timer;
    // Only the open attempt fails here. Once the socket is up, an error or a FIN
    // is the gate's answer and belongs in `state.closed`, not in a rejection the
    // caller has no way to distinguish from a broken test.
    const fail = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      s.destroy();
      reject(err);
    };
    timer = setTimeout(() => fail(new Error(`no connection to ${port} within 6s`)), 6000);
    s.on('error', () => {
      fail(new Error(`socket to ${port} was refused at the TCP level`));
      state.closed = true;
    });
    s.on('close', () => (state.closed = true));
    s.once('connect', () => {
      settled = true;
      clearTimeout(timer);
      resolve(state);
    });
  });
}

// --------------------------------------------------------------- mqtt clients ----

function connect(opts) {
  return new Promise((resolve, reject) => {
    const client = mqtt.connect(url(opts.port), {
      clientId: opts.clientId ?? `abuse-${Math.random().toString(16).slice(2, 8)}`,
      username: opts.username,
      password: opts.password,
      protocolVersion: opts.protocolVersion ?? 4,
      reconnectPeriod: 0,
      connectTimeout: 5000,
      clean: true,
    });
    const timer = setTimeout(() => {
      client.end(true);
      reject(new Error('connect timed out'));
    }, 8000);
    client.once('connect', () => {
      clearTimeout(timer);
      resolve(client);
    });
    client.once('error', (err) => {
      clearTimeout(timer);
      client.end(true);
      reject(err);
    });
  });
}

// refusedOne connects and hands back the reason the broker said no, or null if it
// said yes. mqtt.js reports a refused CONNECT as an error with the return code.
async function refusedOne(opts) {
  try {
    const client = await connect(opts);
    await close(client);
    return null;
  } catch (err) {
    return err.code ?? err.message;
  }
}

const subscribe = (client, topics, qos = 1) =>
  new Promise((resolve, reject) =>
    client.subscribe(topics, { qos }, (err, granted) => (err ? reject(err) : resolve(granted))),
  );

// rawSubscribe answers with the reason codes exactly as the SUBACK carried them.
// mqtt.js promotes any code at or above 0x80 into an error, and here the refusal
// is the result being checked rather than a fault in getting it — the codes still
// ride along on that error's packet.
function rawSubscribe(client, topics, qos = 1) {
  const list = Array.isArray(topics) ? topics : [topics];
  return new Promise((resolve, reject) =>
    client.subscribe(list, { qos }, (err, granted) => {
      if (!err) return resolve(granted.map((g) => g.qos));
      const codes = err.packet?.granted ?? err.granted;
      if (Array.isArray(codes)) return resolve(codes);
      reject(err);
    }),
  );
}

const publish = (client, topic, payload, qos = 1) =>
  new Promise((resolve, reject) =>
    client.publish(topic, payload, { qos }, (err) => (err ? reject(err) : resolve())),
  );

function oneMessage(client, waitMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      client.off('message', handler);
      reject(new Error('nothing arrived'));
    }, waitMs);
    function handler(topic, payload) {
      clearTimeout(timer);
      client.off('message', handler);
      resolve({ topic, payload: payload.toString() });
    }
    client.on('message', handler);
  });
}

const close = (client) => new Promise((resolve) => client.end(true, resolve));

const destroyAll = (sockets) => {
  for (const s of sockets) {
    try {
      s.sock.destroy();
    } catch {
      /* already gone */
    }
  }
};

// ------------------------------------------------------------------- the run ----

const dir = mkdtempSync(join(tmpdir(), 'congmq-abuse-check-'));
const authPath = join(dir, 'auth.jsonl');
writeFileSync(
  authPath,
  ['# one account, digested the way the shipped rules file describes',
    '{"username":"ops","salt":"x","alg":"md5","scheme":"username+salt"}', ''].join('\n'),
);

let off;
let conn;
let rate;
let policy;

async function checkNothingIsArmed() {
  off = startBroker(OFF.port, OFF.metrics, []);
  await waitListening(off);

  check('an unarmed broker says nothing about a gate', off.log('per-address gate armed') === '');

  const held = [];
  for (let i = 0; i < 6; i++) held.push(await silentSocket(OFF.port));
  const m = await waitForMetric(off, 'six silent sockets to be connections', (x) => x.total_connections >= 6, 8000);
  check('six silent sockets from one address are all connections', m.total_connections === 6,
    `total_connections=${m.total_connections}`);
  check('none of them was refused', m.refused_over_per_ip_connection_limit === 0 && m.refused_over_per_ip_connect_rate === 0,
    `refused ${m.refused_over_per_ip_connection_limit}/${m.refused_over_per_ip_connect_rate}`);
  check('and the gate keeps no table at all', m.per_ip_gate_entries === 0 && m.per_ip_gate_held_sockets === 0,
    `entries=${m.per_ip_gate_entries} held=${m.per_ip_gate_held_sockets}`);
  destroyAll(held);

  // Unlimited is the default, so a chatty dashboard is not a special case.
  const wide = await connect({ port: OFF.port, clientId: 'wide' });
  const many = Array.from({ length: 40 }, (_, i) => `abuse/wide/${i}`);
  const granted = await subscribe(wide, many, 1);
  check('forty subscriptions in one request are all granted', granted.every((g) => g.qos === 1),
    granted.map((g) => g.qos).join(','));
  const after = await metrics(off);
  check('nothing was refused over a subscription cap', after.refused_over_subscription_cap === 0,
    `refused_over_subscription_cap=${after.refused_over_subscription_cap}`);
  await close(wide);
}

async function checkConnectionLimit() {
  conn = startBroker(CONN.port, CONN.metrics, ['-max-conns-per-ip', '2']);
  await waitListening(conn);

  const armed = conn.log('per-address gate armed');
  check('the armed numbers are said out loud at startup', /max_conns_per_ip=2/.test(armed), armed);

  const held = [];
  for (let i = 0; i < 3; i++) held.push(await silentSocket(CONN.port));
  const m = await waitForMetric(conn, 'the third socket to be refused', (x) => x.refused_over_per_ip_connection_limit >= 1);
  check('a third silent socket from one address is refused', m.refused_over_per_ip_connection_limit === 1,
    `refused=${m.refused_over_per_ip_connection_limit}`);
  check('only the two admitted ones were ever connections', m.total_connections === 2,
    `total_connections=${m.total_connections}`);
  // The close event is the peer's half of the hangup and lands on its own schedule,
  // so it is waited for rather than assumed: a half-open socket would be the bug.
  await waitFor('the refused socket to be hung up', () => held[2].closed);
  check('a refusal is a hangup, not a silent half-open socket', held[2].closed,
    `socket 3 closed=${String(held[2].closed)}`);
  check('a refusal never becomes a session', m.online === 0, `online=${m.online}`);

  // Five more attempts against the same full bucket. The refusal is a counter, not
  // a log line per socket — otherwise the defence would be the flood.
  for (let i = 0; i < 5; i++) {
    try {
      held.push(await silentSocket(CONN.port));
    } catch {
      /* refused sockets may error before they report open */
    }
  }
  const more = await waitForMetric(conn, 'the five extra refusals', (x) => x.refused_over_per_ip_connection_limit >= 6);
  check('every extra attempt is counted', more.refused_over_per_ip_connection_limit === 6,
    `refused=${more.refused_over_per_ip_connection_limit}`);
  check('and refused six times, logged once', conn.count('refused by the per-address gate') === 1,
    `${conn.count('refused by the per-address gate')} log lines\n     ${conn.log('refused by the per-address gate')}`);

  // The room comes back with the connections that end, and ordinary traffic was
  // never in the gate's way.
  destroyAll(held);
  await waitForMetric(conn, 'the held sockets to go to zero', (x) => x.per_ip_gate_held_sockets === 0);
  const device = await connect({ port: CONN.port, clientId: 'after-the-gate' });
  const seen = oneMessage(device, 4000);
  const pub = await connect({ port: CONN.port, clientId: 'publisher' });
  await subscribe(device, 'abuse/live/1', 1);
  await publish(pub, 'abuse/live/1', 'through', 1);
  const msg = await seen;
  check('a real session still connects and is delivered to once the slots are back',
    msg.topic === 'abuse/live/1' && msg.payload === 'through', `${msg.topic}=${msg.payload}`);
  await close(device);
  await close(pub);
}

async function checkConnectRate() {
  rate = startBroker(RATE.port, RATE.metrics, ['-conn-rate-per-ip', '2', '-conn-burst-per-ip', '2']);
  await waitListening(rate);
  check('the burst is said out loud with the rate', /connect_rate_per_second=2 burst=2/.test(rate.log('per-address gate armed')),
    rate.log('per-address gate armed'));

  // Open, close, open, close: the cheapest evasion of a concurrency limit, and the
  // exact shape a rate window exists to meter.
  const sockets = [];
  for (let i = 0; i < 25; i++) {
    try {
      const s = await silentSocket(RATE.port);
      sockets.push(s);
      s.sock.destroy();
    } catch {
      /* refused or already closed */
    }
    await sleep(20);
  }
  const m = await waitForMetric(rate, 'the churn to be refused', (x) => x.refused_over_per_ip_connect_rate > 0);
  check('arrivals past the burst are refused for rate, not for concurrency',
    m.refused_over_per_ip_connect_rate > 0 && m.refused_over_per_ip_connection_limit === 0,
    `rate=${m.refused_over_per_ip_connect_rate} conns=${m.refused_over_per_ip_connection_limit}`);
  const line = rate.log('refused by the per-address gate');
  check('and the refusal names the rate as the reason', /reason="connect rate"/.test(line), line);

  // Time is the only refill: two and a half quiet seconds at 2/s buys the address
  // its burst back.
  await sleep(2500);
  const before = await metrics(rate);
  const again = await silentSocket(RATE.port);
  await sleep(300);
  const after = await metrics(rate);
  check('a quiet address gets its tokens back and is admitted again',
    after.total_connections > before.total_connections &&
      after.refused_over_per_ip_connect_rate === before.refused_over_per_ip_connect_rate,
    `connections ${before.total_connections}->${after.total_connections}, rate refusals ${before.refused_over_per_ip_connect_rate}->${after.refused_over_per_ip_connect_rate}`);
  destroyAll([again, ...sockets]);
}

async function checkSubscriptionCap() {
  policy = startBroker(POLICY.port, POLICY.metrics, [
    '-auth', authPath,
    '-auth-fail-limit', '3',
    '-auth-fail-window', '60s',
    '-auth-lockout', '3s',
    '-max-subs', '3',
  ]);
  await waitListening(policy);
  check('the credential numbers are armed alongside the connection ones',
    /auth_fail_limit=3/.test(policy.log('per-address gate armed')) && /auth_lockout=3s/.test(policy.log('per-address gate armed')),
    policy.log('per-address gate armed'));

  const c = await connect({ port: POLICY.port, clientId: 'capped', username: 'ops', password: OPS_PASSWORD });
  const codes = await rawSubscribe(c, ['abuse/1', 'abuse/2', 'abuse/3', 'abuse/4', 'abuse/5'], 1);
  check('three filters are granted and the next two are refused', codes.join(',') === '1,1,1,128,128', codes.join(','));
  let m = await waitForMetric(policy, 'the two cap refusals', (x) => x.refused_over_subscription_cap >= 2);
  check('refused_over_subscription_cap counts the two refused filters', m.refused_over_subscription_cap === 2,
    `refused_over_subscription_cap=${m.refused_over_subscription_cap}`);

  // At the cap, a filter the client already holds is still negotiable: it replaces
  // what is already paid for. Without this a device that filled its allowance could
  // never change the QoS of a topic it has.
  const renegotiate = (await rawSubscribe(c, ['abuse/1'], 0))[0];
  check('re-subscribing a held filter at the cap is granted at the new QoS', renegotiate === 0,
    `code=${renegotiate}`);

  // An unsubscribe returns the room, so the cap needs no release path of its own.
  await new Promise((resolve, reject) => c.unsubscribe(['abuse/2'], (err) => (err ? reject(err) : resolve())));
  const sixth = (await rawSubscribe(c, ['abuse/6'], 1))[0];
  check('a new filter after an unsubscribe is granted', sixth === 1, `code=${sixth}`);
  await close(c);

  // MQTT 5 has a reason code for this, and it is not the one an ACL refusal gets.
  const five = await connect({ port: POLICY.port, clientId: 'capped5', username: 'ops', password: OPS_PASSWORD, protocolVersion: 5 });
  const fiveCodes = await rawSubscribe(five, ['abuse5/1', 'abuse5/2', 'abuse5/3', 'abuse5/4'], 1);
  check('a 5.0 client is told quota exceeded (0x97) for the fourth filter',
    fiveCodes[3] === 151, fiveCodes.map((x) => `0x${x.toString(16)}`).join(','));
  await close(five);
}

async function checkCredentialLockout() {
  // Three failures, one at a time, exactly as a brute-force script would.
  for (let i = 0; i < 3; i++) {
    const code = await refusedOne({ port: POLICY.port, clientId: `guesser-${i}`, username: 'ops', password: WRONG_PASSWORD });
    check(`credential failure ${i + 1} is refused as bad credentials`, code === 4, `code ${code}`);
  }
  let m = await waitForMetric(policy, 'the third failure to be counted', (x) => x.auth_rejected >= 3);
  check('auth_rejected counts the three wrong passwords', m.auth_rejected === 3, `auth_rejected=${m.auth_rejected}`);
  m = await waitForMetric(policy, 'the address to be locked out', (x) => x.auth_locked_addresses === 1);
  check('the third failure locks the address out', m.auth_locked_addresses === 1, `auth_locked_addresses=${m.auth_locked_addresses}`);
  check('the lockout is logged once, as the event it is',
    policy.count('address locked out after too many credential failures') === 1,
    policy.log('address locked out after too many credential failures'));

  // The cost, stated plainly to whoever reads this output: while the address serves
  // its term, a correct password is refused too — with the same code, so the
  // lockout leaks nothing to whoever caused it.
  const honest = await refusedOne({ port: POLICY.port, clientId: 'honest', username: 'ops', password: OPS_PASSWORD });
  check('a correct password from a locked address is refused with the same code', honest === 4, `code ${honest}`);
  m = await metrics(policy);
  check('and it is counted as a lockout, not as a bad credential',
    m.auth_lockout_refusals === 1 && m.auth_rejected === 3,
    `auth_lockout_refusals=${m.auth_lockout_refusals} auth_rejected=${m.auth_rejected}`);

  // Trying harder during the term buys the attacker nothing: the refusals pile up
  // and the lockout does not grow.
  for (let i = 0; i < 3; i++) await refusedOne({ port: POLICY.port, clientId: `still-${i}`, username: 'ops', password: WRONG_PASSWORD });
  m = await metrics(policy);
  check('failures during a lockout are neither counted nor logged again',
    m.auth_rejected === 3 && policy.count('address locked out after too many credential failures') === 1,
    `auth_rejected=${m.auth_rejected} lockout lines=${policy.count('address locked out after too many credential failures')}`);

  // Serving the term is the whole penalty: three seconds, then the device is back
  // with no residual count.
  await waitForMetric(policy, 'the lockout term to expire', (x) => x.auth_locked_addresses === 0, 12000);
  const back = await connect({ port: POLICY.port, clientId: 'returned', username: 'ops', password: OPS_PASSWORD });
  check('the honest device connects again once its term is served', back.connected);
  await close(back);

  // The limits never got in the way of the broker doing its job.
  const device = await connect({ port: POLICY.port, clientId: 'device', username: 'ops', password: OPS_PASSWORD });
  const seen = oneMessage(device, 4000);
  const pub = await connect({ port: POLICY.port, clientId: 'pub2', username: 'ops', password: OPS_PASSWORD });
  await subscribe(device, 'abuse/3', 1);
  await publish(pub, 'abuse/3', 'delivered', 1);
  const msg = await seen;
  check('a granted subscription still delivers after all of it', msg.payload === 'delivered', `${msg.topic}=${msg.payload}`);
  await close(device);
  await close(pub);
}

async function checkTextExposition() {
  const { type, text } = await metricsText(conn);
  const { values, types } = promParse(text);
  const names = [
    'congmq_refused_over_per_ip_connection_limit',
    'congmq_refused_over_per_ip_connect_rate',
    'congmq_per_ip_gate_entries',
    'congmq_per_ip_gate_held_sockets',
    'congmq_auth_lockout_refusals',
    'congmq_auth_locked_addresses',
    'congmq_refused_over_subscription_cap',
  ];
  check('every new metric has a sample in the text view', names.every((n) => n in values),
    names.filter((n) => !(n in values)).join(', ') || 'all present');
  check('and a type a scraper can read', names.every((n) => types[n] === 'counter' || types[n] === 'gauge'),
    names.map((n) => `${n}:${types[n] ?? 'missing'}`).join(' '));
  check('the text view is still plain text', /text\/plain/.test(type), type);
}

async function main() {
  console.log(`binary: ${BIN.trim()}\nports: off=${OFF.port} conn=${CONN.port} rate=${RATE.port} policy=${POLICY.port}\n`);
  for (const p of [OFF, CONN, RATE, POLICY]) {
    for (const port of [p.port, p.metrics]) {
      const busy = await new Promise((resolve) => {
        const probe = net.connect({ port, host: '127.0.0.1' });
        probe.once('connect', () => {
          probe.destroy();
          resolve(true);
        });
        probe.once('error', () => resolve(false));
      });
      if (busy) throw new Error(`port ${port} is already taken; set CONGMQ_ABUSE_BASE_PORT to a free block`);
    }
  }

  await checkNothingIsArmed();
  await checkConnectionLimit();
  await checkConnectRate();
  await checkSubscriptionCap();
  await checkCredentialLockout();
  await checkTextExposition();
}

const watchdog = setTimeout(() => {
  console.error('\nFAIL  the run exceeded 150s and was aborted');
  process.exit(1);
}, 150000);

main()
  .then(() => {
    console.log(`\n${total - failures}/${total} checks passed`);
    process.exitCode = failures ? 1 : 0;
  })
  .catch((err) => {
    console.error('\nFAIL', err);
    process.exitCode = 1;
  })
  .finally(async () => {
    clearTimeout(watchdog);
    for (const h of [off, conn, rate, policy]) if (h) await killAndWait(h);
    rmSync(dir, { recursive: true, force: true });
    process.exit(process.exitCode ?? 1);
  });
