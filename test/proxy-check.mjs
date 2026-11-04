// Third-party-client checks for the transport header: what a device sees when its
// broker sits behind a load balancer, and what an operator sees in /metrics.
//
//	node test/proxy-check.mjs
//
// The Go suite owns the parser and every boundary that needs a clock it controls.
// What is worth re-proving here is the deployment shape, because that is where an
// interop bug lives: headers are built to the specification's bytes, from a
// different language, and put on the wire by a process that behaves like a real
// proxy — and the sessions behind it are ordinary mqtt.js clients. If the broker
// believed the wrong nibble or the wrong byte offset, the address it reports would
// be the balancer's or a piece of somebody's port, and the only visible symptom
// would be rules that never match.
//
// Four brokers, one per policy, plus a mini load balancer in this process.
// CONGMQ_BIN and CONGMQ_PROXY_BASE_PORT point at another build or port block; the
// defaults stay clear of the 1883 a dev broker and the 1920s abuse-check use.
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

const BASE_PORT = Number(process.env.CONGMQ_PROXY_BASE_PORT ?? 1930);
const OFF = { port: BASE_PORT, metrics: BASE_PORT + 1 };
const REQ = { port: BASE_PORT + 2, metrics: BASE_PORT + 3 };
const TRUSTED = { port: BASE_PORT + 4, metrics: BASE_PORT + 5 };
const GATE = { port: BASE_PORT + 6, metrics: BASE_PORT + 7 };

const url = (p) => `mqtt://127.0.0.1:${p}`;
const base = (p) => `http://127.0.0.1:${p}`;

const hex = (alg, s) => crypto.createHash(alg).update(s, 'utf8').digest('hex');
// Two accounts: one that only works from one address, one that works from anywhere.
const DEV_PASSWORD = hex('md5', 'dev' + 's');
const ANY_PASSWORD = hex('md5', 'any' + 't');

// Addresses the balancer reports. TEST-NET-3 and -6, so no test can accidentally
// mean a host that exists.
const DEVICE = '203.0.113.7';
const NEIGHBOUR = '198.51.100.9';
const OTHER = '203.0.113.8';

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
  const handle = { proc, lines: [], killed: false, metrics: base(metricsPort), port };
  proc.stderr.on('data', (b) => {
    for (const line of b.toString().split(/\r?\n/)) if (line.trim()) handle.lines.push(line.trim());
  });
  proc.stdout.on('data', (b) => handle.lines.push(b.toString().trim()));
  proc.once('exit', (code) => handle.lines.push(`exit=${code}`));
  proc.on('error', (err) => handle.lines.push(`spawn error: ${err.message}`));
  handle.log = (needle) => handle.lines.find((l) => l.includes(needle)) ?? '';
  return handle;
}

const waitListening = (h) => waitFor(`${h.metrics} to listen`, () => h.log('msg=listening') !== '');

async function killAndWait(h) {
  if (!h || h.killed) return true;
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

async function waitForMetric(h, what, cond, limit = 15000) {
  const started = Date.now();
  for (;;) {
    const m = await metrics(h);
    if (cond(m)) return m;
    if (Date.now() - started > limit) throw new Error(`timed out after ${limit}ms waiting for ${what} (last: ${JSON.stringify(m)})`);
    await sleep(50);
  }
}

// --------------------------------------------------------- the wire, by hand ----

const V2_SIG = Buffer.from('\r\n\r\n\x00\r\nQUIT\n', 'latin1');

// v1 is the text form: PROXY family srcAddr dstAddr srcPort dstPort CRLF.
function v1(src, sport, dst = '127.0.0.1', dport = 1883) {
  return Buffer.from(`PROXY TCP4 ${src} ${dst} ${sport} ${dport}\r\n`, 'latin1');
}

// v2 is the binary form, laid out the way the specification says and not the way
// this repository's parser would like: version and command nibbles, family and
// transport nibbles, a 16-bit body length, then both addresses and then both ports.
function v2(src, sport, dst = '127.0.0.1', dport = 1883) {
  const body = Buffer.alloc(12);
  body.set(src.split('.').map(Number), 0);
  body.set(dst.split('.').map(Number), 4);
  body.writeUInt16BE(sport, 8);
  body.writeUInt16BE(dport, 10);
  const head = Buffer.alloc(4);
  head[0] = 0x21; // version 2, command PROXY
  head[1] = 0x11; // AF_INET, STREAM
  head.writeUInt16BE(body.length, 2);
  return Buffer.concat([V2_SIG, head, body]);
}

// v2Local is a health check: the same signature, the LOCAL command, no address.
function v2Local() {
  const head = Buffer.alloc(4);
  head[0] = 0x20; // version 2, command LOCAL
  head[1] = 0x00; // AF_UNSPEC
  return Buffer.concat([V2_SIG, head]);
}

// connectPacket is a 3.1.1 CONNECT, for the sockets that have to be a device rather
// than a load balancer and for the ones that must not depend on a library noticing.
function connectPacket(clientId, username, password) {
  let flags = 0x02; // clean session
  if (username !== undefined) flags |= 0x80;
  if (password !== undefined) flags |= 0x40;
  const str = (s) => {
    const b = Buffer.alloc(2 + Buffer.byteLength(s, 'utf8'));
    b.writeUInt16BE(Buffer.byteLength(s, 'utf8'), 0);
    b.write(s, 2, 'utf8');
    return b;
  };
  const body = Buffer.concat([
    Buffer.from([0x00, 0x04, ...Buffer.from('MQTT', 'latin1'), 0x04, flags, 0x00, 0x3c]),
    str(clientId),
    username === undefined ? Buffer.alloc(0) : str(username),
    password === undefined ? Buffer.alloc(0) : str(password),
  ]);
  return Buffer.concat([Buffer.from([0x10, body.length]), body]);
}

// rawSession opens a socket with an optional header in front of a real CONNECT and
// reports the CONNACK return code, or 'closed' when the broker hung up first.
function rawSession({ port, header, clientId = 'raw-1', username, password, localAddress, timeoutMs = 4000 }) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ port, host: '127.0.0.1', localAddress }, () => {
      if (header) s.write(header);
      s.write(connectPacket(clientId, username, password));
    });
    const done = (value) => {
      clearTimeout(timer);
      s.destroy();
      resolve(value);
    };
    const timer = setTimeout(() => done('timeout'), timeoutMs);
    s.on('data', (b) => {
      if (b.length >= 4 && b[0] === 0x20) done(`connack:${b[3]}`);
      else done(`junk:${b.toString('hex')}`);
    });
    s.on('close', () => done('closed'));
    s.on('error', () => done('error'));
    s.once('connect', () => {});
    s.on('connectError', reject);
  });
}

// ---------------------------------------------------------- the mini proxy ----

// listenProxy accepts clients, opens a connection to the broker and writes a
// transport header for the client in front of everything else — which is the whole
// job of an L4 load balancer, and enough to be the other side of this contract.
function listenProxy(backendPort, mkHeader) {
  const sockets = new Set();
  const srv = net.createServer((client) => {
    sockets.add(client);
    client.on('error', () => {});
    client.once('close', () => sockets.delete(client));
    const up = net.connect({ port: backendPort, host: '127.0.0.1' });
    sockets.add(up);
    up.on('error', () => {});
    up.once('close', () => sockets.delete(up));
    up.once('connect', () => {
      up.write(mkHeader(client));
      client.pipe(up);
    });
    up.pipe(client);
    client.once('close', () => up.destroy());
  });
  return new Promise((resolve) => {
    srv.listen(0, '127.0.0.1', () =>
      resolve({
        port: srv.address().port,
        close: async () => {
          for (const s of sockets) s.destroy();
          await new Promise((r) => srv.close(r));
        },
      }));
  });
}

// ---------------------------------------------------------------- clients ----

function connectThroughLB(port, opts = {}) {
  return new Promise((resolve, reject) => {
    const client = mqtt.connect(url(port), {
      clientId: opts.clientId ?? `proxy-${Math.random().toString(16).slice(2, 8)}`,
      username: opts.username,
      password: opts.password,
      protocolVersion: opts.protocolVersion ?? 4,
      reconnectPeriod: 0,
      connectTimeout: 5000,
      clean: true,
    });
    const timer = setTimeout(() => {
      client.end(true);
      reject(new Error('connect through the balancer timed out'));
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

// connectsThenFails reports how a client that never got a session ended: the
// balancer's socket is accepted, so a refusal always arrives as a close.
async function connectsThenFails(port, opts = {}) {
  try {
    const c = await connectThroughLB(port, opts);
    c.end(true);
    return 'connected';
  } catch (err) {
    return `refused:${err.message || err.code || 'closed'}`;
  }
}

async function roundTrip(port, topic) {
  const tag = topic.replace(/[^A-Za-z0-9]/g, '_');
  const sub = await connectThroughLB(port, { clientId: `sub-${tag}` });
  const pub = await connectThroughLB(port, { clientId: `pub-${tag}` });
  try {
    const got = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`no message on ${topic} within 6s`)), 6000);
      sub.once('message', (t, p) => {
        clearTimeout(timer);
        resolve(`${t}:${p.toString()}`);
      });
      sub.subscribe(topic, { qos: 1 }, (err) => {
        if (err) {
          clearTimeout(timer);
          reject(err);
        }
      });
    });
    await new Promise((r) => setTimeout(r, 150));
    await pub.publishAsync(topic, 'through', { qos: 1 });
    return await got;
  } finally {
    sub.end(true);
    pub.end(true);
  }
}

// ------------------------------------------------------------------- cases ----

const dir = mkdtempSync(join(tmpdir(), 'congmq-proxy-'));

async function checkNothingIsArmed() {
  off = startBroker(OFF.port, OFF.metrics, []);
  await waitListening(off);
  check('-proxy-protocol absent means no transport header is read', off.log('transport header armed') === '');

  const lb = await listenProxy(OFF.port, () => v1(DEVICE, 41330));
  try {
    // The header is payload on this listener, and payload that is not a CONNECT
    // ends the connection. Nothing is believed, so nothing is counted.
    const r = await rawSession({ port: lb.port, header: v1(DEVICE, 41330) });
    check('a header in front of a CONNECT is not believed', r !== 'connack:0', String(r));
    const m = await metrics(off);
    check('and moves neither transport-header counter',
      m.connections_over_proxy_header === 0 && m.refused_over_proxy_header === 0,
      `${m.connections_over_proxy_header}/${m.refused_over_proxy_header}`);
  } finally {
    await lb.close();
  }
}

async function checkRequireV1() {
  req = startBroker(REQ.port, REQ.metrics, ['-proxy-protocol', 'require', '-proxy-header-timeout', '400ms']);
  await waitListening(req);
  check('the policy is announced before anything is refused',
    /transport header armed.*mode=require/.test(req.log('transport header armed')),
    req.log('transport header armed'));

  const lb = await listenProxy(REQ.port, (s) => v1(DEVICE, s.remotePort));
  try {
    const before = await metrics(req);
    const c = await connectThroughLB(lb.port, { clientId: 'v1-device' });
    const m = await waitForMetric(req, 'a session behind the balancer', (x) => x.online === 1);
    check('a real mqtt.js session lands behind a v1 header',
      m.connections_over_proxy_header === before.connections_over_proxy_header + 1,
      JSON.stringify({ online: m.online, proxied: m.connections_over_proxy_header }));
    c.end(true);

    // The message path has to work, not just the CONNECT: the bytes behind the
    // header are the client's, and a wrapper that read one byte too many would show
    // up here as a session that never subscribes.
    const heard = await roundTrip(lb.port, 'tel/1/telemetry');
    check('and the payload behind the header arrives intact', heard === 'tel/1/telemetry:through', heard);
  } finally {
    await lb.close();
  }

  // A connection that does not open with a header is refused on this listener, and
  // a refusal has to stay out of the connection accounting: an operator comparing
  // refusals against total_connections is counting attacks, not fleet size.
  const before = await metrics(req);
  const direct = await rawSession({ port: REQ.port, clientId: 'direct' });
  check('a direct client on a require listener is refused', direct === 'closed' || direct === 'error', direct);
  const after = await waitForMetric(req, 'the refusal to be counted',
    (x) => x.refused_over_proxy_header > before.refused_over_proxy_header);
  check('and counted as a header refusal, not as a session',
    after.refused_over_proxy_header === before.refused_over_proxy_header + 1 &&
      after.total_connections === before.total_connections,
    JSON.stringify({ refused: after.refused_over_proxy_header, total: after.total_connections }));
}

async function checkRequireV2() {
  const lb = await listenProxy(REQ.port, () => v2(DEVICE, 42000));
  try {
    const before = (await metrics(req)).connections_over_proxy_header;
    const c = await connectThroughLB(lb.port, { clientId: 'v2-device' });
    const m = await waitForMetric(req, 'a v2 session', (x) => x.connections_over_proxy_header === before + 1);
    check('the binary form is believed the way the text form is', m.online === 1,
      JSON.stringify({ online: m.online, proxied: m.connections_over_proxy_header }));
    c.end(true);
    const heard = await roundTrip(lb.port, 'tel/2/telemetry');
    check('and the v2 payload survives too', heard === 'tel/2/telemetry:through', heard);
  } finally {
    await lb.close();
  }

  // A health check is well formed and names nobody: it must not be a refusal, it
  // must not claim an address, and it must not be a proxied session.
  const before = await metrics(req);
  const probe = await rawSession({ port: REQ.port, header: v2Local(), clientId: 'probe' });
  check('a LOCAL header is a probe, not a refusal', probe === 'connack:0', probe);
  const m = await metrics(req);
  check('and it is not counted as a proxied session either',
    m.connections_over_proxy_header === before.connections_over_proxy_header &&
      m.refused_over_proxy_header === before.refused_over_proxy_header,
    JSON.stringify({ proxied: m.connections_over_proxy_header, refused: m.refused_over_proxy_header }));
}

async function checkHeaderTimeout() {
  const before = (await metrics(req)).refused_over_proxy_header;
  const elapsed = await new Promise((resolve) => {
    const s = net.connect({ port: REQ.port, host: '127.0.0.1' }, () => s.write(V2_SIG));
    const start = Date.now();
    s.on('close', () => {
      s.destroy();
      resolve(Date.now() - start);
    });
    s.on('error', () => resolve(Date.now() - start));
    setTimeout(() => {
      s.destroy();
      resolve(-1);
    }, 6000);
  });
  check('a half-written header is closed on the timeout, not the pre-connect window',
    elapsed >= 0 && elapsed < 3000, `${elapsed}ms`);
  const m = await waitForMetric(req, 'the half header to be counted', (x) => x.refused_over_proxy_header > before);
  check('and counted', m.refused_over_proxy_header > before, `${before} -> ${m.refused_over_proxy_header}`);
}

async function checkTrusted() {
  const auth = join(dir, 'auth.jsonl');
  writeFileSync(auth, [
    `{"username":"dev","salt":"s","alg":"md5","scheme":"username+salt","ip":"${DEVICE}"}`,
    '{"username":"any","salt":"t","alg":"md5","scheme":"username+salt"}',
  ].join('\n') + '\n');

  trusted = startBroker(TRUSTED.port, TRUSTED.metrics, [
    '-proxy-protocol', 'trusted', '-trusted-proxy-cidr', '127.0.0.1/32', '-auth', auth,
  ]);
  await waitListening(trusted);
  check('the list is announced with the mode',
    /transport header armed.*mode=trusted.*trusted_proxies=1/.test(trusted.log('transport header armed')),
    trusted.log('transport header armed'));

  // The balancer reports one device, and the ip rule is a rule about that device.
  // Both header forms get the same test against the same rule, because a parser
  // that reads one of them from the wrong byte offset still produces a plausible
  // address and a counter that moves — and only a decision keyed on the address
  // can tell the difference.
  const lbOk = await listenProxy(TRUSTED.port, () => v1(DEVICE, 41330));
  const lbNo = await listenProxy(TRUSTED.port, () => v1(NEIGHBOUR, 41331));
  const lbOk2 = await listenProxy(TRUSTED.port, () => v2(DEVICE, 42330));
  const lbNo2 = await listenProxy(TRUSTED.port, () => v2(NEIGHBOUR, 42331));
  try {
    const good = await connectThroughLB(lbOk.port, { clientId: 'named-device', username: 'dev', password: DEV_PASSWORD });
    check('the address in a v1 header is what the auth rule sees', good.connected === true, 'connected');
    good.end(true);

    const before = await metrics(trusted);
    const bad = await connectsThenFails(lbNo.port, { clientId: 'wrong-place', username: 'dev', password: DEV_PASSWORD });
    check('the same credentials from another claimed address are refused', bad.startsWith('refused:'), bad);
    const m = await waitForMetric(trusted, 'the credential refusal', (x) => x.auth_rejected > before.auth_rejected);
    // Refused by the rule, not by the transport policy: that is the difference
    // between the header reaching the auth layer and never getting there.
    check('as an auth refusal, not a header one',
      m.refused_over_proxy_header === before.refused_over_proxy_header &&
        m.connections_over_proxy_header === before.connections_over_proxy_header + 1,
      JSON.stringify({ auth_rejected: m.auth_rejected, refused: m.refused_over_proxy_header }));

    const good2 = await connectThroughLB(lbOk2.port, { clientId: 'named-device-v2', username: 'dev', password: DEV_PASSWORD });
    check('the address in a v2 header is the same address', good2.connected === true, 'connected');
    good2.end(true);

    const bad2 = await connectsThenFails(lbNo2.port, { clientId: 'wrong-place-v2', username: 'dev', password: DEV_PASSWORD });
    check('and the binary form cannot borrow a neighbour the text form was refused for',
      bad2.startsWith('refused:'), bad2);
  } finally {
    await lbOk.close();
    await lbNo.close();
    await lbOk2.close();
    await lbNo2.close();
  }

  // Direct, from an address that is not on the list: no header expected, and the
  // socket's own address is the whole story.
  const before = await metrics(trusted);
  const direct = await rawSession({
    port: TRUSTED.port,
    localAddress: '127.0.0.2',
    clientId: 'direct',
    username: 'any',
    password: ANY_PASSWORD,
  });
  check('a direct client outside the list keeps working', direct === 'connack:0', direct);
  const afterDirect = await metrics(trusted);
  check('and is not counted as proxied',
    afterDirect.connections_over_proxy_header === before.connections_over_proxy_header,
    `${before.connections_over_proxy_header} -> ${afterDirect.connections_over_proxy_header}`);

  // The same direct client cannot borrow an address by writing a header anyway.
  const spoof = await rawSession({
    port: TRUSTED.port,
    localAddress: '127.0.0.2',
    header: v1(DEVICE, 41330),
    clientId: 'spoof',
    username: 'dev',
    password: DEV_PASSWORD,
  });
  check('a header from an address that may not report one is refused outright',
    spoof === 'closed' || spoof === 'error', spoof);
  const afterSpoof = await waitForMetric(trusted, 'the spoof to be counted',
    (x) => x.refused_over_proxy_header > before.refused_over_proxy_header);
  check('and is the counter that says somebody tried',
    afterSpoof.refused_over_proxy_header === before.refused_over_proxy_header + 1 &&
      afterSpoof.auth_rejected === before.auth_rejected,
    JSON.stringify({ refused: afterSpoof.refused_over_proxy_header, auth_rejected: afterSpoof.auth_rejected }));
}

async function checkGateUsesTheRealAddress() {
  gated = startBroker(GATE.port, GATE.metrics, ['-proxy-protocol', 'require', '-max-conns-per-ip', '1']);
  await waitListening(gated);

  // One balancer, so every socket arrives from 127.0.0.1. Without the header the
  // second client below would be refused, and a fleet behind one endpoint would
  // look like one very noisy address.
  let n = 0;
  const lb = await listenProxy(GATE.port, () => v1(n++ === 0 ? DEVICE : NEIGHBOUR, 41000 + n));
  try {
    const a = await connectThroughLB(lb.port, { clientId: 'gate-a' });
    const b = await connectThroughLB(lb.port, { clientId: 'gate-b' });
    const m = await waitForMetric(gated, 'both tenants', (x) => x.online === 2);
    check('two devices behind one balancer are two addresses to the gate',
      m.per_ip_gate_entries === 2 && m.refused_over_per_ip_connection_limit === 0,
      JSON.stringify({ entries: m.per_ip_gate_entries, refused: m.refused_over_per_ip_connection_limit }));

    // A third socket for an address already holding its one connection.
    const third = await rawSession({ port: GATE.port, header: v1(DEVICE, 41500) });
    check('the limit then bites the device that is over it, not the balancer',
      third === 'closed' || third === 'error', third);
    const after = await waitForMetric(gated, 'the third refusal', (x) => x.refused_over_per_ip_connection_limit === 1);
    check('and the refusal is counted where an operator can graph it',
      after.per_ip_gate_entries === 2 && after.online === 2,
      JSON.stringify({ entries: after.per_ip_gate_entries, online: after.online }));

    a.end(true);
    b.end(true);
  } finally {
    await lb.close();
  }
}

async function checkTextExposition() {
  const res = await fetch(`${req.metrics}/metrics.txt`);
  const text = await res.text();
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
  const names = ['congmq_connections_over_proxy_header', 'congmq_refused_over_proxy_header'];
  check('both transport-header metrics are in the text view', names.every((n) => n in values),
    names.filter((n) => !(n in values)).join(', ') || 'all present');
  check('and typed as counters', names.every((n) => types[n] === 'counter'),
    names.map((n) => `${n}:${types[n] ?? 'missing'}`).join(' '));
  // The two views are built from the same snapshot but written by different code,
  // and a scraper reads one while an operator reads the other.
  const json = await metrics(req);
  const pairs = [
    ['congmq_connections_over_proxy_header', json.connections_over_proxy_header],
    ['congmq_refused_over_proxy_header', json.refused_over_proxy_header],
  ];
  const wrong = pairs.filter(([name, value]) => values[name] !== String(value));
  check('and say the same number the JSON view says', wrong.length === 0,
    wrong.map(([name, value]) => `${name}: text=${values[name]} json=${value}`).join(' '));
}

// --------------------------------------------------------------------- run ----

let off;
let req;
let trusted;
let gated;

async function main() {
  console.log(`binary: ${BIN.trim()}\nports: off=${OFF.port} require=${REQ.port} trusted=${TRUSTED.port} gate=${GATE.port}\n`);
  for (const p of [OFF, REQ, TRUSTED, GATE]) {
    for (const port of [p.port, p.metrics]) {
      const busy = await new Promise((resolve) => {
        const probe = net.connect({ port, host: '127.0.0.1' });
        probe.once('connect', () => {
          probe.destroy();
          resolve(true);
        });
        probe.once('error', () => resolve(false));
      });
      if (busy) throw new Error(`port ${port} is already taken; set CONGMQ_PROXY_BASE_PORT to a free block`);
    }
  }

  await checkNothingIsArmed();
  await checkRequireV1();
  await checkRequireV2();
  await checkHeaderTimeout();
  await checkTrusted();
  await checkGateUsesTheRealAddress();
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
    for (const h of [off, req, trusted, gated]) if (h) await killAndWait(h);
    rmSync(dir, { recursive: true, force: true });
    process.exit(process.exitCode ?? 1);
  });
