// Second-opinion checks: every case here is driven by Eclipse paho-mqtt, an
// independent implementation of the same wire format, started from this script.
//
//	node test/interop-check.mjs
//
// mqtt.js has been the outside voice so far. One client proves the format against
// one encoder; a mis-set nibble, a wrong property varint, or a QoS 2 handshake that
// only looks symmetric is invisible when the same library writes and reads it. paho
// brings its own packet encoder, its own QoS 2 state machine and its own property
// table, so what it accepts is accepted by somebody who did not read our source.
//
// Topology: five brokers (rules, caps, TLS, mTLS, transport header) plus two
// in-process load balancers that put a PROXY v1 header in front of paho, and one
// Python subprocess (test/interop-paho.py) that runs the client cases against them.
// CONGMQ_BIN / CONGMQ_CERT_BIN / PAHO_PYTHON point at another build or interpreter;
// the default port block (1950s) stays clear of every other harness in this
// directory and of the 1883/1884 a developer's machine is usually holding.
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import net from 'node:net';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const exe = (name) => join(here, '..', 'bin', `${name}${process.platform === 'win32' ? '.exe' : ''}`);
const BIN = process.env.CONGMQ_BIN ?? exe('congmq');
const CERT_BIN = process.env.CONGMQ_CERT_BIN ?? exe('congmq-cert');
const CASES = join(here, 'interop-paho.py');

const BASE = Number(process.env.CONGMQ_INTEROP_BASE_PORT ?? 1950);
const P = {
  plain: BASE, plainM: BASE + 1,
  caps: BASE + 2, capsM: BASE + 3,
  tlsPlain: BASE + 4, tls: BASE + 5, tlsM: BASE + 6,
  mtlsPlain: BASE + 7, mtls: BASE + 8, mtlsM: BASE + 9,
  proxy: BASE + 10, proxyM: BASE + 11,
  viaDevice: BASE + 12, viaNeighbour: BASE + 13,
};

const DEVICE = '203.0.113.7';
const NEIGHBOUR = '198.51.100.9';
const NONCE = crypto.randomBytes(4).toString('hex');
const NS = `it/${NONCE}`;

let failures = 0;
let total = 0;
const check = (name, ok, detail = '') => {
  total++;
  console.log(`${ok ? 'pass' : 'FAIL'}  ${name}${detail ? `\n        -> ${String(detail).slice(0, 240)}` : ''}`);
  if (!ok) failures++;
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(what, cond, limit = 20000) {
  const started = Date.now();
  for (;;) {
    const ok = await cond();
    if (ok) return Date.now() - started;
    if (Date.now() - started > limit) throw new Error(`timed out after ${limit}ms waiting for ${what}`);
    await sleep(50);
  }
}

const hex = (alg, s) => crypto.createHash(alg).update(s, 'utf8').digest('hex');
const users = {
  dev: { username: 'dev', password: hex('md5', 'dev' + 's') },
  wide: { username: 'wide', password: hex('sha256', 'w' + 'wide') },
  persist: { username: 'persist', password: hex('md5', 'persist' + 'p') },
  meter: { username: 'meter', password: hex('sha256', 'm' + 'meter') },
  gated: { username: 'gated', password: hex('sha256', 'g' + 'gated') },
};

// ------------------------------------------------------------------ workspace ----

const dir = mkdtempSync(join(tmpdir(), 'congmq-interop-'));
const pki = join(dir, 'pki');
const other = join(dir, 'pki-foreign');
const out = (name, lines) => {
  const path = join(dir, name);
  writeFileSync(path, lines.join('\n') + '\n', 'utf8');
  return path;
};

const authPlain = out('auth-plain.jsonl', [
  `{"username":"${users.dev.username}","salt":"s","alg":"md5","scheme":"username+salt"}`,
  `{"username":"${users.wide.username}","salt":"w","alg":"sha256","scheme":"salt+username"}`,
  `{"username":"${users.persist.username}","salt":"p","alg":"md5","scheme":"username+salt"}`,
]);
const aclPlain = out('acl-plain.jsonl', [
  // '#' for one account only: the dollar-topic rule and the two denial cases both
  // need a subscriber that may take a broad filter, and one that may not.
  '{"effect":"allow","user":"wide","action":"all","topics":["#"]}',
  `{"effect":"deny","user":"dev","action":"publish","topics":["${NS}/secret/#"]}`,
  '{"effect":"deny","user":"dev","action":"subscribe","topics":[{"eq":"#"}]}',
  '{"effect":"allow","user":"dev","action":"all"}',
  '{"effect":"allow","user":"persist","action":"all"}',
  '{"effect":"allow","action":"all"}',
]);
const authTls = out('auth-tls.jsonl', [
  `{"username":"${users.meter.username}","salt":"m","alg":"sha256","scheme":"salt+username"}`,
]);
const authMtls = out('auth-mtls.jsonl', ['{"cert_cn":"congmq-device-1"}']);
const aclMtls = out('acl-mtls.jsonl', [
  `{"effect":"allow","action":"all","cert_cn":"congmq-device-1","topics":["${NS}/plant/#"]}`,
  '{"effect":"allow","action":"all","cert_cn":"congmq-device-1"}',
]);
const authProxy = out('auth-proxy.jsonl', [
  `{"username":"${users.gated.username}","salt":"g","alg":"sha256","scheme":"salt+username","ip":"${DEVICE}"}`,
]);

function genPKI(target) {
  return new Promise((resolve, reject) => {
    const proc = spawn(CERT_BIN, ['-out', target, '-days', '30', '-server-cn', 'congmq.test',
      '-client-cn', 'congmq-device-1'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let err = '';
    proc.stderr.on('data', (b) => (err += b.toString()));
    proc.once('exit', (code) => (code === 0 ? resolve() : reject(new Error(`congmq-cert exit ${code}: ${err}`))));
    proc.once('error', reject);
  });
}

// --------------------------------------------------------------------- brokers ----

const brokers = [];

function startBroker(key, args) {
  const proc = spawn(BIN, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  const handle = { key, proc, lines: [], metrics: `http://127.0.0.1:${argsMetrics(args)}` };
  proc.stderr.on('data', (b) => {
    for (const line of b.toString().split(/\r?\n/)) if (line.trim()) handle.lines.push(line.trim());
  });
  proc.stdout.on('data', (b) => handle.lines.push(b.toString().trim()));
  proc.once('exit', (code) => handle.lines.push(`exit=${code}`));
  proc.on('error', (err) => handle.lines.push(`spawn error: ${err.message}`));
  handle.log = (needle) => handle.lines.find((l) => l.includes(needle)) ?? '';
  handle.waitUp = () => waitFor(`${key} to listen`, () => handle.log('msg=listening') !== '');
  handle.view = async () => (await fetch(`${handle.metrics}/metrics`)).json();
  brokers.push(handle);
  return handle;
}

function argsMetrics(args) {
  const i = args.indexOf('-metrics');
  return i === -1 ? 0 : Number(args[i + 1].split(':').pop());
}

const tlsArgs = (target) => ['-tls-cert', join(target, 'server.crt'), '-tls-key', join(target, 'server.key')];

// ------------------------------------------------------------ the balancers ----

const proxies = [];

// A balancer that is honest about where the device came from: v1 text in front of
// the CONNECT, exactly the bytes nginx's stream module writes.
function startBalancer(listenPort, brokerPort, claimed) {
  const sockets = new Set();
  const server = net.createServer((client) => {
    const upstream = net.connect({ port: brokerPort, host: '127.0.0.1' });
    sockets.add(client);
    sockets.add(upstream);
    const sport = 20000 + (sockets.size % 20000);
    upstream.write(`PROXY TCP4 ${claimed} 127.0.0.1 ${sport} ${brokerPort}\r\n`);
    client.pipe(upstream);
    upstream.pipe(client);
    const drop = () => {
      sockets.delete(client);
      sockets.delete(upstream);
      client.destroy();
      upstream.destroy();
    };
    client.on('error', drop);
    upstream.on('error', drop);
    client.on('close', () => {
      sockets.delete(client);
      upstream.destroy();
    });
    upstream.on('close', () => {
      sockets.delete(upstream);
      client.destroy();
    });
  });
  const listening = new Promise((resolve, reject) => {
    server.once('error', reject);
    server.once('listening', resolve);
  });
  server.listen(listenPort, '127.0.0.1');
  proxies.push({ server, sockets });
  return listening;
}

// ------------------------------------------------------------------ interpreter ----

const interpreterCandidates = [
  process.env.PAHO_PYTHON,
  join(here, '..', '.tmp', 'venv-paho', process.platform === 'win32' ? 'Scripts' : 'bin', 'python'),
  join(here, '..', '.tmp', 'venv-paho', 'Scripts', 'python.exe'),
  'python3',
  'python',
].filter(Boolean);

function probe(py) {
  return new Promise((resolve) => {
    const proc = spawn(py, ['-c', 'import paho.mqtt as m; print(m.__version__)'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let outText = '';
    proc.stdout.on('data', (b) => (outText += b.toString()));
    proc.once('exit', (code) => resolve(code === 0 ? outText.trim() : null));
    proc.once('error', () => resolve(null));
  });
}

async function findInterpreter() {
  for (const py of interpreterCandidates) {
    const version = await probe(py);
    if (version) return { py, version };
  }
  return null;
}

// ---------------------------------------------------------------------- run ----

async function main() {
  if (!existsSync(BIN)) throw new Error(`broker binary missing: ${BIN} (build it, or set CONGMQ_BIN)`);
  if (!existsSync(CERT_BIN)) throw new Error(`cert tool missing: ${CERT_BIN} (build it, or set CONGMQ_CERT_BIN)`);
  const interp = await findInterpreter();
  if (!interp) {
    throw new Error(
      'no Python with paho-mqtt found. Set PAHO_PYTHON, or: python -m venv .tmp/venv-paho && ' +
        (process.platform === 'win32'
          ? '.tmp/venv-paho/Scripts/pip install paho-mqtt'
          : '.tmp/venv-paho/bin/pip install paho-mqtt'),
    );
  }
  console.log(`broker        ${BIN}`);
  console.log(`interpreter   ${interp.py} (paho-mqtt ${interp.version})`);
  console.log(`ports         ${BASE}..${BASE + 13}`);
  console.log(`namespace     ${NS}  (every topic this run touches)\n`);

  await genPKI(pki);
  await genPKI(other);

  // The delayed will only fires on the reaper's tick, so this broker's clock has
  // to run faster than the 10s default or the case waits on a timer that never comes.
  const plain = startBroker('plain', ['-addr', `127.0.0.1:${P.plain}`, '-metrics', `127.0.0.1:${P.plainM}`,
    '-store', join(dir, 'store-plain'), '-id', `interop-plain-${NONCE}`, '-auth', authPlain, '-acl', aclPlain,
    '-log-level', 'info', '-reload-interval', '2s', '-reap-interval', '500ms']);
  const caps = startBroker('caps', ['-addr', `127.0.0.1:${P.caps}`, '-metrics', `127.0.0.1:${P.capsM}`,
    '-store', join(dir, 'store-caps'), '-id', `interop-caps-${NONCE}`,
    '-max-qos', '1', '-max-subs', '3', '-max-packet-size', '1024', '-session-expiry-max', '60s',
    '-log-level', 'info']);
  const tls = startBroker('tls', ['-addr', `127.0.0.1:${P.tlsPlain}`, '-tls-addr', `127.0.0.1:${P.tls}`,
    '-metrics', `127.0.0.1:${P.tlsM}`, '-store', join(dir, 'store-tls'), '-id', `interop-tls-${NONCE}`,
    '-auth', authTls, ...tlsArgs(pki), '-log-level', 'info']);
  const mtls = startBroker('mtls', ['-addr', `127.0.0.1:${P.mtlsPlain}`, '-tls-addr', `127.0.0.1:${P.mtls}`,
    '-metrics', `127.0.0.1:${P.mtlsM}`, '-store', join(dir, 'store-mtls'), '-id', `interop-mtls-${NONCE}`,
    '-auth', authMtls, '-acl', aclMtls, ...tlsArgs(pki), '-tls-ca', join(pki, 'ca.crt'), '-log-level', 'info']);
  const proxy = startBroker('proxy', ['-addr', `127.0.0.1:${P.proxy}`, '-metrics', `127.0.0.1:${P.proxyM}`,
    '-store', join(dir, 'store-proxy'), '-id', `interop-proxy-${NONCE}`, '-auth', authProxy,
    '-proxy-protocol', 'require', '-log-level', 'info']);
  await Promise.all([plain, caps, tls, mtls, proxy].map((b) => b.waitUp()));

  await Promise.all([
    startBalancer(P.viaDevice, P.proxy, DEVICE),
    startBalancer(P.viaNeighbour, P.proxy, NEIGHBOUR),
  ]);

  const before = {
    plain: await plain.view(),
    caps: await caps.view(),
    tls: await tls.view(),
    mtls: await mtls.view(),
    proxy: await proxy.view(),
  };

  const config = {
    nonce: NONCE,
    plain_port: P.plain,
    caps_port: P.caps,
    tls_port: P.tls,
    mtls_port: P.mtls,
    proxy_direct_port: P.proxy,
    proxy_via_device: P.viaDevice,
    proxy_via_neighbour: P.viaNeighbour,
    ca: join(pki, 'ca.crt'),
    foreign_ca: join(other, 'ca.crt'),
    client_cert: join(pki, 'client.crt'),
    client_key: join(pki, 'client.key'),
    users,
  };
  const cfgPath = join(dir, 'config.json');
  writeFileSync(cfgPath, JSON.stringify(config), 'utf8');

  const seen = [];
  const raised = [];
  const summary = await runPython(interp.py, cfgPath, seen, raised);

  console.log(`\npaho-mqtt ${interp.version} drove ${seen.length} cases${summary ? ` (summary said ${summary.ran})` : ''}\n`);
  // One line, before any case is believed: a client callback that throws takes
  // that client's network thread with it, and every delivery on it then reads as
  // a broker failure. This run found twenty such rows from one wrong signature.
  check('no paho client callback raised', raised.length === 0, raised.slice(0, 4).join(' | ') || 'all clean');
  for (const row of seen) check(`paho ${row.name}`, row.ok, row.detail);
  if (summary) check('the runner counted its own cases', summary.ran === seen.length && summary.failed === seen.filter((r) => !r.ok).length, JSON.stringify(summary));
  else check('the runner finished', false, 'no SUMMARY line: the subprocess died mid-run');

  // ------------------------------------------------------ what the broker saw ----
  const after = {
    plain: await plain.view(),
    caps: await caps.view(),
    tls: await tls.view(),
    mtls: await mtls.view(),
    proxy: await proxy.view(),
  };
  const delta = (key, field) => Number(after[key][field] ?? 0) - Number(before[key][field] ?? 0);

  // The client's word is only half the story: each of these says the broker also
  // *recorded* the thing it should have recorded while the case ran.
  check('the broker denied the subscriptions paho was refused', delta('plain', 'acl_denied_subscribe') >= 2,
    `acl_denied_subscribe +${delta('plain', 'acl_denied_subscribe')}`);
  check('and the publishes', delta('plain', 'acl_denied_publish') >= 2,
    `acl_denied_publish +${delta('plain', 'acl_denied_publish')}`);
  check('the oversized publish left a mark, not a silent hole',
    delta('caps', 'protocol_errors') + delta('caps', 'server_disconnects') >= 1,
    `protocol_errors +${delta('caps', 'protocol_errors')}, server_disconnects +${delta('caps', 'server_disconnects')}`);
  check('the fourth subscription was refused by the cap, not by a rule',
    delta('caps', 'refused_over_subscription_cap') >= 1,
    `refused_over_subscription_cap +${delta('caps', 'refused_over_subscription_cap')}`);
  check('tls sessions were counted as tls', delta('tls', 'connections_tls') >= 2 && delta('mtls', 'connections_tls') >= 1,
    `tls +${delta('tls', 'connections_tls')}, mtls +${delta('mtls', 'connections_tls')}`);
  check('a client with no certificate failed the handshake, and said so', delta('mtls', 'tls_handshake_failures') >= 1,
    `tls_handshake_failures +${delta('mtls', 'tls_handshake_failures')}`);
  check('both balancer claims crossed the header', delta('proxy', 'connections_over_proxy_header') >= 2,
    `connections_over_proxy_header +${delta('proxy', 'connections_over_proxy_header')}`);
  check('and the header refused the one that refused to wear one', delta('proxy', 'refused_over_proxy_header') >= 1,
    `refused_over_proxy_header +${delta('proxy', 'refused_over_proxy_header')}`);
  check('the gated account was refused on the wrong claimed address, by auth not by parse',
    delta('proxy', 'auth_rejected') >= 1, `auth_rejected +${delta('proxy', 'auth_rejected')}`);

  // ------------------------------------------------------------- left no mess ----
  for (const [key, handle] of Object.entries({ plain, caps, tls, mtls, proxy })) {
    const view = after[key];
    // Every case closes its client, so a session still online at the end is either
    // a client we failed to shut down or a broker that leaked one. The caps broker
    // is held to the same bar: its cases break connections on purpose, but a
    // broken connection is not an online session.
    check(`${key}: every session that should be gone is gone`, view.online === 0, `online=${view.online}`);
    if (handle.log('level=ERROR')) check(`${key}: no ERROR line`, false, handle.log('level=ERROR'));
  }

  for (const handle of brokers) {
    const exited = handle.lines.some((l) => l.startsWith('exit='));
    if (!exited) handle.proc.kill('SIGKILL');
  }
  await teardown();
}

// Windows keeps a temp directory alive as long as one of the processes we started
// still holds a file inside it, so the kill has to land before the remove. The
// remove is best effort: a leftover directory in %TEMP% is not a failed check, and
// it must not be allowed to swallow the verdict the way it swallowed this one.
async function teardown() {
  await sleep(600);
  for (const { server, sockets } of proxies) {
    for (const s of sockets) s.destroy();
    server.close();
  }
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
  } catch (err) {
    console.log(`note: left ${dir} behind (${err.code})`);
  }
}

function runPython(py, cfgPath, seen, callbackErrors) {
  return new Promise((resolve) => {
    const proc = spawn(py, [CASES, cfgPath], { stdio: ['ignore', 'pipe', 'pipe'] });
    let summary = null;
    let stdoutBuf = '';
    let stderrText = '';
    const onData = (b) => {
      stdoutBuf += b.toString();
      let i;
      while ((i = stdoutBuf.indexOf('\n')) >= 0) {
        const line = stdoutBuf.slice(0, i).trim();
        stdoutBuf = stdoutBuf.slice(i + 1);
        if (line.startsWith('RESULT ')) {
          try {
            seen.push(JSON.parse(line.slice(7)));
          } catch {
            /* a foreign line on stdout is not a case */
          }
        } else if (line.startsWith('ERRORS ')) {
          try {
            callbackErrors.push(...(JSON.parse(line.slice(7)).raised ?? []));
          } catch { /* ignore */ }
        } else if (line.startsWith('SUMMARY ')) {
          try {
            summary = JSON.parse(line.slice(8));
          } catch { /* ignore */ }
        } else if (line) {
          console.log(`  py| ${line}`);
        }
      }
    };
    proc.stdout.on('data', onData);
    proc.stderr.on('data', (b) => {
      // Echo each line once, not the whole accumulated tail per chunk: a run that
      // speaks loudly should not turn the log into 400 KB of repeats.
      for (const line of b.toString().split(/\r?\n/)) {
        if (line.trim()) {
          stderrText += line + '\n';
          process.stderr.write(`  py! ${line}\n`);
        }
      }
    });
    proc.once('exit', (code) => {
      if (code !== 0 && !summary) check('the python runner exited cleanly', false, `exit=${code}, ${seen.length} cases seen`);
      resolve(summary);
    });
    proc.once('error', (err) => {
      check('the python runner started', false, err.message);
      resolve(null);
    });
    // A hung client would otherwise keep five brokers alive forever.
    setTimeout(() => {
      check('the python runner finished inside 420s', false, `seen ${seen.length} cases`);
      proc.kill('SIGKILL');
      resolve(summary);
    }, 420000).unref();
  });
}

main()
  .then(() => {
    console.log(`\n${failures ? 'FAIL' : 'ok'}  ${total - failures}/${total} interop checks passed`);
    process.exit(failures ? 1 : 0);
  })
  .catch(async (err) => {
    console.error(`\nFAIL  ${err.message}`);
    for (const b of brokers) if (b.lines.length) console.error(`  ${b.key}: ${b.lines.slice(-6).join('\n  ')}`);
    for (const b of brokers) b.proc.kill('SIGKILL');
    await teardown();
    process.exit(1);
  });
