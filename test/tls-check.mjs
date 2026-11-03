// Third-party-client checks for the TLS side of the broker: mqtt.js connects
// over mqtts:// to a broker started with -tls-*, using a chain minted by
// congmq-cert, and the certificate rules decide what that session may do.
//
//	node test/tls-check.mjs
//
// Nothing here reads a Go test helper: the CA, the server certificate and the
// client certificate are the same files an operator would put on a device, so
// what passes is what a deployment gets.
//
// CONGMQ_BIN, CONGMQ_TLS_PORT, CONGMQ_PORT and CONGMQ_METRICS_PORT point it at
// another build or another set of ports. The defaults avoid 1883 and 1884, which
// a developer's long-running broker is usually holding.
import mqtt from 'mqtt';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const exe = (name) =>
  fileURLToPath(new URL(`../bin/${name}${process.platform === 'win32' ? '.exe' : ''}`, import.meta.url));
const BIN = process.env.CONGMQ_BIN ?? exe('congmq');
const CERT_BIN = process.env.CONGMQ_CERT_BIN ?? exe('congmq-cert');

const PORT = Number(process.env.CONGMQ_PORT ?? 1895); // plain
const TLSPORT = Number(process.env.CONGMQ_TLS_PORT ?? 1896); // tls
const METRICS_PORT = Number(process.env.CONGMQ_METRICS_PORT ?? 1897);

const PLAIN_URL = `mqtt://127.0.0.1:${PORT}`;
const TLS_URL = `mqtts://127.0.0.1:${TLSPORT}`;

const SERVER_CN = 'congmq.test';
const CLIENT_CN = 'congmq-device-1';

let failures = 0;
let total = 0;
const check = (name, ok, detail = '') => {
  total++;
  console.log(`${ok ? 'pass' : 'FAIL'}  ${name}${detail ? `\n        -> ${detail}` : ''}`);
  if (!ok) failures++;
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(what, cond, limit = 10000) {
  const started = Date.now();
  for (;;) {
    const ok = await cond();
    if (ok) return Date.now() - started;
    if (Date.now() - started > limit) throw new Error(`timed out after ${limit}ms waiting for ${what}`);
    await sleep(50);
  }
}

const dir = mkdtempSync(join(tmpdir(), 'congmq-tls-check-'));
const pki = join(dir, 'pki');

// ------------------------------------------------------------------ pki ----

function genPKI(args = []) {
  return new Promise((resolve, reject) => {
    const proc = spawn(CERT_BIN, ['-out', pki, '-days', '30', '-server-cn', SERVER_CN, '-client-cn', CLIENT_CN, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    proc.stdout.on('data', (b) => (out += b.toString()));
    proc.stderr.on('data', (b) => (err += b.toString()));
    proc.once('exit', (code) => (code === 0 ? resolve(out) : reject(new Error(`congmq-cert exit ${code}: ${err || out}`))));
    proc.once('error', reject);
  });
}

// ---------------------------------------------------------------- broker ----

function startBroker(extra) {
  const proc = spawn(BIN, ['-addr', `127.0.0.1:${PORT}`, '-tls-addr', `127.0.0.1:${TLSPORT}`, ...extra], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const handle = { proc, lines: [], killed: false };
  proc.stderr.on('data', (b) => {
    for (const line of b.toString().split(/\r?\n/)) if (line.trim()) handle.lines.push(line.trim());
  });
  proc.stdout.on('data', (b) => handle.lines.push(b.toString().trim()));
  proc.once('exit', (code) => handle.lines.push(`exit=${code}`));
  handle.log = (needle) => handle.lines.find((l) => l.includes(needle)) ?? '';
  return handle;
}

async function runBin(args) {
  const proc = spawn(BIN, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  proc.stderr.on('data', (b) => (out += b.toString()));
  proc.stdout.on('data', (b) => (out += b.toString()));
  const code = await new Promise((resolve) => proc.once('exit', resolve));
  return { code: code ?? -1, out: out.trim() };
}

async function metrics() {
  const res = await fetch(`http://127.0.0.1:${METRICS_PORT}/metrics`);
  return res.json();
}

// ---------------------------------------------------------------- clients ----

const ca = () => readFileSync(join(pki, 'ca.crt'));
const clientCert = () => readFileSync(join(pki, 'client.crt'));
const clientKey = () => readFileSync(join(pki, 'client.key'));

// tlsOptions is what a device carries: the CA it was provisioned with, its own
// certificate, and the name the server certificate must answer to.
const tlsOptions = (over = {}) => ({ ca: ca(), cert: clientCert(), key: clientKey(), servername: 'localhost', ...over });

function connect(url, options) {
  return new Promise((resolve, reject) => {
    const client = mqtt.connect(url, {
      clientId: options.clientId ?? `tls-check-${Math.random().toString(16).slice(2, 8)}`,
      reconnectPeriod: 0,
      connectTimeout: 6000,
      clean: true,
      ...options,
    });
    const timer = setTimeout(() => {
      client.end(true);
      reject(new Error('connect timed out'));
    }, 9000);
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

const close = (client) => new Promise((resolve) => client.end(true, resolve));

const subscribe = (client, topic, qos = 1) =>
  new Promise((resolve, reject) =>
    client.subscribe(topic, { qos }, (err, granted) => (err ? reject(err) : resolve(granted))),
  );

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

// A refused connection arrives as an error, so the expected-failure cases have a
// shape of their own instead of a try/catch at every call site.
async function expectRefused(url, options, why) {
  try {
    const client = await connect(url, options);
    await close(client);
    return { ok: false, detail: `${why}: it connected` };
  } catch (err) {
    return { ok: true, detail: `${err.code ?? ''} ${err.message}`.trim() };
  }
}

// ------------------------------------------------------------------- run ----

async function main() {
  console.log(`binary   ${BIN}`);
  console.log(`cert     ${CERT_BIN}`);
  console.log(`plain    ${PLAIN_URL}`);
  console.log(`tls      ${TLS_URL}`);
  console.log(`pki      ${pki}\n`);

  const report = await genPKI();
  check('congmq-cert writes a chain with the server SANs', /SANs localhost,127\.0\.0\.1,::1/.test(report), report.trim().split('\n').join(' | '));
  for (const f of ['ca.crt', 'server.crt', 'server.key', 'client.crt', 'client.key']) {
    if (!existsSync(join(pki, f))) throw new Error(`congmq-cert did not produce ${f}`);
  }

  // The rule files a certificate deployment would carry: the certificate is the
  // credential, and the same name scopes what the session may publish.
  const authPath = join(dir, 'auth.jsonl');
  writeFileSync(
    authPath,
    [
      `# the handshake is the whole credential`,
      `{"cert_cn":"${CLIENT_CN}"}`,
      `# a password account that still works on either port`,
      `{"username":"dashboard","salt":"c0ng-2026","alg":"sha256","scheme":"salt+username"}`,
      '',
    ].join('\n'),
  );
  const aclPath = join(dir, 'acl.jsonl');
  writeFileSync(
    aclPath,
    [
      `{"effect":"deny","action":"publish","cert_cn":"${CLIENT_CN}","topics":["plant/secret/#"]}`,
      `{"effect":"allow","action":"all","cert_cn":"${CLIENT_CN}","topics":["plant/#"]}`,
      `{"effect":"allow","action":"all","user":"dashboard","topics":["#"]}`,
      '',
    ].join('\n'),
  );

  const tlsArgs = [
    '-tls-cert', join(pki, 'server.crt'),
    '-tls-key', join(pki, 'server.key'),
    '-tls-ca', join(pki, 'ca.crt'),
    '-auth', authPath,
    '-acl', aclPath,
    '-metrics', `127.0.0.1:${METRICS_PORT}`,
    '-id', 'tls-check',
  ];
  const broker = startBroker(tlsArgs);
  try {
    await waitFor('the broker to listen', () => broker.log('msg=listening') !== '');

    const line = broker.log('tls listener configured');
    check(
      'the start-up log names the certificate, its hosts and the client policy',
      line.includes(`cn=${SERVER_CN}`) && line.includes('sans=localhost,127.0.0.1,::1') && line.includes('required and verified against -tls-ca'),
      line,
    );
    const listening = broker.log('msg=listening');
    check('both ports are up', listening.includes(`tls_addr=127.0.0.1:${TLSPORT}`), listening);

    // 1. The certificate alone is a credential.
    const dev = await connect(TLS_URL, { ...tlsOptions(), username: undefined });
    check('mqtts client with a client certificate and no password connects', dev.connected);

    // 2. …and the same name scopes what it may do.
    const peer = await connect(TLS_URL, tlsOptions());
    await subscribe(peer, 'plant/#');
    await publish(dev, 'plant/row/1', 'over tls');
    const got = await oneMessage(peer, 4000);
    check('a QoS 1 message crosses the TLS listener both ways', got.topic === 'plant/row/1' && got.payload === 'over tls', JSON.stringify(got));

    const before = await metrics();
    await publish(dev, 'plant/secret/1', 'not yours');
    const after = await waitForMetrics('acl_denied_publish', (m) => m.acl_denied_publish > before.acl_denied_publish);
    let refused = false;
    try {
      await oneMessage(peer, 1500);
    } catch {
      refused = true;
    }
    check(
      'the deny rule on the same certificate stops that publish',
      refused && after.acl_denied_publish === before.acl_denied_publish + 1,
      `acl_denied_publish ${before.acl_denied_publish} -> ${after.acl_denied_publish}`,
    );

    // 3. A session that offers no certificate is refused before any MQTT byte.
    const noCert = await expectRefused(TLS_URL, { ca: ca(), servername: 'localhost' }, 'no client certificate');
    check('a client without a certificate cannot get in', noCert.ok, noCert.detail);

    // 4. Nor can one that does not trust the CA that signed the server.
    const noCA = await expectRefused(TLS_URL, { cert: clientCert(), key: clientKey(), servername: 'localhost' }, 'untrusted server');
    check('a client that does not trust the server CA is turned away', noCA.ok, noCA.detail);

    // 5. …or that calls it by a name the certificate does not hold.
    const wrongName = await expectRefused(
      TLS_URL,
      { ...tlsOptions(), servername: 'other.example' },
      'hostname mismatch',
    );
    check('the server certificate is verified against the name it is called by', wrongName.ok, wrongName.detail);

    // 6. The TLS port speaks nothing else: plain bytes are refused, and a TLS
    // client pointed at the plain port gets nothing it can parse.
    const plainToTLS = await expectRefused(`mqtt://127.0.0.1:${TLSPORT}`, {}, 'plain client on the tls port');
    check('a plain client on the TLS port fails', plainToTLS.ok, plainToTLS.detail);
    const tlsToPlain = await expectRefused(PLAIN_URL, tlsOptions(), 'tls client on the plain port');
    check('a TLS client on the plain port fails', tlsToPlain.ok, tlsToPlain.detail);

    // 7. The plain port still works, so a fleet can be moved over one device at
    // a time. The password account is the one the rule file also carries.
    const dashboard = crypto.createHash('sha256').update('c0ng-2026' + 'dashboard').digest('hex');
    const dash = await connect(PLAIN_URL, { username: 'dashboard', password: dashboard });
    check('the plain port still accepts a password account', dash.connected);
    await close(dash);

    // 8. What the broker counted. Four attempts above were turned away at the
    // handshake; the two sessions that got through are the only ones a TLS
    // connection count may name.
    const m = await metrics();
    check(
      'connections_tls counts established TLS sessions and nothing else',
      m.connections_tls === 2,
      `connections_tls=${m.connections_tls}, total_connections=${m.total_connections}`,
    );
    check(
      'tls_handshake_failures counts every refusal before a session exists',
      m.tls_handshake_failures >= 4 && m.total_connections >= m.connections_tls,
      `failures=${m.tls_handshake_failures} total=${m.total_connections} tls=${m.connections_tls}`,
    );
    check('a certificate session is never an auth rejection', m.auth_rejected === 0, `auth_rejected=${m.auth_rejected}`);

    await close(dev);
    await close(peer);
  } finally {
    const gone = await killAndWait(broker);
    if (!gone) console.error('the broker did not exit');
  }

  // Start-up refusals: a broker that would lock out its whole fleet says so
  // before it binds anything.
  const expired = join(dir, 'expired');
  await genPKIInto(expired, ['-days', '-1']);
  const r1 = await runBin(['-addr', '127.0.0.1:0', '-tls-addr', '127.0.0.1:0', '-tls-cert', join(expired, 'server.crt'), '-tls-key', join(expired, 'server.key')]);
  check('an expired certificate stops the broker before it binds', r1.code === 1 && /expired on/.test(r1.out), r1.out);

  const r2 = await runBin(['-addr', '127.0.0.1:0', '-tls-ca', join(pki, 'ca.crt')]);
  check('-tls flags with an empty -tls-addr are refused', r2.code === 2 && /-tls-addr is empty/.test(r2.out), r2.out);

  const r3 = await runBin(['-addr', '127.0.0.1:0', '-auth', authPath]);
  check('cert_cn rules without a TLS port are refused', r3.code === 1 && /no tls listener is configured/.test(r3.out), r3.out);

  const r4 = await runBin(['-addr', '127.0.0.1:0', '-tls-addr', '127.0.0.1:0', '-tls-cert', join(pki, 'server.crt'), '-tls-key', join(pki, 'server.key'), '-tls-min-version', '1.1']);
  check('an old -tls-min-version is refused', r4.code === 1 && /must be 1\.2 or 1\.3/.test(r4.out), r4.out);
}

async function waitForMetrics(what, cond) {
  const started = Date.now();
  for (;;) {
    const m = await metrics();
    if (cond(m)) return m;
    if (Date.now() - started > 8000) throw new Error(`timed out waiting for ${what}`);
    await sleep(50);
  }
}

async function genPKIInto(out, extra) {
  return new Promise((resolve, reject) => {
    const proc = spawn(CERT_BIN, ['-out', out, '-server-cn', SERVER_CN, '-client-cn', CLIENT_CN, ...extra], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    proc.once('exit', (code) => (code === 0 ? resolve() : reject(new Error(`congmq-cert exit ${code}`))));
    proc.once('error', reject);
  });
}

// killAndWait drains a broker. SIGKILL is the only reliable way to stop a
// Windows process from Node, and the graceful path is what the Go suite covers.
async function killAndWait(handle) {
  if (handle.killed) return true;
  handle.killed = true;
  handle.proc.kill('SIGKILL');
  for (let i = 0; i < 100; i++) {
    if (handle.lines.some((l) => l.startsWith('exit='))) return true;
    await sleep(50);
  }
  return false;
}

const watchdog = setTimeout(() => {
  console.error('\nFAIL  the run exceeded 90s and was aborted');
  rmSync(dir, { recursive: true, force: true });
  process.exit(1);
}, 90000);

main()
  .then(() => {
    console.log(`\n${total - failures}/${total} checks passed`);
    process.exitCode = failures ? 1 : 0;
  })
  .catch((err) => {
    console.error('\nFAIL', err);
    process.exitCode = 1;
  })
  .finally(() => {
    clearTimeout(watchdog);
    rmSync(dir, { recursive: true, force: true });
    process.exit(process.exitCode ?? 1);
  });
