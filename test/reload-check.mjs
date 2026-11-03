// Third-party-client checks for the no-restart side of the broker: a rule file
// is rewritten, a server certificate is replaced, and a broken version of each is
// refused — while one mqtt.js session stays connected through all of it. The
// broker is never restarted: the same pid serves every check below, and the
// evidence is the same three endpoints an operator or a scraper would use.
//
//	node test/reload-check.mjs
//
// Nothing here reads a Go test helper: the rule files are the JSONL an operator
// edits, the certificates are the PEMs congmq-cert writes for a device, and the
// counters come from /metrics, /metrics.txt and /readyz over HTTP.
//
// The 503 half of /readyz is the Go suite's job — a probe cannot catch a process
// that is already gone — the same way crash-check leaves the graceful drain to Go.
//
// CONGMQ_BIN, CONGMQ_PORT, CONGMQ_TLS_PORT, CONGMQ_METRICS_PORT, CONGMQ_SIDE_PORT,
// CONGMQ_SIDE_METRICS_PORT and CONGMQ_RELOAD_INTERVAL point it at another build
// or another set of ports. The defaults avoid 1883 and 1884, which a developer's
// long-running broker is usually holding.
import mqtt from 'mqtt';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const exe = (name) =>
  fileURLToPath(new URL(`../bin/${name}${process.platform === 'win32' ? '.exe' : ''}`, import.meta.url));
const BIN = process.env.CONGMQ_BIN ?? exe('congmq');
const CERT_BIN = process.env.CONGMQ_CERT_BIN ?? exe('congmq-cert');

const PORT = Number(process.env.CONGMQ_PORT ?? 1915); // plain
const TLSPORT = Number(process.env.CONGMQ_TLS_PORT ?? 1916); // tls
const METRICS_PORT = Number(process.env.CONGMQ_METRICS_PORT ?? 1917);
const SIDE_PORT = Number(process.env.CONGMQ_SIDE_PORT ?? 1918); // the no-TLS broker
const SIDE_METRICS = Number(process.env.CONGMQ_SIDE_METRICS_PORT ?? 1919);

// One second is the interval under test and the granularity every wait below is
// written against: the reload has to be caught, not waited out indefinitely.
const RELOAD_INTERVAL = process.env.CONGMQ_RELOAD_INTERVAL ?? '1s';
const TICK_MS = 1000;
const TICKS = 4; // how many polls to sit through when proving a refusal is counted once

const PLAIN_URL = `mqtt://127.0.0.1:${PORT}`;
const TLS_URL = `mqtts://127.0.0.1:${TLSPORT}`;
const SIDE_URL = `mqtt://127.0.0.1:${SIDE_PORT}`;
const BASE = `http://127.0.0.1:${METRICS_PORT}`;
const SIDE_BASE = `http://127.0.0.1:${SIDE_METRICS}`;

const SERVER_CN = 'congmq.test';
const ROTATED_CN = 'rotated.test';
const CLIENT_CN = 'congmq-device-1';

const hex = (alg, s) => crypto.createHash(alg).update(s, 'utf8').digest('hex');
// md5(username+salt), which is what these rules describe.
const pw = (user) => hex('md5', user + 'x');

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

const dir = mkdtempSync(join(tmpdir(), 'congmq-reload-check-'));
const pkiA = join(dir, 'pki');
const pkiB = join(dir, 'pki-rotated');

// ------------------------------------------------------------------ pki ----

function genPKI(out, serverCN) {
  return new Promise((resolve, reject) => {
    const proc = spawn(CERT_BIN, ['-out', out, '-days', '30', '-server-cn', serverCN, '-client-cn', CLIENT_CN], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let err = '';
    proc.stderr.on('data', (b) => (err += b.toString()));
    proc.once('exit', (code) => (code === 0 ? resolve() : reject(new Error(`congmq-cert exit ${code}: ${err}`))));
    proc.once('error', reject);
  });
}

// ---------------------------------------------------------------- broker ----

function startBroker(args) {
  const proc = spawn(BIN, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  const handle = { proc, lines: [], killed: false };
  proc.stderr.on('data', (b) => {
    for (const line of b.toString().split(/\r?\n/)) if (line.trim()) handle.lines.push(line.trim());
  });
  proc.stdout.on('data', (b) => handle.lines.push(b.toString().trim()));
  proc.once('exit', (code) => handle.lines.push(`exit=${code}`));
  handle.log = (needle) => handle.lines.find((l) => l.includes(needle)) ?? '';
  return handle;
}

const waitListening = (handle) => waitFor('the broker to listen', () => handle.log('msg=listening') !== '');

// killAndWait drains a broker. SIGKILL is the only reliable way to stop a
// Windows process from Node; the graceful path is what the Go suite covers.
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

// ------------------------------------------------------- the three endpoints ----

async function metrics(base = BASE) {
  return (await fetch(`${base}/metrics`)).json();
}

async function metricsText(base = BASE) {
  const res = await fetch(`${base}/metrics.txt`);
  return { type: res.headers.get('content-type') ?? '', text: await res.text() };
}

async function readyz(base = BASE) {
  const res = await fetch(`${base}/readyz`);
  return { code: res.status, body: await res.json() };
}

// promParse reads the exposition format back. Three parallel counts is the
// cheapest way to catch a metric that got a HELP line and no sample, or a sample
// with no TYPE a scraper would refuse.
function promParse(text) {
  const values = {};
  let help = 0;
  let type = 0;
  let samples = 0;
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    if (line.startsWith('# HELP ')) help++;
    else if (line.startsWith('# TYPE ')) type++;
    else if (line.startsWith('#')) throw new Error(`unexpected comment line: ${line}`);
    else {
      const [name, value] = line.split(' ');
      values[name] = value;
      samples++;
    }
  }
  return { values, help, type, samples, count: Object.keys(values).length };
}

// waitForMetric polls the JSON view until a counter moves. Every claim below is a
// statement about a counter, so this is the only honest way to wait for it.
async function waitForMetric(what, cond, limit = 15000) {
  const started = Date.now();
  for (;;) {
    const m = await metrics();
    if (cond(m)) return m;
    if (Date.now() - started > limit) throw new Error(`timed out after ${limit}ms waiting for ${what} (last: ${JSON.stringify(m)})`);
    await sleep(50);
  }
}

// -------------------------------------------------------------- rule files ----

const authFile = (extra = []) =>
  [
    '# the handshake is the whole credential for a device',
    `{"cert_cn":"${CLIENT_CN}"}`,
    '# operator accounts digest md5(username+salt)',
    '{"username":"one","salt":"x","alg":"md5","scheme":"username+salt"}',
    '{"username":"pub","salt":"x","alg":"md5","scheme":"username+salt"}',
    '{"username":"watch","salt":"x","alg":"md5","scheme":"username+salt"}',
    ...extra,
    '',
  ].join('\n');

// The same policy with no certificate half, for the broker that has no TLS port.
const plainAuthFile = (extra = []) =>
  [
    '{"username":"one","salt":"x","alg":"md5","scheme":"username+salt"}',
    '{"username":"pub","salt":"x","alg":"md5","scheme":"username+salt"}',
    '{"username":"watch","salt":"x","alg":"md5","scheme":"username+salt"}',
    ...extra,
    '',
  ].join('\n');

const aclFile = (watchTopics) =>
  [
    `{"effect":"allow","action":"all","cert_cn":"${CLIENT_CN}","topics":["plant/#"]}`,
    '{"effect":"allow","action":"all","user":"one","topics":["#"]}',
    '{"effect":"allow","action":"all","user":"pub","topics":["shop/#"]}',
    `{"effect":"allow","action":"all","user":"watch","topics":${JSON.stringify(watchTopics)}}`,
    '',
  ].join('\n');

const plainAclFile = () =>
  [
    '{"effect":"allow","action":"all","user":"one","topics":["#"]}',
    '{"effect":"allow","action":"all","user":"pub","topics":["shop/#"]}',
    '{"effect":"allow","action":"all","user":"watch","topics":["shop/#"]}',
    '',
  ].join('\n');

// ---------------------------------------------------------------- clients ----

function connect(url, options) {
  return new Promise((resolve, reject) => {
    const client = mqtt.connect(url, {
      clientId: options.clientId ?? `reload-check-${Math.random().toString(16).slice(2, 8)}`,
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
    return { ok: true, detail: `${why}: ${err.code ?? ''} ${err.message}`.trim() };
  }
}

// dropped counts the events that would show a session being evicted by a policy
// swap — the one thing this phase promises never happens. It has to return the
// object the listeners close over, not a copy.
function dropped(client) {
  const seen = { close: 0, offline: 0, error: 0 };
  client.on('close', () => seen.close++);
  client.on('offline', () => seen.offline++);
  client.on('error', () => seen.error++);
  return seen;
}

// ------------------------------------------------------------------- run ----

async function main() {
  console.log(`binary    ${BIN}`);
  console.log(`plain     ${PLAIN_URL}`);
  console.log(`tls       ${TLS_URL}`);
  console.log(`metrics   ${BASE} (/metrics /metrics.txt /readyz)`);
  console.log(`reload    -reload-interval ${RELOAD_INTERVAL}`);
  console.log(`pki       ${pkiA}, rotated over ${pkiB}\n`);

  await genPKI(pkiA, SERVER_CN);
  await genPKI(pkiB, ROTATED_CN);
  for (const f of ['ca.crt', 'server.crt', 'server.key', 'client.crt', 'client.key']) {
    if (!existsSync(join(pkiA, f)) || !existsSync(join(pkiB, f))) throw new Error(`congmq-cert did not produce ${f}`);
  }

  // What a device carries is fixed at provisioning, so the bytes of the first CA
  // have to be held here: after the rotation the file on disk is the new one and
  // the retired chain exists nowhere but in this run.
  const retiredCA = readFileSync(join(pkiA, 'ca.crt'));
  const retiredCert = readFileSync(join(pkiA, 'client.crt'));
  const retiredKey = readFileSync(join(pkiA, 'client.key'));

  const authPath = join(dir, 'auth.jsonl');
  const aclPath = join(dir, 'acl.jsonl');
  writeFileSync(authPath, authFile());
  writeFileSync(aclPath, aclFile(['shop/#', 'plant/#']));

  const broker = startBroker([
    '-addr', `127.0.0.1:${PORT}`,
    '-tls-addr', `127.0.0.1:${TLSPORT}`,
    '-tls-cert', join(pkiA, 'server.crt'),
    '-tls-key', join(pkiA, 'server.key'),
    '-tls-ca', join(pkiA, 'ca.crt'),
    '-auth', authPath,
    '-acl', aclPath,
    '-metrics', `127.0.0.1:${METRICS_PORT}`,
    '-id', 'reload-check',
    '-reload-interval', RELOAD_INTERVAL,
  ]);

  try {
    await waitListening(broker);

    // ------------------------------------------------ 1. the operator's view --
    const boot = await metrics();
    check(
      'the metrics view opens with generation 1 for policy and certificate',
      boot.rules_generation === 1 && boot.tls_cert_generation === 1 && boot.rules_reloads === 0 && boot.rules_reload_failures === 0,
      `rules_generation=${boot.rules_generation} tls_cert_generation=${boot.tls_cert_generation} reloads=${boot.rules_reloads} failures=${boot.rules_reload_failures}`,
    );
    check(
      'the interval, the live leaf and its expiry are all reported',
      boot.tls_cert_cn === SERVER_CN && boot.reload_interval_seconds === Math.floor(TICK_MS / 1000) && boot.tls_cert_not_after_unix * 1000 > Date.now(),
      `cn=${boot.tls_cert_cn} interval=${boot.reload_interval_seconds}s not_after=${new Date(boot.tls_cert_not_after_unix * 1000).toISOString()}`,
    );

    const txt = await metricsText();
    const prom = promParse(txt.text);
    check(
      '/metrics.txt is the Prometheus exposition format, one block per metric',
      txt.type.startsWith('text/plain; version=0.0.4') && prom.help === prom.type && prom.type === prom.samples && prom.samples === prom.count,
      `content-type=${txt.type} help=${prom.help} type=${prom.type} samples=${prom.samples} names=${prom.count}`,
    );
    const notInteger = Object.entries(prom.values).filter(([, v]) => !/^-?\d+$/.test(v));
    check(
      'every text sample is a whole number a counter can be',
      notInteger.length === 0,
      notInteger.map(([k, v]) => `${k}=${v}`).join(' ') || `${prom.count} metrics, all integer`,
    );
    check(
      'the text view names the same generations the JSON view reports',
      prom.values.congmq_rules_generation === String(boot.rules_generation) && prom.values.congmq_tls_cert_generation === String(boot.tls_cert_generation),
      `rules_generation=${prom.values.congmq_rules_generation} tls_cert_generation=${prom.values.congmq_tls_cert_generation} names=${prom.count}`,
    );

    // ------------------------------------------------ 2. sessions to protect --
    const dev = await connect(TLS_URL, {
      clientId: 'device-boot',
      ca: retiredCA,
      cert: retiredCert,
      key: retiredKey,
      servername: 'localhost',
      username: undefined,
    });
    const devDrops = dropped(dev);
    check('mqtts device with a client certificate connects', dev.connected);

    const watch = await connect(PLAIN_URL, { clientId: 'watch-1', username: 'watch', password: pw('watch') });
    const watchDrops = dropped(watch);
    await subscribe(watch, 'shop/#');
    await subscribe(watch, 'plant/#');
    const pub = await connect(PLAIN_URL, { clientId: 'pub-1', username: 'pub', password: pw('pub') });

    const ready = await readyz();
    const live = await metrics();
    check(
      '/readyz says ready and names the sessions a load balancer may land on',
      ready.code === 200 && ready.body.status === 'ready' && ready.body.online === live.online && ready.body.online >= 3,
      `status=${ready.code} ${JSON.stringify(ready.body)} metrics.online=${live.online}`,
    );

    // The same snapshot through the other door: a scraper that reads the text
    // view and a curl that reads the JSON view must not disagree about anything.
    const liveProm = promParse((await metricsText()).text);
    check(
      'the two endpoints agree while sessions are live',
      liveProm.values.congmq_online === String(live.online) &&
        liveProm.values.congmq_total_connections === String(live.total_connections) &&
        liveProm.values.congmq_subscriptions === String(live.subscriptions) &&
        liveProm.values.congmq_messages_in === String(live.messages_in),
      `online=${liveProm.values.congmq_online} subscriptions=${liveProm.values.congmq_subscriptions} messages_in=${liveProm.values.congmq_messages_in}`,
    );

    await publish(pub, 'shop/a', 'before any change');
    const first = await oneMessage(watch, 5000);
    check('the subscriber receives on the policy that booted', first.topic === 'shop/a', JSON.stringify(first));

    // ------------------------------------------ 3. a rewritten auth file ----
    const unknown = await expectRefused(PLAIN_URL, { clientId: 'two-1', username: 'two', password: pw('two') }, 'user two');
    check('the account the file does not describe yet is refused', unknown.ok, unknown.detail);

    const genBefore = (await metrics()).rules_generation;
    writeFileSync(authPath, authFile(['{"username":"two","salt":"x","alg":"md5","scheme":"username+salt"}']));
    const landed = await waitForMetric('the auth rewrite to land', (m) => m.rules_generation > genBefore);
    check(
      'a rewritten auth file is installed without a restart',
      landed.rules_generation === genBefore + 1 && landed.rules_reloads === 1 && landed.rules_reload_failures === 0,
      `generation ${genBefore} -> ${landed.rules_generation} reloads=${landed.rules_reloads}`,
    );

    const two = await connect(PLAIN_URL, { clientId: 'two-2', username: 'two', password: pw('two') });
    check('the account the new file describes is accepted on its next connect', two.connected);
    await close(two);

    check(
      'the reload log names the generation that landed and how many rules it holds',
      /msg="rules reloaded" generation=2 auth=5 acl=4/.test(broker.log('rules reloaded')),
      broker.log('rules reloaded'),
    );

    const nobody = await expectRefused(PLAIN_URL, { clientId: 'nobody-1', username: 'nobody', password: 'x' }, 'an unlisted account');
    check('a reload does not quietly become an open door', nobody.ok, nobody.detail);

    // -------------------------------------------- 4. a narrowed acl file ----
    const narrowGen = (await metrics()).rules_generation;
    const subsBefore = (await metrics()).subscriptions;
    const deniedBefore = (await metrics()).acl_denied_delivery;
    writeFileSync(aclPath, aclFile(['other/#']));
    await waitForMetric('the acl rewrite to land', (m) => m.rules_generation > narrowGen);

    await publish(pub, 'shop/b', 'after the acl rewrite');
    let nothingArrived = false;
    try {
      await oneMessage(watch, 2000);
    } catch {
      nothingArrived = true;
    }
    const afterNarrow = await waitForMetric('acl_denied_delivery to rise', (m) => m.acl_denied_delivery > deniedBefore);
    check(
      'the narrowed filter stops feeding a session that is already subscribed',
      nothingArrived && afterNarrow.acl_denied_delivery === deniedBefore + 1,
      `acl_denied_delivery ${deniedBefore} -> ${afterNarrow.acl_denied_delivery}`,
    );
    const subsAfter = (await metrics()).subscriptions;
    check(
      'and that session stays open with its subscriptions registered',
      watch.connected && watchDrops.close === 0 && subsAfter === subsBefore,
      `connected=${watch.connected} closes=${watchDrops.close} subscriptions ${subsBefore} -> ${subsAfter}`,
    );

    // --------------------------------------- 5. a file that will not parse --
    const before = await metrics();
    const goodGen = before.rules_generation;
    const failBefore = before.rules_reload_failures;
    const reloadsBefore = before.rules_reloads;
    // Half a line is what an editor crash or a truncated copy leaves behind.
    writeFileSync(authPath, '{"username":"five","salt":"x","alg":"md5","sch');
    await waitForMetric('the broken auth file to be refused', (m) => m.rules_reload_failures > failBefore);
    await sleep(TICK_MS * TICKS); // several more polls against the same refused content
    const settled = await metrics();
    check(
      'a broken rule file is refused and counted once, not once per poll',
      settled.rules_reload_failures === failBefore + 1 && settled.rules_generation === goodGen && settled.rules_reloads === reloadsBefore,
      `failures ${failBefore} -> ${settled.rules_reload_failures} generation=${settled.rules_generation} (unchanged from ${goodGen}) reloads=${settled.rules_reloads}`,
    );
    check(
      'the refusal is in the log, with the generation still being served',
      /rules refused, keeping the policy in force/.test(broker.log('rules refused')) && /generation=\d+/.test(broker.log('rules refused')),
      broker.log('rules refused'),
    );

    const stillInForce = await connect(PLAIN_URL, { clientId: 'two-3', username: 'two', password: pw('two') });
    check('the refused rewrite costs the fleet nothing: the old policy is still in force', stillInForce.connected);
    await close(stillInForce);

    writeFileSync(authPath, authFile(['{"username":"two","salt":"x","alg":"md5","scheme":"username+salt"}', '{"username":"three","salt":"x","alg":"md5","scheme":"username+salt"}']));
    const repaired = await waitForMetric('the repaired file to land', (m) => m.rules_generation > goodGen);
    const three = await connect(PLAIN_URL, { clientId: 'three-1', username: 'three', password: pw('three') });
    check(
      'a fix lands on the next poll with no restart and no operator action',
      repaired.rules_generation === goodGen + 1 &&
        repaired.rules_reloads === reloadsBefore + 1 &&
        repaired.rules_reload_failures === failBefore + 1 &&
        three.connected,
      `generation ${goodGen} -> ${repaired.rules_generation} reloads=${repaired.rules_reloads} failures=${repaired.rules_reload_failures}`,
    );
    await close(three);

    // ------------------------------------ 6. a rotated server certificate ----
    const certGenBefore = (await metrics()).tls_cert_generation;
    const hsBefore = (await metrics()).tls_handshake_failures;
    // Three files, replaced one after another. A poll that lands mid-copy sees a
    // leaf that does not match its key or a CA nobody here signed, refuses it, and
    // the next poll installs the complete generation — so these assertions watch
    // the end state rather than an exact generation number.
    copyFileSync(join(pkiB, 'server.crt'), join(pkiA, 'server.crt'));
    copyFileSync(join(pkiB, 'server.key'), join(pkiA, 'server.key'));
    copyFileSync(join(pkiB, 'ca.crt'), join(pkiA, 'ca.crt'));

    const rotated = await waitForMetric('the new leaf to be served', (m) => m.tls_cert_cn === ROTATED_CN && m.tls_cert_generation > certGenBefore);
    check(
      'a replaced leaf and CA take effect without a restart',
      rotated.tls_cert_generation > certGenBefore && rotated.tls_cert_reloads >= 1,
      `generation ${certGenBefore} -> ${rotated.tls_cert_generation} reloads=${rotated.tls_cert_reloads} cn=${rotated.tls_cert_cn}`,
    );
    check(
      'the rotation is in the log with what is now being served',
      /msg="tls certificate rotated"/.test(broker.log('tls certificate rotated')) && /cn=rotated\.test/.test(broker.log('tls certificate rotated')),
      broker.log('tls certificate rotated'),
    );

    const fresh = await connect(TLS_URL, {
      clientId: 'device-new',
      ca: readFileSync(join(pkiA, 'ca.crt')),
      cert: readFileSync(join(pkiB, 'client.crt')),
      key: readFileSync(join(pkiB, 'client.key')),
      servername: 'localhost',
      username: undefined,
    });
    check('a device provisioned with the new CA connects', fresh.connected);
    await close(fresh);

    const stale = await expectRefused(
      TLS_URL,
      { clientId: 'device-old-ca', ca: retiredCA, cert: retiredCert, key: retiredKey, servername: 'localhost', username: undefined },
      'a device holding the retired CA',
    );
    const afterRotation = await metrics();
    check(
      'the retired CA is turned away, by error and by count',
      stale.ok && afterRotation.tls_handshake_failures > hsBefore,
      `${stale.detail} tls_handshake_failures ${hsBefore} -> ${afterRotation.tls_handshake_failures}`,
    );

    // The same client identifier, presenting the certificate it was provisioned
    // with, trusting the new CA — so it gets past the server and fails on its own
    // chain. The name is not the credential; the verified chain is.
    const retiredName = await expectRefused(
      TLS_URL,
      { clientId: 'device-old-name', ca: readFileSync(join(pkiA, 'ca.crt')), cert: retiredCert, key: retiredKey, servername: 'localhost', username: undefined },
      'a retired certificate whose CN a rule still allows',
    );
    check('a client certificate from the retired chain is refused even though its CN matches', retiredName.ok, retiredName.detail);

    // ------------------------------------- 7. a leaf that will not parse -----
    const servedGen = (await metrics()).tls_cert_generation;
    const failCount = (await metrics()).tls_cert_reload_failures;
    writeFileSync(join(pkiA, 'server.crt'), '-----BEGIN CERTIFICATE-----\nbroken by a truncated copy\n-----END CERTIFICATE-----\n');
    await waitForMetric('the broken leaf to be refused', (m) => m.tls_cert_reload_failures > failCount);
    await sleep(TICK_MS * TICKS);
    const certSettled = await metrics();
    check(
      'a broken leaf is refused and counted once, not once per poll',
      certSettled.tls_cert_reload_failures === failCount + 1 && certSettled.tls_cert_generation === servedGen,
      `failures ${failCount} -> ${certSettled.tls_cert_reload_failures} generation=${certSettled.tls_cert_generation} (unchanged from ${servedGen})`,
    );
    check(
      'the refusal names the material and the leaf still being served',
      /tls material refused/.test(broker.log('tls material refused')) && /cn=rotated\.test/.test(broker.log('tls material refused')),
      broker.log('tls material refused'),
    );

    const survives = await connect(TLS_URL, {
      clientId: 'device-after-garbage',
      ca: readFileSync(join(pkiA, 'ca.crt')),
      cert: readFileSync(join(pkiB, 'client.crt')),
      key: readFileSync(join(pkiB, 'client.key')),
      servername: 'localhost',
      username: undefined,
    });
    check('handshakes keep being answered from the generation in force', survives.connected);
    await close(survives);

    // --------------------------------------- 8. nothing was restarted here --
    const last = await metrics();
    check(
      'one process served every change above',
      last.pid === boot.pid && last.started_unix === boot.started_unix && last.uptime_seconds > boot.uptime_seconds,
      `pid ${boot.pid} -> ${last.pid} uptime ${boot.uptime_seconds}s -> ${last.uptime_seconds}s`,
    );
    check(
      'no session was evicted by a policy swap or a certificate rotation',
      dev.connected && watch.connected && devDrops.close === 0 && devDrops.offline === 0 && watchDrops.close === 0 && watchDrops.offline === 0 && last.server_disconnects === 0,
      `device closes=${devDrops.close} offline=${devDrops.offline} watch closes=${watchDrops.close} offline=${watchDrops.offline} server_disconnects=${last.server_disconnects}`,
    );

    // Widening the filter back restores deliveries to the session that never
    // resubscribed — the reload works in both directions.
    const widenGen = (await metrics()).rules_generation;
    writeFileSync(aclPath, aclFile(['shop/#', 'plant/#']));
    const widened = await waitForMetric('the widened acl to land', (m) => m.rules_generation > widenGen);
    const arrived = oneMessage(watch, 6000);
    await publish(dev, 'plant/row/late', 'the session that booted is still working');
    let late = null;
    try {
      late = await arrived;
    } catch {
      late = null;
    }
    check(
      'the device that booted on the retired leaf still publishes, and delivery came back',
      late !== null && late.topic === 'plant/row/late' && widened.rules_generation === widenGen + 1,
      late === null ? 'nothing arrived' : JSON.stringify(late),
    );
    check(
      'and the counts left behind are exactly the changes this run made',
      widened.rules_reloads === 4 && widened.rules_reload_failures === 1 && widened.tls_cert_reloads >= 1 && widened.tls_cert_reload_failures >= 1,
      `rules ${widened.rules_reloads} landed / ${widened.rules_reload_failures} refused, tls ${widened.tls_cert_reloads} rotated / ${widened.tls_cert_reload_failures} refused`,
    );

    await close(dev);
    await close(watch);
    await close(pub);
  } finally {
    const gone = await killAndWait(broker);
    if (!gone) console.error('the broker did not exit');
  }

  // ------------------------------- 9. a plain broker, and signal-only mode --

  const plainAuth = join(dir, 'auth-plain.jsonl');
  const plainAcl = join(dir, 'acl-plain.jsonl');
  writeFileSync(plainAuth, plainAuthFile());
  writeFileSync(plainAcl, plainAclFile());

  const polled = startBroker([
    '-addr', `127.0.0.1:${SIDE_PORT}`,
    '-auth', plainAuth,
    '-acl', plainAcl,
    '-metrics', `127.0.0.1:${SIDE_METRICS}`,
    '-reload-interval', RELOAD_INTERVAL,
    '-id', 'reload-check-plain',
  ]);
  try {
    await waitListening(polled);
    const base = await metrics(SIDE_BASE);
    const one = await connect(SIDE_URL, { clientId: 'plain-one', username: 'one', password: pw('one') });
    check('the no-TLS broker runs the same rule engine', one.connected && base.tls_cert_generation === 0 && base.tls_cert_cn === '');
    await close(one);

    // An operator pastes a certificate rule into a fleet that has no TLS port.
    // Every device would then be refused, so this rewrite cannot land.
    writeFileSync(plainAuth, plainAuthFile([`{"cert_cn":"${CLIENT_CN}"}`]));
    await waitForMetricOn(SIDE_BASE, 'the certificate rewrite to be refused', (m) => m.rules_reload_failures > base.rules_reload_failures);
    await sleep(TICK_MS * TICKS);
    const still = await metrics(SIDE_BASE);
    const again = await connect(SIDE_URL, { clientId: 'plain-one-2', username: 'one', password: pw('one') });
    check(
      'a rewrite that asks for a certificate on a broker with no TLS port is refused, not installed',
      /no tls listener is configured/.test(polled.log('rules refused')) &&
        still.rules_generation === base.rules_generation &&
        still.rules_reload_failures === base.rules_reload_failures + 1 &&
        again.connected,
      `${polled.log('rules refused') || 'no refusal line'}\n     refusals=${still.rules_reload_failures} generation stayed ${still.rules_generation}`,
    );
    await close(again);
  } finally {
    await killAndWait(polled);
  }

  // -reload-interval 0 hands control to SIGHUP. On a platform that never delivers
  // one that means nothing reloads, which is a decision the operator made and the
  // broker should say out loud rather than look broken.
  const silent = startBroker(['-addr', `127.0.0.1:${SIDE_PORT}`, '-reload-interval', '0', '-id', 'signal-only']);
  try {
    await waitListening(silent);
    check(
      '-reload-interval 0 says reloading is signal-only',
      /msg="rule and certificate reloading is signal-only"/.test(silent.log('signal-only')) && /hint="SIGHUP on unix"/.test(silent.log('signal-only')),
      silent.log('signal-only'),
    );
  } finally {
    await killAndWait(silent);
  }
}

// The side broker has its own metrics address, so the waiter needs one too.
async function waitForMetricOn(base, what, cond, limit = 15000) {
  const started = Date.now();
  for (;;) {
    const m = await metrics(base);
    if (cond(m)) return m;
    if (Date.now() - started > limit) throw new Error(`timed out after ${limit}ms waiting for ${what} (last: ${JSON.stringify(m)})`);
    await sleep(50);
  }
}

const watchdog = setTimeout(() => {
  console.error('\nFAIL  the run exceeded 150s and was aborted');
  rmSync(dir, { recursive: true, force: true });
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
  .finally(() => {
    clearTimeout(watchdog);
    rmSync(dir, { recursive: true, force: true });
    process.exit(process.exitCode ?? 1);
  });
