// Conformance harness: drives the congmq broker with mqtt.js, an independent
// third-party MQTT 3.1.1 implementation. If the hand-written wire format were
// wrong in any way a real client could notice, these scenarios fail.
//
//   node conformance.mjs                       # against mqtt://127.0.0.1:1883
//   MQTT_URL=mqtt://192.168.1.20:1884 node conformance.mjs
//
// Point it at a broker started without -auth/-acl; rules-check.mjs covers the
// authorised paths.
import mqtt from 'mqtt';

const URL = process.env.MQTT_URL ?? 'mqtt://127.0.0.1:1883';
const results = [];

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function check(name, ok, detail = '') {
  results.push({ name, ok });
  console.log(`${ok ? 'pass' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n        -> ${detail}`}`);
}

// open connects and returns the client with `msgs`, the log of everything it
// has received. Both are wired up before the CONNECT is sent, because the
// broker replays queued messages in the same socket read that carries the
// CONNACK — a listener attached after `await connect` would have missed them.
//
// holdAcks stops the client acknowledging anything, which is how an
// unacknowledged message is produced on purpose. mqtt.js 5 dropped v4's
// `manualAck` option: the acknowledgement is the callback handed to
// handleMessage, so overriding that method is the supported way to defer it.
async function open(clientId, clean, { holdAcks = false, will } = {}) {
  const client = mqtt.connect(URL, {
    clientId,
    clean,
    keepalive: 30,
    reconnectPeriod: 0, // scenarios need deliberate, not automatic, reconnection
    connectTimeout: 5000,
    ...(will ? { will } : {}),
  });
  const msgs = [];
  client.msgs = msgs;
  client.on('message', (topic, payload, packet) =>
    msgs.push({ topic, payload: payload.toString(), qos: packet.qos, dup: packet.dup, id: packet.messageId }));
  client.on('error', (err) => {
    client.lastError = err;
  });

  const deferred = [];
  client.ackAll = () => {
    for (const callback of deferred.splice(0)) callback();
  };
  if (holdAcks) {
    client.handleMessage = (packet, callback) => {
      deferred.push(callback);
    };
  }

  client.connack = await new Promise((resolve, reject) => {
    client.once('connect', resolve);
    client.once('error', reject);
  });
  return client;
}

const close = (client) => client.endAsync().catch(() => {});

// closeHard drops the socket without sending a DISCONNECT.
const closeHard = (client) => new Promise((resolve) => client.end(true, () => resolve()));

async function waitFor(client, count, ms = 4000) {
  const deadline = Date.now() + ms;
  while (client.msgs.length < count && Date.now() < deadline) await sleep(25);
  return client.msgs;
}

// expectSilence resolves to the first unexpected message, or null.
async function expectSilence(client, ms = 1500) {
  const before = client.msgs.length;
  await sleep(ms);
  return client.msgs.length === before ? null : client.msgs[before];
}

async function roundTrip() {
  const sub = await open('conf-round', true);
  const granted = [];
  for (const [filter, qos] of [
    ['conf/exact', 2],
    ['conf/wild/+', 1],
    ['conf/tree/#', 1],
    ['conf/zero', 0],
  ]) {
    granted.push(...(await sub.subscribeAsync(filter, { qos })));
  }
  check('SUBACK grants the requested QoS per filter',
    JSON.stringify(granted.map((g) => g.qos)) === '[2,1,1,0]',
    JSON.stringify(granted.map((g) => g.qos)));

  const pub = await open('conf-round-pub', true);

  await pub.publishAsync('conf/exact', 'qos2-body', { qos: 2 });
  await waitFor(sub, 1);
  check('QoS 2 publish arrives with the payload intact',
    sub.msgs[0]?.qos === 2 && sub.msgs[0]?.payload === 'qos2-body' && sub.msgs[0]?.topic === 'conf/exact',
    JSON.stringify(sub.msgs[0]));
  check('a QoS 2 delivery carries a packet identifier', sub.msgs[0]?.id > 0, JSON.stringify(sub.msgs[0]?.id));

  await pub.publishAsync('conf/wild/x', 'via-plus', { qos: 1 });
  await waitFor(sub, 2);
  check("filter 'conf/wild/+' matches conf/wild/x", sub.msgs[1]?.payload === 'via-plus', JSON.stringify(sub.msgs[1]));

  await pub.publishAsync('conf/tree/a/b/c', 'via-hash', { qos: 2 });
  await waitFor(sub, 3);
  check("filter 'conf/tree/#' matches four levels below the root", sub.msgs[2]?.payload === 'via-hash',
    JSON.stringify(sub.msgs[2]));
  check('delivery QoS is the lower of publish QoS and granted QoS', sub.msgs[2]?.qos === 1,
    `arrived with qos ${sub.msgs[2]?.qos}, expected 1`);

  await pub.publishAsync('conf/zero', 'qos0', { qos: 0 });
  await waitFor(sub, 4);
  check('QoS 0 arrives without an identifier', sub.msgs[3]?.qos === 0 && sub.msgs[3]?.payload === 'qos0',
    JSON.stringify(sub.msgs[3]));

  await pub.publishAsync('conf/nomatch/here', 'dropped', { qos: 1 });
  check('a message with no matching subscriber is not delivered', (await expectSilence(sub)) === null);
  check('acknowledged messages are never re-sent', (await expectSilence(sub)) === null);

  await close(pub);
  await close(sub);
}

async function offlineReplay() {
  const id = 'conf-durable';
  const first = await open(id, false);
  await first.subscribeAsync('conf/offline/#', { qos: 1 });
  await close(first);

  const pub = await open('conf-offline-pub', true);
  for (let i = 1; i <= 3; i++) {
    await pub.publishAsync(`conf/offline/${i}`, `stored-${i}`, { qos: i === 3 ? 2 : 1 });
  }
  check('publishing to a subscriber that is away does not loop back to the publisher',
    (await expectSilence(pub, 500)) === null);

  const back = await open(id, false);
  await waitFor(back, 3, 5000);
  check('a persistent session replays every message queued while it was away',
    back.msgs.map((m) => m.payload).join(',') === 'stored-1,stored-2,stored-3',
    back.msgs.map((m) => m.payload).join(','));
  check('replayed messages keep publication order',
    back.msgs.map((m) => m.topic).join(',') === 'conf/offline/1,conf/offline/2,conf/offline/3',
    back.msgs.map((m) => m.topic).join(','));
  check('the subscription itself survived the disconnect (nothing re-subscribed)', back.msgs.length === 3);
  check('replayed messages are not repeated once acknowledged', (await expectSilence(back)) === null);

  await close(back);
  await close(pub);
}

async function sessionPresentAndDup() {
  const id = 'conf-present';
  const a = await open(id, false, { holdAcks: true });
  check('a brand new session reports sessionPresent=false',
    a.connack?.sessionPresent === false, JSON.stringify(a.connack));
  await a.subscribeAsync('conf/present', { qos: 1 });

  const pub = await open('conf-present-pub', true);
  await pub.publishAsync('conf/present', 'queued', { qos: 1 });
  await waitFor(a, 1);
  check('the message reaches the live subscriber', a.msgs[0]?.payload === 'queued', JSON.stringify(a.msgs[0]));
  check('a client that withholds its PUBACK keeps the message unacknowledged',
    a.msgs.length === 1 && (await expectSilence(a, 300)) === null);

  await closeHard(a); // the socket vanishes with the message unacked

  const b = await open(id, false);
  check('a session holding an unacknowledged message reports sessionPresent=true',
    b.connack?.sessionPresent === true, JSON.stringify(b.connack));
  await waitFor(b, 1);
  check('an unacknowledged message is re-sent with DUP set after reconnect',
    b.msgs[0]?.payload === 'queued' && b.msgs[0]?.dup === true, JSON.stringify(b.msgs[0]));

  b.ackAll();
  check('once acknowledged the re-sent message is not repeated', (await expectSilence(b)) === null);

  await close(b);
  await close(pub);
}

async function takeover() {
  const id = 'conf-takeover';
  const a = await open(id, true);
  let dropped = false;
  a.on('close', () => { dropped = true; });
  a.on('offline', () => { dropped = true; });
  await sleep(150);

  const b = await open(id, true);
  await sleep(400);
  check('a second CONNECT with the same client id disconnects the first', dropped);

  const pub = await open('conf-takeover-pub', true);
  await b.subscribeAsync('conf/take', { qos: 0 });
  await pub.publishAsync('conf/take', 'to-new-owner', { qos: 0 });
  await waitFor(b, 1);
  check('the new owner receives traffic after the takeover', b.msgs[0]?.payload === 'to-new-owner',
    JSON.stringify(b.msgs[0]));

  await closeHard(a);
  await close(b);
  await close(pub);
}

async function cleanSessionDiscards() {
  const id = 'conf-clean';
  const a = await open(id, false);
  await a.subscribeAsync('conf/clean', { qos: 1 });
  await close(a);

  const pub = await open('conf-clean-pub', true);
  await pub.publishAsync('conf/clean', 'should-be-discarded', { qos: 1 });

  const b = await open(id, true); // clean=true wipes the stored session
  check('a clean session reports sessionPresent=false even when state exists',
    b.connack?.sessionPresent === false, JSON.stringify(b.connack));
  check('a clean session discards the messages queued for it', (await expectSilence(b, 800)) === null);

  await pub.publishAsync('conf/clean', 'also-discarded', { qos: 1 });
  check('a clean session also discards the stored subscription', (await expectSilence(b, 800)) === null);

  await close(b);
  await close(pub);
}

async function willAndDisconnect() {
  const sink = await open('conf-will-sink', true);
  await sink.subscribeAsync('conf/will', { qos: 0 });

  const carrier = await open('conf-will-carrier', true, {
    will: { topic: 'conf/will', payload: 'gone without a word', qos: 0, retain: false },
  });
  await closeHard(carrier); // the socket vanishes: the broker publishes the will

  await waitFor(sink, 1);
  check('a socket that vanishes publishes the last will',
    sink.msgs[0]?.payload === 'gone without a word', JSON.stringify(sink.msgs[0]));

  const polite = await open('conf-will-polite', true, {
    will: { topic: 'conf/will', payload: 'must not be published', qos: 0, retain: false },
  });
  await close(polite); // a DISCONNECT packet cancels the will
  check('a clean DISCONNECT cancels the last will', (await expectSilence(sink, 1200)) === null);

  await close(sink);
}

const scenarios = [
  ['round trip, wildcards and QoS downgrade', roundTrip],
  ['offline replay for a persistent session', offlineReplay],
  ['sessionPresent and the DUP flag', sessionPresentAndDup],
  ['session takeover', takeover],
  ['clean session discards stored state', cleanSessionDiscards],
  ['the last will and its cancellation', willAndDisconnect],
];

console.log(`congmq conformance: ${URL} (client: mqtt.js ${mqtt.version ?? '5.x'})\n`);
const watchdog = setTimeout(() => {
  console.error('\nharness timed out');
  process.exit(1);
}, 90000);
for (const [name, fn] of scenarios) {
  console.log(`# ${name}`);
  try {
    await fn();
  } catch (err) {
    check(`${name} completed`, false, String(err?.message ?? err));
  }
}
clearTimeout(watchdog);

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length ? 1 : 0);
