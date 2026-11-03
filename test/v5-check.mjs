// MQTT 5.0 conformance harness: drives the congmq broker with mqtt.js, an
// independent third-party implementation, and checks the parts of 5.0 that only
// show up on the wire — properties, reason codes, aliases, shared subscriptions.
//
//   node v5-check.mjs
//
// It expects a broker started with the 5.0 knobs it reads from the CONNACK, for
// example:
//
//   congmq -addr 127.0.0.1:1887 -topic-alias-max 4 -max-packet-size 512 \
//          -receive-max 100 -metrics 127.0.0.1:1888
//
// Point MQTT_URL and METRICS_URL at it. Start it without -auth/-acl; the
// authorised paths are covered by rules-check.mjs.
import net from 'node:net';
import { generate, parser as createParser } from 'mqtt-packet';
import mqtt from 'mqtt';

const BROKER_URL = process.env.MQTT_URL ?? 'mqtt://127.0.0.1:1887';
const METRICS_URL = process.env.METRICS_URL ?? 'http://127.0.0.1:1888/metrics';
const results = [];
// Deliberate protocol violations this harness provokes, so the broker's counter
// can be read back and matched rather than merely expected to be clean.
let provoked = 0;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function check(name, ok, detail = '') {
  results.push({ name, ok });
  console.log(`${ok ? 'pass' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n        -> ${detail}`}`);
}

// open connects a 5.0 client and returns it with `msgs` and `packets`, both
// wired before the CONNECT: the broker replays queued messages in the same
// socket read that carries the CONNACK, and a listener attached afterwards
// would have missed them.
async function open(clientId, clean, { holdAcks, will, connectProperties, keepalive = 30 } = {}) {
  const client = mqtt.connect(BROKER_URL, {
    clientId,
    clean,
    protocolVersion: 5,
    keepalive,
    reconnectPeriod: 0, // scenarios need deliberate, not automatic, reconnection
    connectTimeout: 5000,
    properties: connectProperties,
    ...(will ? { will } : {}),
  });

  client.msgs = [];
  client.packets = [];
  client.on('message', (topic, payload, packet) =>
    client.msgs.push({ topic, payload: payload.toString(), qos: packet.qos, retain: packet.retain, props: packet.properties }));
  client.on('packetreceive', (packet) => {
    client.packets.push(packet);
    if (packet.cmd === 'disconnect') client.forced = packet;
  });
  client.on('error', (err) => {
    client.lastError = err;
  });

  // mqtt.js 5 dropped v4's manualAck: the acknowledgement is the callback
  // handed to handleMessage, so overriding that method is the supported way to
  // hold one back.
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

// lastOf returns the most recent received packet of a command, or null.
function lastOf(client, cmd) {
  return [...client.packets].reverse().find((p) => p.cmd === cmd) ?? null;
}

async function waitFor(client, count, ms = 4000) {
  const deadline = Date.now() + ms;
  while (client.msgs.length < count && Date.now() < deadline) await sleep(25);
  return client.msgs;
}

async function expectSilence(client, ms = 1500) {
  const before = client.msgs.length;
  await sleep(ms);
  return client.msgs.length === before ? null : client.msgs[before];
}

// raw5 connects a socket and writes the frames itself with mqtt-packet, the
// codec mqtt.js is built on. It exists for the packets a well-behaved client
// refuses to build - a filter whose '#' sits mid-stream, a topic alias past the
// advertised maximum, No Local on a shared subscription - and those are exactly
// the cases where the broker's answer is a reason code rather than a message.
async function raw5(clientId) {
  const { hostname, port } = new globalThis.URL(BROKER_URL);
  const sock = net.connect(Number(port), hostname);
  await new Promise((resolve, reject) => {
    sock.once('connect', resolve);
    sock.once('error', reject);
  });
  sock.setNoDelay();

  const peer = {
    packets: [],
    // mqtt-packet reads the version from the packet when it writes a CONNECT and
    // from its options for every other frame, so both are pinned to 5.0 here.
    write(cmd, fields = {}) {
      sock.write(generate({ cmd, protocolVersion: 5, ...fields }, { protocolVersion: 5 }));
    },
    async waitFor(cmd, nth = 1, ms = 4000) {
      const deadline = Date.now() + ms;
      while (peer.packets.filter((p) => p.cmd === cmd).length < nth && Date.now() < deadline) {
        await sleep(20);
      }
      return peer.packets.filter((p) => p.cmd === cmd)[nth - 1] ?? null;
    },
    async end() {
      // Give the broker a moment to take the DISCONNECT off the socket before it
      // disappears, so its cleanup is the polite one rather than a lost connection.
      peer.write('disconnect', { reasonCode: 0 });
      await sleep(80);
      sock.destroy();
    },
  };

  const stream = createParser({ protocolVersion: 5 });
  stream.on('packet', (packet) => peer.packets.push(packet));
  stream.on('error', (err) => {
    peer.error = err;
  });
  sock.on('data', (buf) => stream.parse(buf));

  peer.write('connect', { clientId, clean: true, keepalive: 30 });
  await peer.waitFor('connack');
  return peer;
}

async function capabilities() {
  const c = await open('v5-caps', true);
  const p = c.connack.properties ?? {};
  check('CONNACK reason code 0x00 with a 5.0 client', c.connack.reasonCode === 0, String(c.connack.reasonCode));
  check('Receive Maximum is advertised', p.receiveMaximum > 0, JSON.stringify(p.receiveMaximum));
  check('Maximum Packet Size is advertised as configured', p.maximumPacketSize > 0, JSON.stringify(p.maximumPacketSize));
  check('Maximum Topic Alias is advertised as configured', p.topicAliasMaximum === 4, JSON.stringify(p.topicAliasMaximum));
  // Properties the broker may leave out because they are already the protocol
  // default: QoS 2, retained messages, wildcards and shared subscriptions.
  check('Maximum QoS is left out at its default of 2', p.maximumQoS === undefined, JSON.stringify(p.maximumQoS));
  check('subscription identifiers are asserted as available', p.subscriptionIdentifiersAvailable === true,
    JSON.stringify(p.subscriptionIdentifiersAvailable));
  check('defaults are not cluttered into the CONNACK', p.sharedSubscriptionAvailable === undefined &&
    p.wildcardSubscriptionAvailable === undefined, JSON.stringify(p));
  check('a session-expiring connect is required to get a session back',
    !('sessionExpiryInterval' in p), JSON.stringify(p.sessionExpiryInterval));

  const anon = await open('', true);
  check('an empty client id is answered with an assigned one',
    typeof anon.connack.properties?.assignedClientIdentifier === 'string' &&
      anon.connack.properties.assignedClientIdentifier.length > 0,
    JSON.stringify(anon.connack.properties));

  await close(c);
  await close(anon);
}

async function propertyRoundTrip() {
  const sub = await open('v5-props-sub', true);
  await sub.subscribeAsync('v5/props', { qos: 1 });

  const pub = await open('v5-props-pub', true);
  await pub.publishAsync('v5/props', '{"temp":21}', {
    qos: 1,
    properties: {
      contentType: 'application/json',
      payloadFormatIndicator: true,
      messageExpiryInterval: 120,
      responseTopic: 'v5/reply/1',
      correlationData: Buffer.from('req-7'),
      userProperties: { env: 'stage', attempt: '3' },
    },
  });

  await waitFor(sub, 1);
  const p = sub.msgs[0]?.props ?? {};
  check('Content Type survives the broker', p.contentType === 'application/json', JSON.stringify(p.contentType));
  check('Payload Format Indicator survives', p.payloadFormatIndicator === true, JSON.stringify(p.payloadFormatIndicator));
  check('Response Topic and Correlation Data survive',
    p.responseTopic === 'v5/reply/1' && String(p.correlationData) === 'req-7',
    JSON.stringify([p.responseTopic, String(p.correlationData)]));
  check('User Properties survive in order',
    JSON.stringify(p.userProperties) === JSON.stringify({ env: 'stage', attempt: '3' }),
    JSON.stringify(p.userProperties));
  // The specification asks the broker to hand on what is left of the interval,
  // not the publisher's number, so a value that has not decayed at all is
  // acceptable but a bigger one is not.
  check('Message Expiry is forwarded as what remains',
    p.messageExpiryInterval > 0 && p.messageExpiryInterval <= 120, JSON.stringify(p.messageExpiryInterval));

  await pub.publishAsync('v5/props', 'no-expiry', { qos: 1 });
  await waitFor(sub, 2);
  check('a message with no expiry is forwarded without inventing one',
    sub.msgs[1]?.props?.messageExpiryInterval === undefined, JSON.stringify(sub.msgs[1]?.props));

  await close(pub);
  await close(sub);
}

async function subscriptionIdentifier() {
  const sub = await open('v5-sid', true);
  await sub.subscribeAsync('v5/sid/#', { qos: 0, properties: { subscriptionIdentifier: 42 } });

  const pub = await open('v5-sid-pub', true);
  await pub.publishAsync('v5/sid/1', 'stamped', { qos: 0 });

  await waitFor(sub, 1);
  check('Subscription Identifier is echoed on every delivery made through that filter',
    sub.msgs[0]?.props?.subscriptionIdentifier === 42, JSON.stringify(sub.msgs[0]?.props));

  const plain = await open('v5-sid-plain', true);
  await plain.subscribeAsync('v5/sid/#', { qos: 0 });
  await pub.publishAsync('v5/sid/2', 'unstamped', { qos: 0 });
  await waitFor(plain, 1);
  check('a subscriber that did not ask is not stamped',
    plain.msgs[0]?.props?.subscriptionIdentifier === undefined, JSON.stringify(plain.msgs[0]?.props));

  await close(plain);
  await close(pub);
  await close(sub);
}

async function retainedAndHandling() {
  const pub = await open('v5-ret-pub', true);
  await pub.publishAsync('v5/ret/lamp', 'on', { qos: 1, retain: true });

  const late = await open('v5-ret-late', true);
  await late.subscribeAsync('v5/ret/#', { qos: 1 });
  await waitFor(late, 1);
  check('a new subscriber gets the retained message',
    late.msgs[0]?.payload === 'on' && late.msgs[0]?.topic === 'v5/ret/lamp', JSON.stringify(late.msgs[0]));
  check('the replay arrives with the RETAIN flag set', late.msgs[0]?.retain === true, JSON.stringify(late.msgs[0]?.retain));

  const skip = await open('v5-ret-skip', true);
  await skip.subscribeAsync('v5/ret/#', { qos: 1, rh: 2 });
  check('Retain Handling 2 asks for no retained messages', (await expectSilence(skip)) === null);

  const live = await open('v5-ret-live', true);
  await live.subscribeAsync('v5/ret/#', { qos: 1 });
  await pub.publishAsync('v5/ret/lamp', 'dim', { qos: 1, retain: true });
  await waitFor(live, 2);
  check('a subscriber present at publish time is not told RETAIN',
    live.msgs[1]?.retain === false, JSON.stringify(live.msgs[1]));

  const rap = await open('v5-ret-rap', true);
  await rap.subscribeAsync('v5/ret/#', { qos: 1, rap: true });
  await pub.publishAsync('v5/ret/lamp', 'bright', { qos: 1, retain: true });
  await waitFor(rap, 2);
  check('Retain As Published keeps the flag onward', rap.msgs[1]?.retain === true, JSON.stringify(rap.msgs[1]));

  await pub.publishAsync('v5/ret/lamp', '', { qos: 1, retain: true });
  const gone = await open('v5-ret-gone', true);
  await gone.subscribeAsync('v5/ret/lamp', { qos: 1 });
  check('an empty retained publish clears the stored message', (await expectSilence(gone)) === null);

  await close(gone);
  await close(rap);
  await close(live);
  await close(skip);
  await close(late);
  await close(pub);
}

async function noLocalAndAlias() {
  const echo = await open('v5-nl', true);
  await echo.subscribeAsync('v5/nl/#', { qos: 0, nl: true });
  const friend = await open('v5-nl-friend', true);
  await friend.subscribeAsync('v5/nl/#', { qos: 0 });

  // Both messages must reach `friend`; only the second is echo's own, and that
  // is the difference No Local draws. Publishing from a third client would
  // prove nothing, so the subscription owner sends one itself.
  const pub = await open('v5-nl-pub', true);
  await pub.publishAsync('v5/nl/a', 'from-elsewhere', { qos: 0 });
  await waitFor(friend, 1);
  await echo.publishAsync('v5/nl/b', 'mine', { qos: 0 });
  await waitFor(friend, 2);
  check("No Local spares the publisher its own message",
    echo.msgs.map((m) => m.payload).join(',') === 'from-elsewhere', JSON.stringify(echo.msgs));
  check('No Local hides nothing from the other subscribers',
    friend.msgs.map((m) => m.payload).join(',') === 'from-elsewhere,mine', JSON.stringify(friend.msgs));

  // A client that advertises four alias slots must not be given a fifth, and an
  // aliased repeat may drop the topic name because the peer mapped it earlier.
  const aliased = await open('v5-alias', true, { connectProperties: { topicAliasMaximum: 4 } });
  await aliased.subscribeAsync('v5/alias/#', { qos: 0 });
  const aliasPub = await open('v5-alias-pub', true);
  for (let i = 1; i <= 3; i++) {
    await aliasPub.publishAsync('v5/alias/one', `n${i}`, { qos: 0 });
  }
  await aliasPub.publishAsync('v5/alias/two', 'other', { qos: 0 });
  await waitFor(aliased, 4);
  const seen = aliased.msgs.map((m) => m.props?.topicAlias);
  check('the broker uses a topic alias within the client’s maximum',
    seen.slice(0, 3).every((a) => a >= 1 && a <= 4) && new Set(seen.slice(0, 3)).size === 1,
    JSON.stringify(seen));
  check('every aliased delivery still carries its payload',
    aliased.msgs.map((m) => m.payload).join(',') === 'n1,n2,n3,other',
    JSON.stringify(aliased.msgs.map((m) => m.payload)));
  check('one topic name keeps one alias number across repeats',
    aliased.msgs[3].props?.topicAlias === undefined || aliased.msgs[3].props.topicAlias !== seen[0],
    JSON.stringify([seen[0], aliased.msgs[3].props?.topicAlias]));

  await close(aliasPub);
  await close(aliased);
  await close(pub);
  await close(friend);
  await close(echo);
}

async function sharedSubscriptions() {
  const a = await open('v5-share-a', true);
  await a.subscribeAsync('$share/workers/v5/shared/#', { qos: 1 });
  const b = await open('v5-share-b', true);
  await b.subscribeAsync('$share/workers/v5/shared/#', { qos: 1 });
  const watcher = await open('v5-share-watch', true);
  await watcher.subscribeAsync('v5/shared/#', { qos: 1 });

  const pub = await open('v5-share-pub', true);
  for (let i = 1; i <= 4; i++) {
    await pub.publishAsync('v5/shared/1', `job-${i}`, { qos: 1 });
  }

  await waitFor(a, 2);
  await waitFor(b, 2);
  await waitFor(watcher, 4);
  check('a shared subscription sends each message to one member only',
    a.msgs.length === 2 && b.msgs.length === 2, `${a.msgs.length} and ${b.msgs.length}`);
  const split = [...a.msgs, ...b.msgs].map((m) => m.payload).sort().join(',');
  check('together the group covers the queue exactly once',
    split === 'job-1,job-2,job-3,job-4', split);
  check('the delivery carries the published topic, not the shared filter',
    a.msgs.every((m) => m.topic === 'v5/shared/1'), JSON.stringify(a.msgs.map((m) => m.topic)));
  check('an ordinary subscription to the same topics still sees everything',
    watcher.msgs.length === 4, JSON.stringify(watcher.msgs.map((m) => m.payload)));

  await close(pub);
  await close(watcher);
  await close(b);
  await close(a);
}

async function sessionsAndReasons() {
  const id = 'v5-durable';
  const first = await open(id, false, { connectProperties: { sessionExpiryInterval: 3600 } });
  check('a 5.0 connect with an expiry reports no session on a fresh broker',
    first.connack.reasonCode === 0 && first.connack.sessionPresent === false,
    JSON.stringify({ r: first.connack.reasonCode, s: first.connack.sessionPresent }));
  await first.subscribeAsync('v5/durable/#', { qos: 1 });
  await close(first);

  const pub = await open('v5-durable-pub', true);
  for (let i = 1; i <= 2; i++) {
    await pub.publishAsync(`v5/durable/${i}`, `stored-${i}`, { qos: 1 });
  }

  await pub.publishAsync('v5/nobody/listens', 'dropped', { qos: 1 });
  check('a QoS 1 publish to nothing is answered 0x10, not 0x00',
    lastOf(pub, 'puback')?.reasonCode === 0x10, JSON.stringify(lastOf(pub, 'puback')?.reasonCode));

  const back = await open(id, false, { connectProperties: { sessionExpiryInterval: 3600 } });
  check('reconnecting within the session expiry resumes it', back.connack.sessionPresent === true,
    JSON.stringify(back.connack));
  await waitFor(back, 2);
  check('the messages queued while away are replayed in order',
    back.msgs.map((m) => m.payload).join(',') === 'stored-1,stored-2',
    JSON.stringify(back.msgs.map((m) => m.payload)));

  // Clean Start throws the stored session away, which the CONNACK must say.
  const restarted = await open(id, true);
  check('Clean Start discards the session and says so', restarted.connack.sessionPresent === false,
    JSON.stringify(restarted.connack));
  check('a discarded session replays nothing', (await expectSilence(restarted)) === null);

  await close(restarted);
  await close(back);
  await close(pub);
}

async function serverDisconnects() {
  const old = await open('v5-takeover', true);
  const fresh = await open('v5-takeover', true);
  await sleep(400);
  check('session takeover announces 0x8E to the connection it replaced',
    old.forced?.reasonCode === 0x8e, JSON.stringify(old.forced?.reasonCode));

  const size = old.connack.properties?.maximumPacketSize ?? 0;
  if (size > 0) {
    const fat = await open('v5-size', true);
    // mqtt.js refuses to build an oversized packet itself, which is the client
    // keeping its side of the promise; the broker's answer is what is measured.
    let errored = null;
    try {
      await fat.publishAsync('v5/fat', 'x'.repeat(size + 64), { qos: 0 });
    } catch (err) {
      errored = err;
    }
    await sleep(400);
    check('an oversized publish is refused with 0x95 or client-side first',
      fat.forced?.reasonCode === 0x95 || errored !== null,
      `disconnect=${fat.forced?.reasonCode} clientError=${errored?.message}`);
    await close(fat);
  } else {
    console.log('skip  maximum packet size (the broker advertises no limit)');
  }

  await close(fresh);
  await close(old);
}

// rawVerdicts asks the broker about the frames a friendly client will not send.
// Each one is a deliberate violation, counted so that the metrics endpoint can be
// read back against it.
async function rawVerdicts() {
  const filter = await raw5('v5-raw-filter');
  filter.write('subscribe', { messageId: 1, subscriptions: [{ topic: 'v5/bad/#/trailing', qos: 1 }] });
  const refused = await filter.waitFor('suback');
  check('a filter with a mid-level "#" is refused with 0x8F',
    refused?.granted?.length === 1 && refused.granted[0] === 0x8f, JSON.stringify(refused?.granted));

  // Refusing one filter is not fatal, so the same connection still has a future.
  filter.write('subscribe', { messageId: 2, subscriptions: [{ topic: 'v5/raw/ok', qos: 1 }] });
  const granted = await filter.waitFor('suback', 2);
  check('a refused filter leaves the connection usable', granted?.granted?.[0] === 1,
    JSON.stringify(granted?.granted));
  filter.write('publish', { topic: 'v5/raw/ok', payload: Buffer.from('round trip'), messageId: 3, qos: 1 });
  const ack = await filter.waitFor('puback');
  check('and still answers its QoS 1 publishes with 0x00',
    ack?.messageId === 3 && ack?.reasonCode === 0, JSON.stringify(ack && { id: ack.messageId, code: ack.reasonCode }));
  await filter.end();

  // Four alias slots were advertised; a fifth is the broker's business.
  const alias = await raw5('v5-raw-alias');
  alias.write('publish', { topic: 'v5/raw/alias', payload: Buffer.from('x'), properties: { topicAlias: 99 } });
  provoked++;
  const aliasKick = await alias.waitFor('disconnect');
  check('an alias past the advertised maximum is answered 0x94, not a generic 0x82',
    aliasKick?.reasonCode === 0x94, JSON.stringify(aliasKick?.reasonCode));
  await alias.end();

  // [MQTT-3.8.3-4] calls No Local on a shared subscription a Protocol Error, so
  // the answer is a DISCONNECT rather than a SUBACK that declines the filter.
  const shared = await raw5('v5-raw-shared');
  shared.write('subscribe', {
    messageId: 1,
    subscriptions: [{ topic: '$share/g/v5/raw/#', qos: 1, nl: true }],
  });
  provoked++;
  const nlKick = await shared.waitFor('disconnect');
  check('No Local on a shared subscription breaks the connection with 0x82',
    nlKick?.reasonCode === 0x82, JSON.stringify(nlKick?.reasonCode));
  await shared.end();
}

async function metricsEndpoint() {
  try {
    const res = await fetch(METRICS_URL);
    const m = await res.json();
    check('GET /metrics answers JSON', res.ok && typeof m === 'object' && m.id, String(res.status));
    check('the counters moved while this harness ran',
      m.messages_in > 10 && m.messages_out > 10, JSON.stringify({ in: m.messages_in, out: m.messages_out }));
    check('retained messages are counted', m.retained_messages >= 0, String(m.retained_messages));
    check('server-initiated disconnects are counted', m.server_disconnects >= 1, String(m.server_disconnects));
    check('only the violations this harness provoked reached the protocol-error counter',
      m.malformed_packets === 0 && m.protocol_errors === provoked,
      JSON.stringify({ malformed: m.malformed_packets, protocol: m.protocol_errors, provoked }));
  } catch (err) {
    check('metrics endpoint reachable', false, String(err?.message ?? err));
  }
}

const scenarios = [
  ['what the broker advertises', capabilities],
  ['properties carried across the broker', propertyRoundTrip],
  ['subscription identifiers', subscriptionIdentifier],
  ['retained messages and Retain Handling', retainedAndHandling],
  ['No Local and topic aliases', noLocalAndAlias],
  ['shared subscriptions', sharedSubscriptions],
  ['sessions, expiry and reason codes', sessionsAndReasons],
  ['server-side disconnects', serverDisconnects],
  ['the broker’s own verdicts on frames a polite client will not send', rawVerdicts],
  ['the metrics endpoint', metricsEndpoint],
];

console.log(`congmq MQTT 5.0 conformance: ${BROKER_URL} (client: mqtt.js ${mqtt.version ?? '5.x'})\n`);
const watchdog = setTimeout(() => {
  console.error('\nharness timed out');
  process.exit(1);
}, 120000);
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
