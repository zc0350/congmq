// Capacity baseline harness. It starts a real broker per row, drives it with
// bin/congmq-load (which speaks MQTT through internal/packets, the same codec
// the server uses, so no third-party client can be blamed for a number), and
// turns the JSON reports into markdown tables.
//
//   node load-baseline.mjs
//   node load-baseline.mjs --groups=pump,fsync --seconds=15
//   node load-baseline.mjs --groups=tls --seconds=20   # the plain/TLS pair
//   node load-baseline.mjs --groups=gate               # the per-address gate, armed and off
//   node load-baseline.mjs --groups=proxy              # the transport header, and the gate behind it
//   CONGMQ_BIN=... CONGMQ_LOAD_BIN=... node load-baseline.mjs --out=baseline.md
//
// Every row gets its own broker, its own ports and its own -store directory:
// a shared process would carry memory, counters and durable state from the
// previous row into the next, and the tables would describe the sequence rather
// than the load.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { cpus, totalmem, platform, release, arch, tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const EXE = process.platform === 'win32' ? '.exe' : '';
const BIN = process.env.CONGMQ_BIN ?? fileURLToPath(new URL(`../bin/congmq${EXE}`, import.meta.url));
const LOADER = process.env.CONGMQ_LOAD_BIN ?? fileURLToPath(new URL(`../bin/congmq-load${EXE}`, import.meta.url));
const PORT = Number(process.env.CONGMQ_PORT ?? 1901);
const TLSPORT = Number(process.env.CONGMQ_TLS_PORT ?? 1903);
const METRICS_PORT = Number(process.env.CONGMQ_METRICS_PORT ?? 1902);
const METRICS_URL = `http://127.0.0.1:${METRICS_PORT}/metrics`;
const CERT_BIN = process.env.CONGMQ_CERT_BIN ?? fileURLToPath(new URL(`../bin/congmq-cert${EXE}`, import.meta.url));

const argv = Object.fromEntries(
  process.argv.slice(2).map((a) => {
    const [, k, v] = a.match(/^--([^=]+)(?:=(.*))?$/) ?? ['', a.replace(/^--/, ''), ''];
    return [k, v];
  }),
);
const SECONDS = Number(argv.seconds ?? process.env.CONGMQ_LOAD_SECONDS ?? 10);
const GROUPS = (argv.groups ?? 'conns,gate,proxy,pump,payload,fanout,fsync,tls').split(',').map((g) => g.trim());
const OUT = argv.out ?? `baseline-${new Date().toISOString().slice(0, 10)}.md`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const num = (v) => (typeof v === 'number' ? v : 0);
const mib = (bytes) => (num(bytes) / 1048576).toFixed(1);
const kilo = (bytes) => (num(bytes) / 1024).toFixed(1);
const comma = (n) => Math.round(num(n)).toLocaleString('en-US');

// ---------------------------------------------------------------- broker ----

// pki is the directory holding the chain the TLS rows run against. It is minted
// by congmq-cert, the same tool an operator would use, so the measured cost
// includes a real certificate rather than a benchmark-only one.
let pki = null;

function genPKI() {
  const dir = mkdtempSync(join(tmpdir(), 'congmq-baseline-pki-'));
  return new Promise((resolve, reject) => {
    const proc = spawn(CERT_BIN, ['-out', dir, '-days', '30'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let err = '';
    proc.stderr.on('data', (b) => (err += b));
    proc.once('error', reject);
    proc.once('exit', (code) =>
      code === 0 ? resolve(dir) : reject(new Error(`congmq-cert exited ${code}: ${err.trim()}`)),
    );
  });
}

async function startBroker({ sync, store, queueMax = 1000, tls = false, extra = [] }) {
  const args = [
    '-addr', `127.0.0.1:${PORT}`,
    '-metrics', `127.0.0.1:${METRICS_PORT}`,
    '-store', store,
    '-store-sync', sync,
    '-store-flush-interval', '1s',
    '-queue-max', String(queueMax),
    ...extra,
  ];
  if (tls) {
    args.push('-tls-addr', `127.0.0.1:${TLSPORT}`, '-tls-cert', join(pki, 'server.crt'), '-tls-key', join(pki, 'server.key'));
  }
  const proc = spawn(BIN, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  const handle = { proc, args, lines: [] };
  const onData = (b) => handle.lines.push(...b.toString().split(/\r?\n/).filter(Boolean));
  proc.stderr.on('data', onData);
  proc.stdout.on('data', onData);
  handle.log = (needle) => handle.lines.find((l) => l.includes(needle)) ?? '';
  handle.metrics = async () => (await fetch(METRICS_URL)).json();
  handle.stateBytes = () => {
    try {
      return statSync(join(store, 'state.log')).size;
    } catch {
      return 0;
    }
  };
  handle.stop = async () => {
    // Windows cannot deliver a signal the broker could trap, so this is a kill;
    // the caller waits out the flush interval first, which is the difference
    // between measuring the promised state and measuring a crash.
    proc.kill('SIGKILL');
    await new Promise((r) => proc.once('exit', r));
  };
  // Listening is the readiness signal, not the port being open: Serve replays
  // the store and re-registers sessions before it accepts a connection, so a
  // probe that only got a TCP handshake would race the restore. This is why the
  // broker keeps its default info log level here.
  const started = Date.now();
  for (;;) {
    if (handle.log('msg=listening')) return handle;
    if (proc.exitCode !== null) throw new Error(`broker died at startup:\n${handle.lines.join('\n')}`);
    if (Date.now() - started > 15000) {
      await handle.stop().catch(() => {});
      throw new Error(`broker did not come up within 15s:\n${handle.lines.join('\n')}`);
    }
    await sleep(50);
  }
}

async function runLoader(extra, { tls = false } = {}) {
  const args = ['-addr', `127.0.0.1:${tls ? TLSPORT : PORT}`, '-metrics', METRICS_URL];
  if (tls) {
    // Server authentication only: the client verifies the broker's chain and the
    // broker asks for nothing in return, which is the MQTTS shape most fleets
    // start with and the one that makes this row comparable to the plain one.
    args.push('-tls', '-tls-ca', join(pki, 'ca.crt'));
  }
  args.push(...extra);
  const proc = spawn(LOADER, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  let err = '';
  proc.stdout.on('data', (b) => (out += b));
  proc.stderr.on('data', (b) => {
    const text = b.toString().replace(/\r/g, '');
    err += text;
    for (const line of text.split('\n')) if (line.trim()) process.stdout.write(`    ${line.trim()}\n`);
  });
  // A loader that cannot finish is a bug in the loader, not a slow row: giving up
  // leaves the broker holding thousands of connections for the next row.
  const limit = (Number(extra[extra.indexOf('-seconds') + 1]) || SECONDS) + 120;
  let timer;
  const code = await Promise.race([
    new Promise((r) => proc.once('close', r)),
    new Promise((r) => (timer = setTimeout(() => r('timeout'), limit * 1000))),
  ]).finally(() => clearTimeout(timer));
  if (code === 'timeout') {
    proc.kill('SIGKILL');
    throw new Error(`loader exceeded ${limit}s: ${err.slice(-300)}`);
  }
  if (code !== 0) throw new Error(`loader exited ${code}: ${err.slice(0, 400) || out.slice(0, 400)}`);
  return JSON.parse(out);
}

// Windows keeps a directory unremovable while any process still holds a handle
// inside it, which is exactly the moment right after the broker was killed.
async function removeDir(dir) {
  for (let i = 0; i < 10; i++) {
    try {
      rmSync(dir, { recursive: true, force: true });
      return;
    } catch (e) {
      if (e.code !== 'EPERM' && e.code !== 'EBUSY') throw e;
      await sleep(300);
    }
  }
  console.log(`  (left ${dir} behind: still locked)`);
}

// ------------------------------------------------------------------ rows ----

const PUBSUB = ['-publishers', '8', '-subscribers', '8', '-window', '100'];

// The gate rows stay at 3,000 connections on purpose. Windows hands one
// ephemeral port to every dial and holds it in TIME_WAIT afterwards, so a second
// 10,000-connection row on the same box fails to dial at all — and a row whose
// sockets never reached the broker measures nothing, gate counters prove it.
const GATE_CONNS = 3000;

// The two rows that put a cap on the table stay at 1,000 because the point is the
// arithmetic: a 600 limit and two claimed addresses is a 1,200-address-headroom
// broker, so every connection must be held. With one socket address the same
// broker holds 600 and turns 400 away, and that difference is the feature.
const PROXY_GATE_CONNS = 1000;

const rows = [
  ...GROUPS.includes('conns')
    ? [1000, 5000, 10000].map((n) => ({
        group: 'conns',
        n,
        label: `${comma(n)} 空闲长连接`,
        sync: 'everysec',
        loader: ['-mode', 'conns', '-conns', String(n), '-proto', '5', '-seconds', String(SECONDS)],
      }))
    : [],
  ...GROUPS.includes('gate')
    ? [
        {
          group: 'gate',
          label: `${comma(GATE_CONNS)} 建连 · 闸门全关（默认）`,
          sync: 'everysec',
          loader: ['-mode', 'conns', '-conns', String(GATE_CONNS), '-proto', '5', '-seconds', String(SECONDS)],
        },
        {
          group: 'gate',
          label: `${comma(GATE_CONNS)} 建连 · 闸门开着但一个都没卡`,
          sync: 'everysec',
          // Everything armed, nothing binding: the cost of the meter itself, with
          // the counters as the proof that no connection was turned away.
          brokerArgs: ['-max-conns-per-ip', '20000', '-conn-rate-per-ip', '20000', '-conn-burst-per-ip', '20000'],
          loader: ['-mode', 'conns', '-conns', String(GATE_CONNS), '-proto', '5', '-seconds', String(SECONDS)],
        },
        {
          group: 'gate',
          label: `${comma(GATE_CONNS)} 建连 · -max-conns-per-ip 500`,
          sync: 'everysec',
          brokerArgs: ['-max-conns-per-ip', '500'],
          loader: ['-mode', 'conns', '-conns', String(GATE_CONNS), '-proto', '5', '-seconds', String(SECONDS)],
        },
        {
          group: 'gate',
          label: `${comma(GATE_CONNS)} 建连 · -conn-rate-per-ip 300`,
          sync: 'everysec',
          brokerArgs: ['-conn-rate-per-ip', '300', '-conn-burst-per-ip', '300'],
          loader: ['-mode', 'conns', '-conns', String(GATE_CONNS), '-proto', '5', '-seconds', String(SECONDS)],
        },
      ]
    : [],
  // The first four rows differ in one thing: what the broker was told to read in
  // front of the payload, and what the loader therefore had to write. The last two
  // are the reason the feature exists at all — the same per-address cap, once with
  // the device addresses the header claims and once without, and the difference is
  // how many of a thousand connections the broker is willing to hold.
  ...GROUPS.includes('proxy')
    ? [
        {
          group: 'proxy',
          label: `${comma(GATE_CONNS)} 长连接 · 头部 off（默认）`,
          sync: 'everysec',
          loader: ['-mode', 'conns', '-conns', String(GATE_CONNS), '-proto', '5', '-seconds', String(SECONDS)],
        },
        {
          group: 'proxy',
          label: `${comma(GATE_CONNS)} 长连接 · require + v1 文本`,
          sync: 'everysec',
          brokerArgs: ['-proxy-protocol', 'require'],
          loader: ['-mode', 'conns', '-conns', String(GATE_CONNS), '-proto', '5', '-seconds', String(SECONDS), '-proxy-header', 'v1'],
        },
        {
          group: 'proxy',
          label: `${comma(GATE_CONNS)} 长连接 · require + v2 二进制`,
          sync: 'everysec',
          brokerArgs: ['-proxy-protocol', 'require'],
          loader: ['-mode', 'conns', '-conns', String(GATE_CONNS), '-proto', '5', '-seconds', String(SECONDS), '-proxy-header', 'v2'],
        },
        {
          group: 'proxy',
          label: `${comma(GATE_CONNS)} 长连接 · trusted + v1（名单 127.0.0.0/8）`,
          sync: 'everysec',
          brokerArgs: ['-proxy-protocol', 'trusted', '-trusted-proxy-cidr', '127.0.0.0/8'],
          loader: ['-mode', 'conns', '-conns', String(GATE_CONNS), '-proto', '5', '-seconds', String(SECONDS), '-proxy-header', 'v1'],
        },
        {
          group: 'proxy',
          label: `${comma(PROXY_GATE_CONNS)} 长连接 · 闸门 600 + 两个申报地址（require + v1）`,
          sync: 'everysec',
          brokerArgs: ['-proxy-protocol', 'require', '-max-conns-per-ip', '600'],
          loader: ['-mode', 'conns', '-conns', String(PROXY_GATE_CONNS), '-proto', '5', '-seconds', String(SECONDS),
            '-proxy-header', 'v1', '-proxy-src', '203.0.113.7,198.51.100.9'],
        },
        {
          group: 'proxy',
          label: `${comma(PROXY_GATE_CONNS)} 长连接 · 同一闸门、头部 off（对照）`,
          sync: 'everysec',
          brokerArgs: ['-max-conns-per-ip', '600'],
          loader: ['-mode', 'conns', '-conns', String(PROXY_GATE_CONNS), '-proto', '5', '-seconds', String(SECONDS)],
        },
      ]
    : [],
  ...GROUPS.includes('pump')
    ? [
        ...[0, 1, 2].map((q) => ({
          group: 'pump',
          sync: 'everysec',
          label: `QoS ${q} · 8 发 8 收 · 256 B（压到饱和）`,
          loader: ['-mode', 'pump', ...PUBSUB, '-qos', String(q), '-payload', '256', '-proto', '5', '-seconds', String(SECONDS)],
        })),
        {
          group: 'pump',
          sync: 'everysec',
          label: 'QoS 1 · 8 发 8 收 · 256 B · 限速 5k/s（现实速率的延迟）',
          // A saturated run measures the queue the broker is willing to build; an
          // operator's question is what one hop costs when nothing is backed up.
          loader: ['-mode', 'pump', ...PUBSUB, '-qos', '1', '-payload', '256', '-proto', '5', '-rate', '5000', '-seconds', String(SECONDS)],
        },
        {
          group: 'pump',
          sync: 'everysec',
          label: '3.1.1 QoS 1 · 8 发 8 收 · 256 B（压到饱和）',
          loader: ['-mode', 'pump', ...PUBSUB, '-qos', '1', '-payload', '256', '-proto', '4', '-seconds', String(SECONDS)],
        },
      ]
    : [],
  ...GROUPS.includes('payload')
    ? [64, 256, 1024, 4096].map((p) => ({
        group: 'payload',
        label: `载荷 ${p} B · QoS 1`,
        sync: 'everysec',
        loader: ['-mode', 'pump', ...PUBSUB, '-qos', '1', '-payload', String(p), '-proto', '5', '-seconds', String(SECONDS)],
      }))
    : [],
  ...GROUPS.includes('fanout')
    ? [
        {
          group: 'fanout',
          label: '1 发 8 收 · 同一主题（扇出 ×8）',
          sync: 'everysec',
          loader: ['-mode', 'pump', '-publishers', '1', '-subscribers', '8', '-shards', '1', '-window', '100', '-qos', '1', '-payload', '256', '-proto', '5', '-seconds', String(SECONDS)],
        },
        {
          group: 'fanout',
          label: '8 发 0 收 · QoS 1（纯入站）',
          sync: 'everysec',
          loader: ['-mode', 'pump', '-publishers', '8', '-subscribers', '0', '-window', '100', '-qos', '1', '-payload', '256', '-proto', '5', '-seconds', String(SECONDS)],
        },
      ]
    : [],
  ...GROUPS.includes('fsync')
    ? ['everysec', 'always', 'never'].map((s) => ({
        group: 'fsync',
        label: `-store-sync ${s} · 8 离线会话排队`,
        sync: s,
        // Two connected subscribers ride along: without them the durable rows have
        // no latency to report, and the question "does fsync stall live delivery"
        // is the one an operator actually has.
        loader: ['-mode', 'pump', '-publishers', '4', '-subscribers', '2', '-offline', '8', '-shards', '4', '-window', '100', '-qos', '1', '-payload', '128', '-rate', '3000', '-seconds', String(SECONDS)],
      }))
    : [],
  // The two rows below differ in one flag: the same broker, the same loader, the
  // same 8×8 QoS 1 shape, one with the payload wrapped in TLS. That is the
  // question an operator asks before turning a port on — what does it cost me.
  ...GROUPS.includes('tls')
    ? [
        {
          group: 'tls',
          label: 'QoS 1 · 8 发 8 收 · 256 B · 明文',
          sync: 'everysec',
          loader: ['-mode', 'pump', ...PUBSUB, '-qos', '1', '-payload', '256', '-proto', '5', '-seconds', String(SECONDS)],
        },
        {
          group: 'tls',
          label: 'QoS 1 · 8 发 8 收 · 256 B · TLS（服务端证书）',
          sync: 'everysec',
          tls: true,
          loader: ['-mode', 'pump', ...PUBSUB, '-qos', '1', '-payload', '256', '-proto', '5', '-seconds', String(SECONDS)],
        },
      ]
    : [],
];

// --------------------------------------------------------------- reporting ----

const table = (headers, body) =>
  [`| ${headers.join(' | ')} |`, `| ${headers.map(() => '---').join(' | ')} |`, ...body.map((r) => `| ${r.join(' | ')} |`)].join('\n');

const groupName = {
  conns: '连接成本（idle connection cost）',
  gate: '接入闸门的代价（per-address gate）',
  proxy: '传输头部的代价（PROXY protocol）',
  pump: 'QoS 吞吐',
  payload: '载荷大小',
  fanout: '扇入扇出',
  fsync: '三档 fsync 的代价（离线队列落盘）',
  tls: 'TLS 的代价（同一配置，只差一层加密）',
};

// Delta of one metric between a during-hold sample and the pre-ramp sample, per
// connection actually held. The settled sample is the one to size a deployment
// with; the first sample still carries whatever the GC had not reclaimed yet,
// which is why both are shown.
const perConn = (rep, sample, key) => {
  const online = num(sample?.online);
  if (!online) return '—';
  return `${kilo((num(sample[key]) - num(rep.broker_before?.[key])) / online)} KiB`;
};

function renderConns(got) {
  return table(
    ['连接数', '建立 conn/s', '失败', 'goroutines', 'mem_sys (MiB)', '每连接预留', '每连接活跃', '活跃/连接（刚建完）'],
    got.map(({ row, rep }) => {
      const settled = rep.broker_settled ?? rep.broker_during ?? {};
      const first = rep.broker_during ?? {};
      return [
        comma(row.n),
        comma(rep.connect_per_second),
        String(rep.connect_errors),
        comma(settled.goroutines),
        mib(settled.mem_sys_bytes),
        perConn(rep, settled, 'mem_sys_bytes'),
        perConn(rep, settled, 'mem_alloc_bytes'),
        perConn(rep, first, 'mem_alloc_bytes'),
      ];
    }),
  );
}

// The gate is only worth shipping if both halves of this table hold: an armed
// gate that refuses nothing must cost the same as one switched off, and an armed
// gate that refuses must cost the *survivors* the same as well. The refusals come
// from the cumulative counters, so they are read after the run rather than from a
// sample taken while the ramp was still in progress.
function renderGate(got) {
  return table(
    ['场景', '计划建连', '连上', '压测端报错', 'broker 在线', '闸门拒绝（并发/速率）', '表项/持有 socket', 'goroutines', 'mem_sys (MiB)', '每连接活跃'],
    got.map(({ row, rep, after }) => {
      // Online and held sockets come from the sample taken while the loader was
      // still holding its connections; the refusals are cumulative, so the final
      // read is the one that has counted the whole ramp.
      const settled = rep.broker_settled ?? rep.broker_during ?? {};
      return [
        row.label,
        comma(rep.planned_connections),
        comma(rep.connected),
        String(rep.connect_errors),
        comma(settled.online),
        `${comma(after?.refused_over_per_ip_connection_limit)} / ${comma(after?.refused_over_per_ip_connect_rate)}`,
        `${comma(after?.per_ip_gate_entries)} / ${comma(settled.per_ip_gate_held_sockets)}`,
        comma(settled.goroutines),
        mib(settled.mem_sys_bytes),
        perConn(rep, settled, 'mem_alloc_bytes'),
      ];
    }),
  );
}

// The header rows read like the gate rows because the question is the same one:
// what does the feature cost when it decides nothing, and what does it cost when
// it decides everything. The two columns only this table has are the pair that
// says the header was the path the load actually came in on — a row where the
// broker credited fewer sessions than the loader held is a row about something
// else, and the last two rows are the point of the whole feature: one cap, twice
// the headroom, because the gate is counting devices instead of one balancer.
function renderProxy(got) {
  return table(
    ['场景', '计划建连', '连上', '压测端报错', 'broker 在线', '头部会话/头部拒绝', '闸门拒绝', '表项/持有 socket', 'goroutines', 'mem_sys (MiB)', '每连接活跃'],
    got.map(({ row, rep, after }) => {
      const settled = rep.broker_settled ?? rep.broker_during ?? {};
      return [
        row.label,
        comma(rep.planned_connections),
        comma(rep.connected),
        String(rep.connect_errors),
        comma(settled.online),
        `${comma(after?.connections_over_proxy_header)} / ${comma(after?.refused_over_proxy_header)}`,
        comma(after?.refused_over_per_ip_connection_limit),
        `${comma(after?.per_ip_gate_entries)} / ${comma(settled.per_ip_gate_held_sockets)}`,
        comma(settled.goroutines),
        mib(settled.mem_sys_bytes),
        perConn(rep, settled, 'mem_alloc_bytes'),
      ];
    }),
  );
}

// A hop shorter than one clock tick cannot be resolved on this machine, so the
// cell says so instead of printing a confident 0. The loader reports the
// granularity it measured, which on a Windows box can be half a millisecond.
// Zero samples means nobody was connected to time — "no data", not "fast".
const lat = (ms, rep) => {
  if (!num(rep?.latency_samples)) return '—';
  const g = num(rep.clock_granularity_ns) / 1e6;
  if (g > 0 && ms < g * 1.5) return `≤${g.toFixed(2)} ms†`;
  return ms < 1 ? `${(ms * 1000).toFixed(0)} µs` : `${ms.toFixed(2)} ms`;
};

function renderPump(got) {
  return table(
    ['场景', 'msg/s', '≈Mbit/s（载荷+20B）', '已投递', 'p50', 'p90', 'p99', 'goroutines', 'mem_sys (MiB)', 'dropped', 'spills'],
    got.map(({ row, rep, after }) => [
      row.label,
      comma(rep.msgs_per_second),
      rep.mbit_per_second.toFixed(1),
      comma(rep.delivered),
      lat(rep.p50_ms, rep),
      lat(rep.p90_ms, rep),
      lat(rep.p99_ms, rep),
      comma(rep.broker_during?.goroutines),
      mib(rep.broker_during?.mem_sys_bytes),
      comma(after?.dropped_messages),
      comma(after?.queue_spills),
    ]),
  );
}

function renderFsync(got) {
  const loss = { always: '0（每条落盘）', everysec: '≤1 s', never: '整个进程' };
  return table(
    // p50 next to p99 because that is where the tax shows: everysec and never
    // hold the median still, always moves it by an order of magnitude.
    ['sync 模式', 'msg/s（实发）', '已投递', 'p50', 'p99', 'state.log', '每条落盘', 'spills', 'dropped', '丢失窗口'],
    got.map(({ row, rep, after, state }) => [
      row.sync,
      comma(rep.msgs_per_second),
      comma(rep.delivered),
      lat(rep.p50_ms, rep),
      lat(rep.p99_ms, rep),
      `${(state / 1024).toFixed(1)} KiB`,
      // The append log rewrites a whole session snapshot per durable write, so this
      // ratio is the disk growth an operator actually pays, not the payload size.
      `${(state / Math.max(1, rep.published)).toFixed(0)} B/条`,
      comma(after?.queue_spills),
      comma(after?.dropped_messages),
      loss[row.sync],
    ]),
  );
}

async function main() {
  console.log(`broker   ${BIN}`);
  console.log(`loader   ${LOADER}`);
  console.log(`ports    mqtt 127.0.0.1:${PORT}  metrics ${METRICS_URL}${GROUPS.includes('tls') ? `  tls 127.0.0.1:${TLSPORT}` : ''}`);
  console.log(`seconds  ${SECONDS} per row`);
  console.log(`groups   ${GROUPS.join(', ')} (${rows.length} rows)\n`);

  if (GROUPS.includes('tls')) pki = await genPKI();

  const machine = {
    platform: `${platform()} ${release()} ${arch()}`,
    cpu: `${cpus().length} logical cores — ${cpus()[0]?.model ?? 'unknown'}`,
    ram: `${(totalmem() / 1073741824).toFixed(1)} GiB`,
  };

  const got = [];
  for (const [i, row] of rows.entries()) {
    const store = mkdtempSync(join(tmpdir(), 'congmq-baseline-'));
    console.log(`[${i + 1}/${rows.length}] ${row.label}`);
    let broker = null;
    try {
      broker = await startBroker({ sync: row.sync, store, tls: row.tls, extra: row.brokerArgs });
      // Which limits are live for this row is part of the number, not a detail in
      // the flags file — the broker says them out loud at startup, so echo that.
      // Both announcements, when both are armed: a row measured with a cap and a
      // header has two things live that change what the broker accepts.
      for (const armed of [broker.log('per-address gate armed'), broker.log('transport header armed')]) {
        if (armed) console.log(`    ${armed}`);
      }
      const rep = await runLoader(row.loader, row);
      await sleep(1600); // outlast every flush interval, then read the settled numbers
      const after = await broker.metrics();
      got.push({ row, rep, after, state: broker.stateBytes(), error: (rep.errors ?? [])[0] ?? '' });
    } catch (e) {
      console.log(`  FAIL ${e.message.split('\n')[0]}`);
      got.push({ row, rep: null, error: e.message.split('\n')[0] });
    } finally {
      if (broker) await broker.stop();
      await removeDir(store);
    }
  }

  const sections = [];
  // The loader and the broker count the same deliveries from opposite sides of the
  // socket, so they must agree. They did not, once: QoS 0 and QoS 2 arrivals were
  // counted again on their PUBACK/PUBCOMP leg, which made those rows read 2x high.
  // Keeping the check here means the next such bug announces itself instead of
  // shipping a table of confident numbers.
  const checked = got.filter((x) => x.rep && x.rep.mode === 'pump');
  const mismatched = checked.filter((x) => num(x.rep.delivered) !== num(x.after?.messages_out));

  // A connection the gate turns away never reaches a CONNACK, so the loader counts
  // it as an error too — the two sides have to agree here as well, in the other
  // direction. Loader errors with no matching refusals on the broker means the
  // sockets never got there: on Windows that is the ephemeral port range writing
  // the row, and a table built from it would describe the client, not the gate.
  // The transport header closes sockets the same way and for the same reason, so
  // its counter belongs in the same sum.
  const cappedRows = got.filter((x) => ['gate', 'proxy'].includes(x.row.group) && x.rep);
  const refusedOf = (after) =>
    num(after?.refused_over_per_ip_connection_limit) + num(after?.refused_over_per_ip_connect_rate) + num(after?.refused_over_proxy_header);
  const unaccounted = cappedRows.filter(({ rep, after }) => num(rep.connect_errors) > 0 && refusedOf(after) < num(rep.connect_errors) * 0.95);

  // The probe measures the finest tick this machine showed during one run, and
  // Windows moves that resolution depending on who else holds a timer request, so
  // the rows can span an order of magnitude. One number in the header would make a
  // † cell look either stricter or looser than it is, so show the span.
  const grans = got.map((x) => num(x.rep?.clock_granularity_ns)).filter((n) => n > 0);
  const granMin = grans.length ? Math.min(...grans) : 0;
  const granMax = grans.length ? Math.max(...grans) : 0;
  // A run of connection rows samples no round trip at all, so the tick it would
  // have needed does not exist. Saying "0.00–0.00" would read as a measurement.
  const tick = grans.length
    ? `时钟粒度：${(granMin / 1e6).toFixed(2)}–${(granMax / 1e6).toFixed(2)} ms —— 本机 \`time.Now()\` 逐行实测的最小步进。
单跳延迟低于一个 tick 就无法分辨，表里的 \`†\` 表示"比这一行自己的 tick 还短"，不是 0 ms。`
    : '本次没有采样任何单跳延迟，因此没有时钟粒度可报（只有连接类行数）。';
  for (const g of GROUPS) {
    const subset = got.filter((x) => x.row.group === g && x.rep);
    if (!subset.length) continue;
    const fn =
      g === 'conns' ? renderConns : g === 'gate' ? renderGate : g === 'proxy' ? renderProxy : g === 'fsync' ? renderFsync : renderPump;
    sections.push(`### ${groupName[g]}\n\n${fn(subset)}\n`);
    const errs = subset
      .filter((x) => x.error)
      .map((x) => {
        // A capped row whose connect errors the broker's own refusal counters
        // explain is the feature working, not the run failing. Say which one it
        // is: the note underneath reads like a broken dial, and it is not.
        const refused = refusedOf(x.after);
        const byTheGate = ['gate', 'proxy'].includes(x.row.group) && num(x.rep.connect_errors) > 0 && refused > 0 && !unaccounted.includes(x);
        return (
          `- \`${x.row.label}\`: ${x.error}` +
          (byTheGate
            ? `\n     ↑ 闸门或头部造成的，不是故障：broker 侧拒绝 ${refused.toLocaleString('en-US')} 条，压测端 ${x.rep.connect_errors} 条建连失败`
            : '')
        );
      });
    if (errs.length) sections.push(`失败与告警：\n\n${errs.join('\n')}\n`);
  }

  const selfCheck = [
    checked.length
      ? `压测端的 \`delivered\` 对 broker 的 \`messages_out\`：${checked.length - mismatched.length}/${checked.length} 行相等。` +
          (mismatched.length
            ? `\n\n不等的那些行——至少一侧在数错东西，不要引用：\n\n` +
              mismatched.map((x) => `- \`${x.row.label}\`: loader ${x.rep.delivered} vs broker ${x.after?.messages_out}`).join('\n')
            : `两个计数器从套接口的两侧数同一批投递，相等才说明上面的表值得引用。`)
      : `本次没有 pump 行，投递计数器的两侧对账不适用。`,
  ];
  if (cappedRows.length) {
    selfCheck.push(
      unaccounted.length
        ? `\n\n压测端的 \`connect_errors\` 对 broker 的拒绝数（闸门 + 头部）：${cappedRows.length - unaccounted.length}/${cappedRows.length} 行对得上。` +
            `下面这些行的失败不是闸门或头部造成的（broker 侧拒绝计数对不上），是压测端自己没拿到套接字——\n` +
            `Windows 的动态端口范围和 TIME_WAIT 在连续几行上万建连后就会不够用。这些行不要引用：\n\n` +
            unaccounted
              .map((x) => `- \`${x.row.label}\`: loader 失败 ${x.rep.connect_errors} vs broker 拒绝 ${refusedOf(x.after).toLocaleString('en-US')}`)
              .join('\n')
        : `压测端的 \`connect_errors\` 对 broker 的拒绝数（闸门 + 头部）：${cappedRows.length}/${cappedRows.length} 行一致——` +
            `被拒的连接不会变成会话，只会在这几个计数器上各留一笔，两边对上才证明表里的拒绝是闸门或头部做的。`,
    );
  }
  // The header rows carry one more instrument, and it is the one that says the row
  // measured what its label claims: a session held on a require-mode broker had to
  // come in through a header, so those two counters must be equal — and on the
  // control rows, which read no header at all, the header counter must stay zero.
  const proxyRows = got.filter((x) => x.row.group === 'proxy' && x.rep);
  if (proxyRows.length) {
    const miscredited = proxyRows.filter((x) => {
      const armed = (x.row.brokerArgs ?? []).includes('require') || (x.row.brokerArgs ?? []).includes('trusted');
      return armed
        ? num(x.after?.connections_over_proxy_header) !== num(x.rep.connected)
        : num(x.after?.connections_over_proxy_header) !== 0;
    });
    selfCheck.push(
      miscredited.length
        ? `\n\n\`connections_over_proxy_header\` 对压测端 \`connected\`：${proxyRows.length - miscredited.length}/${proxyRows.length} 行一致，` +
            `不等的那些行说明头部没有真的走过这条路径，不要引用：\n` +
            miscredited.map((x) => `- \`${x.row.label}\`: 头部会话 ${x.after?.connections_over_proxy_header} vs 连上 ${x.rep.connected}`).join('\n')
        : `\`connections_over_proxy_header\` 对压测端 \`connected\`：${proxyRows.length}/${proxyRows.length} 行一致——` +
            `开了头部的那几行，每一条会话都被记成一次头部采信；\`off\` 那一行一个都没记，` +
            `所以表里"这一行读的是什么"是 broker 自己说的，不是行标签说的。`,
    );
  }
  sections.push(`### 仪表自检\n\n${selfCheck.join('\n')}\n`);

  const failures = got.filter((x) => !x.rep);
  const doc = `# 容量基线（实测）

生成时间：${new Date().toISOString()}

机器：${machine.platform} · ${machine.cpu} · 内存 ${machine.ram}
Broker：\`${BIN}\` · 压测端：\`${LOADER}\`（同一台机器，loopback）
每行时长：${SECONDS}s · 每行独立进程 + 独立 \`-store\` 目录
${tick}

> 这些数字是**同一台机器上的 loopback 下限**，不是 SLA。换机器、换网卡、换操作系统都要重跑
> \`node load-baseline.mjs\`；压测端和服务端在同一台机器上会互相抢 CPU，所以真实部署通常更高。

${sections.join('\n')}

原始报告（JSON，逐行）：

\`\`\`json
${JSON.stringify(
  got.map(({ row, rep, after, state }) => ({
    label: row.label,
    sync: row.sync,
    loader: row.loader.join(' '),
    broker_flags: (row.brokerArgs ?? []).join(' '),
    report: rep,
    broker_after: after && {
      online: after.online,
      goroutines: after.goroutines,
      mem_sys_bytes: after.mem_sys_bytes,
      messages_in: after.messages_in,
      messages_out: after.messages_out,
      dropped_messages: after.dropped_messages,
      queue_spills: after.queue_spills,
      server_disconnects: after.server_disconnects,
      protocol_errors: after.protocol_errors,
      subscriptions: after.subscriptions,
      connections_tls: after.connections_tls,
      tls_handshake_failures: after.tls_handshake_failures,
      refused_over_per_ip_connection_limit: after.refused_over_per_ip_connection_limit,
      refused_over_per_ip_connect_rate: after.refused_over_per_ip_connect_rate,
      per_ip_gate_entries: after.per_ip_gate_entries,
      per_ip_gate_held_sockets: after.per_ip_gate_held_sockets,
      refused_over_subscription_cap: after.refused_over_subscription_cap,
      connections_over_proxy_header: after.connections_over_proxy_header,
      refused_over_proxy_header: after.refused_over_proxy_header,
      auth_rejected: after.auth_rejected,
      auth_lockout_refusals: after.auth_lockout_refusals,
      auth_locked_addresses: after.auth_locked_addresses,
    },
    state_log_bytes: state,
    error: row.error ?? '',
  })),
  null,
  2,
)}
\`\`\`
`;

  writeFileSync(new URL(`./${OUT}`, import.meta.url), doc, 'utf8');
  if (pki) rmSync(pki, { recursive: true, force: true });
  console.log(`\n${sections.join('\n')}`);
  const notes = [];
  if (failures.length) notes.push(`${failures.length} row(s) failed`);
  if (mismatched.length) notes.push(`${mismatched.length} counter mismatch(es)`);
  if (unaccounted.length) notes.push(`${unaccounted.length} gate row(s) whose errors never reached the broker`);
  console.log(`written   ${join('test', OUT)}${notes.length ? `  (${notes.join('; ')})` : ''}`);
  // A mismatch means the instrument is broken, and a broken instrument produces
  // tables that look fine. Fail the run rather than let one into a commit.
  if (notes.length) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
