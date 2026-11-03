// Capacity baseline harness. It starts a real broker per row, drives it with
// bin/congmq-load (which speaks MQTT through internal/packets, the same codec
// the server uses, so no third-party client can be blamed for a number), and
// turns the JSON reports into markdown tables.
//
//   node load-baseline.mjs
//   node load-baseline.mjs --groups=pump,fsync --seconds=15
//   node load-baseline.mjs --groups=tls --seconds=20   # the plain/TLS pair
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
const GROUPS = (argv.groups ?? 'conns,pump,payload,fanout,fsync,tls').split(',').map((g) => g.trim());
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

async function startBroker({ sync, store, queueMax = 1000, tls = false }) {
  const args = [
    '-addr', `127.0.0.1:${PORT}`,
    '-metrics', `127.0.0.1:${METRICS_PORT}`,
    '-store', store,
    '-store-sync', sync,
    '-store-flush-interval', '1s',
    '-queue-max', String(queueMax),
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
      broker = await startBroker({ sync: row.sync, store, tls: row.tls });
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

  // The probe measures the finest tick this machine showed during one run, and
  // Windows moves that resolution depending on who else holds a timer request, so
  // the rows can span an order of magnitude. One number in the header would make a
  // † cell look either stricter or looser than it is, so show the span.
  const grans = got.map((x) => num(x.rep?.clock_granularity_ns)).filter((n) => n > 0);
  const granMin = Math.min(...grans) || 0;
  const granMax = Math.max(...grans) || 0;
  for (const g of GROUPS) {
    const subset = got.filter((x) => x.row.group === g && x.rep);
    if (!subset.length) continue;
    const fn = g === 'conns' ? renderConns : g === 'fsync' ? renderFsync : renderPump;
    sections.push(`### ${groupName[g]}\n\n${fn(subset)}\n`);
    const errs = subset.filter((x) => x.error).map((x) => `- \`${x.row.label}\`: ${x.error}`);
    if (errs.length) sections.push(`失败与告警：\n\n${errs.join('\n')}\n`);
  }

  sections.push(
    `### 仪表自检\n\n` +
      `压测端的 \`delivered\` 对 broker 的 \`messages_out\`：${checked.length - mismatched.length}/${checked.length} 行相等。` +
      (mismatched.length
        ? `\n\n不等的那些行——至少一侧在数错东西，不要引用：\n\n` +
          mismatched.map((x) => `- \`${x.row.label}\`: loader ${x.rep.delivered} vs broker ${x.after?.messages_out}`).join('\n')
        : `两个计数器从套接口的两侧数同一批投递，相等才说明上面的表值得引用。`) +
      `\n`,
  );

  const failures = got.filter((x) => !x.rep);
  const doc = `# 容量基线（实测）

生成时间：${new Date().toISOString()}

机器：${machine.platform} · ${machine.cpu} · 内存 ${machine.ram}
Broker：\`${BIN}\` · 压测端：\`${LOADER}\`（同一台机器，loopback）
每行时长：${SECONDS}s · 每行独立进程 + 独立 \`-store\` 目录
时钟粒度：${(granMin / 1e6).toFixed(2)}–${(granMax / 1e6).toFixed(2)} ms —— 本机 \`time.Now()\` 逐行实测的最小步进。
单跳延迟低于一个 tick 就无法分辨，表里的 \`†\` 表示"比这一行自己的 tick 还短"，不是 0 ms。

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
  console.log(`written   ${join('test', OUT)}${notes.length ? `  (${notes.join('; ')})` : ''}`);
  // A mismatch means the instrument is broken, and a broken instrument produces
  // tables that look fine. Fail the run rather than let one into a commit.
  if (notes.length) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
