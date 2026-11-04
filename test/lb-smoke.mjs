// 对着**已经跑起来的那一套**做冒烟：deploy/docker-compose.yml 起的 nginx(PROXY protocol)
// → congmq(require)。它不测解析器——那是 internal/proxyproto 的按字节单测和
// test/proxy-check.mjs 的活；它测的是"照着 README 装完到底能不能用"：
// 镜像起得来、健康检查过、设备从负载均衡进得来、消息真的走到，
// 而且 broker 报出来的计数证明它信了头部（不是"连上了，但所有人共用 LB 的地址"）。
//
//   docker compose -f deploy/docker-compose.yml up -d --build
//   node test/lb-smoke.mjs
//   docker compose -f deploy/docker-compose.yml down
//
// CI 的 docker job 就是这三步。MQTT_URL / METRICS_URL 指到别的堆栈时用环境变量覆盖。
import mqtt from 'mqtt';
import crypto from 'node:crypto';

const BROKER_URL = process.env.MQTT_URL ?? 'mqtt://127.0.0.1:1883';
const METRICS = process.env.METRICS_URL ?? 'http://127.0.0.1:8080/metrics';
const READY = process.env.READY_URL ?? new URL('/readyz', METRICS).href;
const TOPIC = 'demo/lb-smoke';

// 示例规则里的账号（rules/auth.jsonl 第一条：sha256(salt + username)）。
// 用它是因为这套 compose 挂的就是仓库里那份示例规则；真机换自己的。
const credentials = {
  username: 'dashboard',
  password: crypto.createHash('sha256').update('c0ng-2026' + 'dashboard').digest('hex'),
};

let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'pass' : 'FAIL'}  ${name}${detail ? `\n        -> ${detail}` : ''}`);
  if (!ok) failures++;
};

const metrics = async () => (await fetch(METRICS)).json();

function connect(reason) {
  return new Promise((resolve, reject) => {
    const client = mqtt.connect(BROKER_URL, {
      clientId: `lb-smoke-${Math.random().toString(16).slice(2, 8)}`,
      ...credentials,
      protocolVersion: 4,
      clean: true,
      reconnectPeriod: 0,
      connectTimeout: 8000,
    });
    const timer = setTimeout(() => {
      client.end(true);
      reject(new Error(`${reason}: no CONNACK within 8s`));
    }, 10000);
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

async function main() {
  console.log(`stack: ${BROKER_URL}\nmetrics: ${METRICS}\n`);

  const ready = await fetch(READY);
  check('the readiness probe answers 200', ready.status === 200, `GET ${READY} -> ${ready.status}`);

  const before = await metrics();
  check('nothing has been believed through a header yet on a fresh stack',
    before.refused_over_proxy_header === 0,
    `refused_over_proxy_header=${before.refused_over_proxy_header}`);

  // 设备侧：连上 → 订阅 → 另一条连接发布 → 收到。全程只碰负载均衡那个口。
  const sub = await connect('subscriber');
  check('a device session lands through the load balancer', sub.connected === true, 'CONNACK 0');
  const heard = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('no message through the balancer within 10s')), 10000);
    sub.once('message', (t, p) => {
      clearTimeout(timer);
      resolve(`${t}:${p.toString()}`);
    });
    sub.subscribe(TOPIC, { qos: 1 }, (err) => err && reject(err));
  });
  await new Promise((r) => setTimeout(r, 300));
  const pub = await connect('publisher');
  await pub.publishAsync(TOPIC, 'via-load-balancer', { qos: 1 });
  const got = await heard;
  check('and a QoS 1 message makes the round trip', got === `${TOPIC}:via-load-balancer`, got);

  const after = await metrics();
  // 这两条是本次冒烟的落点。计数不涨 = broker 根本没信头部，那么它眼里的"来源地址"
  // 就是 LB ——-max-conns-per-ip、凭据锁定、规则里的 ip、日志与存储里的 RemoteIP
  // 全都记的是同一台机器，而链路看起来一切正常。
  check('both sessions were counted as coming over a transport header',
    after.connections_over_proxy_header >= before.connections_over_proxy_header + 2,
    `${before.connections_over_proxy_header} -> ${after.connections_over_proxy_header}`);
  check('and none of them was refused for the way it was addressed',
    after.refused_over_proxy_header === before.refused_over_proxy_header,
    `${before.refused_over_proxy_header} -> ${after.refused_over_proxy_header}`);

  const text = await (await fetch(new URL('/metrics.txt', METRICS).href)).text();
  const row = text.split('\n').find((l) => l.startsWith('congmq_connections_over_proxy_header '));
  check('the prometheus view carries the same counter',
    !!row && Number(row.split(' ')[1]) === after.connections_over_proxy_header,
    row ?? 'no such line');

  sub.end(true);
  pub.end(true);
}

main()
  .then(() => {
    console.log(failures ? `\n${failures} check(s) failed` : '\nsmoke passed');
    process.exitCode = failures ? 1 : 0;
  })
  .catch((err) => {
    console.error('\nFAIL', err?.message ?? err);
    process.exitCode = 1;
  })
  .finally(() => setTimeout(() => process.exit(process.exitCode ?? 1), 200));
