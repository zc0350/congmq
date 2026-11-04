# congmq

手写内核的单机 MQTT broker：纯 Go 实现，零第三方依赖，MQTT 3.1.1 与 5.0 共用一个监听端口，
按 CONNECT 里的协议级别分派。明文与 TLS 各占一个端口，可以同时开——迁移按设备一台一台来，
不用一次把机队翻过去。

写它的前提不是"再多一个 broker"，而是**敢开机**：重启不丢离线消息，崩溃能恢复，
每一条边界行为都有测试钉住，且行为在源码注释里说清楚为什么这样取舍。

当前版本 `v1.0.0`。预编译二进制在 [Releases](https://github.com/zc0350/congmq/releases)：
linux 的 amd64 / arm64 / armv7、windows amd64（zip）、darwin 的 amd64 / arm64，每个归档一个
`congmq` + `congmq-load` + `congmq-cert` + `SHA256SUMS.txt`。装 Go 的话直接
`go install github.com/zc0350/congmq/cmd/congmq@latest`。

---

## 1. 能力与边界

### 有

| 分类 | 内容 |
| --- | --- |
| 协议 | MQTT 3.1.1（level 4）与 5.0（level 5），同一端口 |
| 传输安全 | 原生 TLS 1.2/1.3，明文与密文**两个端口并跑**（`-tls-addr`），可按设备逐台迁移；服务端认证 + mTLS（`-tls-ca` 校验客户端证书链） |
| 服务质量 | QoS 0 / 1 / 2 全流程；`-max-qos 1` 可整体关掉 QoS 2 |
| 会话 | 持久会话、离线消息队列（`-queue-max` 封顶，超限丢最旧）、5.0 Session Expiry |
| 保留消息 | 含 5.0 Message Expiry 自动清理、空负载删除、Retain As Published |
| 遗嘱 | 普通遗嘱 + 5.0 Will Delay Interval；重连撤回，clean start 接管时立即发布 |
| 共享订阅 | `$share/{group}/{topic}` 轮转分发 |
| 5.0 能力协商 | CONNACK 通告 Receive Maximum / Topic Alias Maximum / Maximum QoS / Maximum Packet Size / Subscription Identifier |
| 5.0 属性透传 | User Property、Content Type、Response Topic、Correlation Data、Payload Format 原样转发给订阅者 |
| 认证 | JSONL 规则：md5/sha1/sha256/sha512 摘要、三种 salt 拼接方案、用户名/clientid 正则、来源 IP/CIDR；**客户端证书可就是凭据本身**（`cert_cn`） |
| 授权 | JSONL 规则：按文件顺序 allow/deny、`%c %u %1..%9` 主题模板、无命中即拒绝 |
| 接入层抗滥用 | 按来源地址限**并发连接**与**建连速率**（`-max-conns-per-ip` / `-conn-rate-per-ip`，判定在 accept）；凭据失败按地址锁定（拒绝而非 sleep，回的 CONNACK 与凭据错误不可分辨）；每会话 topic filter 条数上限（`-max-subs`）。**默认全部为 0 = 完全不计量**（§4） |
| 真实来源地址 | PROXY protocol **v1 文本与 v2 二进制**头部（`-proxy-protocol` + `-trusted-proxy-cidr`），在计量与认证**之前**读，读完只剩 payload。于是网关、锁定、规则里的 `ip`、日志与存储里的 `RemoteIP` 判的都是设备本人，不是那台负载均衡（§4）。**默认 `off`：一个字节都不多读** |
| 持久化 | 会话 + 保留消息 + 延迟遗嘱落盘，三档 fsync 策略，崩溃后重放；连接中的持久会话也留一条"订阅+身份"记录 |
| 换二进制 | 记录格式 `congmq-store-v1` 自 v1.0.0 起字节未变，**跨版本双向接管**实测过（离线队列一条不缺、会话 `sessionPresent` 不用重订阅、遗嘱按原 deadline 准点）；`state.lock` 保证**一个 `-store` 目录只有一个写者**，第二个进程拒绝启动而不是静默覆盖（§6） |
| 观测 | `-metrics` 同一份快照开三个口：`/metrics`（JSON，可直接 curl）、`/metrics.txt`（Prometheus 文本 0.0.4）、`/readyz`（就绪探针） |
| 不停机运维 | 规则文件与服务端证书/CA **热加载**：`-reload-interval`（默认 2s，unix 上 SIGHUP 立刻查一次）；坏文件拒绝并保持旧策略，换证书不断已有会话 |
| 关停 | SIGINT/SIGTERM 先关监听再 drain 会话，15s 上限 |
| 内存护栏 | 报文长度在分配之前校验（`-max-packet-size`） |
| 容量基线 | `cmd/congmq-load` + `test/load-baseline.mjs`：连接成本、QoS 吞吐、延迟分位、三档 fsync 代价、闸门与传输头部的代价，全是实测（§9） |
| 落地形态 | `Dockerfile`（多阶段、非 root、`/readyz` 健康检查）+ `deploy/docker-compose.yml`（nginx 发 PROXY 头 → broker `require`）+ `deploy/systemd/`（`ProtectSystem=strict`、`systemctl reload` 就是 SIGHUP）。CI 的 `docker` job 真的把这一套起来，再从负载均衡外面跑一次设备往返（§2、§8） |

### 没有（别踩坑）

- **TLS 不自动续期**。证书要你自己准备（`cmd/congmq-cert` 造的是**测试链**，别拿到公网），到期前自己换文件——
  换完**不用重启**（写回原路径，一个轮询周期内生效，见 §2 与 §11），但 broker 不会自己去申请或续签。
  过期/未生效的叶子在启动期和重载时**同样被拒**，所以别指望热加载能救一张已经过期的证书。
- **明文端口不会升级成 TLS**（没有 STARTTLS）。要么连 `-addr`，要么连 `-tls-addr`，两个端口各管各的。
- **单写者闸门只在新版本里**。`state.lock` 挡住的是"两个都认得这道闸的进程"，v1.0.0 没有这段代码，
  你用它去开一个当前版本正占着的目录，它照起并照盖（§6 实测）。所以回滚方向仍然靠流程：
  先确认旧进程退干净，再起下一个。同理，闸门是**文件句柄**级别的：把目录拷到另一台机器，那份
  `state.lock` 不带任何含义；两台机器挂同一个共享目录时它能不能拦住，取决于那个挂载怎么实现文件锁——
  这一点没实测过，别把它当成集群保护（本项目本来就是单节点，见 §11）。
- **`cert_cn` 规则管不到离线队列**。设备掉线后存储身份没有证书可查，按证书授权的主题会在**入队之前**
  被拒（`acl_denied_delivery`），回来也补不上——见 §5 第 3 条。
- **抗滥用那一层认的是地址，不是账号**。一个 NAT 出口或一段 IPv6 /64 里的整批设备，在
  `-max-conns-per-ip` / `-conn-rate-per-ip` / `-auth-fail-limit` 眼里就是同一个"人"（§4 与 §11）——
  所以它们默认全是 0，开了之前先确认你的机队不是一个 IP。要按身份限，只有 `-max-conns`、
  `-max-subs` 和规则文件里的 `clientid` / `ip` 这三样。**如果那个"一个 IP"其实是一台负载均衡**，
  让它把真实地址写在连接最前面（`-proxy-protocol`，§4），这句话就不再成立；NAT 出口仍然成立。
- **头部里那个地址是前置说出来的，不是被证明的**。PROXY protocol 没有签名也没有加密，
  谁能连上这个端口，谁就能报任意来源地址——所以 `-trusted-proxy-cidr` 写宽了等于把
  "按地址做的所有判定"交给那段网络里最不受约束的人。要么 `require`（只有前置进得来），
  要么把网段收到只有前置那一台。§11 记了这个取舍。
- **没有 WebSocket / MQTT-SN**，只有 TCP。
- **单机**：无集群、无共享订阅跨节点、无保留消息同步。
- **不发布 `$SYS/#`**。broker 不产生任何内部状态主题，监控走 `/metrics`。
  （`rules/acl.jsonl` 里的 `$SYS/#` 规则只是示范，删掉也不影响运行。）
- **没有 5.0 增强认证（AUTH 报文）**：属性表里认得它，但不参与握手；认证只有 `-auth` 里的摘要规则与
  证书规则，而证书是**TLS 握手**验的，不是 MQTT 握手。
  `Request Problem Information` 同理——解析了，但 Reason String 照常返回。
- **没有管理 HTTP API**：`/metrics` `/metrics.txt` `/readyz` 三个口全是只读的，不能改配置。规则改动靠**热加载**
  （改文件等一个周期，或发 SIGHUP），重载与启动期是同一套严格校验，见 §5。
- **热加载不看文件内容之外的任何东西**：不是 `fsnotify`，靠 `(mtime, size)` 指纹，所以"把文件换成一模一样的内容"
  不会触发任何事（本来也不该触发）；跨机器 NFS 上的时间戳精度问题会体现为多一次重试，不会装上半套策略。

---

## 2. 十分钟跑起来

需要 Go 1.24 及以上。

```bash
# 构建
go build -o bin/congmq ./cmd/congmq          # Windows: go build -o bin/congmq.exe ./cmd/congmq
go build -o bin/congmq-cert ./cmd/congmq-cert # 测试证书链，只用于把 TLS 先跑通

# 裸跑（无认证、无鉴权、纯内存，进程退出即遗忘）
./bin/congmq -addr :1883

# 生产形态：规则 + 落盘 + 指标
./bin/congmq -addr :1883 \
  -auth rules/auth.jsonl -acl rules/acl.jsonl \
  -store /var/lib/congmq -store-sync everysec \
  -metrics 127.0.0.1:1884 -max-packet-size 1048576

# 加密形态：明文端口照旧，另开一个 mqtts 端口，按设备一台一台迁
./bin/congmq-cert -out /etc/congmq/pki -days 365 -dns mqtt.example.com
./bin/congmq -addr :1883 -tls-addr :8883 \
  -tls-cert /etc/congmq/pki/server.crt -tls-key /etc/congmq/pki/server.key \
  -tls-ca /etc/congmq/pki/ca.crt
#  ↑ 给了 -tls-ca 就是「要求并校验客户端证书」（mTLS）。设备侧连
#    mqtts://mqtt.example.com:8883，带 pki/client.crt + pki/client.key。
```

开了 `-store` 之后启动日志会先把恢复结果说清楚（下面是真实输出）：

```
level=INFO msg="store open" path=/tmp/smoke/state.log sync=everysec sessions=0 retained=0 wills=0
level=INFO msg="durable state restored" component=broker id=congmq-1 retained=0 delayed_wills=0
level=INFO msg=listening component=broker id=congmq-1 addr=127.0.0.1:1893 rules="auth=off acl=off" \
       receive_max=100 topic_alias_max=10 max_packet_size=0 max_qos=2
level=INFO msg="metrics endpoint listening" addr=127.0.0.1:1894 paths="/metrics /metrics.txt /readyz"
```

验证：

```bash
curl -s http://127.0.0.1:1884/metrics | jq '.online, .messages_in, .retained_messages'
curl -s http://127.0.0.1:1884/metrics.txt | grep -E '^congmq_(online|messages_in)'  # 同一份快照，Prometheus 抓这个
curl -so /dev/null -w '%{http_code}\n' http://127.0.0.1:1884/readyz                  # 200 可接新连接，503 正在 drain
```

开了 `-tls-addr` 之后，它会先把你**实际会被强制什么**说清楚（下面是真实输出，注意 `client_auth`
那一栏就是 mTLS 的证据，`sans` 少了客户端连的那个名字就连不上）：

```
level=INFO msg="tls listener configured" addr=127.0.0.1:1893 cn=congmq.test \
       sans=localhost,127.0.0.1,::1 not_after=2026-12-03T04:16:39Z min_version=1.2 \
       client_auth="required and verified against -tls-ca" handshake_timeout=10s
level=INFO msg=listening component=broker id=tls-smoke addr=127.0.0.1:1892 tls_addr=127.0.0.1:1893 \
       rules="auth=auth.jsonl (2 rules) acl=acl.jsonl (2 rules)" \
       receive_max=100 topic_alias_max=10 max_packet_size=0 max_qos=2
```

### 改规则、换证书都不用重启

把新内容写回**原来那个路径**就行，broker 每 `-reload-interval`（默认 2s）看一次指纹，unix 上 SIGHUP 立刻看一次。
下面是 `test/reload-check.mjs` 跑出来的原话（省略了 `time=` 前缀，路径缩成 `…`，
同一条日志里重复出现的路径字段 `auth=` / `acl=` / `cert=` / `ca=` 也去掉）：

```
level=INFO msg="rules reloaded" generation=2 auth=5 acl=4
level=ERROR msg="rules refused, keeping the policy in force" err="auth: …/auth.jsonl:1: rules: invalid rule file: unexpected EOF" generation=3
level=INFO msg="tls certificate rotated" generation=2 cn=rotated.test sans=localhost,127.0.0.1,::1 \
       not_after=2026-12-03T06:19:49Z client_auth="required and verified against -tls-ca"
level=ERROR msg="tls material refused, still serving the certificate already in force" \
       err="-tls-cert/-tls-key: tls: failed to find any PEM data in certificate input" cn=rotated.test
```

被拒的那次**什么状态都不改**：旧策略继续判、旧证书继续发，只把 `rules_reload_failures` /
`tls_cert_reload_failures` 加一（同一份坏内容只记一次，不是每个周期记一次）。语义与四条边界见 §5，
证书那一半见 §11。

### 用容器或 systemd 落地

两条路都在仓库里，都不是"参考配置"：`Dockerfile` 与 `deploy/` 是 CI 每个 PR 真起一遍的东西
（`docker compose up` + nginx + 从负载均衡外面打一条设备消息进去，见 §8 的 `docker` job）。

```bash
# 容器：build + 起来，设备口在 127.0.0.1:1883（先过 nginx），指标口在 127.0.0.1:8080
docker compose -f deploy/docker-compose.yml up -d --build
node test/lb-smoke.mjs                    # 设备真的从负载均衡后面连上来，并且被记成一条头部连接
curl -s localhost:8080/metrics | jq '.connections_over_proxy_header, .refused_over_proxy_header'

# systemd：从 Releases 的归档装（归档里就带 deploy/systemd/）
sudo useradd --system --home-dir /var/lib/congmq --no-create-home --shell /usr/sbin/nologin congmq
sudo install -m 0755 congmq /usr/local/bin/congmq
sudo cp deploy/systemd/congmq.default /etc/default/congmq
sudo cp deploy/systemd/congmq.service /etc/systemd/system/ && sudo systemctl daemon-reload
sudo systemctl enable --now congmq
sudo systemctl reload congmq              # 就是发一个 SIGHUP：立刻重查规则与证书，不重启、不断会话
```

四件事要说在前面：

- **裸 `docker run` 是一个开放的 broker**。镜像的默认命令只有 `-addr :1883 -metrics :8080 -store ...`，
  既没有 `-auth` 也没有 `-acl`，那按 §4 的语义就是"任何人可连 + 全部放行"。规则是部署处的数据、
  不是镜像里的内容，所以要么挂 `/etc/congmq` 并覆盖 `command:`（compose 那份就是这么写的），
  要么就别把这条端口发布出去。同理，默认命令也没给 `-max-packet-size`。
- **不发镜像仓库**。`deploy/docker-compose.yml` 里 `image: congmq:local` 配的是 `build:`，
  也就是从这份 checkout 本机构建；没有 `ghcr.io/...` 之类的公开 tag 可拉。要用现成镜像就自己
  推到你们的私有仓库，或按上面第一行在目标机上 build。
- **TLS 证书不在镜像里**。镜像只带二进制；`-tls-cert/-tls-key/-tls-ca` 走挂载或 systemd 的
  `/etc/congmq/pki`。`cmd/congmq-cert` 造的是测试链，别拿到公网（§1）。
- **容器里的来源地址**。compose 那套把 broker 放在只有 nginx 进得来的网络上，所以用
  `-proxy-protocol require`；如果你还要留一条直连口给还没迁的设备，改用 `trusted` 并把
  `-trusted-proxy-cidr` 收到 nginx 那一段（§4）。两种形态下 `docker exec` 进去都看不到设备真实 IP
  ——那是网络 namespace 的事，不是 broker 的事。

---

## 3. 目录结构

```
cmd/congmq/        入口：参数解析、优雅关停、/metrics 三个口、证书轮换与规则热加载
cmd/congmq-cert/   一条测试证书链（CA + 服务端 + 客户端），不需要 openssl
cmd/congmq-load/   零依赖压测客户端，与 broker 共用 internal/packets
internal/packets/  报文编解码（3.1.1 + 5.0 属性层），纯协议无状态
internal/topics/   主题过滤器 trie 树 + 通配符匹配 + $share 轮转
internal/store/    会话存储：MemoryStore / FileStore（追加式日志 + compaction）
internal/rules/    auth.jsonl / acl.jsonl 的严格加载与求值
internal/proxyproto/ 只读 transport header：PROXY protocol v1 文本与 v2 二进制，按字节判定、按长度消费
internal/tlscert/  证书链构造，只被 cmd/congmq-cert 用
internal/broker/   内核：连接状态机、QoS 1/2、离线队列、保留消息、遗嘱、TLS 监听、恢复、规则原子快照、来源地址包装
rules/             可直接使用的示例规则文件（注释即文档）
Dockerfile         多阶段、CGO_ENABLED=0、非 root、/readyz 健康检查
deploy/            落地形态：docker-compose.yml + nginx（发 PROXY 头）+ systemd unit 与 /etc/default
test/              Node 工具层：用 mqtt.js 这个第三方客户端做一致性验证，并留存 §9 那几张表的运行原件
```

依赖关系是单向的：`broker` 依赖 `packets` / `topics` / `store` / `rules`，`packets` 和 `tlscert`
不依赖任何人（`tlscert` 只被 `cmd/congmq-cert` 用，broker 本体走标准库 `crypto/tls`）。

---

## 4. 启动参数

`congmq -h` 是唯一权威列表，这里按用途分组说明取舍。

### 网络与容量

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-addr` | `:1883` | 明文 TCP 监听地址。要加密请另开 `-tls-addr`；两者可以同时跑，也可以只开 TLS 那个 |
| `-id` | `congmq-1` | 日志与 `/metrics` 里的 broker 标识 |
| `-max-conns` | `0`（不限） | 连接上限。稳态实测每条连接 28 KiB 活跃 / 56 KiB 预留（§9），最坏内存由 `-max-packet-size` 决定（§10 第 1 条）。按来源地址的那几个上限见下面「接入层抗滥用」 |
| `-mailbox-size` | `256` | 每条连接在路由与连接协程之间的交接队列深度 |
| `-write-timeout` | `10s` | 单次 socket 写入的截止；超时就认为对端卡死 |
| `-deliver-timeout` | `5s` | 一个慢订阅者最多能拖住发布者多久，超时则断开它（先落盘再断） |

### 接入层抗滥用（默认全部关闭）

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-max-conns-per-ip` | `0`（不限） | 同一来源地址**同时**可持有的连接数，在 accept 处判定 |
| `-conn-rate-per-ip` | `0`（不计量） | 同一来源地址每秒可新建的连接数。令牌桶，可用小数：`0.2` = 五秒一个 |
| `-conn-burst-per-ip` | `0`（一秒的量，下限 1） | 桶容量，即安静之后可以一次性发起多少连接。单独给会 `exit 2`——它是 `-conn-rate-per-ip` 的窗口大小，不是独立的限流 |
| `-auth-fail-limit` / `-auth-fail-window` | `0`（不退避） | 一个窗口内同一地址允许的凭据失败次数，达到就把这个地址锁起来。两个必须成对给，而且必须有 `-auth`，否则 `exit 2` |
| `-auth-lockout` | `0`（= 一个完整窗口） | 锁定时长。锁定期内**再多的失败不会延长它** |
| `-max-subs` | `0`（不限） | 单个客户端可同时持有的**不同** topic filter 条数。这条按会话算、不按地址算，判定在 SUBSCRIBE（语义见下） |

判定都在这条慢路径上——连接类的在 accept、凭据锁定在 CONNECT、订阅上限在 SUBSCRIBE——
发布与投递的热路径没有为它们改过一行（§9 那组 off / armed 对照就是把这件事称出来的）。
地址的键：IPv4 精确、IPv6 取 /64 前缀、`::ffff:a.b.c.d` 折回 IPv4；取不到 IP 的连接共用一个桶。

**为什么限流点在 accept 而不是 CONNECT**：CONNECT 处设限只能管住"会话"，而一个只建 TCP、
一个字节都不发的对端永远走不到 CONNECT——它还占着一个 socket、一个读截止和三个协程，
一直到 30s 的 pre-connect 截止（`preConnectTimeout`，写死在 `internal/broker/client.go:24`）才释放。
只有计量 socket 本身才看得见这种负载。

**这几项都会咬错人，默认才全是 0**：一个 NAT 后面的 200 台设备，在 broker 眼里就是同一个 IP；
一个共享出口的办公网同理。代价与放大半径写在 §11，怎么选值写在 §10 第 2 条。

**锁定的代价，写明白**：锁定期内这个地址**连对了密码也会被拒**，而且回的 CONNACK 和凭据错误
一模一样（`0x04`）——锁定不该成为一条"这里有账号"的泄露。失败计数在锁定期内不再累加，
一次成功登录会把计数清零（但买不通一个正在生效的锁定）。计数看
`auth_lockout_refusals`，当下有没有人在坐看 `auth_locked_addresses`（§7）。

订阅上限刻意按**不同 filter 条数**算，而不是按 SUBSCRIBE 次数：已经持有的 filter 重新订阅
永远允许（否则一台占满额度的设备再也改不了自己主题表的 QoS），UNSUBSCRIBE 自己腾额度，
重连恢复的会话**绕过**上限——把 `-max-subs` 调低不该让一批已经在服役的设备失联。
上限在 ACL 之后判定：一个两样都不合格的订阅，先告诉它"这个你不能订"。
3.1.1 回 `0x80`，5.0 回 `0x97`（Quota Exceeded）。

### 真实来源地址（PROXY 协议，默认关闭）

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-proxy-protocol` | `off` | `off` 不读头部；`require` 要求每条连接都以合法头部开头（专职监听口，只允许前置访问）；`trusted` 只相信 `-trusted-proxy-cidr` 里那些地址报出来的头部 |
| `-trusted-proxy-cidr` | `""` | 允许"替别人报地址"的网段，逗号分隔，如 `10.0.0.0/8,fd00::/8`。`trusted` 不给等于谁都别想报——所以直接 `exit 2`；`require` 给了也 `exit 2`，那条路径根本不查表 |
| `-proxy-header-timeout` | `5s` | 对端把头部写完的预算。必须为正：`0` 不是一个"不限"的写法，而是一个已经过去的截止，会在头部读完之前掐掉每一条连接，所以 `exit 2` |

`-proxy-protocol off` 时，`-trusted-proxy-cidr` 与 `-proxy-header-timeout` 只要被显式给出就 `exit 2`，
并把"这几个不会生效"列在报错里——比没设更糟的是设了并相信它生效了。

两种头部都读：v1 文本（`PROXY TCP4 src dst sport dport`）与 v2 二进制（12 字节签名 +
`ver_cmd` / `fam_trans` + 16 位长度 + 地址块），IPv4 与 IPv6 都支持，v2 尾部 TLV 按长度跳过。
尺寸按规范封顶（文本 108 字节，二进制 16 + 自己声明的长度），**超限是致命错误而不是"这不算头部"**：
一个自称 4000 字节的头部不是"大一点的头部"，是有人在拿它当隧道。`LOCAL`（前置自己的健康检查）是合法且
"没有报别人"，于是放行并用 socket 自己的地址——探针不该被算成一次会话。

`trusted` 的两种错位都刻意做得不舒服，因为含糊的那一侧正是故障藏身处：
一个名单里的地址**没发**头部会被拒（名单说了它会发，没发说明站在那儿的不是那个前置）；
一个名单外的地址**发了**头部也会被拒，而不是"忽略掉继续当直连"——
写一个明知不会被相信的头部，唯一的动机是试探它会不会被相信。

打开之后真实地址走的是 `RemoteAddr()`，所以下游一行都没改就一起对了：接入闸门的按地址限流、
auth 规则里的 `ip`、ACL 里的 `ip`、凭据锁定的键、离线会话存下来的来源地址、以及日志。
日志的字段换成了一对：`remote` 是**做决定时依据的那个地址**，`via` 是连接真正落进来的 socket——
"闸门为什么把我一整批设备关在外面"只有把两个地址放在一起才答得出来。TLS 端口同样生效，
且头部在握手之前读，所以前置可以做四层透传（`deploy/nginx/nginx.conf` 就是这么配的）。

代价：`off` 是零（不读、不缓冲、不开协程，走的是另一条代码路径）；armed 时每条连接多一条短命协程
和一份**常驻到连接结束**的包装 + 128 字节缓冲——解析完那个 reader 不丢，后面的报文解码就从它里面读。
协程开在外面是因为读头部是对端的日程表：一个连上就沉默的对端不该让 accept 循环等满五秒。
实测数字见 §9「传输头部的代价（PROXY protocol）」。

### 传输安全（TLS / mTLS）

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-tls-addr` | `""`（不开） | TLS 监听地址，如 `:8883`。**独立端口**，不做 STARTTLS；`-addr` 照旧收明文，所以能按设备逐台迁 |
| `-tls-cert` / `-tls-key` | `""` | 服务端证书与私钥，PEM。开了 `-tls-addr` 就必须两个都给，否则 `exit 1` |
| `-tls-ca` | `""` | 客户端证书必须链到的 CA 集合。给了它就等于**要求并校验**客户端证书（mTLS） |
| `-tls-require-client-cert` | `false` | 要求客户端证书但**不校验**（`RequireAnyClientCert`）。此时握手成功也拿不到可信身份，`cert_cn` 规则永远不命中——启动时会 WARN 这件事 |
| `-tls-min-version` | `1.2` | 只接受 `1.2` / `1.3`，别的值 `exit 1`。想彻底禁掉 1.2 就写 `1.3` |
| `-tls-handshake-timeout` | `10s` | 握手预算。握手跑在自己的协程里，所以一个只建 TCP 不发数据的对端**拖不住 accept 循环** |

这里没有"默认帮你绑好证书"的路径：证书过期 / 还没生效 / 解析不了 /
`-tls-ca` 里第一个 PEM 块不是证书，全部拒绝启动（`exit 1`）。
反过来，只给了 `-tls-cert` 却没给 `-tls-addr` 也是拒绝（`exit 2`，并列出那些不会生效的 `-tls-*` 参数）——
静悄悄没加密地跑起来，比起不来严重得多。

规则文件里出现 `cert_cn` 而 broker 没开 TLS 端口同样 `exit 1`，见 §5。

### 会话与重试

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-queue-max` | `1000` | 每个离线会话最多留存的消息数，超出丢最旧的，计入 `dropped_messages` |
| `-inflight-window` | `100` | 每个客户端在途未确认消息数，其余排队 |
| `-retry-interval` | `5s` | 未确认消息的重发间隔 |
| `-session-expiry-max` | `0`（不限） | 允许客户端申请的最长 Session Expiry，用于封顶磁盘占用 |
| `-reap-interval` | `10s` | 过期会话回收 + 保留消息清理 + 延迟遗嘱到期的检查频率 |
| `-max-qos` | `2` | 授予的最高 QoS。`1` 时 CONNACK 通告 Maximum QoS=1，QoS 2 订阅被降为 1，发 QoS 2 报文收 `0x9B` 且该报文丢弃、连接保留 |

### 5.0 能力通告（改了就等于改了客户端被允许做的事）

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-receive-max` | `100` | 客户端可以留多少条 QoS 1/2 报文未确认，超过即 `0x93` 断开 |
| `-topic-alias-max` | `10` | 客户端可用的最大 Topic Alias 编号，`0` 表示禁止 |
| `-max-packet-size` | `0` | 客户端可发的最大报文。**生产务必设置**：`0` 表示协议自身的 256MB 上限 |

### 持久化（见 §6）

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-store` | `""` | 状态文件目录；留空则全部留在内存，进程退出即遗忘 |
| `-store-sync` | `everysec` | `everysec` / `always` / `never` |
| `-store-flush-interval` | `1s` | 合并后的会话快照最多能等多久落盘 |
| `-store-compact-mb` | `32` | 追加量超过多少 MB 就重写文件；`0` 用默认的 32 |

### 安全与观测

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-auth` | `""` | auth.jsonl 路径；留空表示任何人可连 |
| `-acl` | `""` | acl.jsonl 路径；留空表示全部放行 |
| `-metrics` | `""` | 计数器地址，如 `127.0.0.1:1884`；只注册三个 GET：`/metrics`（JSON）、`/metrics.txt`（Prometheus 文本）、`/readyz`（就绪探针） |
| `-reload-interval` | `2s` | 规则文件与 TLS 材料重查的间隔；`0` = 只认 SIGHUP（Windows 没有这个信号，等于关掉热加载，启动日志会说明） |
| `-log-level` | `info` | `debug` / `info` / `warn` / `error`，输出到 stderr |
| `-version` | — | 打印版本退出 |

规则文件解析失败一律拒绝启动（`exit 1`）：半个策略比没有策略更危险。**同一套校验也用在热加载上**——
一个起不了 broker 的文件，也换不掉正在跑的规则（§5）。

---

## 5. 认证与授权

两个文件各一行一个 JSON 对象，`#` 开头与空行跳过，**未知字段会导致整个文件拒绝加载**——
拼错字段不能悄悄把规则削弱成默认放行。完整语义写在示例文件的注释里，改规则前先读它：

- [`rules/auth.jsonl`](rules/auth.jsonl)
- [`rules/acl.jsonl`](rules/acl.jsonl)

### 认证要点

- 客户端上送的 password 是**十六进制摘要**，broker 拿规则里的 `salt` 现算再常量时间比较；
  摘要方案由 `alg`（md5/sha1/sha256/sha512）和 `scheme`
  （`username+salt` / `salt+username` / `salt+username+salt`）决定。
- `sanitize`（默认 true）指摘要前把用户名里非 `[A-Za-z0-9]` 的字符去掉；正则匹配作用于**原始**用户名。
- `username` / `clientid` 省略即匹配任意，`"match":"regex"` 走 POSIX 扩展正则，`ip` 支持单 IP 或 CIDR。
  开了 `-proxy-protocol`（§4）之后，这里比的是**头部里那个设备地址**而不是负载均衡——这条规则在两种
  形态下的语义是一样的，变的只是 broker 眼里"对端"是谁。
- 命中顺序：字面用户名（或字面 `cert_cn`，见下）的规则优先，然后按文件顺序尝试正则/`*` 规则；
  同一条规则内 `clientid`、`ip`、`cert_cn` 是 AND 约束。全部试完仍不匹配 → 拒绝。
- 开了 `-auth-fail-limit`（§4）之后，锁定判定在**规则匹配之前**：一个正在坐锁定的地址，
  broker 连"这条规则有没有命中"都不会去答。计数记的是"规则没命中"这件事本身，**不分原因**——
  密码错、证书 CN 对不上、明文连接撞上 `cert_cn` 规则，都算一次。所以一批配置错的设备
  挤在同一个 NAT 出口后面时，是这整个出口一起被锁；这正是它默认关闭的原因之一。

### 证书就是凭据（mTLS）

TLS 握手已经证明对端持有私钥，所以这时候再要一个密码往往是多余的。`cert_cn` 就是为这一步准备的：

```jsonl
{"cert_cn":"congmq-device-1"}                                   # 证书本身就是凭据
{"cert_cn_match":"regex","cert_cn":"^plant-[0-9]+$"}            # 一整批设备
{"cert_cn":"congmq-device-1","user":"meter","topics":["plant/#"]}   # ACL：这块证书只能碰 plant/#
```

- **没有 `alg`/`scheme` 的证书规则 = 凭据就是证书**（`ByCertificate()`），握手过了就算认证通过。
- **证书 + 摘要 = 两个都要中**（AND）。用途是把一个密码钉死在特定证书上：换了证书，密码对也进不来。
- `cert_cn` 与 `user` / `clientid` / `ip` 一样是**同一条规则内的 AND 约束**；字面 `cert_cn` 的规则
  也享受"字面优先"的命中顺序，不会被后面的 `*` / 正则规则抢先。
- `"cert_cn":"*"` 要的是"**任意一张被验过的证书**"，它依然是一个证书要求：明文连接同样不命中。

四条 fail-closed 规矩，都有测试钉住（`internal/broker/cert_test.go`、`test/tls-check.mjs`）：

1. **明文连接答不出证书规则**，连 `"cert_cn":"*"` 也答不出——它的 CertCN 是空串。
2. **没校验过的证书不带身份**。只有 `-tls-require-client-cert`、没给 `-tls-ca` 时，握手能过，
   但 `VerifiedChains` 是空的，CertCN 一律当空——不校验的 CN 是客户端自己写的，拿它授权等于没有授权。
3. **证书规则不覆盖离线队列**。证书属于**连接**，不属于会话：设备掉线后存储身份里没有 CertCN，
   路由时那次投递授权就命不中这条规则，消息**在入队之前**就被拒并记 `acl_denied_delivery`——
   设备回来也补不回来。要一个设备有离线队列，它的 allow 规则就得靠 `user` / `clientid`（这两个会落盘），
   `cert_cn` 只用来收紧"在线时才允许"的主题。（`internal/broker/cert_test.go` 的
   `TestCertificateScopedRulesStopCoveringAnOfflineQueue` 钉住了这一条：同一台设备掉线后，
   `plant/#`（证书规则）零条入队、`shop/#`（clientid 规则）照常送达。）
4. **规则文件里有证书规则而 broker 没开 `-tls-addr` → 启动就 `exit 1`**。这种配置下所有设备都会被判为
   无凭证，与其静悄悄拒绝整个机队，不如不起来。

### 授权要点

- `effect` 必填 `allow`/`deny`；`action` 取 `publish` / `subscribe` / `all`。
- `topics` 里字符串按 MQTT 通配符匹配，`{"eq":"..."}` 做字面比较（把 `#` 当普通字符串），
  省略 `topics` 表示任意主题。
- 模板记号在装载期就校验：`%c` = clientid，`%u` = username，`%1..%9` = `user` 正则的捕获组，
  `%%` = 真百分号。`%1` 要求 `user` 是 regex 且分组足够，否则拒绝加载。
- 运行期若展开出的身份含 `+` 或 `#`，这条规则直接不命中并记 `acl_unsafe_expansions`——
  否则一个 clientid 为 `a/#` 的客户端能把自己的规则放大成任意主题。
- **严格按文件顺序**求值，第一条同时满足 subject + action + topic 的规则说了算；
  没有任何规则命中即拒绝（no_match = deny）。不与 mosquitto 原生 acl 文件同：原生会把 deny
  悄悄提到同用户 allow 之前，这里不重排。

### 热加载：改规则不用重启

规则对（authenticator + ACL）装在**一个原子快照**里（`internal/broker/policy.go`），每个决策点只做一次
load——所以不存在"新 ACL 配旧凭据校验器"这种没人写进文件的中间态。语义由 `internal/broker/reload_test.go`
（5 例）和 `test/reload-check.mjs`（35 项）钉住：

| 你会问的问题 | 实际行为 |
| --- | --- |
| 什么时候开始生效？ | **下一个决策**。已连着的会话不会被踢（"策略交换不是驱逐"），但它的下一次发布、每一次投递都按新规则判 |
| 收窄多快见效？ | 投递侧每条消息都重新授权（上一条），所以不等设备重连；放宽同理，同一个会话**不重新订阅**就继续收得到 |
| auth 和 acl 同时改？ | 两半**先都装载校验、再一次交换**。任一半失败 → 整次拒绝，旧策略原样在位，不会出现一半新一半旧 |
| 文件写坏了？ | `rules_reload_failures` 加一、日志一条；同一份坏内容**不会每个周期再记一次**（按 `(mtime,size)` 指纹认出来了）。改对了，下一个周期就装上 |
| 把规则文件清空？ | 装载成功、0 条规则 → 什么都匹配不上 → **全部拒绝**。这与启动期给一个空文件的结果完全一致；要"关掉这一半"就别传 `-auth` / `-acl` |
| 规则里有 `cert_cn`，但这个 broker 没开 `-tls-addr`？ | 启动 `exit 1`；热加载同样**拒绝**并保持旧策略——否则一次粘贴就锁死整个机队，而日志只有一句"没有证书可查" |

改完想确认"到底装上没有"，看 `rules_generation`（每装上一代加一）与 `rules_reloads`；
想知道"拒了几次"看 `rules_reload_failures`。这两个数在 `/metrics` 和 `/metrics.txt` 里都有（§7）。

---

## 6. 持久化：重启不丢消息

`-store <dir>` 之后，目录里只有一个文件 `state.log`，它是**追加式记录日志**：

```
4 字节大端长度 | JSON 记录 | 4 字节 CRC-32(IEEE)
```

第一条记录是格式头 `congmq-store-v1`；记录类型共 7 种：
`header` / `session` / `session-deleted` / `retain` / `retain-deleted` / `will` / `will-deleted`。
删除写成墓碑记录，因为"不存在"没法重放。会话整份快照写（不是增量），保留消息和遗嘱小而不频繁，直接内联追加。

### 三档 fsync 的取舍

`-store-sync` 决定"崩溃时最多丢什么"。没有第四种既不花钱又什么都不丢的选项。

| 模式 | `Put` 返回时 | 进程被 kill -9 | 整机掉电 |
| --- | --- | --- | --- |
| `everysec` | 快照只在内存 | 最多丢 `-store-flush-interval`（默认 1s）内的会话/保留消息/遗嘱变更 | 同左，再加文件系统未落盘的部分 |
| `always` | 已 fsync | 不丢已确认的状态 | 不丢已确认的状态 |
| `never` | 快照在 OS 页缓存 | 已 flush 的（每 tick 一次）不丢 | 可能丢任意多 |

吞吐敏感的设备接入用 `everysec`；离线队列本身就是业务生命线、每条都要算数的用 `always`
（代价是每条排队消息一次 fsync）。`never` 只适合"重启进程别丢就行"的开发环境。

延迟遗嘱记的是**绝对到期时间**，所以崩溃恢复后它仍按原时刻开火；已过期的在启动时立刻发布，
因为不会再有人来撤回它。

### 一次崩溃到底丢什么

| 状态 | kill -9 之后 | 为什么 |
| --- | --- | --- |
| 离线会话的排队消息 | 回来（`always` 一条不丢） | 队列变更进会话快照，落盘时机就是上表那一档 |
| 订阅关系 | 回来 | 会话记录带订阅集合，SUBACK / UNSUBACK 之前先写盘，所以**连接中**的会话也有一条记录 |
| 会话过期时钟 | 重新起算 | 连接中写的记录标 `Live`，只记 `ExpiryInterval`；重启时按"活过来这一刻"计时，宕机的那段时间不算进过期窗口 |
| 保留消息 | 回来 | 小而不频繁，内联追加 |
| 延迟遗嘱 | 回来，按**原绝对时刻**开火 | 记的是到期时间，不是剩余时长 |
| 在线会话里"已投递但未确认"的那一段 | **不回来** | 接管连接时存储记录被减到"订阅+身份"，信箱与在途窗口由运行态持有（不清的话重启会把已确认过的消息 union 回去，永远清不掉） |

最后一行是这套持久化唯一的诚实边界：发布端早就拿到了 PUBACK，掉电时挂在在线订阅者窗口里的
消息不会再补一次。规避方式是把订阅端也做成"离线优先"——它断开时（正常 DISCONNECT、超时、
慢消费者被踢）运行态会先把剩余队列和在途写回存储，所以只有"连着的时候掉电"这一段会丢。

### 启动时读到坏文件怎么办

- 尾部字节凑不成一条完整记录（硬杀进程的样子）：**截断丢弃**并计入 `Discarded`，
  启动时 `WARN the previous shutdown was not clean bytes_discarded=N`；那之前的记录全部有效。
- CRC 不匹配：把它当停点，等价于一次撕裂写。
- 文件不是本程序写的（格式头不对 / 根本不成帧）：**拒绝启动**，文件一个字节都不动。
  移开文件是可恢复的，因为"看着奇怪"就抹掉别人的离线消息不是。
- 单条记录上限 64MB。超过就拒绝写入并持续报错（不会断开发布者），同时保留内存里的状态，
  下一轮再试。别让 `-queue-max × 平均消息体` 逼近这个量级；真要放大就调低 `-queue-max`。
- 磁盘满、权限变更等写失败：只记日志，不丢连接。`dirty` 只在字节真的排进日志后才清，
  所以下一次 flush 会把同一份状态再写一遍。

### 干净关停

`Close()` 会先把待写快照刷完，再把整个文件按当前活状态重写一遍（compaction），
所以正常退出的日志永远是紧凑的。追加量超过 `-store-compact-mb` 时运行中也会重写一次
（由后台写盘的那个 tick 判断，所以最迟一个 `-store-flush-interval` 之后就发生）。

这条决定的是磁盘的**上界**，值得单独记一句：会话是整份快照追加的，一个压着几千条消息的
离线会话每被更新一次，就往文件里再写一遍它自己的全部队列。所以运行中的文件大小 ≈
"存储还留着的东西 + 自上次重写以来的追加量"，前者看 `store_sessions` / `store_queued`，
后者看 `store_bytes` 与那个阈值。

**注意它不会跟着负载一起掉回去**：设备取完、会话过期回收之后，文件仍留着上一次重写那一刻
的体积——那一刻存的是洪峰的驻留，不是空的存储。要等追加量再过一遍阈值（或干净关停时的那次
重写）它才掉下来。所以按**峰值驻留**规划磁盘，不是按稳态：浸泡实测过一轮，
`store_sessions` / `store_queued` 都归零之后 `state.log` 仍是洪峰大小，而每个数都对得上。
反过来，如果它一路只涨、连阈值都过不了，就是压缩没跑到（看 `store_bytes` 与文件实际大小的差，
两者应当一致）。
重写走"临时文件 → fsync → 关闭活句柄 → rename → 重开"，Windows 不允许 rename 覆盖打开中的文件，
因此顺序不能换。

`os.Exit` 会跳过 defer，所以每个退出路径都显式关一次 store；漏掉这一步的代价是
"你以为已经落盘的那条消息"。

### 换二进制：升级与回滚

`-store` 目录里现在有两个文件：`state.log`，和 `state.lock`。后者一个字节都不写，只是被持有
（`internal/store/lock.go:27`）——它是"这个目录只有一个写者"的闸门。**别删它**：删掉等于把闸门拆了，
下一个进程会在一个新文件上取到锁，两个写者照旧撞在一起。

这道闸门是实测逼出来的。把一个目录同时交给两个进程（升级时"先起新的、再停旧的"就会这样），
两边各自 seek 到当时的文件末尾再追加，于是后写的那个把对方的记录**盖在同一个偏移上**。
而每条记录的长度和 CRC 都是自己那一份，全都对得上，所以重放看不出任何异常：实测那份文件里
47 条记录全部可信、启动日志零告警、`store open` 平静地报 `sessions=1`，
而 60 条已经 PUBACK 的离线消息里有 20 条永远不见了。这种丢失没有"检测到就降级"可言，
只能在打开的那一刻拒绝：第二个进程 `exit 1`，并说清是哪个目录被别人占着。

锁属于**文件句柄**，进程一死操作系统就替它放开，所以被 kill -9 的 broker 不会把后继者关在门外
（`npm run rolling-upgrade` 第三条腿量的就是这个）。它也不跨机器：`state.lock` 被 tar、被 rsync、
被备份走都不带任何含义。唯一还挡不住的是**旧版本**——v1.0.0 里没有这段代码，用它去开一个新版本
正占着的目录，它照起（同一条腿实测："STARTED anyway"）。所以回滚方向仍然要靠流程：
先确认旧进程真的退干净（`systemctl stop` 返回 0、`docker compose up -d` 走的是替换而不是并存），
再起下一个。

格式那一侧可以放心，两个方向都实测过：`congmq-store-v1` 的编解码（`internal/store/record.go`）
从 v1.0.0 到现在是**零字节差异**，新增的全是方法，记录结构没动过。

| 方向 | 离线队列 | 在线会话接管 | 保留消息 | 延迟遗嘱 |
| --- | --- | --- | --- | --- |
| v1.0.0 → 当前 | 98 条跨版本，一条不缺、顺序不变、零重复 | `sessionPresent=true`，客户端没重订阅照样收 | 照旧带 RETAIN 到达 | 15.0s 准点，且只发一次 |
| 当前 → v1.0.0 | 101 条跨版本，同上 | 同上 | 同上 | 同上 |

命令行兼容性是单向的，但方向站在使用者这边：新版本只**新增**开关（`-max-subs`、
`-conn-rate-per-ip`、`-proxy-protocol` 这类，共 10 个），没有改名也没有删除，
所以 v1.0.0 那条 systemd / compose 命令行原样能起新版本。反过来把只属于新开关的命令行喂给
旧二进制，会在 flag 解析阶段就退出——那也是拒绝，不是半起。

升级那一刻丢什么，两条路要分开算。**离线队列不丢**：凡是给过 PUBACK 的，都按写入顺序回来
（`-store-sync always`，上表两向都是零缺零重）。**在线投递是内存转手**：路由器把消息交给订阅者的
mailbox 就算数，它不落盘，所以 kill 会带走"那一刻还没写到 socket 上的那几条"，上界就是
`-mailbox-size`（默认 256）的量级；实测在 16 条/秒的持续负载下两个方向都是 0 条
（66 / 68 个跨版本 ack 一个不丢）。QoS 2 半程（PUBREC 已收、PUBREL 未到）与未确认在途的
跨版本恢复，第三方客户端证明不了——它收到就 ack——那两半由 `internal/broker/restart_test.go`
的裸 socket 客户端钉住。

---

## 7. 观测

`-metrics 127.0.0.1:1884` 之后，同一份快照开三个 GET 口，全部无鉴权，**只应绑回环**：

| 口 | 给谁 |
| --- | --- |
| `GET /metrics` | 人。一份 JSON，`curl` 直接读、`jq` 挑字段；下面这张表就是它的键 |
| `GET /metrics.txt` | Prometheus。`text/plain; version=0.0.4`，`congmq_` 前缀，**名字与 JSON 键一一对应**（不改成 `_total` 那种命名：一张图和一次 curl 不该对两套名字）。`id`、`tls_cert_cn` 两个字符串不进文本视图。漏一个键直接 500，不给你半份抓取——`TestPrometheusTextCoversTheWholeJSONView` 会先在这儿失败 |
| `GET /readyz` | 负载均衡 / 探针。`200 {"status":"ready","online":N}`；`Shutdown` 一开始 drain 就 `503 draining`，新连接被摘掉，而最后的计数器仍可读（指标口比 broker 的排空活得久，这是有意的） |

| 字段 | 含义 |
| --- | --- |
| `id` `online` `total_connections` `subscriptions` `retained_messages` | 瞬时状态 |
| `messages_in` `messages_out` `bytes_in` `bytes_out` | 累计流量 |
| `queue_spills` | **累计**：路由给"当前不在线的订阅者"、真的写进离线队列的消息条数。它和 `dropped_messages` 是一对——这个在涨、那个不涨，说明设备确实回来取、队列也确实接得住；**两个都不涨**说明这一路上根本没有离线投递，`-queue-max` 给多大都无所谓。早期版本这里记的是"队列被裁剪的次数"，那个语义和 `dropped_messages` 重复，而且让一个正常服务的 broker 看起来什么都没做 |
| `dropped_messages` | 被丢弃的消息（离线队列超限、慢消费者等） |
| `store_sessions` `store_queued` | 存储眼下留了多少个会话、这些会话里压了多少条待投消息。离线队列就是内存的主要去向，所以**负载结束后 `mem_alloc_bytes` 不降，先看这两个数**：都归零而 heap 仍高，那是 GC 的时机问题；还有数，就是有设备没回来、或回收器没跑完。注意在线会话也有记录（§6 的"崩溃不失联"），所以 `online` 不为 0 时这里本来就该大于 `online` |
| `store_bytes` | `state.log` 此刻的字节数，没开 `-store` 就是 0。配合 §6 那条压缩承诺读：文件 = 存储还留着的东西 + 自上次重写以来的追加量，所以它长期只涨不缩就是压缩没跟上，旋钮是 `-store-compact-mb` |
| `expired_messages` `expired_sessions` | 5.0 Message Expiry / Session Expiry 回收量 |
| `malformed_packets` `protocol_errors` `rejected_connections` | 非法输入；突增通常是有人在扫描或客户端实现有问题 |
| `dropped_over_peer_max_packet_size` | 因对端自己声明的 Maximum Packet Size 而未发出的消息 |
| `server_disconnects` | broker 主动断开的次数（慢消费者、超时限、关停） |
| `auth_rejected` `acl_denied_publish` `acl_denied_subscribe` `acl_denied_delivery` | 安全拒绝计数，规则收紧时盯这四条 |
| `refused_over_per_ip_connection_limit` `refused_over_per_ip_connect_rate` | 被 `-max-conns-per-ip` / `-conn-rate-per-ip` 在 accept 处直接挂断的 socket 数。它们**从未变成会话、从未被读过一个字节**，对端也收不到任何解释——所以除了这两个数，没有任何地方记录过那场建连风暴。只在闸门开着时才动 |
| `per_ip_gate_entries` `per_ip_gate_held_sockets` | 闸门眼下记了多少个地址 / 这些地址手上还握着多少 socket。前者是表的大小（空闲十分钟回收，一张长满的表本身就是信号），后者是"离上限还有多远"——值得预警的那个值。闸门关着时恒为 0 |
| `auth_lockout_refusals` `auth_locked_addresses` | 因地址正在坐锁定而被拒的 CONNECT 次数（累计）/ 当下有几个地址在锁定里。`auth_rejected` 先涨、`auth_lockout_refusals` 接着涨 = 爆破正在被挡；两个都不涨而设备喊"密码不对" = 有人在改规则文件 |
| `refused_over_subscription_cap` | 因达到 `-max-subs` 而被拒的 SUBSCRIBE **条数**（累计）。突然开涨是两件事之一：客户端每次重连都在往上叠订阅表，或者这个上限设得比机队实际需要的小 |
| `connections_over_proxy_header` | **累计**：靠头部里的来源地址建立起来的会话数（§4「真实来源地址」）。它只统计"确实信了一个头部"，所以 `require` 口的这个数应当贴着 `total_connections` 走（`LOCAL` 探针那一类不涨它，那是有意的）；明显低于它就是有连接在用直连的方式撞这个口 |
| `refused_over_proxy_header` | **累计**：在头部这一步就被挂断、从未成为会话的 socket 数。它和 `refused_over_per_ip_*` 一样，对端收不到任何解释、日志也被节流（每 100 次一行），所以**这是唯一的记录**。涨了通常是三件事之一：有人直连了只该前置能碰的端口、前置的头部配置没打开、或者有人在试探"写个假地址会不会被信"——第三种要去看 `via` 是谁 |
| `connections_tls` `tls_handshake_failures` | 都是**累计**值，且已经含在 `total_connections` 里。前者 = 握手成功并变成会话的连接数；后者 = **从未变成会话**的握手（明文打到 TLS 端口、证书链/域名不被信任、客户端没交证书、握手超时）。**`tls_handshake_failures` 涨而 `connections_tls` 平**就是有人在敲 TLS 端口却进不来，通常是证书过期或 SAN 少了那个名字 |
| `acl_unsafe_expansions` | 展开出的身份含通配符，规则被跳过（见 §5）。**跨重载单调**：被丢弃那一半的计数会折进新一代，不会因为换了规则就归零 |
| `rules_generation` `rules_loaded_unix` | 当前生效的是第几代策略、它什么时候生效的。改完文件先来看这个数有没有加一，再去猜连接为什么变了 |
| `rules_reloads` `rules_reload_failures` `rules_reloaded_unix` | 装上了几次 / **被拒的是几次改写**（不是"坏了几个周期"：同一份坏内容只记一次）/ 最后一次装上的时刻 |
| `reload_interval_seconds` | `-reload-interval` 的秒数，`0` 表示只认 SIGHUP（Windows 上等于不热加载） |
| `tls_cert_generation` `tls_cert_reloads` `tls_cert_reload_failures` | 证书侧同样的三个数 |
| `tls_cert_cn` `tls_cert_not_after_unix` | 现在被服务的这张叶子是谁、什么时候到期。**到期告警钉在后者**：broker 只在文件变化时重新校验，一张正在服役的证书过期它自己不会发现 |
| `goroutines` `mem_alloc_bytes` `mem_sys_bytes` `heap_objects` `gc_cycles` | 进程自身开销。**`mem_alloc` 是上一次 GC 那一刻的活对象快照，不是实时值**：空载的 Go runtime 可以几分钟不回收，于是它会一直停在负载期间的大小（`gc_cycles` 不动就是证据）。所以容量核算用 `mem_sys`（Go 向 OS 拿走的总量，含还没还给内核的部分），泄漏排查比**同等负载谷底之间**的 `mem_alloc` 增速，别看收尾那一眼 |
| `pid` `uptime_seconds` `num_cpu` | 谁在跑、跑了多久、能用几个核——多实例部署时靠 `pid` 把指标和进程对上 |

最有用的告警组合：`dropped_messages` 增速、`server_disconnects` 增速、`online` 绝对值，
开了 TLS 再加一条 `tls_handshake_failures` 增速。不停机运维这一层再加三条：

- **`rules_reload_failures` / `tls_cert_reload_failures` 从 0 变成非 0** —— 有人推了一个起不了作用的
  文件或一张解析不了的证书。它不会打断服务，但**你打算改的东西也没改上**，这是最容易被当成"已经生效"的一类故障。
- **`rules_generation` 在你推完之后没变** —— 同上，配合 `rules_reloaded_unix` 看最后一次真正装上的时刻。
- **`tls_cert_not_after_unix` 距今不足 7/30 天** —— broker 只在证书*文件变化*时才重新校验有效期，
  换文件才是续期，没人换就没人管。轮换成时它自己会打 `WARN the tls certificate expires soon`，
  但那行日志只在**轮换那一刻**出现，所以别把日志当告警用。

抗滥用那一层（§4）另加两条，共同点是**它们不说明系统坏了，只说明有人在按它**：

- **`per_ip_gate_held_sockets` 贴近 `-max-conns-per-ip`** —— 快咬人了。先确认是不是一个 NAT 出口
  在替一整批设备共用一个 IP（那就是设错了值，不是攻击），再谈限速。
- **`auth_lockout_refusals` 开始增长** —— 一个地址坐进了锁定。日志里那一行带 `failures` 和
  `locked_for`，值得看一眼是谁；同时 `refused_over_subscription_cap` 单独增长是另一回事，
  它几乎总是客户端行为或 `-max-subs` 设小了。

开了传输头部（§4）再加一条，它和前两条的区别是**它一定意味着有人在动网络**：

- **`refused_over_proxy_header` 从 0 变成非 0** —— 三种可能，按危险程度排：名单外的地址在写头部
  （`via` 字段告诉你是谁）、前置在往 `require` 口上发直连流量（配置漏了一层）、
  或前置发的头部格式我们读不了。第二种最容易被误读成"设备连不上"，因为它的现象就是间歇性挂断。

---

## 8. 测试

两层：**Go 协议与内核测试**（自研裸 TCP 测试客户端，覆盖到每一个 reason code），
**Node 一致性测试**（用第三方 mqtt.js 打，证明手写线格式真的说标准 MQTT）。

```bash
# Go 全量（含跨重启的集成测试）
go test ./...
gofmt -l . && go vet ./...
```

Node 层要在 `test/` 里跑，它按脚本要求连接特定端口和特定参数的 broker（`npm run` 已把这十个登记成脚本）。
下面都在仓库根目录执行：

```bash
# 依赖只装在 test/ 里（mqtt / mqtt-packet），broker 本体零依赖
(cd test && npm install)

# 3.1.1 一致性：对着无规则的 broker
./bin/congmq -addr 127.0.0.1:1883 &
(cd test && MQTT_URL=mqtt://127.0.0.1:1883 node conformance.mjs)

# 5.0 一致性：要带上它读取的 5.0 能力
./bin/congmq -addr 127.0.0.1:1887 -topic-alias-max 4 -max-packet-size 512 \
             -receive-max 100 -metrics 127.0.0.1:1888 &
(cd test && MQTT_URL=mqtt://127.0.0.1:1887 METRICS_URL=http://127.0.0.1:1888/metrics node v5-check.mjs)

# 规则行为：对着加载了示例规则文件的 broker；addr 不带 IP 才双栈，ipv6 那两条才测得到
# 端口被现存开发实例占着时，用 CONGMQ_PORT 指到另一台
./bin/congmq -addr :1883 -auth rules/auth.jsonl -acl rules/acl.jsonl &
(cd test && CONGMQ_PORT=1883 node rules-check.mjs)

# TLS / mTLS：自己造一条测试证书链、自己起 broker（明文 + 密文两个端口），再用 mqtt.js 从
# 两边打。它需要两个二进制：congmq 和 congmq-cert（Windows 上把 .exe 补上）
#   go build -o bin/congmq.exe ./cmd/congmq && go build -o bin/congmq-cert.exe ./cmd/congmq-cert
(cd test && npm run tls-check)

# 不停机运维：自己起一个带规则 + mTLS + 指标的 broker（1915/1916/1917），然后改 auth.jsonl、
# 收窄 acl.jsonl、把它写成半行 JSON、换掉 server.crt/ca.crt、再把它写成一张坏 PEM——
# 全程用同一个 mqtt.js 会话断言"没有被动过"。同样要 congmq 与 congmq-cert 两个二进制
(cd test && npm run reload-check)

# 崩溃恢复：自己起进程、自己 SIGKILL、自己重启，不需要你先准备 broker
(cd test && node crash-check.mjs)

# 冷备份 → 恢复演练：按运维的做法把目录拷出去（另一条路径、另一个 -id），用**拷贝**起另一个
# broker，问第三方客户端离线队列 / 保留消息 / 延迟遗嘱还在不在。第二条腿拷的是"备份时还在写"
# 的文件并从中途截断——它必须大声降级（报 bytes_discarded、砍到最后一条可信记录）而不是静默少东西。
# 第三条腿比三档 fsync 起回来的东西一样不一样。端口 1985–1990，CONGMQ_DRILL_BASE_PORT 可换
(cd test && npm run restore-drill)

# 跨版本滚动升级：从 v1.0.0 那个 tag 单独编一个二进制，和当前构建跑**同一个 -store 目录、同一个
# 端口**，中间流量不断，两个方向各做一次接管；第三条腿量的是"新进程先起来"那个升级时的手误——
# 现在它被拒绝启动（见 §6）。需要两个二进制：
#   go build -o .tmp/congmq.exe ./cmd/congmq
#   mkdir -p .tmp/v1000 && git archive v1.0.0 | tar -x -C .tmp/v1000
#   (cd .tmp/v1000 && go build -o ../congmq-v1000.exe ./cmd/congmq)
# 端口 1941–1948，CONGMQ_UPGRADE_BASE_PORT 可换；默认从 ../bin 与 ../.tmp 取二进制，
# 也可以用 CONGMQ_BIN / CONGMQ_OLD_BIN 指过去
(cd test && npm run rolling-upgrade)

# 抗滥用：起四个 broker（全关 / 只限并发 / 只限速率 / 锁定 + 订阅上限），用 mqtt.js 和一个
# 一个字节都不发的裸 socket 从外面看它们的裁决，再回到 /metrics 与 /metrics.txt 对账。
# 端口 1920–1927，CONGMQ_ABUSE_BASE_PORT 可以换一块
(cd test && npm run abuse-check)

# 真实来源地址：起四个 broker（头部关闭 / require / trusted + 名单 / require + 每地址上限），
# 在本进程里起一个迷你四层前置，按规范逐字节写 v1 文本与 v2 二进制头部，再用 mqtt.js 打过去。
# 它验的是"跨语言的字节是不是我们以为的那些字节"——Go 侧的测试和解析器共用一个字节序，
# 只有外面写的一方才能证明这些字节真的来自一个负载均衡器。
# 端口 1930–1937，CONGMQ_PROXY_BASE_PORT 可以换一块
(cd test && npm run proxy-check)

# 互操作矩阵：不用自己写的客户端，用 Eclipse 官方的 paho.mqtt.python 打全路径——3.1.1 与 5.0、
# QoS 0/1/2、retained、遗嘱与遗嘱间隔、共享订阅、主题别名、用户属性、错误口令、会话接管，
# 逐条对 reason code。它要一个装了 paho-mqtt 的 python：
#   python -m venv .tmp/venv-paho && .tmp/venv-paho/Scripts/pip install paho-mqtt==2.1.0
# （也可以 PAHO_PYTHON 指到别的解释器）。端口 1950–1963，CONGMQ_INTEROP_BASE_PORT 可换
(cd test && npm run interop)

# 浸泡：四类负载轮换 + 会话 churn，判据是**同等负载谷底之间的堆斜率**，不是收尾那一眼
# （HeapAlloc 是上一次 GC 那一刻的活对象快照，空载的 runtime 没理由回收，收尾读数会一直报洪峰）；
# 并且自己比对压测端 delivered 与 broker 的 messages_out，不等就 exit 1。
# 端口 1980/1981，要 congmq 与 congmq-load 两个二进制，CONGMQ_SOAK_BASE_PORT 可换；约 7 分钟
(cd test && npm run soak)

# 部署形态的冒烟：对着一个**已经在跑**的 compose 拓扑（nginx 写头部 → broker）打一轮
# 发布订阅，再核对 /metrics 与 /metrics.txt 里那两个头部计数器。它自己不起进程，
# 所以这一步的意义完全在于前面那条命令真的把 nginx 起来了：
#   docker compose -f deploy/docker-compose.yml up -d --build
#   (cd test && npm run lb-smoke)
#   docker compose -f deploy/docker-compose.yml down -v

# 容量基线：同样自己起 broker（每行一个独立进程 + 独立 -store 目录），自己打流量
# 它需要两个二进制，跑之前先 build（Windows 上把 .exe 补上）：
#   go build -o bin/congmq ./cmd/congmq && go build -o bin/congmq-load ./cmd/congmq-load
# TLS 那一组还要 congmq-cert
#   go build -o bin/congmq-cert ./cmd/congmq-cert
(cd test && node load-baseline.mjs)                 # 29 行，约 6 分钟，写 test/baseline-<日期>.md
(cd test && node load-baseline.mjs --groups=pump --seconds=5)   # 只跑一组，快速回归
(cd test && node load-baseline.mjs --groups=gate)   # 闸门 off / armed 不咬人 / 两条真咬人的对照
(cd test && node load-baseline.mjs --groups=proxy)  # 头部 off / v1 / v2 / trusted，加一对"同一闸门、两种地址"的对照
```

`internal/broker/restart_test.go` 里那几个用例是持久化的主力回归：
一个 broker 关闭、`FileStore` 重新打开后，离线队列、订阅、保留消息、延迟遗嘱必须按原语义回来，
在线会话的记录必须只剩订阅与身份。恢复一族按"离原始进程多远"从近到远排开：
`crash-check.mjs` 只杀真实进程、原地重启看能否捞回来（同一份二进制、同一个目录）；
`restore-drill.mjs` 从**另一条路径上的拷贝**起另一个 broker（模拟运维的冷备份恢复），
第二趟故意拷"备份时仍在写"的文件并从中途截断——它必须大声降级（报 `bytes_discarded`、
砍到最后一条可信记录）而不是静默少东西；`rolling-upgrade.mjs` 从 `v1.0.0` 那个 tag 单独
编一个二进制，两个方向各做一次跨版本接管（详见 §6）；`internal/store/lock_test.go` 把闸门
自己钉住——第二个 `NewFileStore` 必须**拒绝启动**而不是静默盖过去，那是 §6 那个"47 条合法记录、
20 条离线消息丢了"故事的直接来源。

当前源码上的实测结果（`go1.27.3`，Windows；`proxy-check` 与 `--groups=gate` / `--groups=proxy`
这两组基线跑的是同一份源码另 build 的 `.tmp/congmq.exe`——`bin/congmq.exe` 当时被一个长期开着的
开发实例占着，Windows 写不进去）：

```
conformance  27/27     v5-check  50/50     rules-check  all passed     tls-check  19/19     reload-check  35/35     crash-check  10/10     abuse-check  38/38     proxy-check  30/30
restore-drill  20/20 —— 三条腿：干净拷贝恢复、截断"仍在写"的文件必须大声降级（`bytes_discarded` 非零）、
             三档 fsync 起回来的东西完全一样
rolling-upgrade  30/30 —— 双向跨版本：v1.0.0 → 当前 98 条离线一条不缺、当前 → v1.0.0 101 条同理，
               两个方向 sessionPresent 都为 true（不用重订阅），15.0s 遗嘱按原 deadline 准点；
               第三条腿量"新进程抢在旧进程之前起"—— 现在直接 exit 1
lb-smoke  7/7 —— 这台机器没装 Docker，所以那次是拿一个手写假前置（在本进程里按 v1 写头部）顶着 nginx 跑的，
          证明的是冒烟脚本本身能咬；nginx 那一版要等 CI 的 docker job，本机说不了这句话
load-baseline  23/23 行跑完，0 行失败；仪表自检 16/16 行有投递的都 delivered == messages_out，
           闸门那四行的 connect_errors 全被 broker 的拒绝计数解释掉（表格见 §9；这一批还没有头部那六行）
load-baseline --groups=gate  4/4 行跑完；自检 4/4 行的压测端 connect_errors == broker 侧的闸门拒绝数（表格见 §9）
load-baseline --groups=proxy  6/6 行跑完；自检 6/6 行 connect_errors 被 broker 侧拒绝计数解释掉，
          且 connections_over_proxy_header 六个行全对（四个开头部行 == 各自连上数、两个 off 行 == 0）（表格见 §9）
```

Go 侧 `gofmt -l` 无输出、`go vet ./...` 干净、`go test -count=1 ./...` 全绿（broker 41.9s）。

这一层不用人守着：`.github/workflows/build.yml` 在每次 push 与 PR 上跑 `gofmt`、`go vet`、
`go test`（ubuntu 与 windows 两个系统），再在 ubuntu 上把上面十一个 Node 脚本（`lb-smoke` 与
`soak` 除外，前者要的是一个已经在跑的前置、后者要的是十分钟的堆斜率窗口）逐个跑一遍——为此
`conformance` job 还多带了两步准备：`setup-python` + `paho-mqtt==2.1.0`（互操作矩阵跑的是
第三家实现，不是自己写的客户端），以及 `git fetch --depth 1 origin tag v1.0.0` + `git archive
v1.0.0 | tar -x -C .tmp/v1000 && go build` 造一份 v1.0.0 二进制（`rolling-upgrade` 双向接管与
单写者闸门第三条腿都靠它，浅克隆默认不带 tag 所以只能显式拉）。另有一个 `docker` job 把部署
形态本身跑一遍——`docker build`、镜像里的 `-version` 必须等于源码里的 `const version`、`id`
必须是 `uid=10001`、`docker compose up --build` 起 nginx→broker、然后用**真的 mqtt.js 客户端
穿过真的 nginx** 打一轮（`lb-smoke`），再核对 `connections_over_proxy_header` 因为这一轮而涨、
`refused_over_proxy_header` 一个没动，最后原地重启容器并确认 `state.log` 还在命名卷里。
交叉编译与 Release 挂在 `needs: [go, conformance, docker]` 之后：镜像起不来就不该有 Release。
推 `v*` tag 时额外交叉编译六个平台，把归档与 `SHA256SUMS.txt` 挂到 Release；归档里除了二进制还带
`Dockerfile`、`deploy/`（compose + nginx + systemd 两个单元文件）与 `LICENSE`。
**tag 与 `cmd/congmq/main.go` 里的 `const version` 不一致就直接失败**——发出去的版本号必须等于
二进制 `-version` 打印的那一个，宁可不发。`soak` 单独住在 `.github/workflows/nightly.yml`
（`schedule: 17 18 * * *` UTC ≈ 北京 02:17 + `workflow_dispatch` 手动入口），报告作为 artifact
上传；`load-baseline` 不在 CI 里：基准必须在目标机器上跑，runner 的核数与磁盘不是你的机队会
落到的地方。
其中 TLS 那 12 个用例是这一层的重点：`tls_test.go` 7 个（两个端口互不干扰、明文打到 TLS 端口、
只有 TLS 端口的形态、握手失败不变成会话、静默对端拖不住 accept、需要并校验客户端证书、
验证过的 CN 在任何会话建立之前就已在 broker 手里），`cert_test.go` 5 个（证书即凭据、明文端口答不出
证书规则、未校验的证书不带身份、证书规则不覆盖离线队列、证书 + 密码两个都要中）。
`internal/rules` 的 26 个用例里有 8 个直接打在证书规则上（auth 侧 5 个、acl 侧 3 个，
外加 `TestACLActionAllRuleCoversBothActions`），包含 `cert_cn_match` 缺 `cert_cn` 这种
"约束会静默消失"的写法必须在装载期报错。

热加载这一层是另外 15 个用例。`internal/broker/reload_test.go` 5 个钉**语义**：新一代决定下一个 CONNECT、
重载不驱逐已连会话但按新规则判它的下一次发布、新一代拒掉的订阅立刻停喂、`acl_unsafe_expansions`
跨重载不归零、`SetRules(nil, nil)` 那一半是"关掉"而不是"沿用旧的"。`cmd/congmq/reload_test.go` 10 个钉**机制**：
Prometheus 文本必须覆盖 JSON 视图的每一个键（漏一个就失败）、文本格式合法、`/readyz` 在 drain 之后 503、
换叶子后下一个握手拿到新的、坏 PEM 被拒且此后**保持沉默**、过期叶子在轮换时同样被拒、被拒次数被记进指标、
一次改写只记一次、无 `-tls-addr` 时拒装证书规则、两个规则文件都没给就一个文件都不看。
后一个文件里的 `handshake()` 用的是真实回环 TCP 而不是 `net.Pipe`——`net.Pipe` 无缓冲且同步，
两边同时在刷证书那一段消息，握手会互相等死，测试直接挂住。

`reload-check` 里最值得看的三条（下面是它打印的原话，`->` 是证据）：

```
pass  a broken rule file is refused and counted once, not once per poll
        -> failures 0 -> 1 generation=3 (unchanged from 3) reloads=2
pass  a client certificate from the retired chain is refused even though its CN matches
        -> a retired certificate whose CN a rule still allows: ERR_SSL_TLSV1_ALERT_UNKNOWN_CA ... tlsv1 alert unknown ca
pass  no session was evicted by a policy swap or a certificate rotation
        -> device closes=0 offline=0 watch closes=0 offline=0 server_disconnects=0
```

第一条是"坏文件不记账两遍"，第二条是"名字不是凭据、验过的链条才是"，第三条是整个阶段的那句承诺。

传输头部这一层是 20 个 Go 用例加 30 个 Node 检查，两层的分工和 TLS 那层一样：
`internal/proxyproto` 的 8 个钉**字节**（v1 文本、v2 二进制的地址块顺序、`ver_cmd` 的两个 nibble
——`TestV2CommandNibblesAreTheSpecificationOwn` 就是钉"0x20 是 LOCAL 不是 PROXY"这一件事、
头部之后的剩余字节一条都不许吃、`ErrNotProxy` 必须消耗零字节、108 字节的行上限、空连接、真 socket）；
`internal/broker/proxy_test.go` 的 12 个钉**裁决**（require 拒绝非头部、两种头部形态都被接受、
头部和 CONNECT 挤在同一段里也要解析得开、名单外写头部被拒、名单内直连保留 socket 地址、
`LOCAL` / `UNKNOWN` 不算会话、静默对端在 header 超时那一刻被关掉、真实地址驱动每地址并发上限、
驱动凭据锁定、驱动 ACL 的 `ip` 规则、被离线会话记住，以及 `ProxyOff` 一个头部都不读）。
`proxy-check.mjs` 那 30 条钉的是**跨语言**：迷你前置在本进程里按规范逐字节写头部，会话是普通 mqtt.js 客户端，
所以如果解析器读错了 nibble 或读错了偏移，症状就是"规则永远不命中"，而不是某个测试红了。它最值得看的三条：

```
pass  the same credentials from another claimed address are refused
        -> refused:Connection refused: Bad username or password
pass  and is the counter that says somebody tried
        -> {"refused":1,"auth_rejected":2}
pass  two devices behind one balancer are two addresses to the gate
        -> {"entries":2,"refused":0}
```

第一条是"头部里的地址真的进了 auth"（注意它回的是**凭据**拒绝而不是头部拒绝——规则看见了设备，只是不喜欢它报的那个地址）；
第二条是"有人试过伪造，而且这件事只存在于计数器里"（日志被节流，对端什么也收不到）；
第三条是整个功能的存在理由：一个前置后面的两台设备，在闸门眼里必须是两个地址，否则 `-max-conns-per-ip`
会把一整批设备算成一台很吵的机器。

`crash-check` 里两个值得看的数字（下面是它打印的原话，`->` 是证据）：

```
# 第一档 -store-sync always：遗嘱立起来之后不到一秒就 kill -9
pass  the restart reports three sessions, one retained message and one owed will
        -> level=INFO msg="store open" ... sync=always sessions=3 retained=1 wills=1
pass  all 10 offline messages came back, in order and exactly once
        -> dev/data:q1,dev/data:q2,...,dev/data:q10
pass  the watcher that never resubscribed was still subscribed
        -> will/state:node went dark
pass  the will fired 12.1s after the node died, on the original deadline

# 第二档 everysec：两批各 100 条，第二批 PUBACK 之后几毫秒就 kill -9
pass  every message that had passed a flush tick came back, and only the newest ones could be missing
        -> older burst 100/100, newer burst 0/100
  measured window: 0/100 of the newest burst survived the kill, so 100 acknowledged messages
  were the sub-second everysec agreed to give up
```

过了 flush tick 的一百条全回来、没过的零条回来——everysec 那一秒的窗口是真的，不是文案。

---

## 9. 容量基线（实测）

这一节的数字是跑出来的，不是估的。复现：

```bash
go build -o bin/congmq ./cmd/congmq && go build -o bin/congmq-load ./cmd/congmq-load \
  && go build -o bin/congmq-cert ./cmd/congmq-cert     # 最后一个只给 TLS 那一组用
(cd test && node load-baseline.mjs)      # 29 行 × 10s，约 6 分钟，写 test/baseline-<日期>.md
(cd test && node load-baseline.mjs --groups=gate)        # 只跑闸门那一组，约 1 分钟
(cd test && node load-baseline.mjs --groups=proxy --out=proxy-baseline-run.md)   # 头部那一组，约 1.5 分钟
```

每行一个**独立 broker 进程 + 独立 `-store` 目录**，流量由 `cmd/congmq-load` 打——它用
`internal/packets`，和服务端同一套编解码，所以任何一个数字都不能用"第三方客户端不行"解释掉。
脚本最后会自己核对压测端的 `delivered` 与 broker 的 `messages_out`，本次 **16/16 行相等**（pump / 载荷 / 扇出 / fsync / TLS 五组共 16 行有投递；连接、闸门、头部三组共 13 行是纯建连，没有投递可对）。
闸门那一组还要反过来对一次账（`connect_errors` 必须被 broker 的拒绝计数解释掉，4/4 行成立）；
头部那一组这两道都查，外加第三道：开了头部的行，`connections_over_proxy_header` 必须**等于**压测端连上的条数，`off` 那一行必须**等于 0**——这一道防的是"表里这一行其实根本没走头部"，行标签说了不算，broker 自己的计数器说了才算（本次 6/6 行成立）。
任何一项不等就 `exit 1`，表不会安静地产出。

环境：`win32 10.0.26100 x64` · 12 逻辑核 i5-12400F · 31.8 GiB 内存 · 压测端与被测端同机 loopback ·
Go 1.27.3 · `test/baseline-2026-11-03.md` 是这批数字的原件（含逐行 JSON），闸门那一组是
`test/gate-baseline-2026-11-03.md`、头部那一组是 `test/proxy-baseline-run.md`（都是同一台机器上另起 broker 单独跑的两批；
这两批的 broker 与压测端都是同一份源码另 build 的 `.tmp/congmq.exe` / `.tmp/congmq-load.exe`，
因为 `bin/congmq.exe` 当时被一个开发实例占着，Windows 写不进去——两份原件的表头就写着它们各自用的哪一份）。
每一行的 broker 都带 `-reload-interval 2s` 启动，也就是说下面所有数字都是**热重载开着的时候测的**。
文中「上一批」指本文件此前发布的那一批，它的运行原件留在 `test/baseline-run-pre-b1.log`；
再早的一批（没有 TLS 对照行的那一批）留在 `test/baseline-2026-11-03-0349z.md`。跨批引用只引这两个文件里的数。

读表三条规矩，先说清楚免得被误用：

- 这是**同机 loopback 的下限**，不是 SLA。压测端和服务端在抢同一份 CPU，真实部署通常更高。换机器要重跑。
- 单跳延迟低于本机时钟 tick 就分辨不出来（逐行 0.31–0.51 ms）。`†` 的意思是"比一个 tick 还短"，不是 0 ms。
- 饱和行里的 `dropped` 是**设计行为**：在线会话的运行队列按 `-queue-max`（默认 1000）丢最旧的，
  它回答"已经饱和了"。但**别拿它比较任何东西**——表里 5.0 与 3.1.1 那两行配置只差协议版本，
  在途窗口两边都是 100，`dropped` 在三批里分别是 5,750 对 54,531、4,627 对 27,059、5,303 对 4,821：
  第二批 3.1.1 高 5.8 倍，这一批两边持平。同一个格子换一批跑就见过 5.6× 的差（3.1.1 那行 27,059→4,821），
  所以它是噪声，不是结论。

### 连接成本

| 连接数 | 建立 conn/s | 失败 | goroutines | mem_sys (MiB) | 每连接预留 | 每连接活跃 | 活跃/连接（刚建完） |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1,000 | 11,754 | 0 | 3,011 | 70.0 | 60.9 KiB | 28.7 KiB | 28.6 KiB |
| 5,000 | 11,265 | 0 | 15,011 | 290.9 | 58.2 KiB | 28.7 KiB | 28.6 KiB |
| 10,000 | 10,063 | 0 | 30,011 | 561.6 | 56.4 KiB | 28.3 KiB | 28.3 KiB |

一条连接的成本是**常数**，不是随规模上涨的曲线：活跃堆在 1k→10k 之间稳定在 28.3–28.7 KiB/条，
goroutine 恰好 3 条/连接（`internal/broker/broker.go:430-432` 的 readLoop / writeLoop / stateLoop），
一万个连接建完零失败、零拒绝，建立速率约 1.0–1.2 万 conn/s。`每连接预留`（`mem_sys`，含三条 goroutine
的栈和 span 取整）是活跃值的两倍，1k→10k 的斜率是 55.9 KiB/条——估机器内存要用这个斜率，不是活跃值。
最后两列是"刚建完"与"等过 GC 之后"的对比，这次实测差 ≤0.1 KiB，说明这批连接没让 GC 欠账；
哪一天它们差开了，差值就是还没回收的临时分配。
和上一批（没有热重载的二进制）逐行相减，goroutine 在 1k/5k/10k 三行都是 **+1**（3,010→3,011、
15,010→15,011、30,010→30,011），空闲进程自己是 10→11 条：多出来的那条就是轮询规则与证书的重载协程。
`mem_sys` 是 70.0 / 290.9 / 561.6 MiB，上一批 70.0 / 311.5 / 622.2——1k 那行一模一样，后两行这一批还**更低**，
所以那点差是抖动，不是重载器；重载器的成本只在协程那一列看得见。**不停机运维的价格是一条协程**，
连接数再多也不涨。

### 接入闸门的代价（per-address gate）

同一份二进制、同一批 3,000 条连接，只差启动参数（原件 `test/gate-baseline-2026-11-03.md`）：

| 场景 | 计划建连 | 连上 | 压测端报错 | broker 在线 | 闸门拒绝（并发/速率） | 表项/持有 socket | goroutines | mem_sys (MiB) | 每连接活跃 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 闸门全关（默认） | 3,000 | 3,000 | 0 | 3,000 | 0 / 0 | 0 / 0 | 9,011 | 172.8 | 27.9 KiB |
| 闸门开着但一个都没卡 | 3,000 | 3,000 | 0 | 3,000 | 0 / 0 | 1 / 3,000 | 9,011 | 188.7 | 27.8 KiB |
| `-max-conns-per-ip 500` | 3,000 | 500 | 2,500 | 500 | 2,500 / 0 | 1 / 500 | 1,511 | 41.5 | 32.0 KiB |
| `-conn-rate-per-ip 300` | 3,000 | 343 | 2,657 | 343 | 0 / 2,657 | 1 / 343 | 1,040 | 33.5 | 33.5 KiB |

四行读出来的结论：

- **关着就是不存在的**：表项 0、持有 0、两个拒绝计数 0，启动日志里连 `per-address gate armed`
  那一行都没有。9,011 条 goroutine = 3×3,000 + 11，和上面那张连接成本表的斜率严丝合缝。
- **开着但没咬到人也不收费**：两行都是 3,000 条全上来，ramp 256ms 对 259ms（11,696 对
  11,569 conn/s，差 1.1%）、goroutine 一模一样 9,011、每连接活跃 27.9 对 27.8 KiB。`mem_sys`
  那 16 MiB（9%）的差是 Go 什么时候决定多拿一页的问题——同一份代码两次跑批见过比这更大的差
  （见上面 `dropped` 那段）——活对象那一列没有变贵，装了闸门的进程反而比全关那行少 0.4 MB。
- **咬人的时候，账是平的**：`连上 + 闸门拒绝 = 计划建连`，两行都精确成立（500+2,500、343+2,657），
  而且 `broker 在线` 始终等于 `连上`——被关掉的那部分从未变成会话，一条 goroutine、一份读截止都没占。
  300/s 那行落进 343 条，是令牌桶的算术：burst 300 加上爬坡 146ms 里补进来的 43。
- **这就是它的意义**：同样一场 3,000 条的建连风暴，内存从 172.8 MiB 回到 41.5 MiB，协程从
  9,011 回到 1,511（限速那行 1,040）。能被占多少资源，由你给的那个数字决定，不再由对面发多少连接决定。

每连接活跃在咬人的两行略高（32.0 / 33.5 对 27.9 KiB）是**基数效应**：那一列是从 `settled - 建连前`
再除以在线数算的，只剩 500 条甚至 343 条时进程自身的固定开销摊薄不足。上面 1k 那行（28.7）比 10k 那行（28.3）
高也是同一个原因，不是连接变贵了。

这一组只测了"每条都发了 CONNECT"的建连风暴。一个字节都不发的裸 socket 那一维不在这里——
压测端的每条连接都会握手，它看不到那种负载；那由 `test/abuse-check.mjs` 的 `silentSocket`
和 `internal/broker/abuse_test.go` 覆盖（§8）。

### 传输头部的代价（PROXY protocol）

同一份二进制跑了六行：前四行只差启动参数和压测端写不写头部，后两行是同一个闸门配置的两种地址来源
（原件 `test/proxy-baseline-run.md`，头部由 `cmd/congmq-load -proxy-header v1|v2` 自己写——
它在 TLS 包装之前、按规范和 nginx 一样的位置写，所以这一组测的是**本机解析这一层的代价**，
不含真实前置那台机器抢 CPU 的那一维）：

| 场景 | 计划建连 | 连上 | 压测端报错 | broker 在线 | 头部会话/头部拒绝 | 闸门拒绝 | 表项/持有 socket | goroutines | mem_sys (MiB) | 每连接活跃 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 3,000 长连接 · 头部 off（默认） | 3,000 | 3,000 | 0 | 3,000 | 0 / 0 | 0 | 0 / 0 | 9,011 | 189.0 | 27.6 KiB |
| 3,000 长连接 · require + v1 文本 | 3,000 | 3,000 | 0 | 3,000 | 3,000 / 0 | 0 | 0 / 0 | 9,011 | 184.7 | 29.2 KiB |
| 3,000 长连接 · require + v2 二进制 | 3,000 | 3,000 | 0 | 3,000 | 3,000 / 0 | 0 | 0 / 0 | 9,011 | 180.9 | 28.8 KiB |
| 3,000 长连接 · trusted + v1（名单 127.0.0.0/8） | 3,000 | 3,000 | 0 | 3,000 | 3,000 / 0 | 0 | 0 / 0 | 9,011 | 188.5 | 29.5 KiB |
| 1,000 长连接 · 闸门 600 + 两个申报地址（require + v1） | 1,000 | 1,000 | 0 | 1,000 | 1,000 / 0 | 0 | 2 / 1,000 | 3,011 | 70.0 | 29.4 KiB |
| 1,000 长连接 · 同一闸门、头部 off（对照） | 1,000 | 600 | 400 | 600 | 0 / 0 | 400 | 1 / 600 | 1,811 | 45.5 | 29.2 KiB |

- **稳态协程一条不多**：四行 3,000 连接的 goroutine 全是 9,011，和上面那张连接成本表的 3×N+11 完全一致。
  开了头部的路径确实多一条**短命**协程——`handleOne` 把读头部挪进协程里，就是为了让一个连上就沉默的对端
  占不住 accept 循环（§4）；但 9,011 这个数说明这些协程在取样时已经全部退出——多的那条协程是短命的，
  常驻的是下面那一列说的那点内存。v1 与 v2 之间也分不出差（29.2 对 28.8 KiB，ramp 213ms 对 211ms）。
- **每连接活跃 +1.2~1.9 KiB**（27.6 → 28.8/29.2/29.5），三行头部都在这个区间、方向一致，所以量级可以采信；
  但别读成精确值——同一份 `off` 配置在闸门那批测的是 27.9 / 27.8 KiB，比这一批的 27.6 还高，
  说明这一列本身有 ±1 KiB 的行间抖动。按上限算，一万个连接多摊 12–19 MiB。
  这一层的常驻结构本来就装不下 1.5 KiB：包装一个 `net.Conn` 加它那个 128 字节的读缓冲
  （`internal/broker/proxy.go:168`，缓冲解析完不丢，后面的报文解码继续从它里面读），
  剩下的多半在栈上——读路径从此多绕一层接口。`mem_sys` 那一列反而开了头部的更低（180.9–188.5 对 189.0），
  再次印证 Go 什么时候多拿一页不由这一层决定。
- **ramp 那一列不能反过来读**：`off` 是这一批的**第一行**，10,513 conn/s 对后面三行的 14,070–14,209。
  头部不会让建连变快，那是第一个进程独占了页错误和 GC 起步的代价。要看建连速率就横向比同批的后三行。
- **真正值得看的是最后两行**：同一个 `-max-conns-per-ip 600`、同样 1,000 条连接。头部关着时这 1,000 条
  全从一个 socket 地址进来，闸门眼里只有**一个表项**，于是 600 的含义悄悄变成"这台前置总共 600 条"，
  第 601 到第 1,000 条被关掉（`闸门拒绝 400`、`连上 + 拒绝 = 计划建连` 依然严格成立）。
  头部开着、申报两个地址时，表项变成 **2**，1,000 条全部被持有，闸门一次都没咬。
  **这一对数字就是整个功能的存在理由**：600 这个数在两种情况下含义完全不同，
  而关掉那一行的 400 条设备只看到"连不上"，broker 侧一切正常。
- **开了头部那行更贵，是它在工作**：70.0 MiB / 3,011 协程 对 45.5 MiB / 1,811，差的正是多出来的 400 个真会话。
  传输头部不是省资源的开关，它让该进来的进来。
- **卡在头部不放的连接不会常驻**：只写了十二字节签名、后面的内容不写完的对端，在 `-proxy-header-timeout`
  到点时被关掉并记一次 `refused_over_proxy_header`。这时会话、队列、订阅都还没建，占的是那一条短命协程
  和它的读缓冲。`test/proxy-check.mjs` 用 `-proxy-header-timeout 400ms` 的 broker 钉住这两件事：
  几百毫秒内断开（不是等满预连接窗口），且计数器加一。

一组里 6/6 行的 `connect_errors` 都能被 broker 侧的拒绝计数解释掉（唯一的 400 条 = 闸门 400 + 头部 0），
且四个开了头部的行 `connections_over_proxy_header` 精确等于各自的 `连上`、两个 `off` 行精确等于 0——
所以这张表读的是什么，是 broker 自己报的，不是行标签说的。

### QoS 吞吐

| 场景 | msg/s | ≈Mbit/s（载荷+20B） | 已投递 | p50 | p90 | p99 | goroutines | mem_sys (MiB) | dropped | spills |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| QoS 0 · 8 发 8 收 · 256 B（压到饱和） | 256,163 | 565.6 | 2,562,517 | 42.67 ms | 60.94 ms | 76.13 ms | 59 | 25.5 | 0 | 0 |
| QoS 1 · 8 发 8 收 · 256 B（压到饱和） | 106,214 | 234.5 | 1,057,167 | 20.80 ms | 49.78 ms | 77.82 ms | 59 | 25.5 | 5,303 | 0 |
| QoS 2 · 8 发 8 收 · 256 B（压到饱和） | 51,921 | 114.6 | 519,278 | 31.46 ms | 74.10 ms | 128.10 ms | 59 | 21.6 | 59 | 0 |
| QoS 1 · 8 发 8 收 · 256 B · 限速 5k/s（现实速率的延迟） | 5,000 | 11.0 | 50,003 | ≤0.50 ms† | ≤0.50 ms† | ≤0.50 ms† | 59 | 17.8 | 0 | 0 |
| 3.1.1 QoS 1 · 8 发 8 收 · 256 B（压到饱和） | 100,213 | 221.3 | 997,805 | 23.66 ms | 54.81 ms | 79.45 ms | 59 | 25.2 | 4,821 | 0 |

- **每升一档 QoS，吞吐大致对半砍**：256k → 106k → 52k（2.4× 与 2.0×；上一批是 2.1× 与 2.0×）。
  这是握手轮数换来的，没有别的解释。选 QoS 就是选这个 2×。
- **3.1.1 不比 5.0 快**：三批分别是 5.0 输 4%（105,456 对 109,547）、赢 12%（107,646 对 96,123）、
  赢 6%（106,214 对 100,213）。合起来说的就是"同一量级"——别指望"降级到 3.1.1"能省出性能。
- **饱和时的 21–43 ms p50 是队列，不是网络**：压到饱和就是在测量 broker 愿意堆多深的队列。
  运维真正要的是"没堵的时候一跳多少钱"，所以有第四行——限速 5k/s 时 p50、p90、p99 全落在这一行自己的
  时钟 tick（0.50 ms）以内，**分辨不出具体值，只能确定小于 0.5 ms**（前两批的 p99 是 768 µs 和 1.17 ms）。
  真实负载离饱和很远，看第四行，别看前三行。
- 内存那一列别过度解读：17.8–25.5 MiB 之间摆的是压测端连接数相同、在途报文数不同，
  broker 本体在这个量级上既不随 QoS 涨，也不随协议版本涨。

### 载荷大小

| 场景 | msg/s | ≈Mbit/s（载荷+20B） | 已投递 | p50 | p90 | p99 | goroutines | mem_sys (MiB) | dropped | spills |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 载荷 64 B · QoS 1 | 89,448 | 60.1 | 891,641 | 22.44 ms | 56.01 ms | 89.62 ms | 59 | 25.5 | 3,050 | 0 |
| 载荷 256 B · QoS 1 | 95,582 | 211.0 | 953,994 | 20.44 ms | 53.40 ms | 84.77 ms | 59 | 25.5 | 1,917 | 0 |
| 载荷 1024 B · QoS 1 | 99,320 | 829.5 | 991,205 | 20.56 ms | 49.36 ms | 78.52 ms | 59 | 29.2 | 2,239 | 0 |
| 载荷 4096 B · QoS 1 | 85,245 | 2806.9 | 779,295 | 74.52 ms | 106.19 ms | 127.58 ms | 59 | 114.8 | 73,330 | 0 |

**64 B 到 1 KB 的三个点都在 8.9–10.8 万 msg/s 里摆动（这批 89,448/95,582/99,320，上一批
92,693/107,899/93,291，差值在噪声内），但带宽涨了 13.8 倍**——这个区间瓶颈是每秒报文数（CPU、每包一写），
不是字节。**到 4 KB 才换人**：p50 从 ~20 ms 跳到 75 ms、`mem_sys` 从 29 MiB 涨到 115 MiB、
`dropped` 从两千涨到 7.3 万。**结论：报文小于 1 KB 时按 msg/s 规划，大于 1 KB 时按 Mbit/s 和内存规划。**

### 扇入扇出

| 场景 | msg/s | ≈Mbit/s（载荷+20B） | 已投递 | p50 | p90 | p99 | goroutines | mem_sys (MiB) | dropped | spills |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 发 8 收 · 同一主题（扇出 ×8） | 21,551 | 47.6 | 1,724,432 | 5.79 ms | 9.17 ms | 13.75 ms | 38 | 21.8 | 0 | 0 |
| 8 发 0 收 · QoS 1（纯入站） | 183,660 | 405.5 | 0 | — | — | — | 35 | 21.2 | 0 | 0 |

- 一个发布者对八个订阅者，**投递跑到 ~172,400 次/秒**（1,724,432 ÷ 10s），而入站只有 21,551 msg/s——
  限制是**那一条发布者连接**的编码与写出，不是 broker 的分发。反过来，八个发布者对八条订阅连接时投递能到
  10.6 万/s（QoS 吞吐表第一档除外）。所以"一个主题很多人订阅"按分发次数算，"很多人发布"按连接算。
- 纯入站（没人订阅）183,660 msg/s，端到端 QoS 1 只有 106,214，**差 1.73 倍**（上一批 1.85 倍）：
  订阅侧的写出与在途窗口才是主要成本，路由和落盘不是。这一行也是表里 `—` 的来源——没有投递就没有 hop 可测，
  压测端不猜。

### 三档 fsync 的代价（离线队列落盘）

| sync 模式 | msg/s（实发） | 已投递 | p50 | p99 | state.log | 每条落盘 | spills | dropped | 丢失窗口 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| everysec | 2,882 | 13,708 | 142.40 ms | 171.65 ms | 28017.2 KiB | 995 B/条 | 49,648 | 49,648 | ≤1 s |
| always | 222 | 978 | 2159.13 ms | 2394.74 ms | 2255.1 KiB | 1039 B/条 | 0 | 0 | 0（每条落盘） |
| never | 2,908 | 14,057 | 137.27 ms | 170.32 ms | 28037.5 KiB | 987 B/条 | 50,168 | 50,168 | 整个进程 |

四件事，只有压测会告诉你：

1. **`everysec` 在这一档负载上是免费的**：2,882 vs `never` 的 2,908 msg/s（0.9%），p50 142 vs 137 ms——
   差别在噪声里，但换来了"最多丢 1 秒"。默认值是对的，不用为了性能把它改成 `never`。
2. **`always` 收 13× 的税，而且税打在在线投递上**：222 msg/s，在线订阅者 p50 **2.16 秒**、p99 2.39 秒。
   fsync 不是只拖慢落盘那一条路，它把整个 broker 的节拍拖慢了。
3. **磁盘增长看"每条落盘"，而且它和 fsync 档无关**：三档都是 987–1039 B/条，128 B 的消息被放大约 8 倍。
   因为追加日志每次重写整个会话快照（含队列），`-queue-max` 越大这个放大越狠。
   **选 `always` 不会让磁盘长得更慢，选 `never` 也不会让它长得更少**——fsync 改的是等待和丢失窗口。
4. **`spills` 在 `always` 行是 0，别读成"`always` 不丢消息"**。它是慢到 8 个离线会话的队列
   （`-queue-max` 1000）根本没满；`everysec`/`never` 那 ~5.0 万次裁剪对应的是同一段负载下队列被填满后丢最旧。
   这一列跨行不可比——比较三档 fsync 只看吞吐和延迟分位，因为它们才是同一速率下的对照。

### TLS 的代价（同一配置，只差一层加密）

| 场景 | msg/s | ≈Mbit/s（载荷+20B） | 已投递 | p50 | p90 | p99 | goroutines | mem_sys (MiB) | dropped | spills |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| QoS 1 · 8 发 8 收 · 256 B · 明文 | 95,475 | 210.8 | 953,134 | 21.57 ms | 50.80 ms | 77.66 ms | 59 | 21.5 | 1,925 | 0 |
| QoS 1 · 8 发 8 收 · 256 B · TLS（服务端证书） | 94,928 | 209.6 | 949,013 | 18.41 ms | 41.95 ms | 65.89 ms | 60 | 25.5 | 319 | 0 |

两行**配置完全相同**（8 发 8 收、QoS 1、256 B、`-window 100`、同一二进制），只差 TLS 那一层；
这一行的传输标记是 `transport = tls1.3`（压测端只记录**首个握手**谈成的版本，所以它说明的是这一批走的是 1.3，
不是逐条连接都验过），逐条连接的证据在 broker 侧：`connections_tls = 16`、`tls_handshake_failures = 0`、
`published == acknowledged == 949,332`，投递与 broker 的 `messages_out` 逐条相等（949,013）。
协程那一列 TLS 比明文多一条（60 对 59）：那是 TLS 监听器自己的 accept 循环，两行连接数相同，所以它不随连接涨。

- **稳态吞吐的代价低于噪声**：这一批 0.6%（95,475 → 94,928 msg/s），上一批 1.8%。加密本身在这台机器上
  几乎不收租，因为 AES-NI 让 256 B 的记录加密便宜到看不见，瓶颈仍是每秒报文数（与"载荷大小"同一解释）。
- **尾延迟别再写"TLS 收税"**：上一批是 p50 +5%、p90 +9%、p99 +11%，这一批**反过来**——TLS 行的
  p50/p90/p99 分别低 15%、17%、15%。两批连符号都不一致，说明饱和队列自身的抖动（几十毫秒）比 TLS 的
  每包开销大一个量级，所以这里既不能说它贵也不能说它快。**能说的只有：按吞吐规划时留 2% 就够，
  p99 的余量应该花在队列深度上，不是花在 TLS 上。**
- **握手钱只花在建连那一刻**，所以这两行看不到它：pump 模式不测建连速率，而矩阵里的 TLS 组暂时只加了
  pump 行，**没有 TLS 版的"连接成本"行**。要那个数字得先把 `tls` 接进 `--groups=conns`，
  这里不猜——没测过的就不写进表。
- `dropped` 那两格（1,925 对 319）是**同一行跨批的噪声**，见本章开头第三条规矩，别读成"TLS 更少丢消息"。

### 建连那一刻的 TLS：目前只有定性结论

一条 mTLS 连接 = TCP 三次握手 + TLS 1.3 握手（1-RTT）+ MQTT CONNECT，只在建连时付费。
运维真正要防的是握手被拿来耗资源，所以 broker 把握手放在**独立协程**里、并用
`-tls-handshake-timeout`（默认 10s）封顶：一个只建 TCP 不发数据的对端最多占住一个短命协程，
**拖不住 accept 循环**（`internal/broker/broker.go:448` 的 `acceptTLS`，被
`internal/broker/tls_test.go:358` 的 `TestSilentPeerDoesNotStallTheTLSPort` 钉住）。
代价是每握手失败一次记 `tls_handshake_failures`，且 `total_connections` 不加——连接数没涨而这条涨，
就是有人在试门。

### 一台机器撑多少设备

按实测的 **28 KiB 活跃 / 56 KiB 预留** 每条连接（预留用 1k→10k 的斜率 55.9 KiB/条），再乘 GC 余量
1.5–2×，然后加上第二条内存项——离线队列里的消息是**真的在内存里**
（`internal/broker/session.go:29` 的 `queue []*task`，每条带 payload）：

| 长连接 | 活跃堆 | 进程预留（实测外推） | 建议机器 | 依据 |
| --- | --- | --- | --- | --- |
| 1,000 | 28 MiB | 70 MiB | 256 MiB | 实测点 |
| 10,000 | 276 MiB | 562 MiB | 1.5 GiB | 实测点（零失败、零拒绝） |
| 50,000 | 1.35 GiB | 2.7 GiB | 6 GiB | 从 1,000 那个实测点按斜率外推 |
| 100,000 | 2.70 GiB | 5.4 GiB | 12 GiB | 同上；没实测过，先在 10k 点上验证斜率再往上乘 |

外推用的是 `预留(N) ≈ 70 MiB + (N−1000) × 55.9 KiB`，不是 `N × 55.9 KiB`——后者把进程自身的固定开销
摊成零，N 越小越离谱（1k 那一格两种算法差 22%，10k 差 2.7%）。斜率跨批是摆的：留在 `test/` 的三份原件
分别算出 61.1、62.8、55.9 KiB/条；拿上一批的 62.8 回算这一批的 10k 得 622 MiB，实测 562，高 10.7%。
**所以 50k / 100k 那两格的误差是百分之十，不是数量级**——要更准就在自己的机器上跑到 10k，用实测斜率再乘。

再叠上这两项才是完整预算：

```
离线队列 = 离线会话数 × -queue-max × 平均报文字节     ← 内存和 state.log 双份，通常是磁盘的主要增长源
在途报文 = 连接数 × min(-inflight-window, 对端 Receive Maximum) × 平均报文字节
```

离线队列那一行的两个系数是实测来的，不是 `平均报文字节` 本身：
24,000 条 256B 的消息压在 20 个离线会话里，活跃堆从 0.4 MiB 涨到 8.4 MiB（≈ **350 B/条**，含 payload 与
`Message` 头部、切片的对齐损耗），会话被回收之后回到 0.5 MiB——这条在 `internal/broker/memory_test.go` 里钉着。
同一批消息写进 `state.log` 是 **517 B/条**（浸泡实测峰值 35,492 条 ↔ 17.5 MB 文件）：JSON 里 payload 走 base64
（256B → 342B），再加主题、packet id、字段名。**所以磁盘按消息条数乘 500B 估，别按报文大小估。**
还要记住 §6 那条：文件缩回的前提是追加量再过一遍压缩阈值，所以磁盘的下限是**峰值驻留**而不是稳态驻留。

吞吐侧：这台机器 QoS 1 端到端 10.6 万条/秒（压测端同机抢 CPU，独占部署更高），
5 万条设备 × 每 10 秒 1 条 = 5 千条/秒，离饱和差一个数量级——**设备数先撞内存，速率后撞 CPU**。
加密与否对这个结论没有影响（TLS 那两行差 0.6%，见上面）。

### 这套表怎么保证不是假数字

压测最容易出的错是数字错了还看不出来。六道防线，都已经写进脚本，不是写在文档里：

- **压测端和服务端共用一套编解码**（`internal/packets`），出了问题只有一个责任方；用第三方客户端打，
  第一次异常永远是"客户端实现不行"。
- **两个独立计数器必须相等，而且脚本自己查**：`load-baseline.mjs` 收尾时逐行比对压测端的 `delivered`
  与 broker 的 `messages_out`，不等就 `exit 1` 并把不等的行名列出来。这条抓到过一个真 bug——
  QoS 0/2 的投递在 PUBACK/PUBCOMP 那两条腿上各多算一次，整整高一倍。
- **`TCP_NODELAY` 是必需的，不是调优**：broker 在 accept 里关 Nagle（`internal/broker/broker.go:482`），
  压测端在 dial 里关（`cmd/congmq-load/main.go:284`）。Nagle 撞上对端的延迟确认定时器，一个来回要等
  几十到几百毫秒——那次实测里八个 QoS 1 发布者从约 1.2k 跳到约 90k msg/s。
  **一个开着 Nagle 的 broker，测的是两个定时器，不是它自己。** 开 TLS 之后这条更容易漏：
  `SetNoDelay` 属于底层的 `*net.TCPConn`，套上 `tls.Conn` 就摸不到了，所以两端都在**包装之前**设。
- **延迟不骗自己**：本机 `time.Now()` 的步进实测 0.31–0.51 ms，亚毫秒的单跳用同进程共享的单调基准
  （`time.Since(procStart)`）打时间戳，每行自己的 tick 也写进 JSON；低于 tick 的格子印 `†`，不印 0 ms。
- **闸门与头部那一组还多加一道反向对账**：一条被关掉的连接，压测端看到的是"建连失败"，broker 看到的是
  "拒绝了一次"，所以脚本要求 `connect_errors` 必须能被 broker 侧的拒绝计数（闸门两种 + 头部一种）解释掉，
  解释不掉就 `exit 1`。
  它一上来就抓到过一张假表：第一版把 10,000 条连接的行连跑四遍，从第二行起 Windows 的动态端口范围
  已经不够用，表里那 2,109 条"失败"其实是压测端自己没拿到 socket——同一时刻 broker 的闸门拒绝数是 **0**。
  没有这道对账，那张表读起来就像"限流只挡住了一半"。现在这些行缩到 3,000 条，四行都对得上
  （500+2,500、343+2,657 都正好等于计划建连数）。
- **头部那一组还要证明"这一行真的走了头部"**：行标签说自己开了 `require + v1`，但那只是脚本的参数，
  broker 可能压根没读到头部（压测端忘写、写歪、被前面的分支绕开）。所以脚本再要求一次：
  开了头部的行 `connections_over_proxy_header` 必须**等于**压测端连上的条数，`off` 的行必须**等于 0**。
  它把"这一行读的是什么"从脚本的自述变成 broker 的证词——上面那张表六个行里，四个开了头部的各自等于
  那一行的连上数，两个 `off` 的各自等于 0。

顺带记两个压测端自己的坑，都会把数字打得"看起来很糟"：令牌桶的容量下限要留 1 个令牌，
否则 `-rate` 给小了会永久饿死；每行必须换独立 broker 进程和独立 `-store`，
否则上一行的内存、计数器和落盘状态会混进下一行。

---

## 10. 上线检查清单

1. **`-max-packet-size` 必须设**。留 `0` 时上限是协议的 256MB，最坏内存 ≈ `256MB × 连接数`，
   一个恶意客户端 announce 大报文就够打穿（解码器在 `make([]byte, n)` **之前**查这个上限，
   见 `internal/packets/decode.go:190` 与它的 `TestDecodeFrameLimitedRefusesBeforeAllocating`，
   所以设了就是真拦得住）。稳态实测是每条连接 28 KiB，见 §9——公式给的是最坏情况，基线给的是稳态。
   建议 `max-packet-size × max-conns` 与进程内存上限一起算。
2. **`-max-conns` 按业务量设**，别用默认不限。每连接 56 KiB 预留是实测值（§9 的 1k→10k 斜率），
   乘上去就是内存下限，再加离线队列那一项。
   要不要再加**按地址**的那三个（`-max-conns-per-ip` / `-conn-rate-per-ip` / `-auth-fail-limit`），
   取决于你的入站形状，先量一遍 `/metrics` 里的 `per_ip_gate_*` 和 `auth_*` 再决定，别一次全开：
   ① 机队在一个 NAT 出口后面 → 按地址限会一次锁掉一整批设备，这种拓扑该用的是 `-max-conns` 和规则里的 `clientid`；
   ② 前面挂了云 LB 且**没有 PROXY protocol**（见第 4 条）→ 所有连接的来源地址都是那台 LB，
   按地址设限等于给 LB 设限，锁定更是会把整个入口一起锁掉；
   ③ 公网直挂、且日志里见过扫端口的（`auth_rejected` 在涨而 `online` 没涨）→ 这三个正是为这种场景准备的，
   从宽往严收：`-max-conns-per-ip` 给到单地址实际峰值的 2–3 倍，`-conn-rate-per-ip` 用 `0.5` 这类小数起步。
   开之前先跑一遍 `npm run abuse-check`，它会把四个 broker 的裁决和拒绝计数都打给你看（§8）。
3. **TLS 自己终结**：`-tls-addr :8883` + `-tls-cert/-tls-key`，要认设备就再加 `-tls-ca`（那就是 mTLS）。
   先用 `./bin/congmq-cert -out /etc/congmq/pki -days 365 -dns <客户端实际连的那个名字>` 造一条链把通路跑通，
   再换成真证书。三个坑：
   ① SAN 必须含客户端用的那个名字（连 IP 就得有 IP SAN），否则客户端拒链条，`tls_handshake_failures` 涨而
   `connections_tls` 平；② 给了 `-tls-ca` 就是**要求**客户端证书，机队里有一台没刷证书就连不上，
   迁移期先只上服务端证书（不给 `-tls-ca`），逐台换完再收口；③ 换证书**不用重启**——把新的
   `server.crt` / `server.key` / `ca.crt` 写回同一路径，一个 `-reload-interval` 周期之内下一个握手就答新一代，
   已经连着的会话继续用它握手时那一代（不会被打断）。但 broker **不续期**，到期前得有人把文件放上去，
   所以给 `tls_cert_not_after_unix` 设告警（§7）。
   仍然放在云 LB / Nginx 后面也可以，而且那种拓扑下的来源地址现在有解了：前置写 PROXY protocol 头部、
   broker 读它（下面第 4 条）。不读头部的话，`ip` 规则匹配到的是 LB，不是设备。
4. **前面挂了负载均衡就必须开 `-proxy-protocol`**，否则每一条按地址的裁决都在判错机器——闸门给 LB 限流、
   `ip` 规则永远命中不了、锁定会把整个入口一起锁掉、日志里的 `remote` 是一个内网 IP。两种形态选一种：
   ① 这个端口只允许前置访问 → `-proxy-protocol require`，直连进来的 socket 一律挂断。两者中更严的那个，
   它把"绕过前置直接打 broker"变成一件不可能的事，代价是这个端口再也收不了直连设备；② 这个端口既要收前置也要收直连 →
   `-proxy-protocol trusted -trusted-proxy-cidr <前置网段>`，名单外发头部的连接**被拒而不是被忽略**。
   云 LB 要显式打开 PROXY protocol（AWS NLB 两种版本都能发，nginx 的 `stream` 模块只发 v1 文本，
   `deploy/nginx/nginx.conf` 是可用的参照；其余厂商先确认自己那款发的是哪一版再配），并且**只打开这一个开关**——
   不要指望 LB 顺手证明地址是真的：
   头部里的地址是前置**说**出来的，不是被**证明**的（§11）。上真实拓扑前先跑 `npm run proxy-check`（§8），
   它会把"名单外伪造一个地址"和"前置没发头部"这两种故障分别打给你看。
5. **容器 / systemd 落地**：`deploy/docker-compose.yml` 是 nginx→broker 的完整拓扑，`deploy/systemd/`
   是两个单元文件（`congmq.service` + `/etc/default/congmq`）。三条要在自己的机器上确认的事：
   ① 镜像不带规则文件也不带证书，都用挂载进去（`/etc/congmq` 只读挂载就是热加载的入口，见 §2）；
   ② `docker build` 与 `compose up` 只在 CI 里被真跑过（见 §8），本机没装 Docker 就别说它"应该能起"；
   ③ systemd 那份 `EnvironmentFile` **不做变量展开**，所以 `/etc/default/congmq` 里是整行替换
   `CONGMQ_ARGS=...`，不是往里拼片段。
6. **`-metrics` 只绑 127.0.0.1** 或监控网段：三个口全都没有鉴权。`/readyz` 给 LB / 探针（drain 期间返回
   503，于是新连接被摘掉而最后的计数器仍可读），`/metrics.txt` 给 Prometheus 抓，`/metrics` 留给人 curl。
7. **`-store` 给独立可写目录**，并把它纳入备份/巡检范围（一个 `state.log` 就是全部状态）。
   文件系统选 ext4/xfs；网络盘上 fsync 的代价会被放大。容器里它就是命名卷——`compose restart` 之后
   `ls -l /var/lib/congmq/state.log` 还在，才算"换容器不丢状态"这句话被验证过（CI 的 docker job 每次都在做这件事）。
   目录里的第二个文件 `state.lock` 只被持有、不写内容，备份不需要它，也**别删**它（§6）。
   **一个 `-store` 目录只允许一个进程**：升级与回滚都要"先确认旧的退干净、再起新的"。新版本会拒绝第二个
   进程并 `exit 1`（两个进程各按自己的偏移追加，后写的把前者的记录盖掉，而 CRC 全对——实测这样丢过 20 条
   已确认消息，见 §6）；v1.0.0 没有这段代码，所以回滚方向只能靠流程保证。跨版本接管本身实测过双向
   （`npm run rolling-upgrade`：98 / 101 条离线消息跨版本一条不缺、会话 `sessionPresent=true` 不用重订阅、
   保留消息与延迟遗嘱照准点）。
8. **`-queue-max` 与 `-session-expiry-max` 一起设**：离线队列是无界磁盘占用的主要来源，
   后者封顶"客户端不回来"的会话存活时间。
9. 规则文件先在一台灰度机上验证再全量：**启动期**加载失败直接 `exit 1`（这是有意的）。
   **运行期**改写失败不会打断服务，但也**没装上**——所以推完别只看推送成功，去比一下
   `rules_generation` 加了几、`rules_reload_failures` 有没有从 0 动过（§5、§7）。
10. 热加载的三种形态先想清楚用哪种：默认 `-reload-interval 2s` 轮询（Windows 唯一可行）；
   unix 上想立刻生效就 `SIGHUP`；`-reload-interval 0` 表示**只认信号**——那种"改文件必须有人明确
   按一下"的流程，此时在 Windows 上等于不热加载，启动日志会直说。
11. systemd 例子（`ExecReload` 就是给 SIGHUP 用的；不配它也没关系，轮询本来就会查）：

```ini
[Service]
ExecStart=/usr/local/bin/congmq -addr :1883 \
  -store /var/lib/congmq -store-sync everysec \
  -auth /etc/congmq/auth.jsonl -acl /etc/congmq/acl.jsonl \
  -metrics 127.0.0.1:1884 -max-packet-size 1048576 -max-conns 5000
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
StateDirectory=congmq
```

崩溃恢复的手动验证（比读代码诚实）：

```bash
./bin/congmq -addr :1883 -store /var/lib/congmq &   # 起 broker
# 一个 cleanSession=false 的订阅者上线后掉线，再往它的主题发几条 QoS 1
kill -9 <pid>                                        # 模拟掉电/被杀
./bin/congmq -addr :1883 -store /var/lib/congmq &   # 重启
# 订阅者带 sessionPresent 重连，必须收到全部离线消息；保留消息和延迟遗嘱也在
```

这一步不用手工做：`cd test && node crash-check.mjs` 就是它的自动化版本（自己起进程、自己
`kill -9`、自己重启、用 mqtt.js 断言），上线前拿要部署的那个二进制跑一遍——
`CONGMQ_BIN=/usr/local/bin/congmq node crash-check.mjs`。10 项检查应当全绿，
其中 everysec 那一档会打印"最新 100 条里活下来几条"，那个数字就是你接受的丢失窗口。

启动日志里 `store open ... sessions=N retained=M wills=K` 就是恢复结果；
若上次是被硬杀的，还会有一条 `WARN the previous shutdown was not clean`。

---

## 11. 几个刻意的设计取舍

- **属性区用协议自身的编解码做持久化格式**，不另发明一套。MQTT 5.0 的 Properties 把
  "哪些属性出现过"记在一个非导出字段里，JSON/gob 反射都会悄悄丢掉它，所以它有
  `MarshalBinary`（即线上格式）+ 一层 base64 的 `MarshalJSON`。
- **TLS 走独立端口，不做 STARTTLS**。迁移期"两个端口并跑、按设备逐台换"比"一条端口两种语义"简单得多，
  代价是要开两个口、客户端要改 URL，而且明文端口永远存在——不想留就把 `-addr` 绑到只本机可达的地址，
  或者干脆只给 `-tls-addr`（`TestTLSOnlyBroker` 钉住了这种形态）。
- **握手放在独立协程里，并给它自己的超时**。看起来只是多一次调度，实际买的是"一个静默的对端拖不住
  accept 循环"——否则一个不发数据的客户端能让整个端口停 10 秒。
- **证书轮换挂在 `GetConfigForClient` 上，而不是重启**。每个握手先问"这一轮答哪一代"，回调把配置
  `Clone()` 一份、填进那一代的 leaf 与 pool，并把克隆里的 `GetConfigForClient` 置 nil（留着就是一个递归）。
  代价是每个握手多一次结构体拷贝——相对握手本身要做的非对称运算可以忽略；买回来的是
  "换证书不再是一次会让整个机队同时重连的发布"。启动期 `Certificates` 照常填满，
  所以"没证书就别开 TLS 端口"那条前置检查仍然成立。
- **热加载用轮询，不用 fsnotify**。零第三方依赖是这项目的立场，而 `(mtime, size)` 指纹 + 一次严格重读够用：
  文件被挪走、被 truncate、被写成半行 JSON，都表现为"这一次装载被拒、旧的继续在位"。
  代价是最坏要等一个 `-reload-interval`（默认 2s）；三个证书文件是分别替换的，
  一个正好落在中间的轮询会读到"叶子与私钥不配对"这种撕裂状态——它被拒、被计数，下个周期自愈。
- **重载失败一律是"什么都不改"**。规则两半先都装载校验成功才交换；证书任一个文件读不成就不换代。
  被拒内容按指纹记账，一次改写只计一次，所以 `*_reload_failures` 读作"拒了几次改写"，
  不是"坏了几个周期"。换来的是运行中的 broker 不会因为一次手滑而突然降级或锁死机队。
- **重载不驱逐会话**。已连的客户端不会被踢——踢它等于把一次规则改动变成一次机队重连风暴，
  而那正是热加载要避免的事。新规则从**下一个决策点**生效：下一次 CONNECT、下一次发布、每一次投递。
  代价是"已经建立的订阅"这件事本身不受新规则约束：要把某个会话立刻断掉，仍然只能重启或等它自己重连。
- **没校验的证书一律当没有证书**。`RequireAnyClientCert`（只给 `-tls-require-client-cert`、没给 `-tls-ca`）
  能握手成功，但 CertCN 留空——未校验的 CN 是客户端自己填的，拿它认证等于把门禁交给访客自己写。
- **慢订阅者被断开前先落盘**。3.1.1 没有流控，保护发布者只能牺牲订阅者，那就不能让它牺牲完还丢消息。
- **写失败只报警，不断开连接**。磁盘满不是发布者的错，把错误传导给客户端只会放大成雪崩。
- **限流判定在 accept，不在 CONNECT**。CONNECT 处设限只量得到"会话"，而一个只建 TCP、一个字节都不发的
  对端永远走不到 CONNECT——它白占一个 socket、一个读截止和三条协程，一直到 30s 的 pre-connect 截止。
  代价是被拒的连接收不到任何解释（没有 CONNACK 可回，只能挂断），谁被挡了多少只能从
  `refused_over_per_ip_*` 里读；买回来的是"风暴在最便宜的那一步就被挡掉，且一条会话都不曾建立"——
  §9 那两行 500 / 343 就是把这件事称出来的。
- **凭据失败是拒绝，不是 sleep**。让爆破者慢下来最直觉的做法是叫他多等一会儿，但等待期间
  那个 socket、那三条协程和那份读截止全是你自己付的——用一个正在被打的进程去计时，等于把攻击放大一层。
  所以锁定只回一个和凭据错误**一模一样**的 `0x04`。代价写在 §4：锁定期内连对的密码也被拒，
  而且这条没有"先认出来是自己人再放行"的余地——一旦允许正确密码绕过锁定，锁定本身就成了一条探测接口。
- **按地址设限的东西，默认全是 0**。IPv6 取 /64、NAT 后面一整批设备共用一个 IP，这不是可以两边都讨好的
  设计：管得粗会咬到自己人，管得细就挡不住谁。所以每一项都要显式打开，`-auth-fail-limit` 还额外要求
  必须有 `-auth`（没有规则文件时每个凭据都通过，那就没有失败可计——一个永远不会触发的限流参数
  比没有更糟，`exit 2` 说清楚）。
- **传输头部默认 `off`，而且是两条代码路径而不是一个开关**。`off` 时 `b.proxy` 是 nil，accept 路径上
  不建包装、不缓冲、不开协程——一个没要求这个功能的 broker 一行都不为它付。代价是要付出时才付：armed
  之后每条连接一个短命协程 + 128 字节缓冲，因为读头部用的是对端的日程表，一个连上就沉默的对端不该让
  accept 循环等满五秒。为什么不做成"总是试着读一下"：那会让直连客户端的第一段 CONNECT 多一次带超时的读，
  而 `ErrNotProxy` 必须消耗零字节的契约（`TestNotAHeaderConsumesNothing`）也就成了每天都得依赖的东西。
- **头部里那个地址是被断言的，不是被证明的**。PROXY protocol 本身没有任何鉴权，v2 尾部的 TLV 也只是
  按长度跳过、不校验，所以我们能判的只有一件事——**谁能往这个端口写包**。`-trusted-proxy-cidr` 就是这条
  信任边界写成的一行配置，网络可达性是它唯一的凭据。这就是 `require` 存在的原因：一个只有前置进得来的
  端口上，"断言"和"事实"第一次重合。代价是这份文档不能替你的安全组说话——`deploy/docker-compose.yml`
  故意不把 1883 发布到宿主机，就是因为一旦有旁路，`refused_over_proxy_header` 之外的一切裁决又回到判错机器。
- **名单外发头部是拒绝，不是忽略**。忽略的写法更好过日子（透明代理偶尔注入头部也照样能连），但它把
  "有人在自己不是前置的时候冒充前置"降格成了一行都不留的事件。拒绝之后这件事只存在于
  `refused_over_proxy_header` 和一条每 100 次才打一行的日志里——不对称是故意的，探测要付的是失败而不是痕迹。
  代价是混用监听口上的一种真实故障：某台中间设备（透明代理、某些云 NAT）自己注入了头部，
  而它的客户端并不在名单里——那种拓扑要么把网段加进名单，要么用 `require` 让前置成为唯一入口。
- **v1 与 v2 都读，而不是只读自己测试里那一种**。真实拓扑里两种都会出现：nginx 的 `stream` 只发 v1 文本，
  云厂商的 L4 大多发 v2 二进制。代价是一份解析器、两套字节布局、两套边界测试（文本的 108 字节行上限 vs
  二进制的"16 + 自己声明的长度"），加上一个必须逐字对齐规范的 nibble 约定（`0x20` 是 LOCAL、`0x21` 是 PROXY——
  写反了的症状是健康检查变成会话、而会话变成拒绝）。
- **镜像用 `golang:1.27-alpine` 构建，而 `go.mod` 只写 `go 1.24`**。这两个数字不冲突：下面那个是这个仓库
  的语言下限（用到的特性到这里为止），上面那个是实际编译它的编译器（带当前补丁的那一个）。
  代价是"`go 1.24` 也编得过"这句话 CI 并没有覆盖——CI 覆盖的是镜像那条路径，这也是为什么
  `docker` job 要拿镜像自己打印的 `-version` 去比 `cmd/congmq/main.go` 里的 `const version`。
- **容器镜像里不带规则、不带证书**。镜像是可替换的工件，策略是部署处的数据，热加载要的是"把文件写回
  原路径"这一件事——把它们烤进镜像就两头都丢了。代价很硬：默认 `CMD` 没有 `-auth`，裸 `docker run`
  起来的是一个开放 broker（§2 第一条说的就是它）。所以 compose 那份 `command:` 覆盖了默认值，
  而 `/etc/congmq` 是只读挂载（只读不影响轮询：它只 stat 和读）。
- **`-race` 在本机跑不了**（需要 cgo/gcc）。这条限制是环境性的，不是代码的；有 gcc 的机器直接
  `go test -race ./...` 即可。

## 12. 许可

MIT（见 `LICENSE`）。选它而不是更严格的许可证，是因为这仓库的目的是让人**敢把设备交给它**：
源码可以直接读、可以改、可以闭源分发，唯一条件是把版权与许可声明一起带上。
代价是没有任何明示担保——`THE SOFTWARE IS PROVIDED "AS IS"`。
「行为在源码注释里说清为什么这样取舍」是这项目实际提供的保证，它不写在许可证里。
