# 两段构建：编译段留下一个静态二进制，运行段除了它只剩一个能发 HTTP 请求的 shell。
#
# CGO_ENABLED=0 是这个项目的既有约定（CI 的每个 build 都是它，见 .github/workflows/build.yml），
# 所以二进制不依赖运行段的 libc —— 运行段可以是 8MB 的 alpine 而不必是几百 MB 的发行版。
# 选 alpine 而不是 scratch 的唯一理由是 HEALTHCHECK 里要有 wget，以及出问题时 operator 能
# `docker exec -it congmq sh` 进去看一眼；这两件事在半夜比 60MB 镜像层值钱。

FROM golang:1.27-alpine AS build
WORKDIR /src

# 这个模块零第三方依赖，所以没有 go.sum、也没有值得单独一层缓存的下载。
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/

# go.mod 里的 `go 1.24` 是**语言下限**，不是编译器版本：用仍在收安全补丁的工具链构建，
# 二进制里带才是打过补丁的 stdlib。换 tag 时别把它改回 1.24 去"跟 go.mod 对齐"。
# TARGETOS/TARGETARCH 由 buildx 按 --platform 注入，所以 mac 上
# `docker buildx build --platform linux/arm64` 真的出 arm64，而不是宿主机架构。
ARG TARGETOS
ARG TARGETARCH
# 不加 -s -w：panic trace 和 goroutine dump 是 operator 唯一的现场，省那几 MB 不值得。
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -o /congmq ./cmd/congmq

FROM alpine:3.24

RUN addgroup -g 10001 -S congmq \
 && adduser -u 10001 -G congmq -S -H -D congmq \
 && mkdir -p /var/lib/congmq /etc/congmq \
 && chown congmq:congmq /var/lib/congmq

COPY --from=build /congmq /usr/local/bin/congmq

# 1883 明文 / 8883 TLS。指标口（默认 8080）不在这里 EXPOSE：它是给宿主机或管理网读的，
# 怎么发布交给编排层决定（compose 里只绑到 127.0.0.1）。
EXPOSE 1883 8883

# 就绪探针读的就是 §7 那个 /readyz：drain 期间返回 503，所以容器会被标成 unhealthy，
# 编排层据此摘流量——不需要为了 docker 另做一套健康检查协议。
ENV CONGMQ_HEALTH_PORT=8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null "http://127.0.0.1:${CONGMQ_HEALTH_PORT}/readyz" || exit 1

# 数字 uid，不查 /etc/passwd：Kubernetes 的 runAsNonRoot 和大多数 PaaS 只认这个。
# 1883 > 1024，所以绑定它不需要任何 capability。
USER 10001:10001

# 可执行文件就是 broker 本体，参数全部走 CMD/`command:`：
# 覆盖 `command:` 是加 flag，不是进镜像里跑 shell，也不藏任何 env→flag 的翻译层。
ENTRYPOINT ["/usr/local/bin/congmq"]
# 不带规则文件 = 谁都能连，这是"先跑起来"的默认，不是生产形态。
# 生产形态见 deploy/docker-compose.yml（规则 + 落盘 + 只允许负载均衡进来）。
CMD ["-addr", ":1883", "-metrics", ":8080", "-store", "/var/lib/congmq"]
