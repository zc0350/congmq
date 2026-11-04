// congmq-load drives a running broker with the MQTT it speaks itself: the frames
// are built by internal/packets, the same codec the server decodes, so the tool
// needs no third-party client and nobody can attribute the numbers to one.
//
//	go build -o bin/congmq-load.exe ./cmd/congmq-load
//
//	bin/congmq-load -mode conns -conns 5000 -seconds 30 -metrics http://127.0.0.1:1884/metrics
//	bin/congmq-load -mode pump  -publishers 20 -subscribers 20 -qos 1 -payload 256 -seconds 20
//	bin/congmq-load -mode pump  -publishers 20 -offline 500 -qos 1 -seconds 20
//	bin/congmq-load -mode pump  -addr 127.0.0.1:8883 -tls -tls-ca pki/ca.crt \
//	                -tls-client-cert pki/client.crt -tls-client-key pki/client.key
//	bin/congmq-load -mode conns -conns 3000 -proxy-header v2 -proxy-src 203.0.113.7,198.51.100.9
//
// conns answers "what does an idle connection cost", pump answers "how many
// messages per second, at what latency, and what does durable queueing add".
// -metrics makes the loader sample the broker itself before, during and after,
// which is the only way to attribute memory to the held load rather than to the
// ramp. Everything is printed as one JSON object for scripts; the readable lines
// go to stderr.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zc0350/congmq/internal/packets"
)

var (
	addr          = flag.String("addr", "127.0.0.1:1883", "broker address")
	metrics       = flag.String("metrics", "", "broker /metrics URL, sampled before, during and after the run")
	mode          = flag.String("mode", "conns", "conns (hold idle connections) or pump (publish and subscribe)")
	proto         = flag.Int("proto", 5, "protocol level: 5 for MQTT 5.0, 4 for 3.1.1")
	conns         = flag.Int("conns", 1000, "conns mode: connections to hold open")
	publishers    = flag.Int("publishers", 10, "pump mode: publishing connections")
	subscribers   = flag.Int("subscribers", 10, "pump mode: connected subscribers")
	offline       = flag.Int("offline", 0, "pump mode: persistent subscribers that subscribe, leave, and make the broker queue")
	qos           = flag.Int("qos", 1, "quality of service for the published messages")
	payload       = flag.Int("payload", 256, "payload size in bytes; at least 16, which is what the latency stamp costs")
	rate          = flag.Int("rate", 0, "aggregate messages per second, 0 for as fast as the loader can push")
	seconds       = flag.Int("seconds", 20, "how long to hold the connections or keep pumping")
	window        = flag.Int("window", 100, "unacknowledged messages each publisher may hold")
	shards        = flag.Int("shards", 8, "distinct topics; each is <topic>/<n>")
	topic         = flag.String("topic", "congmq-load", "topic prefix")
	sessionExpiry = flag.Int("session-expiry", 300, "Session Expiry Interval for the away subscribers")
	username      = flag.String("username", "", "credentials for a broker started with -auth")
	password      = flag.String("password", "", "credentials for a broker started with -auth")
	dialSpread    = flag.Bool("spread", false, "bind source addresses 127.0.0.1..253 in turn, which is how one machine gets past its own ephemeral port range")
	connectRate   = flag.Int("connect-rate", 0, "connections per second during the ramp, 0 for as fast as possible")
	dialParallel  = flag.Int("dial-parallel", 64, "connection attempts in flight at once")

	// TLS. The TCP socket is still opened by the dialer above, so -spread keeps
	// multiplying source addresses; TLS is layered on the connection that results.
	tlsOn   = flag.Bool("tls", false, "wrap every connection in TLS (mqtts)")
	tlsCA   = flag.String("tls-ca", "", "PEM CA(s) the broker certificate must chain to; empty trusts the system roots")
	tlsCert = flag.String("tls-client-cert", "", "PEM client certificate for a broker started with -tls-ca")
	tlsKey  = flag.String("tls-client-key", "", "PEM private key matching -tls-client-cert")
	tlsName = flag.String("tls-server-name", "", "name the broker certificate is verified against; the -addr host is used when empty")

	// The transport header. A broker started with -proxy-protocol require closes
	// every connection that does not open with one, so the shape worth measuring
	// needs a client that writes it — which is exactly what the load balancer in
	// front of that broker is doing.
	proxyHdr = flag.String("proxy-header", "none", "write a PROXY protocol header before the CONNECT: none, v1 (text) or v2 (binary)")
	proxySrc = flag.String("proxy-src", "", "source addresses the header claims, comma separated and cycled per connection; empty means this socket's own address")
)

// The header to write, resolved once at startup so dial() does no parsing.
const (
	proxyNone = iota
	proxyV1
	proxyV2
)

var (
	proxyForm  int
	proxyClaim []netip.Addr
	proxySeq   atomic.Uint64
)

// buildProxy turns the two header flags into what dial() needs, and refuses the
// combinations that would silently measure a different run than the one asked for
// — the same discipline the broker applies to its own flags.
func buildProxy() {
	switch *proxyHdr {
	case "none", "":
		proxyForm = proxyNone
	case "v1":
		proxyForm = proxyV1
	case "v2":
		proxyForm = proxyV2
	default:
		exitf("-proxy-header must be none, v1 or v2")
	}
	if *proxySrc == "" {
		return
	}
	if proxyForm == proxyNone {
		exitf("-proxy-src does nothing without -proxy-header: with no header there is nobody to claim an address")
	}
	for _, item := range strings.Split(*proxySrc, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			exitf("-proxy-src has an empty entry")
		}
		a, err := netip.ParseAddr(item)
		if err != nil {
			exitf("-proxy-src %q: %v", item, err)
		}
		proxyClaim = append(proxyClaim, a)
	}
}

// proxyHeader lays the header out the way the specification fixes it, from the
// socket that is about to carry it. The destination is the broker's own address
// and the source is either the claimed one or this socket's, because a real L4
// proxy reports what it saw on the client side and nothing else.
func proxyHeader(conn net.Conn) []byte {
	if proxyForm == proxyNone {
		return nil
	}
	n := proxySeq.Add(1) - 1
	src, sport := socketAddr(conn.LocalAddr())
	if len(proxyClaim) > 0 {
		src = proxyClaim[int(n%uint64(len(proxyClaim)))]
		// A claimed device needs a claimed port, and it has to vary: a session is
		// a four-tuple, and a log line that repeats one port for ten thousand
		// devices is a log line nobody can read.
		sport = uint16(20000 + n%40000)
	}
	dst, dport := socketAddr(conn.RemoteAddr())
	if dst.Is4() != src.Is4() {
		// The families have to agree — a v2 header carries one family for both
		// addresses. This only happens when a claim list mixes families against a
		// single-stack broker, so the fallback is the same-family wildcard.
		if src.Is4() {
			dst = netip.AddrFrom4([4]byte{0, 0, 0, 0})
		} else {
			dst = netip.AddrFrom16([16]byte{})
		}
	}

	if proxyForm == proxyV1 {
		fam := "TCP4"
		if !src.Is4() {
			fam = "TCP6"
		}
		return []byte(fmt.Sprintf("PROXY %s %s %s %d %d\r\n", fam, src, dst, sport, dport))
	}

	addrLen := 16
	famByte := byte(0x21) // AF_INET6, STREAM
	if src.Is4() {
		addrLen, famByte = 4, 0x11 // AF_INET, STREAM
	}
	body := make([]byte, addrLen*2+4)
	copy(body[0:addrLen], src.AsSlice())
	copy(body[addrLen:2*addrLen], dst.AsSlice())
	binary.BigEndian.PutUint16(body[2*addrLen:], sport)
	binary.BigEndian.PutUint16(body[2*addrLen+2:], dport)
	head := make([]byte, 0, len(v2Sig)+4+len(body))
	head = append(head, v2Sig...)
	head = append(head, 0x21, famByte) // version 2 + command PROXY, then family + STREAM
	head = binary.BigEndian.AppendUint16(head, uint16(len(body)))
	return append(head, body...)
}

// v2Sig is the twelve-byte signature every PROXY protocol v2 header starts with.
const v2Sig = "\r\n\r\n\x00\r\nQUIT\n"

// socketAddr splits a net.Addr into the two numbers a header needs. Anything that
// does not carry an IP (a unix socket, in principle) reports itself as the v4
// wildcard rather than failing the dial: the loader is not the peer being judged.
func socketAddr(a net.Addr) (netip.Addr, uint16) {
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return netip.AddrFrom4([4]byte{0, 0, 0, 0}), 0
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrFrom4([4]byte{0, 0, 0, 0}), 0
	}
	p, _ := strconv.Atoi(port)
	return ip.Unmap(), uint16(p)
}

// clientTLS is nil when -tls is off, so dial() does not branch on the flag.
var clientTLS *tls.Config

// clientTLSVersion records what the first handshake actually negotiated, so the
// report names the protocol the run used instead of the one that was asked for.
var clientTLSVersion atomic.Int32

func main() {
	flag.Parse()
	if *mode == "pump" && *payload < 16 {
		exitf("-payload must be at least 16 bytes: that stamp is what latency is measured from")
	}
	buildTLS()
	buildProxy()

	sample := newSampler(*metrics)
	before := sample.get()

	var rep report
	switch *mode {
	case "conns":
		rep = runConns(sample, before)
	case "pump":
		rep = runPump()
	default:
		exitf("unknown -mode %q (conns or pump)", *mode)
	}

	rep.Mode = *mode
	rep.Transport = transportLabel()
	rep.ClockGranNS = clockGranularityNS
	rep.Proto = *proto
	rep.QoS = *qos
	rep.PayloadBytes = *payload
	rep.BrokerBefore = before
	rep.BrokerAfter = sample.get()
	rep.Loader = loaderCost()

	out, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		exitf("encode report: %v", err)
	}
	fmt.Println(string(out))
}

// ---------------------------------------------------------------- shared ----

type report struct {
	Mode          string         `json:"mode"`
	Transport     string         `json:"transport"`
	Proto         int            `json:"proto"`
	QoS           int            `json:"qos"`
	PayloadBytes  int            `json:"payload_bytes"`
	Planned       int            `json:"planned_connections"`
	Connected     int64          `json:"connected"`
	ConnectErrors int64          `json:"connect_errors"`
	ConnectPerSec float64        `json:"connect_per_second"`
	RampSeconds   float64        `json:"ramp_seconds"`
	SubscribeErrs int64          `json:"subscribe_errors"`
	Published     int64          `json:"published"`
	PumpSeconds   float64        `json:"pump_seconds"`
	Acknowledged  int64          `json:"acknowledged"`
	Delivered     int64          `json:"delivered"`
	MsgsPerSecond float64        `json:"msgs_per_second"`
	MbPerSecond   float64        `json:"mbit_per_second"`
	AwaySessions  int            `json:"away_sessions"`
	Samples       int64          `json:"latency_samples"`
	ClockGranNS   int64          `json:"clock_granularity_ns"`
	MeanMS        float64        `json:"mean_ms"`
	P10MS         float64        `json:"p10_ms"`
	P50MS         float64        `json:"p50_ms"`
	P90MS         float64        `json:"p90_ms"`
	P99MS         float64        `json:"p99_ms"`
	MaxMS         float64        `json:"max_ms"`
	Errors        []string       `json:"errors,omitempty"`
	BrokerBefore  map[string]any `json:"broker_before,omitempty"`
	BrokerDuring  map[string]any `json:"broker_during,omitempty"`
	// BrokerSettled is the last sample of the hold. Memory read 2s into a ramp is
	// still carrying whatever the GC had not collected yet, so the settled sample
	// is the one that should size a deployment; the gap between the two is the
	// transient an operator will see under the same load.
	BrokerSettled map[string]any `json:"broker_settled,omitempty"`
	BrokerAfter   map[string]any `json:"broker_after,omitempty"`
	Loader        loaderStats    `json:"loader"`
}

type loaderStats struct {
	Goroutines   int    `json:"goroutines"`
	MemSysBytes  uint64 `json:"mem_sys_bytes"`
	MemAllocByte uint64 `json:"mem_alloc_bytes"`
}

func loaderCost() loaderStats {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return loaderStats{Goroutines: runtime.NumGoroutine(), MemSysBytes: ms.Sys, MemAllocByte: ms.Alloc}
}

// sampler reads the broker's own counters. Packet counts alone cannot tell a
// broker that grew because of load from one that grew because of a leak, and
// capacity planning is exactly that question.
type sampler struct{ url string }

func newSampler(url string) *sampler { return &sampler{url: url} }

func (s *sampler) get() map[string]any {
	if s.url == "" {
		return nil
	}
	client := &http.Client{Timeout: 3 * time.Second}
	res, err := client.Get(s.url)
	if err != nil {
		warnf("cannot read %s: %v (the broker needs -metrics, and the memory fields need a current build)", s.url, err)
		return nil
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil
	}
	return out
}

func field(m map[string]any, key string) int64 {
	if m == nil {
		return 0
	}
	if v, ok := m[key].(float64); ok {
		return int64(v)
	}
	return 0
}

// notes collects what went wrong without letting one refused connection decide
// the whole run; a capacity number is still a number if 3 of 5000 dials failed,
// as long as the report says so.
type notes struct {
	mu    sync.Mutex
	items []string
}

func (n *notes) add(format string, args ...any) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.items) < 40 {
		n.items = append(n.items, fmt.Sprintf(format, args...))
	}
}

func (n *notes) all() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.items...)
}

type client struct {
	id   string
	conn net.Conn
	r    *bufio.Reader
	ver  packets.Version
	mu   sync.Mutex

	dead atomic.Bool

	// win holds one token per unacknowledged message, so a publisher never runs
	// ahead of what it is allowed to have in flight.
	win chan struct{}

	// onMessage is what a subscriber does with a delivery; publishers leave it nil.
	onMessage func(*packets.Publish)

	// delivered counts Publish packets that arrived on this connection.
	delivered atomic.Int64

	// acks counts the acknowledgements this publisher got back, so a run can
	// tell "the broker was slow" from "the loader stopped sending".
	acks atomic.Int64
}

func dial(id string, spreadIndex int) (*client, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	if *dialSpread {
		// A distinct loopback source per connection multiplies the four-tuples
		// available to one machine; without it a few thousand connections to a
		// single address hit the ephemeral port ceiling of the host.
		d.LocalAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, byte(1+spreadIndex%253)), Port: 0}
	}
	conn, err := d.Dial("tcp", *addr)
	if err != nil {
		return nil, err
	}
	// The deadline bounds the whole session, so a wedged broker shows up as a
	// finished run with errors rather than as a loader that never exits. It is set
	// before the handshake on purpose: a peer that accepts TCP and then says
	// nothing must cost this process a bounded amount of time.
	if err := conn.SetDeadline(time.Now().Add(time.Duration(*seconds+120) * time.Second)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	v := packets.V5
	if *proto == 4 {
		v = packets.V311
	}
	// The loader is a client too: its PUBACKs are small writes, and Nagle on this
	// side would stall the very exchange the run is measuring. Under TLS the flag
	// belongs to the socket underneath, so it is set before that one is wrapped.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	// The header goes on the socket, outside TLS: that is where a load balancer
	// writes it, and a broker that reads it before the handshake is a broker this
	// loader could not otherwise reach.
	if hdr := proxyHeader(conn); len(hdr) > 0 {
		if _, err := conn.Write(hdr); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("write transport header: %w", err)
		}
	}
	if clientTLS != nil {
		sc := tls.Client(conn, clientTLS)
		if err := sc.Handshake(); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("tls handshake with %s: %w", *addr, err)
		}
		clientTLSVersion.CompareAndSwap(0, int32(sc.ConnectionState().Version))
		conn = sc
	}
	return &client{id: id, conn: conn, r: bufio.NewReaderSize(conn, 4096), ver: v}, nil
}

// buildTLS turns the -tls flags into a client config, or leaves it nil. The
// name to verify comes from the address unless the operator overrode it, which
// is what makes a certificate issued for a host name usable through an IP dial.
func buildTLS() {
	if !*tlsOn {
		return
	}
	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		host = *addr
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if *tlsName != "" {
		cfg.ServerName = *tlsName
	}
	if *tlsCA != "" {
		raw, err := os.ReadFile(*tlsCA)
		if err != nil {
			exitf("-tls-ca: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			exitf("-tls-ca %s holds no certificate", *tlsCA)
		}
		cfg.RootCAs = pool
	}
	switch {
	case (*tlsCert == "") != (*tlsKey == ""):
		exitf("-tls-client-cert and -tls-client-key go together")
	case *tlsCert != "":
		pair, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			exitf("-tls-client-cert/-tls-client-key: %v", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	clientTLS = cfg
}

// transportLabel names the transport the run actually used, which is what makes
// a TLS baseline row comparable to the plain one next to it. The version comes
// from the first handshake, so a run that negotiated down to 1.2 says so.
func transportLabel() string {
	base := "tcp"
	if *tlsOn {
		switch clientTLSVersion.Load() {
		case tls.VersionTLS13:
			base = "tls1.3"
		case tls.VersionTLS12:
			base = "tls1.2"
		default:
			base = "tls"
		}
	}
	// The header form belongs in the label for the same reason the TLS version
	// does: two rows that differ only in what they wrote in front of the CONNECT
	// have to say so in the row itself.
	switch proxyForm {
	case proxyV1:
		return base + "+proxyv1"
	case proxyV2:
		return base + "+proxyv2"
	}
	return base
}

func (c *client) send(p packets.Packet) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return packets.EncodeVersion(c.conn, c.ver, p)
}

// connect performs the handshake. clean false with a positive expiry is what
// makes a session outlive this connection, which is the only way an offline
// queue exists to be measured.
func (c *client) connect(clean bool) (*packets.Connack, error) {
	p := &packets.Connect{
		ProtocolName:  packets.ProtocolName,
		ProtocolLevel: byte(c.ver),
		ClientID:      c.id,
		CleanSession:  clean,
		KeepAlive:     60,
	}
	if c.ver.Is5() && !clean && *sessionExpiry > 0 {
		p.Props = &packets.Properties{}
		p.Props.SetSessionExpiry(uint32(*sessionExpiry))
	}
	if *username != "" {
		p.HasUsername, p.Username = true, *username
		if *password != "" {
			p.HasPassword, p.Password = true, []byte(*password)
		}
	}
	if err := c.send(p); err != nil {
		return nil, err
	}
	for {
		got, err := c.read()
		if err != nil {
			return nil, err
		}
		ack, ok := got.(*packets.Connack)
		if !ok {
			continue
		}
		code := ack.ReturnCode
		if c.ver.Is5() {
			code = ack.ReasonCode
		}
		if code != packets.ConnAccepted {
			return ack, fmt.Errorf("refused with 0x%02X (%s)", code, packets.ReasonName(code))
		}
		return ack, nil
	}
}

func (c *client) subscribe(packetID uint16, filter string) error {
	sub := &packets.Subscribe{
		PacketID:      packetID,
		Subscriptions: []packets.Subscription{{TopicFilter: filter, MaxQoS: byte(*qos)}},
	}
	if err := c.send(sub); err != nil {
		return err
	}
	for {
		got, err := c.read()
		if err != nil {
			return err
		}
		sa, ok := got.(*packets.Suback)
		if !ok {
			continue
		}
		for i, code := range sa.ReturnCodes {
			if code >= 0x80 {
				return fmt.Errorf("filter %d refused with 0x%02X (%s)", i, code, packets.ReasonName(code))
			}
		}
		return nil
	}
}

// read handles one inbound packet the way a compliant client must, including
// the acknowledgement side of QoS 1 and 2: a loader that did not ack would be
// measuring a broker stuck behind a broken client.
func (c *client) read() (packets.Packet, error) {
	p, err := packets.DecodeVersion(c.r, c.ver)
	if err != nil {
		c.dead.Store(true)
		return nil, err
	}
	switch m := p.(type) {
	case *packets.Publish:
		// Counted once, here, whatever the QoS: the PUBACK and PUBCOMP legs are
		// acknowledgements of the same arrival, and a second increment would
		// report a delivery the broker never made.
		c.delivered.Add(1)
		if c.onMessage != nil {
			c.onMessage(m)
		}
		switch m.QoS {
		case packets.QoS1:
			_ = c.send(&packets.Puback{PacketID: m.PacketID})
		case packets.QoS2:
			_ = c.send(&packets.Pubrec{PacketID: m.PacketID})
		}
	case *packets.Puback, *packets.Pubcomp:
		c.release()
	case *packets.Pubrec:
		_ = c.send(&packets.Pubrel{PacketID: m.PacketID})
	case *packets.Pubrel:
		_ = c.send(&packets.Pubcomp{PacketID: m.PacketID})
	}
	return p, nil
}

func (c *client) release() {
	select {
	case <-c.win:
		c.acks.Add(1)
	default:
	}
}

func (c *client) readLoop() {
	for !c.dead.Load() {
		if _, err := c.read(); err != nil {
			return
		}
	}
}

func (c *client) close() {
	if c.dead.Swap(true) {
		return
	}
	_ = c.send(&packets.Disconnect{})
	_ = c.conn.Close()
}

// tokens is the shared schedule every publisher draws from. Two things a naive
// version gets wrong are measured here: pacing by sleeping per message reports
// the OS timer resolution instead of the broker, and pacing by a fixed ticker
// reports that ticker's jitter. This accrues credits from elapsed wall time, so
// the offered rate is arithmetic and only its burst shape is scheduling.
type tokens struct {
	mu     sync.Mutex
	have   float64
	room   float64
	last   time.Time
	perSec float64
}

func newTokens() *tokens {
	if *rate <= 0 {
		return nil
	}
	return &tokens{
		// A tenth of a second's worth, so a stalled run cannot burst to catch up.
		// Floored at one token: with a smaller room the accrued amount is clamped
		// below 1 every round and wait() never returns, which is why -rate 1 used
		// to hang instead of pacing one message per second.
		room:   max(1, float64(*rate)/10),
		last:   time.Now(),
		perSec: float64(*rate),
	}
}

func (t *tokens) wait() {
	if t == nil {
		return
	}
	for {
		t.mu.Lock()
		now := time.Now()
		t.have += now.Sub(t.last).Seconds() * t.perSec
		t.last = now
		if t.have > t.room {
			t.have = t.room
		}
		if t.have >= 1 {
			t.have--
			t.mu.Unlock()
			return
		}
		// Sleep exactly the deficit: the time slept is credited on the next
		// round, so a coarse timer costs shape and never rate.
		wait := time.Duration((1 - t.have) / t.perSec * float64(time.Second))
		t.mu.Unlock()
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		time.Sleep(wait)
	}
}

// stamp writes the send time and a sequence number into the head of the
// payload; the subscriber turns those bytes back into a latency.
// procStart is the monotonic origin every latency sample is taken against.
var procStart = time.Now()

// clockGranularityNS is the smallest step this machine's clock is seen to make.
//
// It belongs in the report because it decides what a latency number means: a
// Windows box can update time.Now() twice a millisecond, and then every delivery
// faster than that samples as exactly 0. Percentiles under one granularity are
// not measurements of the broker, they are measurements of the clock.
var clockGranularityNS = func() int64 {
	const samples = 64
	var seen [samples]int64
	prev := time.Now()
	for i := 0; i < samples; {
		n := time.Now()
		if d := int64(n.Sub(prev)); d > 0 {
			seen[i] = d
			prev = n
			i++
		}
	}
	sort.Slice(seen[:], func(a, b int) bool { return seen[a] < seen[b] })
	return seen[0]
}()

// stamp writes the send time and the sequence into the payload.
//
// The clock is time.Since(procStart), not time.Now().UnixNano(): publisher and
// subscriber are the same process, so one monotonic base covers the whole hop,
// and on Windows the wall reading this box exposes advances in ~0.5 ms steps,
// which made every sub-millisecond delivery measure as exactly 0.
func stamp(buf []byte, seq uint64) {
	binary.BigEndian.PutUint64(buf, uint64(time.Since(procStart).Nanoseconds()))
	binary.BigEndian.PutUint64(buf[8:], seq)
}

func shardTopic(n int) string {
	return fmt.Sprintf("%s/%d", *topic, n%max1(*shards))
}

// nextID hands out packet identifiers in 1..65534. Zero means "no identifier"
// on the wire, and a publisher may not have the same identifier in flight twice.
func nextID(prev uint64) uint16 {
	return uint16(prev%65534) + 1
}

// ----------------------------------------------------------------- conns ----

// runConns opens the planned connections, holds them for -seconds with one
// subscription each, and reports the ramp rate. The number worth having is
// broker_during minus broker_before divided by the connections held open.
func runConns(sample *sampler, before map[string]any) report {
	rep := report{Planned: *conns}
	var (
		mu                         sync.Mutex
		clients                    []*client
		n                          notes
		connected, failed, subErrs atomic.Int64
	)
	sem := make(chan struct{}, max1(*dialParallel))

	start := time.Now()
	var gap time.Duration
	if *connectRate > 0 {
		gap = time.Second / time.Duration(*connectRate)
	}
	var wg sync.WaitGroup
	for i := 0; i < *conns; i++ {
		if gap > 0 {
			time.Sleep(gap)
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			id := fmt.Sprintf("load-%d", i)
			c, err := dial(id, i)
			if err != nil {
				failed.Add(1)
				n.add("dial %s: %v", id, err)
				return
			}
			if _, err := c.connect(true); err != nil {
				failed.Add(1)
				n.add("connect %s: %v", id, err)
				_ = c.conn.Close()
				return
			}
			if err := c.subscribe(1, shardTopic(i)); err != nil {
				subErrs.Add(1)
				n.add("subscribe %s: %v", id, err)
			}
			go c.readLoop()
			mu.Lock()
			clients = append(clients, c)
			mu.Unlock()
			connected.Add(1)
		}(i)
	}
	wg.Wait()
	ramp := time.Since(start)

	rep.Connected = connected.Load()
	rep.ConnectErrors = failed.Load()
	rep.SubscribeErrs = subErrs.Load()
	rep.RampSeconds = ramp.Seconds()
	if ramp > 0 {
		rep.ConnectPerSec = float64(rep.Connected) / ramp.Seconds()
	}
	fprintf("  ramp: %d/%d connections up in %s (%.0f/s), %d refused, %d subscribe errors\n",
		rep.Connected, *conns, ramp.Round(time.Millisecond), rep.ConnectPerSec, rep.ConnectErrors, rep.SubscribeErrs)

	// Hold and sample during the hold: memory attributed after the teardown has
	// already been given back, which measures nothing.
	deadline := time.Now().Add(time.Duration(*seconds) * time.Second)
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var settled map[string]any
	for time.Now().Before(deadline) {
		select {
		case <-tick.C:
			if s := sample.get(); s != nil {
				if rep.BrokerDuring == nil {
					rep.BrokerDuring = s
				}
				settled = s
			}
		case <-ping.C:
			mu.Lock()
			live := append([]*client(nil), clients...)
			mu.Unlock()
			for _, c := range live {
				_ = c.send(&packets.Pingreq{})
			}
		case <-time.After(200 * time.Millisecond):
		}
	}
	if rep.BrokerDuring == nil {
		rep.BrokerDuring = sample.get()
	}
	rep.BrokerSettled = settled
	for _, s := range []struct {
		name string
		samp map[string]any
	}{{"first", rep.BrokerDuring}, {"settled", rep.BrokerSettled}} {
		during := s.samp
		if during == nil {
			continue
		}
		online := field(during, "online")
		per := func(key string) int64 {
			if online <= 0 {
				return 0
			}
			return (field(during, key) - field(before, key)) / online
		}
		fprintf("  %s: online=%d goroutines=%d gc=%d mem_sys=%d MiB heap=%d MiB -> %d B/conn reserved, %d B/conn live\n",
			s.name, online, field(during, "goroutines"), field(during, "gc_cycles"),
			field(during, "mem_sys_bytes")>>20, field(during, "mem_alloc_bytes")>>20,
			per("mem_sys_bytes"), per("mem_alloc_bytes"))
	}

	mu.Lock()
	for _, c := range clients {
		c.close()
	}
	mu.Unlock()
	rep.Errors = n.all()
	return rep
}

// ------------------------------------------------------------------- pump ----

// runPump measures message rate and delivery latency. -offline adds persistent
// subscribers that leave before the publishing starts, which is the only shape
// of load that puts the durable store on the measured path.
func runPump() report {
	rep := report{Planned: max1(*publishers) + max0(*subscribers) + *offline}
	pubN, subN := max1(*publishers), max0(*subscribers)
	var n notes

	// Away first: an offline session has to be on record before a single message
	// arrives, otherwise the run measures a broker that never had to queue.
	var away []*client
	for i := 0; i < *offline; i++ {
		id := fmt.Sprintf("load-away-%d", i)
		c, err := dial(id, i)
		if err != nil {
			n.add("dial %s: %v", id, err)
			continue
		}
		if _, err := c.connect(false); err != nil {
			n.add("connect %s: %v", id, err)
			_ = c.conn.Close()
			continue
		}
		if err := c.subscribe(1, shardTopic(i)); err != nil {
			n.add("subscribe %s: %v", id, err)
		}
		away = append(away, c)
		// Closing the socket without DISCONNECT is the case that queues: a
		// graceful goodbye would let the broker drain the session instead.
		c.dead.Store(true)
		_ = c.conn.Close()
	}
	rep.AwaySessions = len(away)

	// Latency is collected per subscriber and merged at the end; the slice is
	// guarded because a subscriber's own deliveries arrive on its own goroutine.
	var latMu sync.Mutex
	var lats []int64

	var subs []*client
	for i := 0; i < subN; i++ {
		id := fmt.Sprintf("load-sub-%d", i)
		c, err := dial(id, i+pubN)
		if err != nil {
			n.add("dial %s: %v", id, err)
			continue
		}
		if _, err := c.connect(true); err != nil {
			n.add("connect %s: %v", id, err)
			_ = c.conn.Close()
			continue
		}
		c.onMessage = func(p *packets.Publish) {
			if len(p.Payload) < 16 {
				return
			}
			elapsed := time.Since(procStart).Nanoseconds() - int64(binary.BigEndian.Uint64(p.Payload))
			if elapsed < 0 {
				return
			}
			latMu.Lock()
			lats = append(lats, elapsed)
			latMu.Unlock()
		}
		// One shard each: every subscriber taking every topic would measure
		// fanout amplification instead of the broker's delivery rate, and
		// -shards exists to dial that up deliberately.
		if err := c.subscribe(2, shardTopic(i)); err != nil {
			n.add("subscribe %s: %v", id, err)
		}
		go c.readLoop()
		subs = append(subs, c)
	}

	var pubs []*client
	for i := 0; i < pubN; i++ {
		id := fmt.Sprintf("load-pub-%d", i)
		c, err := dial(id, i)
		if err != nil {
			n.add("dial %s: %v", id, err)
			continue
		}
		if _, err := c.connect(true); err != nil {
			n.add("connect %s: %v", id, err)
			_ = c.conn.Close()
			continue
		}
		c.win = make(chan struct{}, max1(*window))
		go c.readLoop()
		pubs = append(pubs, c)
	}
	rep.Connected = int64(len(pubs) + len(subs))
	fprintf("  %d publishers, %d subscribers, %d away sessions, qos %d, %d B payload\n",
		len(pubs), len(subs), len(away), *qos, *payload)

	var sent atomic.Int64
	tk := newTokens()
	pumpStart := time.Now()
	deadline := pumpStart.Add(time.Duration(*seconds) * time.Second)
	var wg sync.WaitGroup
	for i, c := range pubs {
		wg.Add(1)
		go func(i int, c *client) {
			defer wg.Done()
			buf := make([]byte, *payload)
			var seq uint64
			for time.Now().Before(deadline) {
				seq++
				if *qos > 0 {
					// Blocking here is the measurement: a publisher that cannot
					// get a token is waiting on the broker, not on the loader.
					select {
					case c.win <- struct{}{}:
					case <-time.After(20 * time.Second):
						n.add("%s stalled waiting for its window at %d", c.id, seq)
						return
					}
				}
				tk.wait()
				stamp(buf, uint64(i)*1e9+seq)
				p := &packets.Publish{
					Topic:    shardTopic(i),
					QoS:      byte(*qos),
					Payload:  buf,
					PacketID: nextID(seq),
				}
				if err := c.send(p); err != nil {
					n.add("%s publish: %v", c.id, err)
					return
				}
				sent.Add(1)
			}
		}(i, c)
	}

	sample := newSampler(*metrics)
	var during map[string]any
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for time.Now().Before(deadline) {
		select {
		case <-tick.C:
			if s := sample.get(); s != nil && during == nil {
				during = s
			}
		case <-time.After(200 * time.Millisecond):
		}
	}
	rep.BrokerDuring = during
	// The rate is closed at the deadline, not after the drain: the publishers
	// keep going until their window empties, and folding those tail messages
	// into a window that stopped earlier would invent throughput.
	ran := time.Since(pumpStart)
	inWindow := sent.Load()
	wg.Wait()

	// Give the in-flight deliveries a moment to arrive; stopping the publishers
	// and reading immediately would under-report the broker's own fanout.
	time.Sleep(800 * time.Millisecond)
	for _, c := range pubs {
		rep.Acknowledged += c.acks.Load()
	}
	for _, c := range subs {
		rep.Delivered += c.delivered.Load()
	}
	rep.Published = sent.Load()
	rep.PumpSeconds = ran.Seconds()
	rep.MsgsPerSecond = float64(inWindow) / ran.Seconds()
	rep.MbPerSecond = float64(inWindow) * float64(*payload+20) * 8 / ran.Seconds() / 1e6

	latMu.Lock()
	sort.Slice(lats, func(a, b int) bool { return lats[a] < lats[b] })
	if len(lats) > 0 {
		at := func(q float64) float64 {
			i := int(q * float64(len(lats)))
			if i >= len(lats) {
				i = len(lats) - 1
			}
			return float64(lats[i]) / float64(time.Millisecond)
		}
		var sum int64
		for _, v := range lats {
			sum += v
		}
		rep.Samples = int64(len(lats))
		rep.P10MS, rep.P50MS, rep.P90MS, rep.P99MS = at(0.1), at(0.5), at(0.9), at(0.99)
		rep.MeanMS = float64(sum) / float64(len(lats)) / float64(time.Millisecond)
		rep.MaxMS = float64(lats[len(lats)-1]) / float64(time.Millisecond)
	}
	latMu.Unlock()

	fprintf("  %.0f msg/s in (%.1f Mbit/s), %.0f delivered, %d timed, mean=%.3fms p10=%.3f p50=%.3f p90=%.3f p99=%.3f max=%.1fms (clock granularity %.2fms)\n",
		rep.MsgsPerSecond, rep.MbPerSecond, float64(rep.Delivered), rep.Samples,
		rep.MeanMS, rep.P10MS, rep.P50MS, rep.P90MS, rep.P99MS, rep.MaxMS,
		float64(clockGranularityNS)/float64(time.Millisecond))

	for _, c := range subs {
		c.close()
	}
	for _, c := range pubs {
		c.close()
	}
	rep.Errors = n.all()
	return rep
}

// ---------------------------------------------------------------- helpers ---

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

func fprintf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "congmq-load: "+format+"\n", args...)
	os.Exit(2)
}

func warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "congmq-load: "+format+"\n", args...)
}
