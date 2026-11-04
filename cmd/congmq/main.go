// Command congmq runs a single-machine MQTT 3.1.1 and 5.0 broker.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/zc0350/congmq/internal/broker"
	"github.com/zc0350/congmq/internal/rules"
	"github.com/zc0350/congmq/internal/store"
)

// The release workflow refuses to publish when this and the git tag disagree.
const version = "1.1.1"

func main() {
	var (
		addr    = flag.String("addr", ":1883", "TCP listen address")
		id      = flag.String("id", "congmq-1", "broker identifier")
		showVer = flag.Bool("version", false, "print the version and exit")

		queueMax  = flag.Int("queue-max", 1000, "messages kept per offline session")
		window    = flag.Int("inflight-window", 100, "unacknowledged messages outstanding per client")
		mailbox   = flag.Int("mailbox-size", 256, "per-connection handoff queue depth")
		maxConns  = flag.Int("max-conns", 0, "connection limit, 0 for unlimited")
		maxSubs   = flag.Int("max-subs", 0, "topic filters one client may hold at once, 0 for unlimited")
		retry     = flag.Duration("retry-interval", 5*time.Second, "resend interval for unacknowledged messages")
		writeTO   = flag.Duration("write-timeout", 10*time.Second, "deadline for a single socket write")
		deliverTO = flag.Duration("deliver-timeout", 5*time.Second, "how long a slow subscriber may stall a publisher")
		logLevel  = flag.String("log-level", "info", "debug, info, warn or error")

		authPath = flag.String("auth", "", "path to an auth.jsonl rules file; empty means anyone may connect")
		aclPath  = flag.String("acl", "", "path to an acl.jsonl rules file; empty means everything is granted")

		// Durability. Without -store the broker forgets every offline queue the
		// moment it exits, which is fine for a laptop and not fine for a field.
		storeDir      = flag.String("store", "", "directory holding the durable state file; empty keeps everything in memory")
		storeSync     = flag.String("store-sync", "everysec", "how hard the store works to survive a crash: everysec, always or never")
		compactMB     = flag.Int("store-compact-mb", 32, "rewrite the store file once this many bytes are appended past it, 0 for the default")
		storeFlushInt = flag.Duration("store-flush-interval", time.Second, "longest a coalesced session snapshot may wait for the disk")

		// MQTT 5.0 capabilities. Each one is advertised in the CONNACK, so
		// changing it changes what a 5.0 client is allowed to ask for.
		receiveMax  = flag.Int("receive-max", 100, "inbound QoS 1/2 messages a client may leave unacknowledged")
		aliasMax    = flag.Uint("topic-alias-max", 10, "highest topic alias a client may use, 0 to forbid them")
		maxPacket   = flag.Uint("max-packet-size", 0, "largest packet a client may send, 0 for the protocol's own 256MB")
		maxQoS      = flag.Uint("max-qos", 2, "highest QoS this broker grants; 1 turns QoS 2 off")
		expiryMax   = flag.Duration("session-expiry-max", 0, "longest session expiry a client may ask for, 0 for any")
		reapInt     = flag.Duration("reap-interval", 10*time.Second, "how often to expire sessions and prune retained messages")
		metricsAddr = flag.String("metrics", "", "serve JSON counters on this address, e.g. 127.0.0.1:1884")

		// Transport security. TLS is a second listener next to the plain one, so a
		// fleet can be moved over a device at a time instead of all at once.
		tlsAddr      = flag.String("tls-addr", "", "TLS listen address, e.g. 127.0.0.1:8883; empty means no TLS port")
		tlsCert      = flag.String("tls-cert", "", "PEM certificate the broker presents on -tls-addr")
		tlsKey       = flag.String("tls-key", "", "PEM private key matching -tls-cert")
		tlsCA        = flag.String("tls-ca", "", "PEM CAs that client certificates must chain to; implies they are required")
		tlsClient    = flag.Bool("tls-require-client-cert", false, "require a client certificate without checking it against a CA")
		tlsMinVer    = flag.String("tls-min-version", "1.2", "lowest TLS version accepted: 1.2 or 1.3")
		tlsHandshake = flag.Duration("tls-handshake-timeout", 10*time.Second, "how long a client may take to finish a TLS handshake")

		// Abuse resistance. All three are off by default, because the broker cannot
		// tell a factory floor behind one NAT from a connect storm — both look like
		// a single address asking for many connections. Whoever knows which one they
		// are running turns them on, and the counters say what got refused.
		maxConnsIP  = flag.Int("max-conns-per-ip", 0, "connections one source address may hold at once, 0 for unlimited")
		connRateIP  = flag.Float64("conn-rate-per-ip", 0, "new connections per second one source address may start, 0 for unmetered; 0.2 is one every five seconds")
		connBurstIP = flag.Float64("conn-burst-per-ip", 0, "connections a quiet address may start at once, 0 for one second's worth")

		// Credential failures. The broker never sleeps to slow a brute-force run
		// down: a suspended attempt still holds a socket and three goroutines, so
		// the waiting would be paid by the broker. It refuses instead, and the
		// refusal looks exactly like a wrong password — which also means a correct
		// password from a locked address is refused. On a NAT'd floor of devices
		// that is a real cost, so nothing here is armed by default.
		authFailLimit = flag.Int("auth-fail-limit", 0, "credential failures one source address may make inside -auth-fail-window, 0 to keep refusing without waiting")
		authFailWin   = flag.Duration("auth-fail-window", 0, "how long the credential failures count for; needs -auth-fail-limit")
		authLockout   = flag.Duration("auth-lockout", 0, "how long a locked address stays refused, 0 for one full window")

		// Where a connection really came from. Behind a load balancer every device
		// arrives wearing the balancer's address, so the three limits above, the ip
		// rules and the logs are all decisions about the wrong machine. The PROXY
		// protocol is how a balancer says whose traffic it is forwarding; reading it
		// before anything else is what makes those decisions about the device again.
		proxyMode    = flag.String("proxy-protocol", "off", "read a PROXY protocol header before the payload: off, require (only a balancer may reach these ports) or trusted (believe -trusted-proxy-cidr only)")
		proxyCIDR    = flag.String("trusted-proxy-cidr", "", "comma separated networks allowed to report another address, e.g. 10.0.0.0/8,fd00::/8; needed by -proxy-protocol trusted")
		proxyTimeout = flag.Duration("proxy-header-timeout", 5*time.Second, "how long a peer may take to write the transport header")

		// Living with no restart between a decision and its fix.
		reloadInt = flag.Duration("reload-interval", 2*time.Second, "how often the rule and certificate files are re-checked, 0 for signal-only")
	)
	flag.Parse()

	if *showVer {
		os.Stdout.WriteString("congmq " + version + "\n")
		return
	}
	// The zero value of every Options field means "the default", so 0 here would
	// quietly come back as 2. Saying so out loud beats granting what the
	// operator did not ask for.
	if *maxQoS < 1 || *maxQoS > 2 {
		os.Stderr.WriteString("-max-qos must be 1 or 2 (0 means the default of 2)\n")
		os.Exit(2)
	}
	// The same reasoning: a negative limit is neither the default nor a limit, and
	// treating it as "off" would let a typo read back as a deliberate choice.
	if *maxConnsIP < 0 || *connRateIP < 0 || *connBurstIP < 0 {
		os.Stderr.WriteString("-max-conns-per-ip, -conn-rate-per-ip and -conn-burst-per-ip are limits; 0 turns each one off\n")
		os.Exit(2)
	}
	// The same for -max-subs: a negative cap would read back as "unlimited", which
	// is the opposite of the sentence "-1" was typed to mean.
	if *maxSubs < 0 {
		os.Stderr.WriteString("-max-subs is a limit; 0 means unlimited\n")
		os.Exit(2)
	}
	// -conn-burst-per-ip sizes the bucket that -conn-rate-per-ip fills. Set on its
	// own it would be a number no code reads, which is the one thing a limit flag
	// must never be mistaken for.
	if *connBurstIP > 0 && *connRateIP == 0 {
		os.Stderr.WriteString("-conn-burst-per-ip needs -conn-rate-per-ip: burst is the size of the rate window\n")
		os.Exit(2)
	}
	if *authFailLimit < 0 || *authFailWin < 0 || *authLockout < 0 {
		os.Stderr.WriteString("-auth-fail-limit, -auth-fail-window and -auth-lockout are limits; 0 turns the credential lockout off\n")
		os.Exit(2)
	}
	// A failure count with no window to count inside, or a window with nothing to
	// count, is a limit that never fires. Half a policy is worse than none.
	if (*authFailLimit > 0) != (*authFailWin > 0) {
		os.Stderr.WriteString("-auth-fail-limit and -auth-fail-window are a pair: a failure count needs the window it counts in\n")
		os.Exit(2)
	}
	if *authLockout > 0 && *authFailLimit == 0 {
		os.Stderr.WriteString("-auth-lockout needs -auth-fail-limit and -auth-fail-window: nothing would ever be locked out\n")
		os.Exit(2)
	}
	// The other half of the same trap: with no auth file every credential is
	// accepted, so there is no failure to count and the lockout never fires.
	if *authFailLimit > 0 && *authPath == "" {
		os.Stderr.WriteString("-auth-fail-limit needs -auth: without an auth file every credential is accepted\n")
		os.Exit(2)
	}

	// The transport header. A word that is not one of the three modes is not a
	// typo to be guessed at: "yes" would have to mean either "believe whoever sends
	// a header" or "only believe the list", and those are opposite answers.
	var proxy broker.ProxyMode
	switch *proxyMode {
	case "off":
		proxy = broker.ProxyOff
	case "require":
		proxy = broker.ProxyRequire
	case "trusted":
		proxy = broker.ProxyTrusted
	default:
		os.Stderr.WriteString("-proxy-protocol must be off, require or trusted\n")
		os.Exit(2)
	}
	// trusted with no list believes nobody, so every header gets refused and the
	// broker is an endpoint that only closes connections. That is not a conservative
	// reading of the flag, it is a broken one, so it is refused at startup instead.
	if proxy == broker.ProxyTrusted && *proxyCIDR == "" {
		os.Stderr.WriteString("-proxy-protocol trusted needs -trusted-proxy-cidr: with no list every header would be refused\n")
		os.Exit(2)
	}
	// require expects a header from every peer and consults no list, so the list is
	// a number no code reads. Keep the two shapes apart rather than letting an
	// operator believe the narrower policy was in force.
	if proxy == broker.ProxyRequire && *proxyCIDR != "" {
		os.Stderr.WriteString("-trusted-proxy-cidr does nothing with -proxy-protocol require: require believes a header from every address\n")
		os.Exit(2)
	}
	if proxy == broker.ProxyOff {
		if names := proxyGiven(); len(names) > 0 {
			os.Stderr.WriteString("-proxy-protocol is off, so these flags would do nothing: " +
				strings.Join(names, ", ") + "\n")
			os.Exit(2)
		}
	}
	var proxies []netip.Prefix
	if *proxyCIDR != "" {
		p, err := broker.ParsePrefixes(*proxyCIDR)
		if err != nil {
			os.Stderr.WriteString("-trusted-proxy-cidr: " + err.Error() + "\n")
			os.Exit(2)
		}
		proxies = p
	}
	// A zero timeout is a deadline that has already passed, which would close every
	// connection before the header is read. It is not a way to say "no limit".
	if proxy != broker.ProxyOff && *proxyTimeout <= 0 {
		os.Stderr.WriteString("-proxy-header-timeout must be positive; it bounds a read, and 0 would fail every connection\n")
		os.Exit(2)
	}

	tlsOpt := tlsSettings{
		Addr:          *tlsAddr,
		CertPath:      *tlsCert,
		KeyPath:       *tlsKey,
		CAPath:        *tlsCA,
		RequireClient: *tlsClient,
		MinVersion:    *tlsMinVer,
		Handshake:     *tlsHandshake,
	}
	// A TLS flag with no TLS port is a silent no-op, and the one thing an
	// operator must never be given is the impression that mTLS is on.
	if !tlsOpt.enabled() {
		if names := tlsGiven(); len(names) > 0 {
			os.Stderr.WriteString("-tls-addr is empty, so these flags would do nothing: " +
				strings.Join(names, ", ") + "\n")
			os.Exit(2)
		}
	}

	log := newLogger(*logLevel)
	certs, err := tlsOpt.holder(log)
	if err != nil {
		log.Error("cannot set up tls", "err", err)
		os.Exit(1)
	}
	var tlsCfg *tls.Config
	if certs != nil {
		tlsCfg = certs.cfg
	}
	opt := broker.Options{
		ID:             *id,
		Store:          store.NewMemoryStore(),
		QueueMax:       *queueMax,
		InflightWindow: *window,
		MailboxSize:    *mailbox,
		MaxConns:       *maxConns,
		MaxSubs:        *maxSubs,
		RetryInterval:  *retry,
		WriteTimeout:   *writeTO,
		DeliverTimeout: *deliverTO,
		Logger:         log,

		ReceiveMax:       *receiveMax,
		TopicAliasMax:    uint16(*aliasMax),
		MaxPacketSize:    uint32(*maxPacket),
		MaxQoS:           byte(*maxQoS),
		SessionExpiryMax: *expiryMax,
		ReapInterval:     *reapInt,

		TLSConfig:        tlsCfg,
		HandshakeTimeout: *tlsHandshake,

		MaxConnsPerIP:     *maxConnsIP,
		ConnectRatePerIP:  *connRateIP,
		ConnectBurstPerIP: *connBurstIP,

		AuthFailLimit:  *authFailLimit,
		AuthFailWindow: *authFailWin,
		AuthLockout:    *authLockout,

		Proxy:              proxy,
		TrustedProxies:     proxies,
		ProxyHeaderTimeout: *proxyTimeout,
	}
	// A rule file that will not parse is never ignored: half a policy is worse
	// than no policy, so the operator fixes it before anything connects.
	if *authPath != "" {
		auth, err := rules.LoadAuth(*authPath)
		if err != nil {
			log.Error("cannot load auth rules", "err", err)
			os.Exit(1)
		}
		opt.Auth = auth
	}
	if *aclPath != "" {
		acl, err := rules.LoadACL(*aclPath)
		if err != nil {
			log.Error("cannot load acl rules", "err", err)
			os.Exit(1)
		}
		opt.ACL = acl
	}
	// A cert_cn rule is a promise that the broker can look at a client
	// certificate. With no TLS port on the command line no connection can ever
	// carry one, so every device that follows the rules would be refused and the
	// only clue would be a debug line about a missing common name.
	if !tlsOpt.enabled() {
		switch {
		case opt.Auth != nil && opt.Auth.UsesCertificates():
			log.Error("auth rules ask for a client certificate but no tls listener is configured, so they can never be met",
				"file", *authPath, "hint", "add -tls-addr with -tls-ca")
			os.Exit(1)
		case opt.ACL != nil && opt.ACL.UsesCertificates():
			log.Error("acl rules ask for a client certificate but no tls listener is configured, so they can never be met",
				"file", *aclPath, "hint", "add -tls-addr with -tls-ca")
			os.Exit(1)
		}
	}

	// os.Exit skips defers, so the store is closed by hand on every path that
	// leaves the process. Closing is what flushes the last snapshot and rewrites
	// the file compact; skipping it costs the operator messages they believe are
	// already saved.
	closeStore := func() error { return nil }
	if *storeDir != "" {
		fs, err := store.NewFileStore(store.FileStoreOptions{
			Dir:           *storeDir,
			Sync:          store.SyncMode(*storeSync),
			CompactAfter:  int64(*compactMB) << 20,
			FlushInterval: *storeFlushInt,
			OnError:       func(err error) { log.Error("store write failed", "err", err) },
		})
		if err != nil {
			log.Error("cannot open the store", "dir", *storeDir, "sync", *storeSync, "err", err)
			os.Exit(1)
		}
		opt.Store = fs
		opt.Durable = fs
		closeStore = fs.Close
		logStore(log, fs, *storeSync)
	}

	b := broker.New(opt)
	if err := b.Listen(*addr); err != nil {
		log.Error("cannot start", "err", err)
		_ = closeStore()
		os.Exit(1)
	}
	if err := b.ListenTLS(tlsOpt.Addr); err != nil {
		log.Error("cannot start the tls listener", "addr", tlsOpt.Addr, "err", err)
		_ = b.Shutdown(context.Background())
		_ = closeStore()
		os.Exit(1)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- b.Serve() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The reloader owns the one copy of the file stamps, so the signal trigger
	// arrives on a channel it reads instead of running a second check in the
	// signal's own goroutine.
	rel := &reloader{
		log:       log,
		b:         b,
		authPath:  *authPath,
		aclPath:   *aclPath,
		certs:     certs,
		interval:  *reloadInt,
		tlsOn:     tlsOpt.enabled(),
		ruleStamp: stampPair(*authPath, *aclPath),
	}
	hup := make(chan os.Signal, 1)
	// SIGHUP means "check now" on the platforms that deliver it; everywhere the
	// ticker does the work, so a Windows operator gets the same behaviour without
	// a signal that never arrives.
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go rel.run(ctx, hup)

	if *metricsAddr != "" {
		_, closeMetrics, err := serveMetrics(*metricsAddr, b, certs, rel, log)
		if err != nil {
			log.Error("cannot start the metrics endpoint", "addr", *metricsAddr, "err", err)
			_ = closeStore()
			os.Exit(1)
		}
		defer closeMetrics()
	}

	select {
	case err := <-serveErr:
		if err != nil {
			log.Error("listener stopped", "err", err)
			_ = b.Shutdown(context.Background())
			_ = closeStore()
			os.Exit(1)
		}
	case <-ctx.Done():
		log.Info("signal received, draining sessions")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := b.Shutdown(shutdownCtx); err != nil {
			log.Error("shutdown incomplete", "err", err)
			_ = closeStore()
			os.Exit(1)
		}
	}
	if err := closeStore(); err != nil {
		// The sessions are already drained and the listener is gone, so this is
		// not a data-loss emergency; it is the operator being told the file may
		// grow faster than usual or hold a snapshot the next start will not see.
		log.Error("cannot finish the store", "err", err)
		os.Exit(1)
	}
}

// logStore reports what a restart found. An operator deciding whether to trust
// the file needs the counts before the first connection, not after the week's
// worth of drift.
func logStore(log *slog.Logger, fs *store.FileStore, sync string) {
	if fs.Discarded > 0 {
		// Trailing bytes that never formed a whole record: the previous process
		// died mid-write. Nothing before them was lost, but say so out loud.
		log.Warn("the previous shutdown was not clean", "bytes_discarded", fs.Discarded)
	}
	log.Info("store open",
		"path", fs.Path(), "sync", sync,
		"sessions", len(fs.Sessions()),
		"retained", len(fs.LoadRetained()),
		"wills", len(fs.LoadWills()))
}

// proxyGiven names the transport-header flags set on the command line, other than
// the switch that turns the feature on. With -proxy-protocol off they are numbers
// no code reads, and the worse outcome than not setting them is setting them and
// believing they did something.
func proxyGiven() []string {
	var names []string
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "trusted-proxy-cidr", "proxy-header-timeout":
			names = append(names, "-"+f.Name)
		}
	})
	slices.Sort(names)
	return names
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv})
	return slog.New(h)
}
