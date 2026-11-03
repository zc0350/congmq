// congmq-cert mints a throwaway certificate chain — one CA, one server leaf, one
// client leaf — so TLS can be turned on and exercised without openssl or a
// purchased certificate.
//
//	go build -o bin/congmq-cert.exe ./cmd/congmq-cert
//
//	bin/congmq-cert -out test/pki                    # loopback defaults
//	bin/congmq-cert -out pki -dns mqtt.example.com -ip 192.168.1.20 -days 7
//	bin/congmq-cert -out pki -days -1                # already expired, for tests
//
// What it writes is ca.crt, server.crt, server.key, client.crt and client.key —
// the five files a broker and a client need to start. Everything is signed by a
// brand-new CA that exists only in -out, which makes the chain good for a test on
// this machine and wrong for anything reachable from a network. It prints the
// identities and the expiry so the operator sees what they just made.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zc0350/congmq/internal/tlscert"
)

// list collects a flag that may be given more than once and may also hold
// comma-separated values, because "-dns a.com -dns b.com" and "-dns a.com,b.com"
// are both obvious ways to write the same thing.
type list []string

func (l *list) String() string {
	if l == nil {
		return ""
	}
	return strings.Join(*l, ",")
}

func (l *list) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

var (
	out      = flag.String("out", "pki", "directory to write the chain into; existing files are replaced")
	days     = flag.Int("days", 1, "how long the certificates stay valid; negative mints already-expired ones")
	serverCN = flag.String("server-cn", "congmq.test", "CommonName of the server certificate")
	clientCN = flag.String("client-cn", "congmq-device-1", "CommonName of the client certificate")
	dnsNames list
	ips      list
)

func main() {
	flag.Var(&dnsNames, "dns", "Subject Alternative Name hostname, repeatable; giving any SAN flag replaces the loopback defaults")
	flag.Var(&ips, "ip", "Subject Alternative Name IP address, repeatable; default 127.0.0.1 and ::1, replaced the same way")
	flag.Parse()

	parsedIPs := make([]net.IP, 0, len(ips))
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			exitf("-ip %q is not an IP address", s)
		}
		parsedIPs = append(parsedIPs, ip)
	}

	b, err := tlscert.Generate(tlscert.Options{
		ServerCN: *serverCN,
		ClientCN: *clientCN,
		DNSNames: dnsNames,
		IPs:      parsedIPs,
		ValidFor: time.Duration(*days) * 24 * time.Hour,
	})
	if err != nil {
		exitf("%v", err)
	}
	if err := b.WriteDir(*out); err != nil {
		exitf("%v", err)
	}

	fmt.Printf("dir        %s\n", *out)
	fmt.Printf("ca.crt     %s\n", b.CACommonName)
	fmt.Printf("server     %s  SANs %s\n", b.ServerCN, strings.Join(b.ServerSANs, ","))
	fmt.Printf("client     %s\n", b.ClientCN)
	fmt.Printf("expires    %s\n", b.NotAfter.Format(time.RFC3339))
	if time.Now().After(b.NotAfter) {
		fmt.Printf("note       already expired on purpose — for tests only\n")
	} else {
		fmt.Printf("note       self-signed; trust %s explicitly on every client that connects\n",
			filepath.Join(*out, "ca.crt"))
	}
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "congmq-cert: "+format+"\n", args...)
	os.Exit(1)
}
