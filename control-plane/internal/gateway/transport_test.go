package gateway_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"muistamo.dev/muistamo/control-plane/internal/gateway"
)

// HUMAN REVIEW REQUIRED: mutual TLS between agentgateway and the authz and ingest endpoints.

const gatewayIdentity = "spiffe://muistamo.dev/agentgateway"

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newAuthority(t *testing.T, name string) authority {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return authority{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// intermediate is a CA issued by a, as an operator's issuing CA under an offline root.
func (a authority) intermediate(t *testing.T) authority {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "issuing CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return authority{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

type leafSpec struct {
	uris, dns []string
	urls      []*url.URL // taken as given, for encodings url.Parse would normalise
	eku       x509.ExtKeyUsage
	notAfter  time.Time
}

func (a authority) issue(t *testing.T, s leafSpec) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if s.notAfter.IsZero() {
		s.notAfter = time.Now().Add(time.Hour)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: s.notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{s.eku}, DNSNames: s.dns}
	for _, raw := range s.uris {
		u, _ := url.Parse(raw)
		tmpl.URIs = append(tmpl.URIs, u)
	}
	tmpl.URIs = append(tmpl.URIs, s.urls...)
	if s.eku == x509.ExtKeyUsageServerAuth {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// leaf issues a server certificate for gateway-authz, or a client certificate naming uri.
func (a authority) leaf(t *testing.T, uri string, server bool, notAfter time.Time) tls.Certificate {
	if server {
		return a.issue(t, leafSpec{dns: []string{"gateway-authz"}, eku: x509.ExtKeyUsageServerAuth, notAfter: notAfter})
	}
	return a.issue(t, leafSpec{uris: []string{uri}, eku: x509.ExtKeyUsageClientAuth, notAfter: notAfter})
}

func writePEM(t *testing.T, dir, name string, c tls.Certificate) (string, string) {
	t.Helper()
	certPath, keyPath := filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key")
	keyDER, _ := x509.MarshalECPrivateKey(c.PrivateKey.(*ecdsa.PrivateKey))
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]}), 0o600)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certPath, keyPath
}

type pki struct {
	ca, other  authority
	dir        string
	serverCert string
	serverKey  string
	caFile     string
}

func newPKI(t *testing.T) pki {
	t.Helper()
	p := pki{ca: newAuthority(t, "muistamo test CA"), other: newAuthority(t, "another CA"), dir: t.TempDir()}
	p.serverCert, p.serverKey = writePEM(t, p.dir, "server", p.ca.leaf(t, "", true, time.Now().Add(time.Hour)))
	p.caFile = filepath.Join(p.dir, "ca.pem")
	_ = os.WriteFile(p.caFile, p.ca.pem, 0o600)
	return p
}

// serve runs a gRPC server with the endpoints' transport options and returns its address.
func serve(t *testing.T, transport gateway.ServerTransport) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(transport.ServerOptions()...)
	healthpb.RegisterHealthServer(server, health.NewServer())
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)
	return lis.Addr().String()
}

func serveTLS(t *testing.T, p pki, identity string) string {
	t.Helper()
	tr, err := gateway.ChooseTransport(false, p.serverCert, p.serverKey, p.caFile, identity, quiet)
	if err != nil {
		t.Fatal(err)
	}
	return serve(t, tr)
}

func check(ctx context.Context, conn *grpc.ClientConn) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

func call(addr string, creds credentials.TransportCredentials) error {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	return check(context.Background(), conn)
}

func clientTLS(p pki, cert *tls.Certificate, roots []byte, maxVersion uint16) credentials.TransportCredentials {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(roots)
	cfg := &tls.Config{RootCAs: pool, ServerName: "gateway-authz", MaxVersion: maxVersion}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return credentials.NewTLS(cfg)
}

func TestMutualTLSAdmitsOnlyTheGatewayIdentityFromTheOperatorsCA(t *testing.T) {
	p := newPKI(t)
	cfg, err := gateway.ServerTLS(p.serverCert, p.serverKey, p.caFile, gatewayIdentity, quiet)
	if err != nil {
		t.Fatal(err)
	}
	// Client certificates are required and verified by the TLS stack itself, not only by the hook.
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert || cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("client auth %v, min version %x", cfg.ClientAuth, cfg.MinVersion)
	}
	addr := serveTLS(t, p, gatewayIdentity)
	good := p.ca.leaf(t, gatewayIdentity, false, time.Now().Add(time.Hour))
	if err := call(addr, clientTLS(p, &good, p.ca.pem, 0)); err != nil {
		t.Fatalf("the gateway's certificate was refused: %v", err)
	}
	// An operator's issuing CA under the configured root: the gateway sends the chain.
	issuing := p.ca.intermediate(t)
	chained := issuing.leaf(t, gatewayIdentity, false, time.Now().Add(time.Hour))
	chained.Certificate = append(chained.Certificate, issuing.cert.Raw)
	if err := call(addr, clientTLS(p, &chained, p.ca.pem, 0)); err != nil {
		t.Fatalf("a chain through an intermediate was refused: %v", err)
	}
	unchained := issuing.leaf(t, gatewayIdentity, false, time.Now().Add(time.Hour))

	otherCA := p.other.leaf(t, gatewayIdentity, false, time.Now().Add(time.Hour))
	wrongName := p.ca.leaf(t, "spiffe://muistamo.dev/another-service", false, time.Now().Add(time.Hour))
	expired := p.ca.leaf(t, gatewayIdentity, false, time.Now().Add(-time.Minute))
	serverEKU := p.ca.issue(t, leafSpec{uris: []string{gatewayIdentity}, eku: x509.ExtKeyUsageServerAuth})
	asDNS := p.ca.issue(t, leafSpec{dns: []string{"muistamo.dev"}, eku: x509.ExtKeyUsageClientAuth})
	twoURIs := p.ca.issue(t, leafSpec{uris: []string{gatewayIdentity, "spiffe://muistamo.dev/another-service"}, eku: x509.ExtKeyUsageClientAuth})
	withQuery := p.ca.issue(t, leafSpec{uris: []string{gatewayIdentity + "?x=1"}, eku: x509.ExtKeyUsageClientAuth})
	upperHost := p.ca.issue(t, leafSpec{uris: []string{"spiffe://MUISTAMO.dev/agentgateway"}, eku: x509.ExtKeyUsageClientAuth})
	encoded := p.ca.issue(t, leafSpec{uris: []string{"spiffe://muistamo.dev/%61gentgateway"}, eku: x509.ExtKeyUsageClientAuth})
	upperScheme := p.ca.issue(t, leafSpec{urls: []*url.URL{{Scheme: "SPIFFE", Host: "muistamo.dev", Path: "/agentgateway"}}, eku: x509.ExtKeyUsageClientAuth})
	for name, creds := range map[string]credentials.TransportCredentials{
		"no client certificate":                clientTLS(p, nil, p.ca.pem, 0),
		"certificate from another CA":          clientTLS(p, &otherCA, p.ca.pem, 0),
		"same CA, another identity":            clientTLS(p, &wrongName, p.ca.pem, 0),
		"expired certificate":                  clientTLS(p, &expired, p.ca.pem, 0),
		"server-auth-only certificate":         clientTLS(p, &serverEKU, p.ca.pem, 0),
		"trust domain as a DNS SAN":            clientTLS(p, &asDNS, p.ca.pem, 0),
		"two URI SANs":                         clientTLS(p, &twoURIs, p.ca.pem, 0),
		"identity with a query":                clientTLS(p, &withQuery, p.ca.pem, 0),
		"uppercase trust domain":               clientTLS(p, &upperHost, p.ca.pem, 0),
		"percent-encoded identity":             clientTLS(p, &encoded, p.ca.pem, 0),
		"uppercase scheme":                     clientTLS(p, &upperScheme, p.ca.pem, 0),
		"intermediate not sent":                clientTLS(p, &unchained, p.ca.pem, 0),
		"TLS 1.2 only":                         clientTLS(p, &good, p.ca.pem, tls.VersionTLS12),
		"plaintext":                            insecure.NewCredentials(),
		"server not trusted":                   clientTLS(p, &good, p.other.pem, 0),
		"server certificate for another name":  credentials.NewTLS(&tls.Config{RootCAs: poolOf(p.ca.pem), ServerName: "gateway-ingest", Certificates: []tls.Certificate{good}}),
		"server certificate without client CA": credentials.NewTLS(&tls.Config{ServerName: "gateway-authz", Certificates: []tls.Certificate{good}}),
	} {
		if err := call(addr, creds); err == nil {
			t.Errorf("%s: call succeeded", name)
		}
	}
}

func poolOf(pemBytes []byte) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemBytes)
	return pool
}

func TestDNSIdentityMatchesOnlyDNSSANs(t *testing.T) {
	p := newPKI(t)
	addr := serveTLS(t, p, "agentgateway.muistamo.internal")
	for name, s := range map[string]leafSpec{
		"exact":         {dns: []string{"agentgateway.muistamo.internal"}},
		"other case":    {dns: []string{"AgentGateway.Muistamo.Internal"}},
		"trailing dot":  {dns: []string{"agentgateway.muistamo.internal."}},
		"among several": {dns: []string{"other.muistamo.internal", "agentgateway.muistamo.internal"}},
	} {
		s.eku = x509.ExtKeyUsageClientAuth
		cert := p.ca.issue(t, s)
		if err := call(addr, clientTLS(p, &cert, p.ca.pem, 0)); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	for name, s := range map[string]leafSpec{
		"as a URI SAN":   {uris: []string{"dns://agentgateway.muistamo.internal"}},
		"wildcard":       {dns: []string{"*.muistamo.internal"}},
		"suffix only":    {dns: []string{"muistamo.internal"}},
		"longer name":    {dns: []string{"agentgateway.muistamo.internal.evil"}},
		"no SAN at all":  {},
		"another name":   {dns: []string{"other.muistamo.internal"}},
		"spiffe instead": {uris: []string{"spiffe://agentgateway.muistamo.internal/x"}},
	} {
		s.eku = x509.ExtKeyUsageClientAuth
		cert := p.ca.issue(t, s)
		if err := call(addr, clientTLS(p, &cert, p.ca.pem, 0)); err == nil {
			t.Errorf("%s: call succeeded", name)
		}
	}
}

func TestParseIdentityRefusesAmbiguousIdentities(t *testing.T) {
	for _, ok := range []string{gatewayIdentity, "spiffe://example.org/ns/prod/sa/agentgateway", "agentgateway", "agentgateway.muistamo.internal"} {
		if _, err := gateway.ParseIdentity(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "spiffe://", "spiffe://muistamo.dev", "spiffe://muistamo.dev/", "spiffe://muistamo.dev:443/agentgateway",
		"spiffe://user@muistamo.dev/agentgateway", "spiffe://muistamo.dev/agentgateway?x=1", "spiffe://muistamo.dev/agentgateway?",
		"spiffe://muistamo.dev/agentgateway#frag", "spiffe://MUISTAMO.dev/agentgateway", "spiffe://muistamo.dev/*",
		"https://muistamo.dev/agentgateway", "SPIFFE://muistamo.dev/agentgateway", "*.muistamo.internal", "AgentGateway",
		"agentgateway.", "agent gateway", "agentgateway\n", "-agentgateway", "127.0.0.1:443",
		"spiffe://muistamo.dev/agentgateway/", "spiffe://muistamo.dev/a//b", "spiffe://muistamo.dev/../x",
		"spiffe://muistamo.dev/a/./b", "spiffe://muistamo.dev/a%2Fb", "spiffe://muistamo.dev/%61gentgateway",
		"spiffe://muistamo.dev/a b", "spiffe://muistamo.dev/agentgateway#",
	} {
		if _, err := gateway.ParseIdentity(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

// waitPast sleeps until a certificate's NotAfter (second-truncated by x509) has passed.
func waitPast(t *testing.T, c tls.Certificate) {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(leaf.NotAfter) + 1500*time.Millisecond)
}

func dial(t *testing.T, addr string, creds credentials.TransportCredentials) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := check(context.Background(), conn); err != nil {
		t.Fatalf("valid certificate refused: %v", err)
	}
	return conn
}

// Certificate validity is only checked at the handshake; every call re-verifies it, so a client
// certificate that expires on an open connection is refused at use time.
func TestExpiredClientCertificateIsRefusedOnItsOpenConnection(t *testing.T) {
	p := newPKI(t)
	addr := serveTLS(t, p, gatewayIdentity)
	expiresSoon := p.ca.leaf(t, gatewayIdentity, false, time.Now().Add(5*time.Second))
	conn := dial(t, addr, clientTLS(p, &expiresSoon, p.ca.pem, 0))
	waitPast(t, expiresSoon)
	if err := check(context.Background(), conn); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("a call on a connection whose client certificate expired = %v, want Unauthenticated", err)
	}
}

// Removing a CA reaches open connections at the next call, not when the connection is recycled.
func TestCallsOnOpenConnectionsAreVerifiedAgainstTheCurrentCA(t *testing.T) {
	defer gateway.RecheckEvery(0)()
	p := newPKI(t)
	addr := serveTLS(t, p, gatewayIdentity)
	good := p.ca.leaf(t, gatewayIdentity, false, time.Now().Add(time.Hour))
	conn := dial(t, addr, clientTLS(p, &good, p.ca.pem, 0))
	_ = os.WriteFile(p.caFile, newAuthority(t, "next CA").pem, 0o600)
	if err := check(context.Background(), conn); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("a call from a removed CA on an open connection = %v, want Unauthenticated", err)
	}
}

// The pin holds at the handshake itself, not only per call: a certificate from the right CA that
// names another workload never completes a TLS session.
func TestHandshakeRefusesAnotherIdentity(t *testing.T) {
	p := newPKI(t)
	addr := serveTLS(t, p, gatewayIdentity)
	attempt := func(c tls.Certificate) error {
		conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: poolOf(p.ca.pem), ServerName: "gateway-authz",
			Certificates: []tls.Certificate{c}, NextProtos: []string{"h2"}})
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		// TLS 1.3 reports a refused client certificate on the first read after the handshake.
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err = conn.Read(make([]byte, 1))
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil
		}
		return err
	}
	if err := attempt(p.ca.leaf(t, gatewayIdentity, false, time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("the gateway's certificate was refused at the handshake: %v", err)
	}
	if err := attempt(p.ca.leaf(t, "spiffe://muistamo.dev/another-service", false, time.Now().Add(time.Hour))); err == nil {
		t.Fatal("a certificate naming another workload completed the handshake")
	}
}

// Handshakes and calls cannot turn into file system load: the files are read once per interval.
func TestFilesAreReadAtMostOncePerInterval(t *testing.T) {
	defer gateway.RecheckEvery(time.Hour)()
	p := newPKI(t)
	addr := serveTLS(t, p, gatewayIdentity)
	_ = os.WriteFile(p.caFile, newAuthority(t, "next CA").pem, 0o600)
	good := p.ca.leaf(t, gatewayIdentity, false, time.Now().Add(time.Hour))
	if err := call(addr, clientTLS(p, &good, p.ca.pem, 0)); err != nil {
		t.Fatalf("the files were reread before the interval passed: %v", err)
	}
}

// A bounded connection age moves open connections onto a rotated server certificate.
func TestConnectionsAreRecycledOntoARotatedServerCertificate(t *testing.T) {
	defer gateway.ShortenConnectionAge(time.Second, 200*time.Millisecond)()
	defer gateway.RecheckEvery(0)()
	p := newPKI(t)
	addr := serveTLS(t, p, gatewayIdentity)
	good := p.ca.leaf(t, gatewayIdentity, false, time.Now().Add(time.Hour))
	// The client trusts only the old server CA, so a reconnection after rotation fails visibly.
	conn := dial(t, addr, clientTLS(p, &good, p.ca.pem, 0))
	next := newAuthority(t, "next server CA")
	cert, key := writePEM(t, t.TempDir(), "server", next.leaf(t, "", true, time.Now().Add(time.Hour)))
	for src, dst := range map[string]string{cert: p.serverCert, key: p.serverKey} {
		body, _ := os.ReadFile(src)
		_ = os.WriteFile(dst, body, 0o600)
	}
	time.Sleep(3 * time.Second)
	var err error
	for range 3 {
		if err = check(context.Background(), conn); err != nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err == nil {
		t.Fatal("an open connection was never moved onto the rotated server certificate")
	}
}

func TestRotatedFilesApplyWithoutRestartAndBadWritesKeepTheLastGoodSet(t *testing.T) {
	defer gateway.RecheckEvery(0)()
	p := newPKI(t)
	var logs strings.Builder
	var logsMu sync.Mutex
	tr, err := gateway.ChooseTransport(false, p.serverCert, p.serverKey, p.caFile, gatewayIdentity,
		slog.New(slog.NewTextHandler(lockedWriter{&logsMu, &logs}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, tr)
	good := p.ca.leaf(t, gatewayIdentity, false, time.Now().Add(time.Hour))
	if err := call(addr, clientTLS(p, &good, p.ca.pem, 0)); err != nil {
		t.Fatal(err)
	}
	// Change detection is by content: keep every file's modification time unchanged.
	stamps := map[string]time.Time{}
	for _, path := range []string{p.serverCert, p.serverKey, p.caFile} {
		st, _ := os.Stat(path)
		stamps[path] = st.ModTime()
	}
	restamp := func() {
		for path, at := range stamps {
			_ = os.Chtimes(path, at, at)
		}
	}
	// Rotation to a new CA: new handshakes use the new server certificate and client CA.
	next := newAuthority(t, "next CA")
	cert, key := writePEM(t, t.TempDir(), "server", next.leaf(t, "", true, time.Now().Add(time.Hour)))
	for src, dst := range map[string]string{cert: p.serverCert, key: p.serverKey} {
		body, _ := os.ReadFile(src)
		_ = os.WriteFile(dst, body, 0o600)
	}
	_ = os.WriteFile(p.caFile, next.pem, 0o600)
	restamp()
	rotated := next.leaf(t, gatewayIdentity, false, time.Now().Add(time.Hour))
	if err := call(addr, clientTLS(p, &rotated, next.pem, 0)); err != nil {
		t.Fatalf("rotated certificates not applied: %v", err)
	}
	// The client trusts the new server certificate, so only the server's CA decides this.
	if err := call(addr, clientTLS(p, &good, next.pem, 0)); err == nil {
		t.Fatal("the retired CA is still trusted after rotation")
	}
	// A half-written certificate, then a missing CA: the server keeps serving the last good set,
	// the rotated one, and logs each problem once however many handshakes see it.
	_ = os.WriteFile(p.serverCert, []byte("-----BEGIN CERTIFICATE-----\ntruncat"), 0o600)
	for range 3 {
		if err := call(addr, clientTLS(p, &rotated, next.pem, 0)); err != nil {
			t.Fatalf("a bad write replaced the last good set: %v", err)
		}
	}
	body, _ := os.ReadFile(cert)
	_ = os.WriteFile(p.serverCert, body, 0o600)
	_ = os.Remove(p.caFile)
	for range 3 {
		if err := call(addr, clientTLS(p, &rotated, next.pem, 0)); err != nil {
			t.Fatalf("a missing file replaced the last good set: %v", err)
		}
	}
	logsMu.Lock()
	defer logsMu.Unlock()
	if n := strings.Count(logs.String(), "not reloaded"); n != 2 {
		t.Fatalf("two bad sets were logged %d times, want once each:\n%s", n, logs.String())
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

func TestServerTLSRefusesIncompleteOrInconsistentMaterial(t *testing.T) {
	p := newPKI(t)
	_, otherKey := writePEM(t, p.dir, "other", p.ca.leaf(t, "", true, time.Now().Add(time.Hour)))
	empty := filepath.Join(p.dir, "empty.pem")
	_ = os.WriteFile(empty, []byte("not a certificate"), 0o600)
	for name, args := range map[string][4]string{
		"missing certificate":        {filepath.Join(p.dir, "absent.pem"), p.serverKey, p.caFile, gatewayIdentity},
		"key of another certificate": {p.serverCert, otherKey, p.caFile, gatewayIdentity},
		"empty CA file":              {p.serverCert, p.serverKey, empty, gatewayIdentity},
		"missing CA":                 {p.serverCert, p.serverKey, filepath.Join(p.dir, "absent-ca.pem"), gatewayIdentity},
		"no identity":                {p.serverCert, p.serverKey, p.caFile, ""},
		"ambiguous identity":         {p.serverCert, p.serverKey, p.caFile, "spiffe://muistamo.dev/agentgateway?x"},
	} {
		if _, err := gateway.ServerTLS(args[0], args[1], args[2], args[3], quiet); err == nil {
			t.Errorf("%s: built a TLS configuration", name)
		}
	}
}

func TestEndpointModeGate(t *testing.T) {
	p := newPKI(t)
	if tr, err := gateway.ChooseTransport(true, "", "", "", "", quiet); err != nil || tr.TLS != nil || tr.ServerOptions() != nil {
		t.Fatalf("explicit development plaintext = %+v, %v", tr, err)
	}
	tr, err := gateway.ChooseTransport(false, p.serverCert, p.serverKey, p.caFile, gatewayIdentity, quiet)
	if err != nil || tr.TLS == nil || tr.Identity.String() != gatewayIdentity {
		t.Fatalf("mutual TLS = %+v, %v", tr, err)
	}
	if got := gateway.ServerNotAfter(tr.TLS); got.IsZero() || got.Before(time.Now()) {
		t.Fatalf("server certificate expiry = %v", got)
	}
	for name, c := range map[string]struct {
		dev  bool
		args [4]string
	}{
		"neither":     {false, [4]string{}},
		"mixed":       {true, [4]string{p.serverCert, p.serverKey, p.caFile, gatewayIdentity}},
		"partial":     {false, [4]string{p.serverCert, p.serverKey, "", ""}},
		"no identity": {false, [4]string{p.serverCert, p.serverKey, p.caFile, ""}},
	} {
		if _, err := gateway.ChooseTransport(c.dev, c.args[0], c.args[1], c.args[2], c.args[3], quiet); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, err = gateway.ChooseTransport(false, "", "", "", "", quiet)
	if err == nil || !strings.Contains(err.Error(), "--insecure-development") {
		t.Fatalf("the refusal does not name both modes: %v", err)
	}
}
