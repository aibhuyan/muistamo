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
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"muistamo.dev/muistamo/control-plane/internal/gateway"
)

// HUMAN REVIEW REQUIRED: mutual TLS between agentgateway and the authz and ingest endpoints.

const gatewayIdentity = "spiffe://muistamo.dev/agentgateway"

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

// leaf issues a certificate; server certificates name 127.0.0.1, client certificates a URI.
func (a authority) leaf(t *testing.T, uri string, server bool, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tmpl.DNSNames = []string{"gateway-authz"}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		u, _ := url.Parse(uri)
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
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

// serve runs a gRPC server with the endpoints' TLS configuration and returns its address.
func serve(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	healthpb.RegisterHealthServer(server, health.NewServer())
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)
	return lis.Addr().String()
}

func call(addr string, creds credentials.TransportCredentials) error {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
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
	cfg, err := gateway.ServerTLS(p.serverCert, p.serverKey, p.caFile, gatewayIdentity)
	if err != nil {
		t.Fatal(err)
	}
	// Client certificates are required and verified by the TLS stack itself, not only by the hook.
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert || cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("client auth %v, min version %x", cfg.ClientAuth, cfg.MinVersion)
	}
	addr := serve(t, cfg)
	good := p.ca.leaf(t, gatewayIdentity, false, time.Now().Add(time.Hour))
	if err := call(addr, clientTLS(p, &good, p.ca.pem, 0)); err != nil {
		t.Fatalf("the gateway's certificate was refused: %v", err)
	}
	otherCA := p.other.leaf(t, gatewayIdentity, false, time.Now().Add(time.Hour))
	wrongName := p.ca.leaf(t, "spiffe://muistamo.dev/another-service", false, time.Now().Add(time.Hour))
	expired := p.ca.leaf(t, gatewayIdentity, false, time.Now().Add(-time.Minute))
	for name, creds := range map[string]credentials.TransportCredentials{
		"no client certificate":       clientTLS(p, nil, p.ca.pem, 0),
		"certificate from another CA": clientTLS(p, &otherCA, p.ca.pem, 0),
		"same CA, another identity":   clientTLS(p, &wrongName, p.ca.pem, 0),
		"expired certificate":         clientTLS(p, &expired, p.ca.pem, 0),
		"TLS 1.2 only":                clientTLS(p, &good, p.ca.pem, tls.VersionTLS12),
		"plaintext":                   insecure.NewCredentials(),
		"server not trusted":          clientTLS(p, &good, p.other.pem, 0),
	} {
		if err := call(addr, creds); err == nil {
			t.Errorf("%s: call succeeded", name)
		}
	}
}

func TestServerTLSRefusesIncompleteOrInconsistentMaterial(t *testing.T) {
	p := newPKI(t)
	otherCert, otherKey := writePEM(t, p.dir, "other", p.ca.leaf(t, "", true, time.Now().Add(time.Hour)))
	empty := filepath.Join(p.dir, "empty.pem")
	_ = os.WriteFile(empty, []byte("not a certificate"), 0o600)
	for name, args := range map[string][4]string{
		"missing certificate":        {filepath.Join(p.dir, "absent.pem"), p.serverKey, p.caFile, gatewayIdentity},
		"key of another certificate": {p.serverCert, otherKey, p.caFile, gatewayIdentity},
		"empty CA file":              {p.serverCert, p.serverKey, empty, gatewayIdentity},
		"missing CA":                 {p.serverCert, p.serverKey, filepath.Join(p.dir, "absent-ca.pem"), gatewayIdentity},
		"no identity":                {p.serverCert, p.serverKey, p.caFile, ""},
	} {
		if _, err := gateway.ServerTLS(args[0], args[1], args[2], args[3]); err == nil {
			t.Errorf("%s: built a TLS configuration", name)
		}
	}
	_ = otherCert
}

func TestEndpointModeGate(t *testing.T) {
	p := newPKI(t)
	if tr, err := gateway.ChooseTransport(true, "", "", "", ""); err != nil || tr.TLS != nil {
		t.Fatalf("explicit development plaintext = %+v, %v", tr, err)
	}
	if tr, err := gateway.ChooseTransport(false, p.serverCert, p.serverKey, p.caFile, gatewayIdentity); err != nil || tr.TLS == nil {
		t.Fatalf("mutual TLS = %+v, %v", tr, err)
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
		if _, err := gateway.ChooseTransport(c.dev, c.args[0], c.args[1], c.args[2], c.args[3]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, err := gateway.ChooseTransport(false, "", "", "", "")
	if err == nil || !strings.Contains(err.Error(), "--insecure-development") {
		t.Fatalf("the refusal does not name both modes: %v", err)
	}
}
