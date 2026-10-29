package gateway

// HUMAN REVIEW REQUIRED: the transport that authenticates agentgateway to the authorization and
// usage-ingest endpoints. Mutual TLS: the endpoints accept only a client certificate issued by the
// operator's CA that names the configured gateway identity, over TLS 1.3. Certificates and keys
// are operator-provided files; Muistamo never generates or stores production keys.
//
// The identity pin is only as strong as the CA's issuance policy: if anyone who can request a
// certificate from that CA can ask for the gateway's identity, they can impersonate the gateway.
// Use a dedicated issuer (or an approval policy) for the gateway identity.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// MaxConnectionAge recycles connections so a rotated server certificate reaches every connection
// (gRPC adds up to 10% jitter, then the grace). Client certificate expiry and CA removal do not
// wait for it: every call re-verifies the caller's chain (verifyPeer).
const MaxConnectionAge = time.Hour

// connectionAge, connectionAgeGrace (which lets calls in progress finish before the connection
// closes) and recheckEvery are variables only so tests can shorten them.
var (
	connectionAge, connectionAgeGrace = MaxConnectionAge, 30 * time.Second
	// recheckEvery bounds how often the files are read, so handshakes (not yet authenticated) and
	// calls cannot turn into file system load. A hung file system blocks handshakes: fails closed.
	recheckEvery = time.Second
)

// Identity is the gateway workload the endpoints accept: a SPIFFE id that must be the
// certificate's single URI SAN byte for byte, or a DNS name matched against DNS SANs only.
type Identity struct {
	spiffe string
	dns    string
}

// String is the identity as configured.
func (i Identity) String() string {
	if i.spiffe != "" {
		return i.spiffe
	}
	return i.dns
}

// spiffePath is the SPIFFE path grammar: one or more /segment of letters, digits, '.', '_' or '-'.
var spiffePath = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)+$`)

// ParseIdentity accepts spiffe://trust-domain/path in the SPIFFE grammar (a lowercase DNS trust
// domain, so no port; no user, query, fragment, percent-encoding, empty, '.' or '..' segments)
// or a plain lowercase DNS name without wildcards. Anything else is refused at startup.
func ParseIdentity(raw string) (Identity, error) {
	if rest, ok := strings.CutPrefix(raw, "spiffe://"); ok {
		domain, path, _ := strings.Cut(rest, "/")
		path = "/" + path
		valid := dnsName.MatchString(domain) && spiffePath.MatchString(path)
		for _, segment := range strings.Split(path[1:], "/") {
			valid = valid && segment != "." && segment != ".."
		}
		if !valid {
			return Identity{}, fmt.Errorf("gateway identity %q is not a SPIFFE id (spiffe://trust-domain/path)", raw)
		}
		return Identity{spiffe: raw}, nil
	}
	if !dnsName.MatchString(raw) {
		return Identity{}, fmt.Errorf("gateway identity %q is neither a SPIFFE id nor a lowercase DNS name without wildcards", raw)
	}
	return Identity{dns: raw}, nil
}

// Names reports whether a certificate carries the identity in the matching SAN type. A SPIFFE
// identity requires exactly one URI SAN (X509-SVID), compared as encoded in the certificate, so
// no normalisation (case, percent-encoding, an empty fragment) can make another name equal. A
// DNS identity matches a DNS SAN, ignoring case and a trailing dot.
func (i Identity) Names(cert *x509.Certificate) bool {
	if i.spiffe != "" {
		uris, ok := rawURISANs(cert)
		return ok && len(uris) == 1 && len(cert.URIs) == 1 && uris[0] == i.spiffe
	}
	for _, name := range cert.DNSNames {
		if strings.EqualFold(strings.TrimSuffix(name, "."), i.dns) {
			return true
		}
	}
	return false
}

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// rawURISANs are the certificate's URI SANs exactly as encoded; Go's parsed URLs are normalised.
func rawURISANs(cert *x509.Certificate) ([]string, bool) {
	var out []string
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		var seq asn1.RawValue
		rest, err := asn1.Unmarshal(ext.Value, &seq)
		if err != nil || len(rest) != 0 || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
			return nil, false
		}
		for inner := seq.Bytes; len(inner) > 0; {
			var name asn1.RawValue
			if inner, err = asn1.Unmarshal(inner, &name); err != nil {
				return nil, false
			}
			if name.Class == asn1.ClassContextSpecific && name.Tag == 6 { // uniformResourceIdentifier
				out = append(out, string(name.Bytes))
			}
		}
	}
	return out, true
}

// tlsFiles reloads the server certificate, key and client CA when their contents change, so
// certificates rotate without a restart. Changes are detected by content hash, and a set is
// built from the same bytes that were hashed. A set that fails to load (for example a
// half-written file) keeps the last good set; each distinct problem is logged once.
type tlsFiles struct {
	cert, key, ca string
	identity      Identity
	log           *slog.Logger

	mu      sync.Mutex
	checked time.Time
	digest  [sha256.Size]byte // of the set in use
	problem string            // the last problem logged, so each is logged once
	current *tls.Config
}

func (f *tlsFiles) read() (contents [3][]byte, digest [sha256.Size]byte, err error) {
	h := sha256.New()
	for i, path := range []string{f.cert, f.key, f.ca} {
		if contents[i], err = os.ReadFile(path); err != nil {
			return contents, digest, err
		}
		_, _ = fmt.Fprintf(h, "%d:", len(contents[i]))
		h.Write(contents[i])
	}
	copy(digest[:], h.Sum(nil))
	return contents, digest, nil
}

func (f *tlsFiles) build(contents [3][]byte) (*tls.Config, error) {
	pair, err := tls.X509KeyPair(contents[0], contents[1])
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(contents[2]) {
		return nil, errors.New("client CA file holds no certificate")
	}
	identity := f.identity
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pair},
		// RequireAndVerifyClientCert verifies the chain against ClientCAs and the clientAuth EKU.
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  roots,
		// gRPC needs HTTP/2; a config returned per handshake must carry it itself.
		NextProtos: []string{"h2"},
		// After chain verification: pin which workload the certificate belongs to, so another
		// service's certificate from the same CA is refused.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no client certificate")
			}
			if !identity.Names(cs.PeerCertificates[0]) {
				return errors.New("client certificate does not name the gateway identity")
			}
			return nil
		},
	}, nil
}

// refresh returns the set in use, reloading it first when the files changed. It never returns
// nil and never widens what is accepted on failure: the last good set stays.
func (f *tlsFiles) refresh() *tls.Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if now.Sub(f.checked) < recheckEvery {
		return f.current
	}
	f.checked = now
	contents, digest, err := f.read()
	if err == nil && digest == f.digest {
		f.problem = ""
		return f.current
	}
	var cfg *tls.Config
	if err == nil {
		cfg, err = f.build(contents)
	}
	if err != nil {
		if problem := err.Error(); problem != f.problem {
			f.problem = problem
			f.log.Error("gateway endpoint TLS material not reloaded; keeping the last good set", "error", err)
		}
		return f.current
	}
	f.current, f.digest, f.problem = cfg, digest, ""
	f.log.Info("gateway endpoint TLS material reloaded", "not_after", notAfter(cfg))
	return cfg
}

// verifyPeer re-verifies the caller's certificate on every call, against the CA and identity in
// use now: a certificate that expired, or whose CA was removed, after the handshake is refused at
// use time rather than when the connection is next recycled.
func (f *tlsFiles) verifyPeer(ctx context.Context) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no peer")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return status.Error(codes.Unauthenticated, "no client certificate")
	}
	leaf := info.State.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, c := range info.State.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: f.refresh().ClientCAs, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: time.Now()})
	if err != nil || !f.identity.Names(leaf) {
		return status.Error(codes.Unauthenticated, "client certificate no longer valid for the gateway identity")
	}
	return nil
}

func notAfter(cfg *tls.Config) time.Time {
	if leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0]); err == nil {
		return leaf.NotAfter
	}
	return time.Time{}
}

// loadTLSFiles refuses (fails closed) when a file is missing or unreadable, the key does not
// match the certificate, the CA file holds no certificate, or the identity is not a valid SPIFFE
// id or DNS name.
func loadTLSFiles(certFile, keyFile, clientCAFile, clientIdentity string, log *slog.Logger) (*tlsFiles, error) {
	if certFile == "" || keyFile == "" || clientCAFile == "" || clientIdentity == "" {
		return nil, errors.New("mutual TLS requires a server certificate, its key, the client CA and the gateway's client identity")
	}
	identity, err := ParseIdentity(clientIdentity)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	f := &tlsFiles{cert: certFile, key: keyFile, ca: clientCAFile, identity: identity, log: log}
	contents, digest, err := f.read()
	if err != nil {
		return nil, err
	}
	if f.current, err = f.build(contents); err != nil {
		return nil, err
	}
	f.digest, f.checked = digest, time.Now()
	return f, nil
}

func (f *tlsFiles) serverConfig() *tls.Config {
	// The outer config is what gRPC wraps; each handshake gets the current files' config.
	outer := f.current.Clone()
	outer.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return f.refresh(), nil }
	return outer
}

// ServerTLS builds the endpoints' TLS configuration; loadTLSFiles says what it refuses.
func ServerTLS(certFile, keyFile, clientCAFile, clientIdentity string, log *slog.Logger) (*tls.Config, error) {
	f, err := loadTLSFiles(certFile, keyFile, clientCAFile, clientIdentity, log)
	if err != nil {
		return nil, err
	}
	return f.serverConfig(), nil
}

// ServerTransport is how an endpoint command was told to listen.
type ServerTransport struct {
	TLS      *tls.Config // nil only in explicit insecure development mode
	Identity Identity
	files    *tlsFiles
}

// ServerOptions are the gRPC options for the transport: TLS credentials, the caller's certificate
// re-verified on every call, and a bounded connection age so a rotated server certificate reaches
// every connection.
func (t ServerTransport) ServerOptions() []grpc.ServerOption {
	if t.TLS == nil {
		return nil
	}
	return []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(t.TLS)),
		grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
			if err := t.files.verifyPeer(ctx); err != nil {
				return nil, err
			}
			return next(ctx, req)
		}),
		grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, next grpc.StreamHandler) error {
			if err := t.files.verifyPeer(ss.Context()); err != nil {
				return err
			}
			return next(srv, ss)
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionAge: connectionAge, MaxConnectionAgeGrace: connectionAgeGrace}),
	}
}

// ChooseTransport applies the endpoint commands' mode gate: mutual TLS when all four files and the
// identity are given, plaintext only with the explicit development flag, and nothing else.
func ChooseTransport(development bool, certFile, keyFile, clientCAFile, clientIdentity string, log *slog.Logger) (ServerTransport, error) {
	anyTLS := certFile != "" || keyFile != "" || clientCAFile != "" || clientIdentity != ""
	switch {
	case development && anyTLS:
		return ServerTransport{}, errors.New("--insecure-development is plaintext; do not combine it with TLS flags")
	case development:
		return ServerTransport{}, nil
	case !anyTLS:
		return ServerTransport{}, errors.New("give --tls-cert, --tls-key, --client-ca and --client-identity for mutual TLS, or --insecure-development for plaintext on an isolated local network")
	}
	f, err := loadTLSFiles(certFile, keyFile, clientCAFile, clientIdentity, log)
	if err != nil {
		return ServerTransport{}, err
	}
	return ServerTransport{TLS: f.serverConfig(), Identity: f.identity, files: f}, nil
}

// ServerNotAfter is the server certificate's expiry, for the startup log.
func ServerNotAfter(cfg *tls.Config) time.Time {
	if cfg == nil || len(cfg.Certificates) == 0 {
		return time.Time{}
	}
	return notAfter(cfg)
}
