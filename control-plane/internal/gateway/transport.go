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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// MaxConnectionAge bounds how long one TLS session lives. Certificate validity is checked at the
// handshake only, and the gateway keeps long-lived HTTP/2 connections, so without this an expired
// (or deliberately expired, as revocation) certificate would keep a connection open indefinitely.
const MaxConnectionAge = time.Hour

// connectionAge and connectionAgeGrace (which lets calls in progress finish before the
// connection closes) are variables only so tests can shorten them.
var connectionAge, connectionAgeGrace = MaxConnectionAge, 30 * time.Second

// Identity is the gateway workload the endpoints accept: a SPIFFE id matched against URI SANs
// only, or a DNS name matched against DNS SANs only.
type Identity struct {
	spiffe *url.URL
	dns    string
}

// String is the identity as configured.
func (i Identity) String() string {
	if i.spiffe != nil {
		return i.spiffe.String()
	}
	return i.dns
}

// ParseIdentity accepts spiffe://trust-domain/path (the trust domain a DNS name, so no port; no
// user, query or fragment) or a plain
// lowercase DNS name without wildcards. Anything else is refused at startup.
func ParseIdentity(raw string) (Identity, error) {
	if strings.HasPrefix(raw, "spiffe://") {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "spiffe" || u.Host == "" || u.User != nil || u.RawQuery != "" ||
			u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || u.Path == "" || u.Path == "/" ||
			!dnsName.MatchString(u.Host) || strings.ContainsAny(u.Path, "*") {
			return Identity{}, fmt.Errorf("gateway identity %q is not a SPIFFE id (spiffe://trust-domain/path)", raw)
		}
		return Identity{spiffe: u}, nil
	}
	if !dnsName.MatchString(raw) {
		return Identity{}, fmt.Errorf("gateway identity %q is neither a SPIFFE id nor a lowercase DNS name without wildcards", raw)
	}
	return Identity{dns: raw}, nil
}

// Names reports whether a certificate carries the identity in the matching SAN type. A SPIFFE
// identity requires exactly one URI SAN (X509-SVID); a DNS identity matches a DNS SAN, ignoring
// case and a trailing dot.
func (i Identity) Names(cert *x509.Certificate) bool {
	if i.spiffe != nil {
		if len(cert.URIs) != 1 {
			return false
		}
		u := cert.URIs[0]
		return u.Scheme == "spiffe" && u.Host == i.spiffe.Host && u.Path == i.spiffe.Path && u.User == nil &&
			u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == ""
	}
	for _, name := range cert.DNSNames {
		if strings.EqualFold(strings.TrimSuffix(name, "."), i.dns) {
			return true
		}
	}
	return false
}

// tlsFiles reloads the server certificate, key and client CA when their files change, so
// certificates rotate without a restart. A failed reload (for example a half-written file) keeps
// the last good set and logs; a rotated set applies to new handshakes, and MaxConnectionAge
// moves every connection onto it within an hour.
type tlsFiles struct {
	cert, key, ca string
	identity      Identity
	log           *slog.Logger

	mu       sync.Mutex
	modified [3]time.Time // of the set in use
	refused  [3]time.Time // of the last set that failed to load, logged once
	current  *tls.Config
}

func (f *tlsFiles) stamps() ([3]time.Time, error) {
	var out [3]time.Time
	for i, path := range []string{f.cert, f.key, f.ca} {
		st, err := os.Stat(path)
		if err != nil {
			return out, err
		}
		out[i] = st.ModTime()
	}
	return out, nil
}

func (f *tlsFiles) build() (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(f.cert, f.key)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	pem, err := os.ReadFile(f.ca)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
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

func (f *tlsFiles) config(*tls.ClientHelloInfo) (*tls.Config, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	stamps, err := f.stamps()
	if err == nil && stamps != f.modified && stamps != f.refused {
		if cfg, berr := f.build(); berr == nil {
			f.current, f.modified = cfg, stamps
			f.log.Info("gateway endpoint TLS material reloaded", "not_after", notAfter(cfg))
		} else {
			f.refused, err = stamps, berr
		}
	}
	if err != nil {
		f.log.Error("gateway endpoint TLS material not reloaded; keeping the last good set", "error", err)
	}
	return f.current, nil
}

func notAfter(cfg *tls.Config) time.Time {
	if leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0]); err == nil {
		return leaf.NotAfter
	}
	return time.Time{}
}

// ServerTLS builds the endpoints' TLS configuration. It refuses to build (fails closed) when a
// file is missing or unreadable, the key does not match the certificate, the CA file holds no
// certificate, or the identity is not a valid SPIFFE id or DNS name.
func ServerTLS(certFile, keyFile, clientCAFile, clientIdentity string, log *slog.Logger) (*tls.Config, error) {
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
	files := &tlsFiles{cert: certFile, key: keyFile, ca: clientCAFile, identity: identity, log: log}
	if files.current, err = files.build(); err != nil {
		return nil, err
	}
	if files.modified, err = files.stamps(); err != nil {
		return nil, err
	}
	// The outer config is what gRPC wraps; each handshake gets the current files' config.
	outer := files.current.Clone()
	outer.GetConfigForClient = files.config
	return outer, nil
}

// ServerTransport is how an endpoint command was told to listen.
type ServerTransport struct {
	TLS      *tls.Config // nil only in explicit insecure development mode
	Identity Identity
}

// ServerOptions are the gRPC options for the transport: TLS credentials, and a bounded
// connection age so certificate expiry and rotation reach every connection.
func (t ServerTransport) ServerOptions() []grpc.ServerOption {
	if t.TLS == nil {
		return nil
	}
	return []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(t.TLS)),
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
	cfg, err := ServerTLS(certFile, keyFile, clientCAFile, clientIdentity, log)
	if err != nil {
		return ServerTransport{}, err
	}
	identity, _ := ParseIdentity(clientIdentity)
	return ServerTransport{TLS: cfg, Identity: identity}, nil
}

// ServerNotAfter is the server certificate's expiry, for the startup log.
func ServerNotAfter(cfg *tls.Config) time.Time {
	if cfg == nil || len(cfg.Certificates) == 0 {
		return time.Time{}
	}
	return notAfter(cfg)
}
