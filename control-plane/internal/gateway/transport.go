package gateway

// HUMAN REVIEW REQUIRED: the transport that authenticates agentgateway to the authorization and
// usage-ingest endpoints. Mutual TLS: the endpoints accept only a client certificate issued by the
// operator's CA that names the configured gateway identity, over TLS 1.3. Certificates and keys
// are operator-provided files; Muistamo never generates or stores production keys.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"slices"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// ServerTLS builds the endpoints' TLS configuration. It refuses to build (fails closed) when a
// file is missing or unreadable, the key does not match the certificate, the CA file holds no
// certificate, or no client identity is given.
func ServerTLS(certFile, keyFile, clientCAFile, clientIdentity string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" || clientCAFile == "" || clientIdentity == "" {
		return nil, errors.New("mutual TLS requires a server certificate, its key, the client CA and the gateway's client identity")
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	pem, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("client CA file holds no certificate")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
		// The chain is verified against ClientCAs before this runs; this pins which workload the
		// certificate may belong to, so another service's certificate from the same CA is refused.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no client certificate")
			}
			if !CertificateNames(cs.PeerCertificates[0], clientIdentity) {
				return errors.New("client certificate does not name the gateway identity")
			}
			return nil
		},
	}, nil
}

// CertificateNames reports whether a certificate's subject alternative names include identity
// exactly, as a URI (for example a SPIFFE id) or a DNS name.
func CertificateNames(cert *x509.Certificate, identity string) bool {
	for _, u := range cert.URIs {
		if u.String() == identity {
			return true
		}
	}
	return slices.Contains(cert.DNSNames, identity)
}

// PeerIdentity is the verified client certificate's first URI SAN (or DNS SAN), or "" for a
// plaintext peer. For logs: the TLS handshake has already enforced the configured identity.
func PeerIdentity(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return ""
	}
	cert := info.State.PeerCertificates[0]
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String()
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return ""
}

// ServerTransport is how an endpoint command was told to listen.
type ServerTransport struct {
	TLS *tls.Config // nil only in explicit insecure development mode
}

// ChooseTransport applies the endpoint commands' mode gate: mutual TLS when all four files and the
// identity are given, plaintext only with the explicit development flag, and nothing else.
func ChooseTransport(development bool, certFile, keyFile, clientCAFile, clientIdentity string) (ServerTransport, error) {
	anyTLS := certFile != "" || keyFile != "" || clientCAFile != "" || clientIdentity != ""
	switch {
	case development && anyTLS:
		return ServerTransport{}, errors.New("--insecure-development is plaintext; do not combine it with TLS flags")
	case development:
		return ServerTransport{}, nil
	case !anyTLS:
		return ServerTransport{}, errors.New("give --tls-cert, --tls-key, --client-ca and --client-identity for mutual TLS, or --insecure-development for plaintext on an isolated local network")
	}
	cfg, err := ServerTLS(certFile, keyFile, clientCAFile, clientIdentity)
	if err != nil {
		return ServerTransport{}, err
	}
	return ServerTransport{TLS: cfg}, nil
}
