//go:build e2e

package entra

// HUMAN REVIEW REQUIRED (AGENTS.md): this file exists only in test builds (`go build -tags e2e`).
// It sends every Entra and Graph request to a loopback fake of Microsoft's services, for the
// separate-binary end-to-end run (deploy/dev/e2e). The fixed hostnames, the destination allowlist
// and TLS verification all still apply: the fake must present a certificate for the real
// hostnames, issued by the throwaway CA named here, and nothing else is trusted.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
)

func init() {
	address, caFile := os.Getenv("MUISTAMO_E2E_MICROSOFT_ADDR"), os.Getenv("MUISTAMO_E2E_MICROSOFT_CA")
	if address == "" || caFile == "" {
		panic("e2e build: MUISTAMO_E2E_MICROSOFT_ADDR and MUISTAMO_E2E_MICROSOFT_CA are required")
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		panic(fmt.Sprintf("e2e build: read the fake's CA: %v", err))
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		panic("e2e build: the fake's CA is not PEM")
	}
	fmt.Fprintf(os.Stderr, "E2E BUILD: Microsoft services are a loopback fake at %s; never deploy this binary\n", address)
	e2eTransport = func() http.RoundTripper {
		return &http.Transport{
			Proxy:             nil,
			TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: false,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, address)
			},
		}
	}
}
