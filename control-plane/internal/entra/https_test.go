package entra

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

// Native HTTPS stays on loopback while preserving the client's fixed authority/Graph URLs,
// headers, redirect behavior and TLS verification. No fake endpoint switch exists in production.
func routeHTTPS(t *testing.T, c *Client, server *httptest.Server) {
	t.Helper()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	host, _, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = host
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("test must verify TLS")
	}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	c.http.Transport = transport
	t.Cleanup(transport.CloseIdleConnections)
}

func TestProviderHTTPSLifecycle(t *testing.T) {
	f := &fakeGraph{read404: 1, staleEnable: 2, staleDelete: 1}
	fixture := f.transport(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Error("not HTTPS")
			w.WriteHeader(500)
			return
		}
		r.URL.Scheme = "https"
		r.URL.Host = r.Host
		res, err := fixture.RoundTrip(r)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		defer func() { _ = res.Body.Close() }()
		for name, values := range res.Header {
			for _, v := range values {
				w.Header().Add(name, v)
			}
		}
		w.WriteHeader(res.StatusCode)
		if res.StatusCode != 204 {
			_, _ = io.Copy(w, res.Body)
		}
	}))
	defer server.Close()
	c := testClient(t, &fakeGraph{})
	routeHTTPS(t, c, server)
	ctx := context.Background()
	created, err := c.CreateDisabled(ctx, testTenant, testCreate)
	if err != nil || created.Enabled {
		t.Fatalf("create=%+v err=%v", created, err)
	}
	if _, err := c.FindCreated(ctx, testTenant, testCreate); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetEnabled(ctx, testTenant, created.Ref, true, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetEnabled(ctx, testTenant, created.Ref, false, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, testTenant, created.Ref, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if countMethod(f.calls, "POST") != 1 || countMethod(f.calls, "PATCH") != 2 || countMethod(f.calls, "DELETE") != 1 {
		t.Fatalf("unexpected effects: %v", f.calls)
	}
}

func TestProviderHTTPSRedirectsRefused(t *testing.T) {
	for _, stage := range []string{"authenticate", "create"} {
		for _, status := range []int{301, 302, 303, 307, 308} {
			t.Run(stage+"/"+http.StatusText(status), func(t *testing.T) {
				var followed atomic.Int32
				var server *httptest.Server
				server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/stolen" {
						followed.Add(1)
						w.WriteHeader(200)
						return
					}
					if stage == "authenticate" || r.Host == "graph.microsoft.com" {
						w.Header().Set("Location", server.URL+"/stolen")
						w.WriteHeader(status)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fakeToken, "token_type": "Bearer", "expires_in": 3600})
				}))
				defer server.Close()
				c := testClient(t, &fakeGraph{})
				routeHTTPS(t, c, server)
				if _, err := c.CreateDisabled(context.Background(), testTenant, testCreate); err == nil {
					t.Fatal("redirect accepted")
				}
				if followed.Load() != 0 {
					t.Fatal("followed redirect with credentials or bearer token")
				}
			})
		}
	}
}

func TestProviderHTTPSLostWriteResponseDoesNotRetry(t *testing.T) {
	for _, action := range []string{"create", "enable"} {
		t.Run(action, func(t *testing.T) {
			var writes atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host == "login.microsoftonline.com" {
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fakeToken, "token_type": "Bearer", "expires_in": 3600})
					return
				}
				if r.Method == "GET" {
					_ = json.NewEncoder(w).Encode(owned(false))
					return
				}
				writes.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = conn.Close() // Provider may have applied the effect; no response is delivered.
			}))
			defer server.Close()
			c := testClient(t, &fakeGraph{})
			routeHTTPS(t, c, server)
			var err error
			if action == "create" {
				_, err = c.CreateDisabled(context.Background(), testTenant, testCreate)
			} else {
				_, err = c.SetEnabled(context.Background(), testTenant, reference(), true, uuid.New())
			}
			if !errors.Is(err, ErrUncertain) || writes.Load() != 1 {
				t.Fatalf("err=%v writes=%d", err, writes.Load())
			}
		})
	}
}
