package entra

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestProviderRejectsZeroOperationIDs(t *testing.T) {
	f := &fakeGraph{}
	c := testClient(t, f)
	ctx := context.Background()
	_, create := c.CreateDisabled(ctx, testTenant, uuid.Nil)
	_, discover := c.FindCreated(ctx, testTenant, uuid.Nil)
	_, inspect := c.Inspect(ctx, testTenant, Reference{CreationID: testCreate})
	_, marker := c.Inspect(ctx, testTenant, Reference{ID: testIdentity})
	_, enable := c.SetEnabled(ctx, testTenant, reference(), true, uuid.Nil)
	del := c.Delete(ctx, testTenant, reference(), uuid.Nil)
	for _, err := range []error{create, discover, inspect, marker, enable, del} {
		if !errors.Is(err, ErrScope) {
			t.Fatalf("zero operation accepted: %v", err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("HTTP with invalid operation: %v", f.calls)
	}
}

func TestProviderBindingRejectsSecretAndEndpointOverrides(t *testing.T) {
	raw, _ := json.Marshal(binding())
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"clientSecret", "graphUrl", "authority", "credentialPath"} {
		doc[key] = fakeSecret
		raw, _ := json.Marshal(doc)
		if _, err := ParseBinding(raw); !errors.Is(err, ErrConfiguration) || strings.Contains(err.Error(), fakeSecret) {
			t.Fatalf("err=%v", err)
		}
		delete(doc, key)
	}
	if _, err := ParseBinding(append(raw, []byte(fakeSecret)...)); !errors.Is(err, ErrConfiguration) || strings.Contains(err.Error(), fakeSecret) {
		t.Fatalf("err=%v", err)
	}
}

func TestProviderSendRefusesUnapprovedDestinations(t *testing.T) {
	f := &fakeGraph{}
	c := testClient(t, f)
	c.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("request to unapproved destination")
		return nil, nil
	})
	for _, target := range []string{
		"https://attacker.invalid/v1.0/servicePrincipals/microsoft.graph.agentIdentity",
		"http://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity",
		"https://graph.microsoft.com.attacker.invalid/v1.0/servicePrincipals/microsoft.graph.agentIdentity",
		"https://user:password@graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity",
		"https://graph.microsoft.com/beta/servicePrincipals/microsoft.graph.agentIdentity",
		"https://graph.microsoft.com/v1.0/users",
		"https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentity#leak",
		"https://login.microsoftonline.com/common/oauth2/v2.0/token",
		"https://login.microsoftonline.com/" + binding().EntraTenantId + "/oauth2/v2.0/token?leak=value",
	} {
		method := http.MethodGet
		if strings.Contains(target, "login.microsoftonline.com") {
			method = http.MethodPost
		}
		if _, err := c.send(context.Background(), "test", method, target, nil, nil, uuid.New(), false); err == nil {
			t.Fatalf("accepted %s", target)
		}
	}
}

func TestProviderTransportFailuresArePrivateAndUncertain(t *testing.T) {
	for _, action := range []string{"create", "enable", "delete"} {
		t.Run(action, func(t *testing.T) {
			f := &fakeGraph{}
			c := testClient(t, f)
			original := c.http.Transport
			writes := 0
			c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "graph.microsoft.com" && r.Method != "GET" {
					writes++
					return nil, errors.New(fakeSecret + fakeToken)
				}
				return original.RoundTrip(r)
			})
			var err error
			switch action {
			case "create":
				_, err = c.CreateDisabled(context.Background(), testTenant, testCreate)
			case "enable":
				_, err = c.SetEnabled(context.Background(), testTenant, reference(), true, uuid.New())
			case "delete":
				err = c.Delete(context.Background(), testTenant, reference(), uuid.New())
			}
			if !errors.Is(err, ErrUncertain) || writes != 1 || strings.Contains(err.Error(), fakeSecret) || strings.Contains(err.Error(), fakeToken) {
				t.Fatalf("err=%v writes=%d", err, writes)
			}
		})
	}
}

func TestProviderResponseSizeBound(t *testing.T) {
	f := &fakeGraph{}
	c := testClient(t, f)
	original := c.http.Transport
	c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "graph.microsoft.com" && r.Method == "POST" {
			doc := owned(false)
			doc["padding"] = strings.Repeat("x", (1<<20)+1)
			return response(r, 201, doc), nil
		}
		return original.RoundTrip(r)
	})
	_, err := c.CreateDisabled(context.Background(), testTenant, testCreate)
	if !errors.Is(err, ErrUncertain) {
		t.Fatalf("oversized response: %v", err)
	}
}

func TestProviderConcurrentTokenReuse(t *testing.T) {
	f := &fakeGraph{}
	c := testClient(t, f)
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if _, err := c.Inspect(context.Background(), testTenant, reference()); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if len(f.calls) != 9 {
		t.Fatalf("expected one token and eight scoped reads: %v", f.calls)
	}
}

func TestProviderTokensNeverCrossBindings(t *testing.T) {
	for _, version := range []string{"version-1", "version-2"} {
		b := binding()
		b.CredentialVersion = version
		if version == "version-2" {
			b.BindingVersion = uuid.New().String()
			b.EntraTenantId = uuid.New().String()
			b.BlueprintAppId = uuid.New().String()
		}
		resolved := 0
		c, err := New(b, func(_ context.Context, ref, requestedVersion string) (string, error) {
			resolved++
			if ref != b.CredentialRef || requestedVersion != version {
				t.Fatal("wrong resolver partition")
			}
			return fakeSecret + version, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == "login.microsoftonline.com" {
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if r.URL.Path != "/"+b.EntraTenantId+"/oauth2/v2.0/token" || r.Form.Get("client_id") != b.BlueprintAppId || r.Form.Get("client_secret") != fakeSecret+version {
					t.Fatal("credential crossed tenant/blueprint/version")
				}
				return response(r, 200, map[string]any{"access_token": fakeToken + version, "token_type": "Bearer", "expires_in": 3600}), nil
			}
			if r.Header.Get("Authorization") != "Bearer "+fakeToken+version {
				t.Fatal("token crossed bindings")
			}
			d := owned(false)
			d["agentIdentityBlueprintId"] = b.BlueprintAppId
			return response(r, 200, d), nil
		})
		for range 2 {
			if _, err := c.Inspect(context.Background(), testTenant, reference()); err != nil {
				t.Fatal(err)
			}
		}
		if resolved != 1 {
			t.Fatalf("resolver calls=%d", resolved)
		}
	}
}

func TestProviderVerificationErrorKeepsRequestCorrelation(t *testing.T) {
	f := &fakeGraph{mutate: func(r *http.Request, _ map[string]any) (int, any) { return 0, nil }}
	c := testClient(t, f)
	original := c.http.Transport
	serverID := uuid.New()
	var failedReadID uuid.UUID
	c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == "GET" && f.enabled {
			failedReadID = uuid.MustParse(r.Header.Get("client-request-id"))
			res := response(r, 403, nil)
			res.Header.Set("request-id", serverID.String())
			return res, nil
		}
		return original.RoundTrip(r)
	})
	_, err := c.SetEnabled(context.Background(), testTenant, reference(), true, uuid.New())
	var metadata *Error
	if !errors.As(err, &metadata) || !metadata.Uncertain || metadata.RequestID != failedReadID || metadata.ServerRequestID != serverID {
		t.Fatalf("mismatched request metadata: %v", err)
	}
}
