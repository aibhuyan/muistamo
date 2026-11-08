package entra

// HUMAN REVIEW REQUIRED: who the control plane accepts from the console
// (docs/control-plane-console-plan.md).

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

var (
	consoleApp = uuid.MustParse("c0c0c0c0-0000-4000-8000-0000000c0501")
	apiApp     = uuid.MustParse("a9a9a9a9-0000-4000-8000-0000000a9a9a")
)

// consoleClaims are a console token for the control plane: the tenant's API app, the
// Registry.Console scope, obtained by the console app.
func consoleClaims(oid uuid.UUID) map[string]any {
	c := userClaims(oid)
	c["aud"] = apiApp.String()
	c["scp"] = "Registry.Console"
	c["azp"] = consoleApp.String()
	return c
}

type consoleFixture struct {
	delegationFixture
	resolver *ConsoleResolver
}

func setupConsole(t *testing.T) consoleFixture {
	t.Helper()
	f := setupDelegation(t)
	if err := store.SetConsoleClient(context.Background(), f.db.OwnerURL, testTenant, consoleApp, apiApp); err != nil {
		t.Fatal(err)
	}
	return consoleFixture{delegationFixture: f, resolver: NewConsoleResolver(f.delegator)}
}

func (f consoleFixture) resolve(token string) (uuid.UUID, string, error) {
	r := httptest.NewRequest(http.MethodGet, "/v1/catalogue/requests", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return f.resolver.Resolve(r)
}

func TestAConsoleTokenNamesTheTenantAndThePerson(t *testing.T) {
	f := setupConsole(t)
	tenant, actor, err := f.resolve(f.dir.token(consoleClaims(userA)))
	if err != nil || tenant != testTenant || actor != "entra:"+userA.String() {
		t.Fatalf("resolve = %s %q %v", tenant, actor, err)
	}
}

func TestOnlyAConsoleTokenForTheControlPlaneIsAccepted(t *testing.T) {
	f := setupConsole(t)
	with := func(change func(map[string]any)) string {
		c := consoleClaims(userA)
		change(c)
		return f.dir.token(c)
	}
	for name, token := range map[string]string{
		// A token the knowledge service receives: never accepted here.
		"the blueprint's token":  f.dir.token(userClaims(userA)),
		"the blueprint audience": with(func(c map[string]any) { c["aud"] = binding().BlueprintAppId }),
		"two audiences":          with(func(c map[string]any) { c["aud"] = []string{apiApp.String(), binding().BlueprintAppId} }),
		"another scope":          with(func(c map[string]any) { c["scp"] = "Knowledge.Read" }),
		"a scope as a substring": with(func(c map[string]any) { c["scp"] = "Registry.ConsoleAll" }),
		"an assistant's token":   with(func(c map[string]any) { c["azp"] = uuid.NewString() }),
		"no client app":          with(func(c map[string]any) { delete(c, "azp") }),
		"another directory":      with(func(c map[string]any) { c["tid"] = uuid.NewString() }),
		"another issuer":         with(func(c map[string]any) { c["iss"] = "https://login.microsoftonline.com/common/v2.0" }),
		"an app token":           with(func(c map[string]any) { c["idtyp"] = "app" }),
		"version 1.0":            with(func(c map[string]any) { c["ver"] = "1.0" }),
		"expired":                with(func(c map[string]any) { c["exp"] = time.Now().Add(-2 * time.Minute).Unix() }),
		"not a token":            "obviously-fake-not-a-jwt",
		"oversized":              f.dir.token(consoleClaims(userA)) + strings.Repeat("A", maxUserToken),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := f.resolve(token); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestAConsoleCallerMustBeACurrentEmployeeNow(t *testing.T) {
	f := setupConsole(t)
	if _, _, err := f.resolve(f.dir.token(consoleClaims(userA))); err != nil {
		t.Fatal(err)
	}
	// Someone the directory knows but Muistamo has no current link for.
	if _, _, err := f.resolve(f.dir.token(consoleClaims(userB))); err == nil {
		t.Fatal("an unlinked person was accepted")
	}
	// After the leaver event, at the very next call: no cache.
	seedAdapterHR(t, f.conn, f.key, f.actor, "leave", "leaver", 2)
	if _, _, err := f.resolve(f.dir.token(consoleClaims(userA))); err == nil {
		t.Fatal("a leaver was accepted")
	}
}

func TestATenantWithoutAConsoleClientAcceptsNoConsoleCaller(t *testing.T) {
	f := setupDelegation(t)
	r := NewConsoleResolver(f.delegator)
	req := httptest.NewRequest(http.MethodGet, "/v1/catalogue/requests", nil)
	req.Header.Set("Authorization", "Bearer "+f.dir.token(consoleClaims(userA)))
	if _, _, err := r.Resolve(req); err == nil {
		t.Fatal("accepted without a console client row")
	}
}

func TestTheConsoleClientIsTheTenantsOwn(t *testing.T) {
	f := setupConsole(t)
	// The row names other apps: the same token is no longer accepted.
	if err := store.SetConsoleClient(context.Background(), f.db.OwnerURL, testTenant, uuid.New(), uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.resolve(f.dir.token(consoleClaims(userA))); err == nil {
		t.Fatal("accepted for apps the tenant no longer names")
	}
}

func TestTheSharedValidationCoreRefusesWhatEveryPersonTokenMust(t *testing.T) {
	f := setupConsole(t)
	with := func(change func(map[string]any)) string {
		c := consoleClaims(userA)
		change(c)
		return f.dir.token(c)
	}
	for name, token := range map[string]string{
		"no expiry":                  with(func(c map[string]any) { delete(c, "exp") }),
		"no not-before":              with(func(c map[string]any) { delete(c, "nbf") }),
		"not yet valid":              with(func(c map[string]any) { c["nbf"] = time.Now().Add(5 * time.Minute).Unix() }),
		"no user":                    with(func(c map[string]any) { delete(c, "oid") }),
		"a user id not canonical":    with(func(c map[string]any) { c["oid"] = strings.ToUpper(userA.String()) }),
		"another directory's issuer": with(func(c map[string]any) { c["iss"] = "https://login.microsoftonline.com/" + uuid.NewString() + "/v2.0" }),
		"an unknown key":             sign(t, f.dir.key, "unknown-key", consoleClaims(userA)),
		"unsigned":                   strings.Join(strings.Split(f.dir.token(consoleClaims(userA)), ".")[:2], ".") + ".",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := f.resolve(token); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestADirectoryBoundToTwoTenantsRefusesOnlyItsConsoleCallers(t *testing.T) {
	f := setupConsole(t)
	// A second tenant whose binding names the same directory.
	f.delegator.clients[uuid.New()] = f.client
	r := NewConsoleResolver(f.delegator) // starts: the rest of the server keeps working
	if _, kept := r.clients[f.client.Directory()]; kept {
		t.Fatal("an ambiguous directory was kept for console callers")
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/catalogue/requests", nil)
	req.Header.Set("Authorization", "Bearer "+f.dir.token(consoleClaims(userA)))
	if _, _, err := r.Resolve(req); err == nil {
		t.Fatal("an ambiguous directory's console caller was accepted")
	}
}

func TestAKeyOutageIsTryAgainNotRefused(t *testing.T) {
	f := setupConsole(t)
	f.client.http = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("keys unreachable")
	})}
	_, _, err := f.resolve(f.dir.token(consoleClaims(userA)))
	if !errors.Is(err, registry.ErrUnavailable) {
		t.Fatalf("a key outage = %v, want ErrUnavailable", err)
	}
}

func TestTheServerRoleCannotChangeTheConsoleClient(t *testing.T) {
	f := setupConsole(t)
	for _, sql := range []string{
		`INSERT INTO console_clients (tenant_id, client_app, api_app) VALUES ('` + testTenant.String() + `', gen_random_uuid(), gen_random_uuid())`,
		`UPDATE console_clients SET client_app = gen_random_uuid()`,
		`DELETE FROM console_clients`,
	} {
		if err := testdb.ExecErr(f.db.AppURL, testTenant, sql); err == nil {
			t.Fatalf("the server role could run %s", sql)
		}
	}
}
