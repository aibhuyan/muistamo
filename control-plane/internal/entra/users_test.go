package entra

// HUMAN REVIEW REQUIRED: matching an HR person to their Entra user.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
)

var (
	userA = uuid.MustParse("6f1c2a3b-0000-4000-8000-00000000000a")
	userB = uuid.MustParse("6f1c2a3b-0000-4000-8000-00000000000b")
)

func user(id uuid.UUID, employeeID string) map[string]any {
	return map[string]any{"id": id.String(), "employeeId": employeeID}
}

func TestLookupMatchesExactlyOneUserByEmployeeID(t *testing.T) {
	f := &fakeGraph{users: []map[string]any{user(userA, "P-77"), user(userB, "P-78")}}
	c := testClient(t, f)
	got, err := c.LookupUserByEmployeeID(context.Background(), testTenant, "P-77")
	if err != nil || got.Status != "matched" || got.ObjectID != userA {
		t.Fatalf("lookup = %+v, %v", got, err)
	}
	for name, users := range map[string][]map[string]any{
		"no user":                 {user(userB, "P-78")},
		"only a case variant":     {user(userA, "p-77")},
		"another id as substring": {user(userA, "P-777")},
	} {
		f.users = users
		got, err := c.LookupUserByEmployeeID(context.Background(), testTenant, "P-77")
		if err != nil || got.Status != "unmatched" || got.ObjectID != uuid.Nil {
			t.Errorf("%s: lookup = %+v, %v", name, got, err)
		}
	}
	for name, users := range map[string][]map[string]any{
		"two users":                {user(userA, "P-77"), user(userB, "P-77")},
		"exact and a case variant": {user(userA, "P-77"), user(userB, "p-77")},
	} {
		f.users = users
		got, err := c.LookupUserByEmployeeID(context.Background(), testTenant, "P-77")
		if err != nil || got.Status != "ambiguous" || got.ObjectID != uuid.Nil {
			t.Errorf("%s: lookup = %+v, %v", name, got, err)
		}
	}
}

// An HR id that cannot be an Entra employeeId is never quoted into an OData filter.
func TestLookupNeverSendsAnIDThatCouldChangeTheFilter(t *testing.T) {
	f := &fakeGraph{users: []map[string]any{user(userA, "P-77")}}
	c := testClient(t, f)
	for _, id := range []string{"", "P-77' or employeeId ne '", "P 77", "P-77)", "x' or 1 eq 1 or 'a", "a-very-long-employee-id", "ä"} {
		got, err := c.LookupUserByEmployeeID(context.Background(), testTenant, id)
		if err != nil || got.Status != "unmatched" {
			t.Errorf("%q: lookup = %+v, %v", id, got, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("Graph was called: %v", f.calls)
	}
}

func TestLookupRefusesInconclusiveAnswersAndOtherTenants(t *testing.T) {
	for name, body := range map[string]any{
		"no count":               map[string]any{"value": []any{user(userA, "P-77")}},
		"not an object":          []any{},
		"bad user id":            map[string]any{"value": []any{map[string]any{"id": "not-a-uuid", "employeeId": "P-77"}}, "@odata.count": 1},
		"count below the page":   map[string]any{"value": []any{user(userA, "P-77")}, "@odata.count": 0},
		"page beyond the count":  map[string]any{"value": []any{user(userA, "P-77"), user(userB, "p-77")}, "@odata.count": 1},
		"short page of many":     map[string]any{"value": []any{user(userA, "P-77")}, "@odata.count": 3},
		"page larger than asked": map[string]any{"value": []any{user(userA, "P-77"), user(userB, "x"), user(userB, "y")}, "@odata.count": 3},
	} {
		f := &fakeGraph{mutate: func(*http.Request, map[string]any) (int, any) { return 200, body }}
		if got, err := testClient(t, f).LookupUserByEmployeeID(context.Background(), testTenant, "P-77"); err == nil {
			t.Errorf("%s: lookup = %+v", name, got)
		}
	}
	f := &fakeGraph{mutate: func(*http.Request, map[string]any) (int, any) {
		return 403, map[string]any{"error": map[string]any{"code": "Authorization_RequestDenied"}}
	}}
	var provider *Error
	if _, err := testClient(t, f).LookupUserByEmployeeID(context.Background(), testTenant, "P-77"); !errors.As(err, &provider) || provider.Status != 403 {
		t.Fatalf("missing permission = %v", err)
	}
	if _, err := testClient(t, &fakeGraph{}).LookupUserByEmployeeID(context.Background(), uuid.New(), "P-77"); err == nil {
		t.Fatal("looked up a user for another tenant")
	}
}

func TestOnlyTheEmployeeIDLookupReachesUsers(t *testing.T) {
	c := testClient(t, &fakeGraph{})
	good := url.Values{"$filter": {"employeeId eq 'P-77'"}, "$select": {"id,employeeId"}, "$count": {"true"}, "$top": {"2"}}
	allowed := func(method string, q url.Values, path string) bool {
		req, _ := http.NewRequest(method, "https://graph.microsoft.com/v1.0/"+path+"?"+q.Encode(), nil)
		return c.allowedDestination(req)
	}
	if !allowed("GET", good, "users") {
		t.Fatal("the lookup itself is refused")
	}
	with := func(change func(url.Values)) url.Values {
		q := url.Values{}
		for k, v := range good {
			q[k] = append([]string(nil), v...)
		}
		change(q)
		return q
	}
	for name, q := range map[string]url.Values{
		"another select":    with(func(q url.Values) { q.Set("$select", "id,mail,employeeId") }),
		"another filter":    with(func(q url.Values) { q.Set("$filter", "mail eq 'a@example.invalid'") }),
		"an injected id":    with(func(q url.Values) { q.Set("$filter", "employeeId eq 'P' or 'a' eq 'a'") }),
		"extra parameter":   with(func(q url.Values) { q.Set("$expand", "manager") }),
		"two filters":       with(func(q url.Values) { q.Add("$filter", "employeeId eq 'P-78'") }),
		"no filter prefix":  with(func(q url.Values) { q.Set("$filter", "P-77'") }),
		"unquoted id":       with(func(q url.Values) { q.Set("$filter", "employeeId eq 'P-77") }),
		"two selects":       with(func(q url.Values) { q.Add("$select", "mail") }),
		"two tops":          with(func(q url.Values) { q.Add("$top", "999") }),
		"two counts":        with(func(q url.Values) { q.Add("$count", "false") }),
		"a larger page":     with(func(q url.Values) { q.Set("$top", "999") }),
		"without the count": with(func(q url.Values) { q.Del("$count") }),
	} {
		if allowed("GET", q, "users") {
			t.Errorf("%s: allowed", name)
		}
	}
	for _, method := range []string{"POST", "PATCH", "DELETE"} {
		if allowed(method, good, "users") {
			t.Errorf("%s on users allowed", method)
		}
	}
	if allowed("GET", good, "users/"+userA.String()) || allowed("GET", url.Values{}, "users") {
		t.Fatal("another users path is allowed")
	}
}
