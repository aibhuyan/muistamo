package contracts_test

import (
	"encoding/json"
	"testing"

	"muistamo.dev/muistamo/contracts"
)

func entraBinding() map[string]any {
	return map[string]any{
		"tenantId":             "11111111-1111-4111-8111-111111111111",
		"bindingVersion":       "22222222-2222-4222-8222-222222222222",
		"entraTenantId":        "33333333-3333-4333-8333-333333333333",
		"blueprintAppId":       "44444444-4444-4444-8444-444444444444",
		"blueprintObjectId":    "55555555-5555-4555-8555-555555555555",
		"blueprintPrincipalId": "66666666-6666-4666-8666-666666666666",
		"sponsorUserIds":       []any{"77777777-7777-4777-8777-777777777777"},
		"credentialRef":        "entra-development", "credentialVersion": "version-1",
	}
}

func TestEntraBindingContract(t *testing.T) {
	cases := []struct {
		name   string
		change func(map[string]any)
		valid  bool
	}{
		{"valid", func(map[string]any) {}, true},
		{"inline secret", func(d map[string]any) { d["clientSecret"] = "obviously-fake-test-secret" }, false},
		{"custom endpoint", func(d map[string]any) { d["graphUrl"] = "https://attacker.invalid" }, false},
		{"missing version", func(d map[string]any) { delete(d, "bindingVersion") }, false},
		{"missing credential version", func(d map[string]any) { delete(d, "credentialVersion") }, false},
		{"no sponsors", func(d map[string]any) { d["sponsorUserIds"] = []any{} }, false},
		{"duplicate sponsors", func(d map[string]any) {
			d["sponsorUserIds"] = []any{d["sponsorUserIds"].([]any)[0], d["sponsorUserIds"].([]any)[0]}
		}, false},
		{"url as credential ref", func(d map[string]any) { d["credentialRef"] = "https://attacker.invalid/secret" }, false},
	}
	for _, field := range []string{"tenantId", "bindingVersion", "entraTenantId", "blueprintAppId", "blueprintObjectId", "blueprintPrincipalId"} {
		cases = append(cases, struct {
			name   string
			change func(map[string]any)
			valid  bool
		}{field + " injection", func(d map[string]any) { d[field] = "../common?secret=value" }, false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := entraBinding()
			tc.change(doc)
			body, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if err := contracts.ValidateAgainst("entraidentitybinding.json", body); (err == nil) != tc.valid {
				t.Fatalf("valid=%v, want %v: %v", err == nil, tc.valid, err)
			}
		})
	}
}
