package main

import (
	"encoding/json"
	"testing"

	"muistamo.dev/muistamo/cli/internal/manifest"
)

func TestWithServerStateKeepsTheServersInstanceState(t *testing.T) {
	local := manifest.Document{
		Kind: "AgentInstance",
		Name: "analyst-intern-person-a",
		JSON: []byte(`{"kind":"AgentInstance","spec":{"state":"requested","sponsor":"person-b@example.invalid"}}`),
	}
	server := []byte(`{"kind":"AgentInstance","spec":{"state":"suspended"}}`)

	out, err := withServerState(local, server)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Spec struct {
			State   string `json:"state"`
			Sponsor string `json:"sponsor"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.State != "suspended" || got.Spec.Sponsor != "person-b@example.invalid" {
		t.Fatalf("got %+v, want server state with local sponsor", got.Spec)
	}
}

func TestWithServerStateLeavesTemplatesAlone(t *testing.T) {
	local := manifest.Document{Kind: "AgentTemplate", JSON: []byte(`{"kind":"AgentTemplate","spec":{"purpose":"x"}}`)}

	out, err := withServerState(local, []byte(`{"spec":{"purpose":"y"}}`))
	if err != nil || string(out) != string(local.JSON) {
		t.Fatalf("out = %s, err = %v; want the template unchanged", out, err)
	}
}
