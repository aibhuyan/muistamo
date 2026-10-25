package registry

import (
	"testing"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

func TestTransitionMatrix(t *testing.T) {
	const (
		req = muistamov1.InstanceStateRequested
		act = muistamov1.InstanceStateActive
		rev = muistamov1.InstanceStateUnderReview
		sus = muistamov1.InstanceStateSuspended
		ret = muistamov1.InstanceStateRetired
		qua = muistamov1.InstanceStateQuarantined
	)
	allowed := map[[2]muistamov1.InstanceState]bool{
		{req, act}: true, {req, sus}: true, {req, qua}: true,
		{act, rev}: true, {act, sus}: true, {act, qua}: true,
		{rev, act}: true, {rev, sus}: true, {rev, qua}: true,
		{sus, act}: true, {sus, ret}: true, {sus, qua}: true,
		{qua, sus}: true,
	}
	states := []muistamov1.InstanceState{req, act, rev, sus, ret, qua}

	for _, from := range states {
		for _, to := range states {
			want := allowed[[2]muistamov1.InstanceState{from, to}]
			if got := CanTransition(from, to); got != want {
				t.Errorf("CanTransition(%s, %s) = %v, want %v", from, to, got, want)
			}
		}
	}
}
