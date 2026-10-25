package registry

import "muistamo.dev/muistamo/contracts/gen/go/muistamov1"

// transitions lists every allowed lifecycle move. Anything absent is refused; retired has no
// outgoing moves. requested -> suspended exists for a leaver who leaves before activation.
var transitions = map[muistamov1.InstanceState][]muistamov1.InstanceState{
	muistamov1.InstanceStateRequested:   {muistamov1.InstanceStateActive, muistamov1.InstanceStateSuspended, muistamov1.InstanceStateQuarantined},
	muistamov1.InstanceStateActive:      {muistamov1.InstanceStateUnderReview, muistamov1.InstanceStateSuspended, muistamov1.InstanceStateQuarantined},
	muistamov1.InstanceStateUnderReview: {muistamov1.InstanceStateActive, muistamov1.InstanceStateSuspended, muistamov1.InstanceStateQuarantined},
	muistamov1.InstanceStateSuspended:   {muistamov1.InstanceStateActive, muistamov1.InstanceStateRetired, muistamov1.InstanceStateQuarantined},
	muistamov1.InstanceStateQuarantined: {muistamov1.InstanceStateSuspended},
}

// CanTransition reports whether an instance may move from one state to another.
func CanTransition(from, to muistamov1.InstanceState) bool {
	for _, allowed := range transitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}
