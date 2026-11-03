package lifecycle

// HUMAN REVIEW REQUIRED (CLAUDE.md): a signed service call and the deletion path of a live
// leaver's personal layer (docs/live-review-plan.md). The leaver opens the review at its HR
// generation; the knowledge service refuses any call older than the person's fence, and a
// rehire's joiner raises that fence, so a late call from the old leaving changes nothing.
//
// Entra object ids are read inside these activities and sent only in the signed request. They are
// never returned to the workflow, so they stay out of Temporal history, and control-plane
// evidence never names them.

import (
	"context"
	"errors"
	"time"

	"go.temporal.io/sdk/temporal"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// liveReviewID is the review's id in the knowledge service: one per leaving, so a reset or
// replaced workflow run opens the same review again.
func liveReviewID(ref muistamov1.EntraLifecycleRef) string {
	return "entra-leaver:" + ref.ReceiptId.String()
}

func entraIdentity(id string) string { return "entra:" + id }

// knowledgeSecret is the tenant's secret for signed knowledge-service calls, or a reason why
// there is none (the call then cannot be made, and evidence says so).
func (a *EntraActivities) knowledgeSecret(ctx context.Context, ref muistamov1.EntraLifecycleRef) ([]byte, string, error) {
	if a.Knowledge == nil {
		return nil, "the worker has no knowledge service configured (MUISTAMO_KNOWLEDGE_URL)", nil
	}
	secret, err := a.Registry.KnowledgeSecret(ctx, liveActor(ref))
	if err != nil {
		return nil, "", err
	}
	if len(secret) == 0 {
		return nil, "the tenant has no knowledge service secret (control-plane tenant knowledge-secret)", nil
	}
	return secret, "", nil
}

// EntraOpenReview opens the review of the live leaver's personal layer at the leaver's
// generation, naming the person and the manager by their Entra users. Like the legacy step, a
// review that cannot be opened is recorded as not opened, with the reason, and never fails the
// leaver: revocation has already happened.
func (a *EntraActivities) EntraOpenReview(ctx context.Context, ref muistamov1.EntraLifecycleRef) (ReviewOpened, error) {
	actor := liveActor(ref)
	parties, err := a.Registry.LiveReviewParties(ctx, actor, ref.ReceiptId)
	if err != nil {
		return ReviewOpened{}, liveError(err)
	}
	notOpened := func(reason string) (ReviewOpened, error) {
		return ReviewOpened{}, a.Registry.RecordPersonEvent(ctx, actor, "personal-layer.review-not-opened", parties.Person,
			map[string]any{"reason": reason, "generation": parties.Generation})
	}
	if parties.Superseded {
		return notOpened("superseded by a later HR event for the person")
	}
	if parties.User == nil {
		return notOpened("the person has no Entra user linked by an earlier joiner")
	}
	secret, missing, err := a.knowledgeSecret(ctx, ref)
	if err != nil {
		return ReviewOpened{}, err
	}
	if missing != "" {
		return notOpened(missing)
	}
	generation, person, user := int(parties.Generation), parties.Person, entraIdentity(parties.User.String())
	req := muistamov1.LeaverReviewOpen{Id: liveReviewID(ref), Generation: &generation}
	req.Person.User, req.Person.HrPersonId = &user, &person
	req.Deciders = []deciderEntry{}
	if parties.Manager != nil {
		manager := entraIdentity(parties.Manager.String())
		req.Deciders = append(req.Deciders, deciderEntry{User: &manager, Kind: muistamov1.LeaverReviewOpenDecidersKindManager})
	}
	review, err := a.Knowledge.Open(ctx, ref.TenantId, secret, req)
	if errors.Is(err, ErrSuperseded) {
		return ReviewOpened{}, a.Registry.RecordPersonEvent(ctx, actor, "personal-layer.review-superseded", person,
			map[string]any{"review": req.Id, "generation": generation})
	}
	if errors.Is(err, ErrRefused) {
		return notOpened(err.Error())
	}
	if err != nil {
		return ReviewOpened{}, err
	}
	after := map[string]any{"review": review.Id, "status": review.Status, "deciderKind": review.DeciderKind,
		"entryCount": review.EntryCount, "deadline": review.Deadline, "generation": generation}
	if review.Outcome != nil {
		after["outcome"] = *review.Outcome
	}
	if err := a.Registry.RecordPersonEvent(ctx, actor, "personal-layer.review-opened", person, after); err != nil {
		return ReviewOpened{}, err
	}
	return ReviewOpened{ID: review.Id, Opened: review.Status == muistamov1.LeaverReviewStatusOpen}, nil
}

// EntraExpireReview asks for the undecided layer to be purged once the grace period is over. A
// kept review comes back open with a later deadline. A superseded expiry (the person was
// rehired) purges nothing and closes the workflow's wait.
func (a *EntraActivities) EntraExpireReview(ctx context.Context, ref muistamov1.EntraLifecycleRef, id string) (ReviewState, error) {
	actor := liveActor(ref)
	event, _, _, err := a.Registry.ResolveEntraReceipt(ctx, actor, ref.ReceiptId, false)
	if err != nil {
		return ReviewState{}, liveError(err)
	}
	secret, missing, err := a.knowledgeSecret(ctx, ref)
	if err != nil {
		return ReviewState{}, err
	}
	if missing != "" {
		return ReviewState{}, temporal.NewNonRetryableApplicationError(missing, "unconfigured", nil)
	}
	review, err := a.Knowledge.Expire(ctx, ref.TenantId, secret, id)
	if errors.Is(err, ErrSuperseded) {
		return ReviewState{Closed: true}, a.Registry.RecordPersonEvent(ctx, actor, "personal-layer.review-closed", event.Person.Id,
			map[string]any{"review": id, "outcome": "superseded"})
	}
	if errors.Is(err, ErrRefused) {
		return ReviewState{}, temporal.NewNonRetryableApplicationError(err.Error(), "refused", err)
	}
	if err != nil {
		return ReviewState{}, err
	}
	if review.Status == muistamov1.LeaverReviewStatusOpen {
		return ReviewState{Deadline: review.Deadline}, nil
	}
	return ReviewState{Closed: true}, a.Registry.RecordPersonEvent(ctx, actor, "personal-layer.review-closed", event.Person.Id,
		map[string]any{"review": id, "outcome": review.Outcome})
}

// EntraFenceReview tells the knowledge service a live person has rejoined at this joiner's
// generation, before the joiner relinks them, under the Entra user any earlier review of theirs
// was opened with. Every earlier review is cancelled and every later call from it refused, even
// if the rehire signal never reached the old leaver run.
func (a *EntraActivities) EntraFenceReview(ctx context.Context, ref muistamov1.EntraLifecycleRef) error {
	actor := liveActor(ref)
	person, user, generation, err := a.Registry.FenceUser(ctx, actor, ref.ReceiptId)
	if err != nil {
		return liveError(err)
	}
	if user == nil {
		return nil // never linked: no live review of theirs can have been opened
	}
	secret, missing, err := a.knowledgeSecret(ctx, ref)
	if err != nil {
		return err
	}
	if missing != "" {
		return a.Registry.RecordPersonEvent(ctx, actor, "personal-layer.fence-not-sent", person,
			map[string]any{"reason": missing, "generation": generation})
	}
	fenced, err := a.Knowledge.Fence(ctx, ref.TenantId, secret, muistamov1.LeaverReviewFence{User: entraIdentity(user.String()), Generation: int(generation)})
	if errors.Is(err, ErrRefused) {
		return temporal.NewNonRetryableApplicationError(err.Error(), "refused", err)
	}
	if err != nil {
		return err
	}
	return a.Registry.RecordPersonEvent(ctx, actor, "personal-layer.review-fenced", person,
		map[string]any{"generation": fenced.Generation, "cancelled": fenced.Cancelled})
}

// EntraRecordFenceFailure records that a rejoining person's earlier reviews could not be fenced
// after every attempt, so an operator can see it; the old leaver run's rehire signal still stops
// its own expiry.
func (a *EntraActivities) EntraRecordFenceFailure(ctx context.Context, ref muistamov1.EntraLifecycleRef) error {
	event, _, generation, err := a.Registry.ResolveEntraReceipt(ctx, liveActor(ref), ref.ReceiptId, false)
	if err != nil {
		return liveError(err)
	}
	return a.Registry.RecordPersonEvent(ctx, liveActor(ref), "personal-layer.fence-failed", event.Person.Id,
		map[string]any{"generation": generation})
}

// liveReviewWait is the shortest wait between expiry attempts for a kept review.
const liveReviewWait = time.Minute
