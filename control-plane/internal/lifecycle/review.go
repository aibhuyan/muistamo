package lifecycle

// HUMAN REVIEW REQUIRED (CLAUDE.md): a signed service call and the leaver's personal-layer review
// (E4.2). The leaver workflow opens a review in the knowledge service, which freezes the person's
// personal layer and asks their manager (else an instance sponsor, else the privacy officers) to
// merge, keep or purge it. After the grace period the workflow asks the knowledge service to
// purge an undecided layer; a rehire cancels the review.
//
// Revocation never waits on this: it has already happened when the review is opened, and a
// review that cannot be opened is recorded as not opened, with the reason, rather than retried
// for ever or skipped silently.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/signature"
)

// LeaverReviews is the knowledge service's leaver-review API, as the workflow uses it.
type LeaverReviews interface {
	Open(ctx context.Context, tenant uuid.UUID, secret []byte, req muistamov1.LeaverReviewOpen) (muistamov1.LeaverReview, error)
	Expire(ctx context.Context, tenant uuid.UUID, secret []byte, id string) (muistamov1.LeaverReview, error)
	Cancel(ctx context.Context, tenant uuid.UUID, secret []byte, id string) (muistamov1.LeaverReview, error)
}

// ErrRefused means the knowledge service answered with a client error: retrying cannot help.
var ErrRefused = errors.New("refused by the knowledge service")

// KnowledgeClient calls the knowledge service, signing each request with the tenant's secret.
type KnowledgeClient struct {
	base string
	http *http.Client
}

// NewKnowledgeClient returns a client for the knowledge service at base.
func NewKnowledgeClient(base string) *KnowledgeClient {
	return &KnowledgeClient{base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: 30 * time.Second}}
}

// Open opens (or returns the existing) review.
func (c *KnowledgeClient) Open(ctx context.Context, tenant uuid.UUID, secret []byte, req muistamov1.LeaverReviewOpen) (muistamov1.LeaverReview, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return muistamov1.LeaverReview{}, err
	}
	return c.call(ctx, tenant, secret, "/v1/knowledge/internal/leaver-reviews", body)
}

// Expire asks for an undecided layer past its deadline to be purged.
func (c *KnowledgeClient) Expire(ctx context.Context, tenant uuid.UUID, secret []byte, id string) (muistamov1.LeaverReview, error) {
	return c.call(ctx, tenant, secret, "/v1/knowledge/internal/leaver-reviews/"+url.PathEscape(id)+"/expire", nil)
}

// Cancel closes an open review because the person was rehired.
func (c *KnowledgeClient) Cancel(ctx context.Context, tenant uuid.UUID, secret []byte, id string) (muistamov1.LeaverReview, error) {
	return c.call(ctx, tenant, secret, "/v1/knowledge/internal/leaver-reviews/"+url.PathEscape(id)+"/cancel", nil)
}

func (c *KnowledgeClient) call(ctx context.Context, tenant uuid.UUID, secret []byte, path string, body []byte) (muistamov1.LeaverReview, error) {
	var review muistamov1.LeaverReview
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return review, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Muistamo-Tenant", tenant.String())
	req.Header.Set("X-Muistamo-Signature", signature.Sign(secret, body, time.Now()))
	res, err := c.http.Do(req)
	if err != nil {
		return review, fmt.Errorf("knowledge service %s: %w", path, err)
	}
	defer func() { _ = res.Body.Close() }()
	out, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return review, err
	}
	switch {
	case res.StatusCode == http.StatusOK || res.StatusCode == http.StatusCreated:
		return review, json.Unmarshal(out, &review)
	case res.StatusCode >= 400 && res.StatusCode < 500:
		var p muistamov1.Problem
		detail := res.Status
		if json.Unmarshal(out, &p) == nil && p.Title != "" {
			detail = fmt.Sprintf("%d %s", p.Status, p.Title)
			if p.Detail != nil {
				detail += ": " + *p.Detail
			}
		}
		return review, fmt.Errorf("%s: %w", detail, ErrRefused)
	default:
		return review, fmt.Errorf("knowledge service %s returned %d", path, res.StatusCode)
	}
}

// ReviewOpened reports whether a personal-layer review is open, so the workflow must close it.
type ReviewOpened struct {
	ID     string
	Opened bool
}

// ReviewState is what the workflow needs after asking for expiry.
type ReviewState struct {
	Closed   bool
	Deadline time.Time
}

// OpenPersonalLayerReview opens the review of the leaver's personal layer. It never fails the
// leaver flow for a configuration gap: it records why no review was opened instead.
func (a *Activities) OpenPersonalLayerReview(ctx context.Context, scope Scope, person Person, instances []string) (ReviewOpened, error) {
	actor := scope.actor()
	notOpened := func(reason string) (ReviewOpened, error) {
		return ReviewOpened{}, a.Registry.RecordPersonEvent(ctx, actor, "personal-layer.review-not-opened", person.ID,
			map[string]any{"reason": reason})
	}
	if a.Knowledge == nil {
		return notOpened("the worker has no knowledge service configured (MUISTAMO_KNOWLEDGE_URL)")
	}
	secret, err := a.Registry.KnowledgeSecret(ctx, actor)
	if err != nil {
		return ReviewOpened{}, err
	}
	if len(secret) == 0 {
		return notOpened("the tenant has no knowledge service secret (control-plane tenant knowledge-secret)")
	}

	req := muistamov1.LeaverReviewOpen{Id: scope.WorkflowID + ":" + activity.GetInfo(ctx).WorkflowExecution.RunID}
	req.Person.Email = person.Email
	if person.ID != "" {
		req.Person.HrPersonId = &person.ID
	}
	req.Deciders = []deciderEntry{}
	if person.ManagerEmail != "" {
		req.Deciders = append(req.Deciders, decider(person.ManagerEmail, muistamov1.LeaverReviewOpenDecidersKindManager))
	}
	seen := map[string]bool{}
	for _, name := range instances {
		rec, err := a.Registry.GetInstance(ctx, actor, name)
		if err != nil {
			return ReviewOpened{}, err
		}
		if s := rec.Document.Spec.Sponsor; s != nil && *s != "" && !seen[*s] {
			seen[*s] = true
			req.Deciders = append(req.Deciders, decider(*s, muistamov1.LeaverReviewOpenDecidersKindSponsor))
		}
	}

	review, err := a.Knowledge.Open(ctx, scope.Tenant, secret, req)
	if errors.Is(err, ErrRefused) {
		return notOpened(err.Error())
	}
	if err != nil {
		return ReviewOpened{}, err
	}
	after := map[string]any{"review": review.Id, "status": review.Status, "deciderKind": review.DeciderKind,
		"entryCount": review.EntryCount, "deadline": review.Deadline}
	if review.Outcome != nil {
		after["outcome"] = *review.Outcome
	}
	if err := a.Registry.RecordPersonEvent(ctx, actor, "personal-layer.review-opened", person.ID, after); err != nil {
		return ReviewOpened{}, err
	}
	return ReviewOpened{ID: review.Id, Opened: review.Status == muistamov1.LeaverReviewStatusOpen}, nil
}

// ExpirePersonalLayerReview asks the knowledge service to purge an undecided layer whose deadline
// has passed. A review the decider kept comes back open with a later deadline.
func (a *Activities) ExpirePersonalLayerReview(ctx context.Context, scope Scope, personID, id string) (ReviewState, error) {
	review, err := a.closeReview(ctx, scope, id, a.Knowledge.Expire)
	if err != nil {
		return ReviewState{}, err
	}
	if review.Status == muistamov1.LeaverReviewStatusOpen {
		return ReviewState{Deadline: review.Deadline}, nil
	}
	return ReviewState{Closed: true}, a.Registry.RecordPersonEvent(ctx, scope.actor(), "personal-layer.review-closed", personID,
		map[string]any{"review": id, "outcome": review.Outcome})
}

// CancelPersonalLayerReview closes the review because the person was rehired.
func (a *Activities) CancelPersonalLayerReview(ctx context.Context, scope Scope, personID, id string) error {
	review, err := a.closeReview(ctx, scope, id, a.Knowledge.Cancel)
	if err != nil {
		return err
	}
	return a.Registry.RecordPersonEvent(ctx, scope.actor(), "personal-layer.review-closed", personID,
		map[string]any{"review": id, "outcome": review.Outcome})
}

func (a *Activities) closeReview(ctx context.Context, scope Scope, id string,
	call func(context.Context, uuid.UUID, []byte, string) (muistamov1.LeaverReview, error)) (muistamov1.LeaverReview, error) {
	if a.Knowledge == nil {
		return muistamov1.LeaverReview{}, temporal.NewNonRetryableApplicationError("no knowledge service configured", "unconfigured", nil)
	}
	secret, err := a.Registry.KnowledgeSecret(ctx, scope.actor())
	if err != nil {
		return muistamov1.LeaverReview{}, err
	}
	if len(secret) == 0 {
		return muistamov1.LeaverReview{}, temporal.NewNonRetryableApplicationError("the tenant's knowledge service secret was removed", "unconfigured", nil)
	}
	review, err := call(ctx, scope.Tenant, secret, id)
	if errors.Is(err, ErrRefused) {
		return review, temporal.NewNonRetryableApplicationError(err.Error(), "refused", err)
	}
	return review, err
}

// deciderEntry is one item of LeaverReviewOpen.Deciders, which the generator leaves anonymous.
type deciderEntry = struct {
	Email string                                  `json:"email"`
	Kind  muistamov1.LeaverReviewOpenDecidersKind `json:"kind"`
}

func decider(email string, kind muistamov1.LeaverReviewOpenDecidersKind) deciderEntry {
	return deciderEntry{Email: email, Kind: kind}
}
