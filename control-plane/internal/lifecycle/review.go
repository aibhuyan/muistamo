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
	Fence(ctx context.Context, tenant uuid.UUID, secret []byte, req muistamov1.LeaverReviewFence) (muistamov1.LeaverReviewFenced, error)
}

// ErrRefused means the knowledge service answered with a client error: retrying cannot help.
var ErrRefused = errors.New("refused by the knowledge service")

// ErrSuperseded is the refusal of a live review call from an HR generation older than the
// person's fence: a later HR event (a rehire) has overtaken it, so it is final, not a fault.
var ErrSuperseded = fmt.Errorf("superseded by a later HR event: %w", ErrRefused)

// supersededProblem is the knowledge service's problem type for ErrSuperseded.
const supersededProblem = "https://muistamo.dev/problems/superseded"

// Refusal is a client error answer from the knowledge service. Its detail can echo the request
// (for a live review, entra: identities), so only Public may go into evidence or workflow history.
type Refusal struct {
	Status     int
	Title      string
	detail     string
	superseded bool
}

func (r *Refusal) Error() string {
	if r.detail == "" {
		return r.Public()
	}
	return r.Public() + ": " + r.detail
}

// Public is the status and title only: never the detail.
func (r *Refusal) Public() string { return fmt.Sprintf("knowledge service refused: %d %s", r.Status, r.Title) }

func (r *Refusal) Unwrap() error {
	if r.superseded {
		return ErrSuperseded
	}
	return ErrRefused
}

// publicReason is what evidence and workflow history may say about err.
func publicReason(err error) string {
	var refusal *Refusal
	if errors.As(err, &refusal) {
		return refusal.Public()
	}
	return "knowledge service call failed"
}

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

// Fence orders a live person's earlier reviews before their rehire's generation.
func (c *KnowledgeClient) Fence(ctx context.Context, tenant uuid.UUID, secret []byte, req muistamov1.LeaverReviewFence) (muistamov1.LeaverReviewFenced, error) {
	var fenced muistamov1.LeaverReviewFenced
	body, err := json.Marshal(req)
	if err != nil {
		return fenced, err
	}
	return fenced, c.post(ctx, tenant, secret, "/v1/knowledge/internal/leaver-reviews/fence", body, &fenced)
}

func (c *KnowledgeClient) call(ctx context.Context, tenant uuid.UUID, secret []byte, path string, body []byte) (muistamov1.LeaverReview, error) {
	var review muistamov1.LeaverReview
	return review, c.post(ctx, tenant, secret, path, body, &review)
}

func (c *KnowledgeClient) post(ctx context.Context, tenant uuid.UUID, secret []byte, path string, body []byte, answer any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Muistamo-Tenant", tenant.String())
	// Method and path are signed too (v2), so the signature verifies for this review and call only.
	// The fields are newline-joined, so a path with a control character is never signed (the
	// knowledge service refuses one too).
	if strings.ContainsFunc(req.URL.Path, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("knowledge service path %q cannot be signed", req.URL.Path)
	}
	req.Header.Set("X-Muistamo-Signature", signature.SignRequest(secret, req.Method, req.URL.Path, body, time.Now()))
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("knowledge service %s: %w", path, err)
	}
	defer func() { _ = res.Body.Close() }()
	out, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	switch {
	case res.StatusCode == http.StatusOK || res.StatusCode == http.StatusCreated:
		return json.Unmarshal(out, answer)
	case res.StatusCode >= 400 && res.StatusCode < 500:
		var p muistamov1.Problem
		refusal := &Refusal{Status: res.StatusCode, Title: http.StatusText(res.StatusCode)}
		if json.Unmarshal(out, &p) == nil && p.Title != "" {
			refusal.Title = p.Title
			if p.Detail != nil {
				refusal.detail = *p.Detail
			}
		}
		refusal.superseded = res.StatusCode == http.StatusConflict && p.Type != nil && *p.Type == supersededProblem
		return refusal
	default:
		return fmt.Errorf("knowledge service %s returned %d", path, res.StatusCode)
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
	req.Person.Email = &person.Email
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
	Email *string                                 `json:"email,omitempty"`
	Kind  muistamov1.LeaverReviewOpenDecidersKind `json:"kind"`
	User  *string                                 `json:"user,omitempty"`
}

func decider(email string, kind muistamov1.LeaverReviewOpenDecidersKind) deciderEntry {
	return deciderEntry{Email: &email, Kind: kind}
}
