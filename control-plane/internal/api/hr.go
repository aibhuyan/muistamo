package api

// HUMAN REVIEW REQUIRED (CLAUDE.md): token handling. HR events authenticate with a per-tenant
// HMAC secret instead of the user resolver.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

const (
	hrEventsPath       = "/v1/hr/events"
	signatureTolerance = 5 * time.Minute
)

// HRIntake verifies and accepts HR events. lifecycle.Intake implements it.
type HRIntake interface {
	Secret(ctx context.Context, tenant uuid.UUID) ([]byte, error)
	Accept(ctx context.Context, tenant uuid.UUID, actor, requestID string, event muistamov1.HREvent) (workflowID string, duplicate bool, err error)
}

// Sign returns the X-Muistamo-Signature value for body at time t. HR connectors and tests use it.
func Sign(secret, body []byte, t time.Time) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac(secret, ts, body))
}

func mac(secret []byte, ts string, body []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(ts))
	h.Write([]byte("."))
	h.Write(body)
	return h.Sum(nil)
}

// verifyHR authenticates an HR event request and returns its tenant. Every failure is the same
// errUnauthenticated to the caller; the reason is only logged.
func verifyHR(r *http.Request, intake HRIntake, now time.Time) (uuid.UUID, error) {
	if intake == nil {
		return uuid.Nil, errors.New("HR intake is not configured")
	}
	tenant, err := uuid.Parse(r.Header.Get("X-Muistamo-Tenant"))
	if err != nil {
		return uuid.Nil, errors.New("missing or malformed X-Muistamo-Tenant")
	}
	ts, sig, err := parseSignature(r.Header.Get("X-Muistamo-Signature"))
	if err != nil {
		return uuid.Nil, err
	}
	sent, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return uuid.Nil, errors.New("signature timestamp is not a number")
	}
	if skew := now.Sub(time.Unix(sent, 0)); skew > signatureTolerance || skew < -signatureTolerance {
		return uuid.Nil, fmt.Errorf("signature timestamp outside %s", signatureTolerance)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return uuid.Nil, errors.New("unreadable or oversized body")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	secret, err := intake.Secret(r.Context(), tenant)
	if err != nil {
		return uuid.Nil, fmt.Errorf("load HR secret: %w", err)
	}
	if !hmac.Equal(sig, mac(secret, ts, body)) {
		return uuid.Nil, errors.New("signature does not match")
	}
	return tenant, nil
}

func parseSignature(header string) (ts string, sig []byte, err error) {
	for _, part := range strings.Split(header, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch key {
		case "t":
			ts = value
		case "v1":
			if sig, err = hex.DecodeString(value); err != nil {
				return "", nil, errors.New("signature is not hex")
			}
		}
	}
	if ts == "" || len(sig) == 0 {
		return "", nil, errors.New("missing or malformed X-Muistamo-Signature")
	}
	return ts, sig, nil
}
