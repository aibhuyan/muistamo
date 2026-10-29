package registry

// Virtual keys for the gateway (docs/agentgateway-plan.md, step 3a).
//
// HUMAN REVIEW REQUIRED (AGENTS.md): token generation, hashing and comparison, and who may issue
// and revoke keys. A key is mvk_<id>_<secret>: 32 bytes from crypto/rand, base64url without
// padding. Only SHA-256 of the 32 decoded bytes is stored. The secret is returned once, by
// IssueKey, and never logged, stored or put in evidence.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

const keyPrefix = "mvk_"

// secretBytes is the key's entropy: 256 bits.
const secretBytes = 32

// DefaultMaxCallsWithoutUsage is a key's monthly allowance of calls that ran without a usage
// report, when issuance names none (matches the column default in 00016).
const DefaultMaxCallsWithoutUsage = 3

// ParseKey splits a presented key into its id and decoded secret. It never says which part was
// wrong: a caller learns only that the key is not valid.
func ParseKey(presented string) (uuid.UUID, []byte, error) {
	invalid := fmt.Errorf("not a virtual key: %w", ErrForbidden)
	rest, ok := strings.CutPrefix(presented, keyPrefix)
	if !ok || len(rest) != 36+1+43 || rest[36] != '_' {
		return uuid.Nil, nil, invalid
	}
	id, err := uuid.Parse(rest[:36])
	if err != nil || id.String() != rest[:36] {
		return uuid.Nil, nil, invalid
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(rest[37:])
	if err != nil || len(secret) != secretBytes {
		return uuid.Nil, nil, invalid
	}
	return id, secret, nil
}

// KeyMatches compares a presented secret with a stored hash in constant time.
func KeyMatches(storedHash, secret []byte) bool {
	sum := sha256.Sum256(secret)
	return len(storedHash) == sha256.Size && subtle.ConstantTimeCompare(storedHash, sum[:]) == 1
}

func isGatewayAdmin(ctx context.Context, tx pgx.Tx, name string) (bool, error) {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM gateway_admins WHERE admin = $1)`, name).Scan(&ok); err != nil {
		return false, fmt.Errorf("check gateway admin: %w", err)
	}
	return ok, nil
}

func requireGatewayAdmin(ctx context.Context, tx pgx.Tx, actor Actor, what string) error {
	ok, err := isGatewayAdmin(ctx, tx, actor.Name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("only gateway administrators can %s: %w", what, ErrForbidden)
	}
	return nil
}

const keyColumns = `SELECT id, instance, aliases, budget_amount::text, budget_currency, expires_at, status,
	created_at, created_by, revoked_at, revoked_by, revoke_reason, max_calls_without_usage FROM virtual_keys`

func scanKey(row pgx.Row, now time.Time) (muistamov1.VirtualKey, error) {
	var k muistamov1.VirtualKey
	var amount, currency, status string
	if err := row.Scan(&k.Id, &k.Instance, &k.Aliases, &amount, &currency, &k.ExpiresAt, &status,
		&k.CreatedAt, &k.CreatedBy, &k.RevokedAt, &k.RevokedBy, &k.RevokeReason, &k.MaxCallsWithoutUsage); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return k, fmt.Errorf("virtual key: %w", ErrNotFound)
		}
		return k, fmt.Errorf("scan virtual key: %w", err)
	}
	k.MonthlyBudget = muistamov1.Money{Amount: trimDecimal(amount), Currency: muistamov1.MoneyCurrency(currency)}
	k.Status = muistamov1.VirtualKeyStatus(status)
	// Expiry is a time, never stored as a status.
	if k.Status == muistamov1.VirtualKeyStatusActive && k.ExpiresAt != nil && !now.Before(*k.ExpiresAt) {
		k.Status = muistamov1.VirtualKeyStatusExpired
	}
	return k, nil
}

// trimDecimal turns numeric's fixed scale ("10.000000000000") into the contract's exact form ("10").
func trimDecimal(s string) string {
	if !strings.Contains(s, ".") {
		return s
	}
	s = strings.TrimRight(s, "0")
	return strings.TrimSuffix(s, ".")
}

// IssueKey creates a key for an instance and returns its secret, once.
func (s *Service) IssueKey(ctx context.Context, actor Actor, req muistamov1.VirtualKeyRequest) (muistamov1.VirtualKeyIssued, error) {
	var out muistamov1.VirtualKeyIssued
	if req.MonthlyBudget.Currency != muistamov1.MoneyCurrencyEUR {
		return out, fmt.Errorf("budgets are in EUR, like model price sheets: %w", ErrInvalid)
	}
	now := time.Now()
	if req.ExpiresAt != nil && !req.ExpiresAt.After(now) {
		return out, fmt.Errorf("expiresAt must be in the future: %w", ErrInvalid)
	}
	// Calls without a usage report (aborted streams) a key may make per UTC month (00016).
	maxWithoutUsage := DefaultMaxCallsWithoutUsage
	if req.MaxCallsWithoutUsage != nil {
		maxWithoutUsage = *req.MaxCallsWithoutUsage
	}
	if maxWithoutUsage < 0 || maxWithoutUsage > 1000 {
		return out, fmt.Errorf("maxCallsWithoutUsage must be 0 to 1000: %w", ErrInvalid)
	}
	secret := make([]byte, secretBytes)
	if _, err := rand.Read(secret); err != nil {
		return out, fmt.Errorf("generate key: %w", err)
	}
	id := uuid.New()
	hash := sha256.Sum256(secret)
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		person, err := identityPersonLock(ctx, tx, actor.Tenant, req.Instance)
		if err != nil {
			return err
		}
		if err := requireGatewayAdmin(ctx, tx, actor, "issue virtual keys"); err != nil {
			return err
		}
		inst, err := lockInstance(ctx, tx, req.Instance)
		if err != nil {
			return err
		}
		if inst.Document.Spec.State != muistamov1.InstanceStateActive {
			return fmt.Errorf("instance %q is not active: %w", req.Instance, ErrConflict)
		}
		if err := checkIdentityTransition(ctx, tx, inst, muistamov1.InstanceStateActive, person); err != nil {
			return err
		}
		if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now()) {
			return fmt.Errorf("expiresAt must be in the future: %w", ErrInvalid)
		}
		// A key may call only the instance's own model alias, and only while that alias is compliant.
		eff, err := effectiveSpec(ctx, tx, req.Instance)
		if err != nil {
			return err
		}
		for _, alias := range req.Aliases {
			if alias != eff.Spec.ModelAlias {
				return fmt.Errorf("alias %q is not the model alias of instance %q (%s): %w", alias, req.Instance, eff.Spec.ModelAlias, ErrInvalid)
			}
			compliant, why, err := aliasCompliance(ctx, tx, alias)
			if err != nil {
				return err
			}
			if !compliant {
				return fmt.Errorf("model alias %q is not compliant: %s: %w", alias, why, ErrInvalid)
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO virtual_keys (tenant_id, id, instance, aliases, budget_amount,
			budget_currency, expires_at, secret_sha256, created_by, max_calls_without_usage)
			VALUES ($1, $2, $3, $4, $5::numeric, $6, $7, $8, $9, $10)`,
			actor.Tenant, id, req.Instance, req.Aliases, req.MonthlyBudget.Amount, string(req.MonthlyBudget.Currency),
			req.ExpiresAt, hash[:], actor.Name, maxWithoutUsage); err != nil {
			return fmt.Errorf("store virtual key: %w", err)
		}
		key, err := scanKey(tx.QueryRow(ctx, keyColumns+` WHERE id = $1`, id), time.Now())
		if err != nil {
			return err
		}
		out.Key = key
		// Evidence names the key, never its secret or hash.
		return recordEvidence(ctx, tx, s.signer, actor, "gateway.key.issued", "VirtualKey", id.String(), nil,
			map[string]any{"instance": key.Instance, "aliases": key.Aliases, "monthlyBudget": key.MonthlyBudget, "expiresAt": key.ExpiresAt,
				"maxCallsWithoutUsage": key.MaxCallsWithoutUsage})
	})
	if err != nil {
		return muistamov1.VirtualKeyIssued{}, err
	}
	out.Secret = keyPrefix + id.String() + "_" + base64.RawURLEncoding.EncodeToString(secret)
	return out, nil
}

// ListKeys returns the tenant's keys, newest first, optionally for one instance. Never secrets.
func (s *Service) ListKeys(ctx context.Context, actor Actor, instance string) ([]muistamov1.VirtualKey, error) {
	out := []muistamov1.VirtualKey{}
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		if err := requireGatewayAdmin(ctx, tx, actor, "list virtual keys"); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, keyColumns+` WHERE $1 = '' OR instance = $1 ORDER BY created_at DESC, id`, instance)
		if err != nil {
			return fmt.Errorf("list virtual keys: %w", err)
		}
		defer rows.Close()
		now := time.Now()
		for rows.Next() {
			k, err := scanKey(rows, now)
			if err != nil {
				return err
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	return out, err
}

// GetKey returns one key, never its secret.
func (s *Service) GetKey(ctx context.Context, actor Actor, id uuid.UUID) (muistamov1.VirtualKey, error) {
	var out muistamov1.VirtualKey
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		if err := requireGatewayAdmin(ctx, tx, actor, "read virtual keys"); err != nil {
			return err
		}
		var err error
		out, err = scanKey(tx.QueryRow(ctx, keyColumns+` WHERE id = $1`, id), time.Now())
		return err
	})
	return out, err
}

// RevokeInstanceKeys revokes every active key of an instance for the leaver workflow and returns
// their ids. Keys past expiry are still active rows, so they are made final too: a rehire never
// resurrects them. There is no administrator check: the actor is the lifecycle workflow, never a
// person, and the reason is the fixed code "leaver". Idempotent: a retry finds nothing active.
//
// The instance must already be suspended, quarantined or retired: IssueKey requires an active
// instance under the same instance lock, so no key can be minted after this commits.
//
// It returns every key this actor (one leaver workflow) has revoked for the instance, including
// on an earlier attempt, so a retried activity reports the same keys.
//
// HUMAN REVIEW REQUIRED (AGENTS.md): revocation path.
func (s *Service) RevokeInstanceKeys(ctx context.Context, actor Actor, instance string) ([]uuid.UUID, error) {
	var revoked []uuid.UUID
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		// Same lock order as IssueKey and AuthorizeGateway: HR and person, instance, then keys.
		if _, err := identityPersonLock(ctx, tx, actor.Tenant, instance); err != nil {
			return err
		}
		inst, err := lockInstance(ctx, tx, instance)
		if err != nil {
			return err
		}
		switch inst.Document.Spec.State {
		case muistamov1.InstanceStateSuspended, muistamov1.InstanceStateQuarantined, muistamov1.InstanceStateRetired:
		default:
			return fmt.Errorf("instance %q is %s; suspend it before revoking its keys: %w", instance, inst.Document.Spec.State, ErrConflict)
		}
		if _, err := revokeActiveKeys(ctx, tx, s.signer, actor, instance, "leaver"); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id FROM virtual_keys WHERE instance = $1 AND revoke_reason = 'leaver'
			AND revoked_by = $2 ORDER BY id`, instance, actor.Name)
		if err != nil {
			return fmt.Errorf("list revoked keys: %w", err)
		}
		revoked, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return fmt.Errorf("list revoked keys: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return revoked, nil
}

// revokeActiveKeys revokes the instance's active keys with a fixed system reason code, one signed
// event each, in the caller's transaction. The caller holds the instance lock. HUMAN REVIEW REQUIRED.
func revokeActiveKeys(ctx context.Context, tx pgx.Tx, signer evidence.Signer, actor Actor, instance, reason string) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM virtual_keys WHERE instance = $1 AND status = 'active'
		ORDER BY id FOR UPDATE`, instance)
	if err != nil {
		return nil, fmt.Errorf("lock instance keys: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("lock instance keys: %w", err)
	}
	for _, id := range ids {
		var revokedAt time.Time
		if err := tx.QueryRow(ctx, `UPDATE virtual_keys SET status = 'revoked', revoked_by = $2, revoke_reason = $3
			WHERE id = $1 RETURNING revoked_at`, id, actor.Name, reason).Scan(&revokedAt); err != nil {
			return nil, fmt.Errorf("revoke virtual key: %w", err)
		}
		if err := recordEvidence(ctx, tx, signer, actor, "gateway.key.revoked", "VirtualKey", id.String(),
			map[string]any{"status": "active"},
			map[string]any{"instance": instance, "reason": reason, "by": "lifecycle", "revokedAt": revokedAt}); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

// revokeBeforeReactivation keeps keys issued before a suspension from surviving reinstatement:
// when a suspended instance becomes active again, its still-active keys are revoked in the same
// transaction (reason "reactivation"). A leaver normally revoked them already; this closes the
// gap when that revocation never succeeded. The caller holds the instance lock.
// HUMAN REVIEW REQUIRED (AGENTS.md): revocation path.
func revokeBeforeReactivation(ctx context.Context, tx pgx.Tx, signer evidence.Signer, actor Actor, current muistamov1.AgentInstanceRecord, to muistamov1.InstanceState) error {
	if current.Document.Spec.State != muistamov1.InstanceStateSuspended || to != muistamov1.InstanceStateActive {
		return nil
	}
	_, err := revokeActiveKeys(ctx, tx, signer, actor, current.Document.Metadata.Name, "reactivation")
	return err
}

// refuseReactivationWithKeys is updateInstance's backstop: a suspended instance never becomes
// active while it still has active keys, whichever path changes its state (fail closed).
func refuseReactivationWithKeys(ctx context.Context, tx pgx.Tx, current muistamov1.AgentInstanceRecord, next muistamov1.AgentInstance) error {
	if current.Document.Spec.State != muistamov1.InstanceStateSuspended || next.Spec.State != muistamov1.InstanceStateActive {
		return nil
	}
	var active bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM virtual_keys WHERE instance = $1 AND status = 'active')`,
		next.Metadata.Name).Scan(&active); err != nil {
		return fmt.Errorf("check keys before reactivation: %w", err)
	}
	if active {
		return fmt.Errorf("instance %q still has active keys from before its suspension: %w", next.Metadata.Name, ErrConflict)
	}
	return nil
}

// RevokeKey revokes a key. Final: the database refuses any later change to the revocation.
func (s *Service) RevokeKey(ctx context.Context, actor Actor, id uuid.UUID, reason string) (muistamov1.VirtualKey, error) {
	var out muistamov1.VirtualKey
	// Free text cannot be reliably scrubbed from retained rows or immutable evidence.
	switch reason {
	case "operator", "compromised", "rotation", "leaver":
	default:
		return out, fmt.Errorf("a fixed revocation reason code is required: %w", ErrInvalid)
	}
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		if err := store.LockHRPrivacy(ctx, tx, actor.Tenant, false); err != nil {
			return err
		}
		if err := requireGatewayAdmin(ctx, tx, actor, "revoke virtual keys"); err != nil {
			return err
		}
		before, err := scanKey(tx.QueryRow(ctx, keyColumns+` WHERE id = $1 FOR UPDATE`, id), time.Now())
		if err != nil {
			return err
		}
		if before.Status == muistamov1.VirtualKeyStatusRevoked {
			return fmt.Errorf("virtual key %s is already revoked: %w", id, ErrConflict)
		}
		if _, err := tx.Exec(ctx, `UPDATE virtual_keys SET status = 'revoked', revoked_by = $2, revoke_reason = $3
			WHERE id = $1`, id, actor.Name, reason); err != nil {
			return fmt.Errorf("revoke virtual key: %w", err)
		}
		if out, err = scanKey(tx.QueryRow(ctx, keyColumns+` WHERE id = $1`, id), time.Now()); err != nil {
			return err
		}
		return recordEvidence(ctx, tx, s.signer, actor, "gateway.key.revoked", "VirtualKey", id.String(),
			map[string]any{"status": before.Status},
			map[string]any{"instance": out.Instance, "reason": reason, "revokedAt": out.RevokedAt})
	})
	return out, err
}
