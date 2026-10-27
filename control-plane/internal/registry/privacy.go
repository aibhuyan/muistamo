package registry

// HUMAN REVIEW REQUIRED (CLAUDE.md): erasure and access requests, a deletion path (FR-309,
// GDPR Arts 15-17).
//
// Only privacy officers erase, and never themselves. A person may export the records held under
// their own identity; anything keyed by an email or HR id needs an officer, because those cannot
// be verified as the caller's. Erasure refuses while the person still has an instance that is not
// retired. The rewriting itself is erase_subject (migration 00006), the only path by which the
// server's role can change history columns. Evidence events are retained, never rewritten.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

// PersonalDataTables are the tenant tables that can hold a person's identifiers. Access exports
// search all of them, and the tests scan all of them after an erasure.
var PersonalDataTables = []string{
	"agent_template_versions", "agent_instances", "hr_events", "catalogue_approvers", "catalogue_requests",
	"catalogue_approvals", "policy_documents", "privacy_officers", "erasure_requests", "agent_clones",
	"model_catalogue", "model_aliases", "rollouts", "evidence_events",
	"entra_bindings", "instance_identities", "identity_operations",
}

type retention = struct {
	Data   string `json:"data"`
	Reason string `json:"reason"`
}

// controlPlaneRetained is what erasure keeps, and why. It is part of every proof.
var controlPlaneRetained = []retention{
	{Data: "evidence_events", Reason: "Retained under GDPR Art 17(3)(b) and (e): the signed, hash-chained audit record (NFR-10). " +
		"Rewriting an event would break every signature after it."},
	{Data: "agent_instances names and the HR person label", Reason: "They contain the HR person id, are primary keys, and are " +
		"referenced by the retained evidence. Email and other identifiers in the documents are pseudonymised."},
	{Data: "hr_events.person_id and payload person.id", Reason: "The HR system's own key for the person, kept with the retained evidence of " +
		"the joiner and leaver flows. Email and other fields are pseudonymised."},
	{Data: "erasure_requests.proof.hrFenceKeys", Reason: "Tenant-scoped one-way alias/HR-key digests prevent pre-erasure HR input from restoring deleted data, including before a person's first HR event. Retained with the erasure/idempotency proof."},
	{Data: "entra_bindings, instance_identities and identity_operations", Reason: "Binding digests and opaque receipt, instance, operation and provider IDs are retained for ownership, cleanup and idempotency proof tied to signed evidence. No employee email, sponsor list, credential or raw HR payload is stored in these rows."},
	{Data: "backups", Reason: "Backups expire on their own schedule; data restored from one must be erased again."},
}

// SubjectDigest identifies a subject without naming them: SHA-256 over the tenant id and the
// sorted, de-duplicated identifiers, newline-separated. The knowledge service computes the same.
func SubjectDigest(tenant uuid.UUID, s muistamov1.PrivacySubject) string {
	values := subjectIdentifiers(s, true)
	h := sha256.New()
	h.Write([]byte(tenant.String()))
	for _, v := range values {
		h.Write([]byte("\n" + v))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// subjectIdentifiers returns the identities and email, plus the HR person id if withHR, sorted
// and de-duplicated.
func subjectIdentifiers(s muistamov1.PrivacySubject, withHR bool) []string {
	values := append([]string{s.Email}, s.Identities...)
	if withHR && s.HrPersonId != nil {
		values = append(values, *s.HrPersonId)
	}
	slices.Sort(values)
	return slices.Compact(values)
}

func isPrivacyOfficer(ctx context.Context, tx pgx.Tx, name string) (bool, error) {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM privacy_officers WHERE officer = $1)`, name).Scan(&ok); err != nil {
		return false, fmt.Errorf("check privacy officer: %w", err)
	}
	return ok, nil
}

// Erase erases a person's control-plane data and returns the proof. It reports whether this call
// did the erasure (false: the id was already completed and the stored proof is returned).
func (s *Service) Erase(ctx context.Context, actor Actor, req muistamov1.ErasureRequest) (muistamov1.ErasureProof, bool, error) {
	var proof muistamov1.ErasureProof
	var created bool
	values := subjectIdentifiers(req.Subject, false)
	digest := SubjectDigest(actor.Tenant, req.Subject)
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		if err := store.LockHRPrivacy(ctx, tx, actor.Tenant, true); err != nil {
			return err
		}
		officer, err := isPrivacyOfficer(ctx, tx, actor.Name)
		if err != nil {
			return err
		}
		if !officer {
			return fmt.Errorf("only privacy officers can erase personal data: %w", ErrForbidden)
		}
		// An officer's authoritative HR key also selects the employee's retained email aliases.
		// Never infer ownership from managerEmail: that belongs to a different person.
		if req.Subject.HrPersonId != nil {
			rows, err := tx.Query(ctx, `SELECT DISTINCT payload->'person'->>'email' FROM hr_events WHERE person_id=$1`, *req.Subject.HrPersonId)
			if err != nil {
				return fmt.Errorf("resolve HR subject aliases: %w", err)
			}
			for rows.Next() {
				var email *string
				if err := rows.Scan(&email); err != nil {
					rows.Close()
					return err
				}
				if email != nil && len(*email) >= 3 && !strings.HasPrefix(*email, "erased:") {
					values = append(values, *email)
				}
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			slices.Sort(values)
			values = slices.Compact(values)
		}
		if slices.Contains(values, actor.Name) || slices.Contains(values, strings.TrimPrefix(actor.Name, "dev:")) {
			return fmt.Errorf("a privacy officer cannot erase their own data; another officer must: %w", ErrForbidden)
		}
		for _, v := range values {
			if strings.Contains(strings.ToLower(req.Reason), strings.ToLower(v)) {
				return fmt.Errorf("the reason must not contain the person's identifiers; it is stored: %w", ErrInvalid)
			}
		}

		var storedDigest string
		var stored []byte
		err = tx.QueryRow(ctx, `SELECT subject_digest, proof FROM erasure_requests WHERE id = $1`, req.Id).Scan(&storedDigest, &stored)
		if err == nil {
			if storedDigest != digest {
				return fmt.Errorf("erasure %s was already used for a different person: %w", req.Id, ErrConflict)
			}
			return json.Unmarshal(stored, &proof)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("read erasure %s: %w", req.Id, err)
		}

		resolvedSubject := req.Subject
		resolvedSubject.Identities = append([]string(nil), values...)
		active, err := activeInstances(ctx, tx, resolvedSubject)
		if err != nil {
			return err
		}
		if len(active) > 0 {
			return fmt.Errorf("the person still has instances that are not retired (%s); run the leaver flow first: %w",
				strings.Join(active, ", "), ErrConflict)
		}

		pseudonym := "erased:" + req.Id.String()
		fenceKeys := []string{}
		for _, value := range values {
			fenceKeys = append(fenceKeys, store.HRFenceKey(actor.Tenant, "identifier", value))
		}
		personIDs := []string{}
		if req.Subject.HrPersonId != nil {
			personIDs = append(personIDs, *req.Subject.HrPersonId)
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT person_id FROM hr_events WHERE person_id=ANY($1::text[]) OR payload->'person'->>'email'=ANY($2::text[])`, personIDs, values)
		if err != nil {
			return fmt.Errorf("resolve HR erasure keys: %w", err)
		}
		for rows.Next() {
			var person string
			if err := rows.Scan(&person); err != nil {
				rows.Close()
				return err
			}
			personIDs = append(personIDs, person)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, person := range personIDs {
			fenceKeys = append(fenceKeys, store.HRFenceKey(actor.Tenant, "hr-person", person))
		}
		slices.Sort(fenceKeys)
		fenceKeys = slices.Compact(fenceKeys)
		// The HR key is authoritative for an officer request even when the person's email changed.
		// A dispatched child can still create an instance or forward the original manager.
		// Its setup marker is committed only after those activities have finished.
		cancelledHR := 0
		{
			personID := ""
			if req.Subject.HrPersonId != nil {
				personID = *req.Subject.HrPersonId
			}
			// Legacy histories have no setup marker; absence is not evidence they finished.
			rows, err := tx.Query(ctx, `SELECT dispatch_attempted_at IS NOT NULL OR dispatch_state='legacy' FROM hr_events WHERE (dispatch_state IN ('pending','legacy') OR (dispatch_state='dispatched' AND setup_completed_at IS NULL)) AND (($1::text<>'' AND person_id=$1) OR EXISTS(SELECT 1 FROM unnest($2::text[]) v WHERE strpos(payload::text,to_jsonb(v)::text)>0)) FOR UPDATE`, personID, values)
			if err != nil {
				return fmt.Errorf("lock pending HR work: %w", err)
			}
			for rows.Next() {
				var attempted bool
				if err := rows.Scan(&attempted); err != nil {
					rows.Close()
					return err
				}
				if attempted {
					rows.Close()
					return fmt.Errorf("reconcile the person's pending HR handoff before erasure: %w", ErrConflict)
				}
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `UPDATE hr_events SET dispatch_state='cancelled' WHERE dispatch_state='pending' AND (($1::text<>'' AND person_id=$1) OR payload->'person'->>'email'=ANY($2::text[]) OR payload->'person'->>'id'=ANY($2::text[]))`, personID, values)
			if err != nil {
				return fmt.Errorf("cancel erased HR work: %w", err)
			}
			cancelledHR = int(tag.RowsAffected())
		}
		var countsJSON []byte
		if err := tx.QueryRow(ctx, `SELECT erase_subject($1, $2)`, values, pseudonym).Scan(&countsJSON); err != nil {
			return fmt.Errorf("erase subject: %w", err)
		}
		proof = muistamov1.ErasureProof{
			Id: req.Id, Service: muistamov1.ErasureProofServiceControlPlane, CompletedAt: time.Now().UTC().Truncate(time.Microsecond),
			RequestedBy: actor.Name, Pseudonym: pseudonym, Retained: controlPlaneRetained, SubjectDigest: digest,
		}
		proof.HrFenceKeys = &fenceKeys
		if err := json.Unmarshal(countsJSON, &proof.Counts); err != nil {
			return fmt.Errorf("decode erasure counts: %w", err)
		}
		proof.Counts["hr_events.pending_dispatch"] += cancelledHR
		body, err := json.Marshal(proof)
		if err != nil {
			return fmt.Errorf("encode proof: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO erasure_requests (tenant_id, id, subject_digest, requested_by, reason, proof, completed_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, actor.Tenant, req.Id, digest, actor.Name, req.Reason, body, proof.CompletedAt); err != nil {
			return fmt.Errorf("record erasure: %w", err)
		}
		created = true
		return recordEvidence(ctx, tx, s.signer, actor, "privacy.erasure.completed", "ErasureRequest", req.Id.String(), nil, proof)
	})
	return proof, created, err
}

// GetErasure returns the proof of a completed erasure.
func (s *Service) GetErasure(ctx context.Context, actor Actor, id uuid.UUID) (muistamov1.ErasureProof, error) {
	var proof muistamov1.ErasureProof
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		officer, err := isPrivacyOfficer(ctx, tx, actor.Name)
		if err != nil {
			return err
		}
		if !officer {
			return fmt.Errorf("only privacy officers can read erasure proofs: %w", ErrForbidden)
		}
		var body []byte
		err = tx.QueryRow(ctx, `SELECT proof FROM erasure_requests WHERE id = $1`, id).Scan(&body)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("erasure %s: %w", id, ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("read erasure %s: %w", id, err)
		}
		return json.Unmarshal(body, &proof)
	})
	return proof, err
}

// ExportPersonalData returns every row of PersonalDataTables that holds one of the person's
// identifiers as a whole JSON value. A privacy officer may export anyone; anyone else only the
// records under their own identity.
func (s *Service) ExportPersonalData(ctx context.Context, actor Actor, subject muistamov1.PrivacySubject) (muistamov1.AccessExport, error) {
	out := muistamov1.AccessExport{Service: muistamov1.AccessExportServiceControlPlane, Sections: map[string][]map[string]any{}}
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		officer, err := isPrivacyOfficer(ctx, tx, actor.Name)
		if err != nil {
			return err
		}
		values := subjectIdentifiers(subject, false)
		if !officer {
			if len(subject.Identities) != 1 || subject.Identities[0] != actor.Name {
				return fmt.Errorf("you can export only your own data; ask a privacy officer for anyone else's: %w", ErrForbidden)
			}
			values = []string{actor.Name}
		}
		counts := map[string]int{}
		for _, table := range PersonalDataTables {
			rows, err := RowsMentioning(ctx, tx, table, values)
			if err != nil {
				return err
			}
			personID := ""
			if officer && subject.HrPersonId != nil {
				personID = *subject.HrPersonId
			}
			related, err := identityPrivacyRows(ctx, tx, table, values, personID)
			if err != nil {
				return err
			}
			rows = mergeRows(rows, related)
			if officer && subject.HrPersonId != nil {
				byHR, err := rowsForHRPerson(ctx, tx, table, *subject.HrPersonId)
				if err != nil {
					return err
				}
				rows = mergeRows(rows, byHR)
			}
			out.Sections[table] = rows
			counts[table] = len(rows)
		}
		out.GeneratedAt = time.Now().UTC()
		after := map[string]any{"counts": counts, "self": !officer}
		if officer {
			after["subjectDigest"] = SubjectDigest(actor.Tenant, subject)
		}
		return recordEvidence(ctx, tx, s.signer, actor, "privacy.access.exported", "AccessRequest", uuid.NewString(), nil, after)
	})
	return out, err
}

// Follow opaque journal/receipt relationships without broadening self-service identifier
// authority: email aliases and HR IDs are included only in the officer's existing scope.
func identityPrivacyRows(ctx context.Context, tx pgx.Tx, table string, values []string, personID string) ([]map[string]any, error) {
	prefix := ""
	switch table {
	case "instance_identities":
		prefix = `SELECT DISTINCT to_jsonb(t) FROM instance_identities t JOIN instance_identities i ON i.tenant_id=t.tenant_id AND i.id=t.id`
	case "identity_operations":
		prefix = `SELECT DISTINCT to_jsonb(t) FROM identity_operations t JOIN instance_identities i ON i.tenant_id=t.tenant_id AND i.id=t.instance_identity_id`
	case "entra_bindings":
		prefix = `SELECT DISTINCT to_jsonb(t) FROM entra_bindings t JOIN instance_identities i ON i.tenant_id=t.tenant_id AND i.binding_version=t.binding_version`
	default:
		return nil, nil
	}
	rows, err := tx.Query(ctx, prefix+` JOIN agent_instances a ON a.tenant_id=i.tenant_id AND a.name=i.instance_name LEFT JOIN hr_events h ON h.tenant_id=i.tenant_id AND h.receipt_id=i.assignment_receipt_id WHERE t.tenant_id=current_setting('muistamo.tenant_id',true)::uuid AND (a.document->'spec'->'binding'->>'ref'=ANY($1::text[]) OR a.document->'spec'->>'sponsor'=ANY($1::text[]) OR a.document->'spec'->>'delegate'=ANY($1::text[]) OR h.payload->'person'->>'email'=ANY($1::text[]) OR ($2::text<>'' AND h.person_id=$2))`, values, personID)
	if err != nil {
		return nil, fmt.Errorf("export related identity metadata: %w", err)
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var row map[string]any
		if err := rows.Scan(&row); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// RowsMentioning returns the rows of table (one of PersonalDataTables, never input) in which any
// of values appears as a whole JSON string value. It names the tenant explicitly as well as
// relying on row-level security, so it is scoped whichever role runs it.
func RowsMentioning(ctx context.Context, tx pgx.Tx, table string, values []string) ([]map[string]any, error) {
	if !slices.Contains(PersonalDataTables, table) {
		return nil, fmt.Errorf("table %q is not a personal-data table", table)
	}
	needles := make([]string, len(values))
	for i, v := range values {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		needles[i] = string(b)
	}
	rows, err := tx.Query(ctx, `SELECT to_jsonb(t) FROM `+table+` t
		WHERE t.tenant_id = current_setting('muistamo.tenant_id', true)::uuid
		  AND EXISTS (SELECT 1 FROM unnest($1::text[]) n WHERE strpos(to_jsonb(t)::text, n) > 0)`, needles)
	if err != nil {
		return nil, fmt.Errorf("search %s: %w", table, err)
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var row map[string]any
		if err := rows.Scan(&row); err != nil {
			return nil, fmt.Errorf("scan %s: %w", table, err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// hrPersonQueries find rows keyed by an HR person id. An HR id can be short ("1"), so it is
// matched only where it is a person key, never as an arbitrary value.
var hrPersonQueries = map[string]string{
	"hr_events":       `SELECT to_jsonb(t) FROM hr_events t WHERE t.tenant_id = current_setting('muistamo.tenant_id', true)::uuid AND person_id = $1`,
	"agent_instances": `SELECT to_jsonb(t) FROM agent_instances t WHERE t.tenant_id = current_setting('muistamo.tenant_id', true)::uuid AND document -> 'metadata' -> 'labels' ->> '` + PersonLabel + `' = $1`,
	"evidence_events": `SELECT to_jsonb(t) FROM evidence_events t WHERE t.tenant_id = current_setting('muistamo.tenant_id', true)::uuid AND subject_kind = 'HRPerson' AND subject_name = $1`,
}

func rowsForHRPerson(ctx context.Context, tx pgx.Tx, table, personID string) ([]map[string]any, error) {
	q, ok := hrPersonQueries[table]
	if !ok {
		return nil, nil
	}
	rows, err := tx.Query(ctx, q, personID)
	if err != nil {
		return nil, fmt.Errorf("search %s by HR person: %w", table, err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var row map[string]any
		if err := rows.Scan(&row); err != nil {
			return nil, fmt.Errorf("scan %s: %w", table, err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// mergeRows appends the rows of b not already in a.
func mergeRows(a, b []map[string]any) []map[string]any {
	seen := map[string]bool{}
	for _, row := range a {
		k, _ := json.Marshal(row)
		seen[string(k)] = true
	}
	for _, row := range b {
		k, _ := json.Marshal(row)
		if !seen[string(k)] {
			seen[string(k)] = true
			a = append(a, row)
		}
	}
	return a
}

// activeInstances names the person's instances that are not retired: bound to one of their
// identifiers, or labelled with their HR person id.
func activeInstances(ctx context.Context, tx pgx.Tx, subject muistamov1.PrivacySubject) ([]string, error) {
	rows, err := RowsMentioning(ctx, tx, "agent_instances", subjectIdentifiers(subject, false))
	if err != nil {
		return nil, err
	}
	if subject.HrPersonId != nil {
		byHR, err := rowsForHRPerson(ctx, tx, "agent_instances", *subject.HrPersonId)
		if err != nil {
			return nil, err
		}
		rows = mergeRows(rows, byHR)
	}
	var names []string
	for _, row := range rows {
		state, _ := row["state"].(string)
		if state != string(muistamov1.InstanceStateRetired) {
			name, _ := row["name"].(string)
			names = append(names, name)
		}
	}
	return names, nil
}
