package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

type subjectFlags struct {
	identities []string
	email, hr  string
}

func (f *subjectFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(&f.identities, "identity", nil, "an identity as Muistamo records it, e.g. dev:person@example.com (repeatable)")
	cmd.Flags().StringVar(&f.email, "email", "", "the person's email")
	cmd.Flags().StringVar(&f.hr, "hr-person-id", "", "the HR system's person id, if any")
	_ = cmd.MarkFlagRequired("identity")
	_ = cmd.MarkFlagRequired("email")
}

func (f *subjectFlags) subject() muistamov1.PrivacySubject {
	s := muistamov1.PrivacySubject{Identities: f.identities, Email: f.email}
	if f.hr != "" {
		s.HrPersonId = &f.hr
	}
	return s
}

func privacyCmd(opts *options) *cobra.Command {
	cmd := &cobra.Command{Use: "privacy", Short: "Erasure and access requests across both services (privacy officers)"}

	var sf subjectFlags
	var id, reason string
	var redact []string
	erase := &cobra.Command{
		Use:   "erase --identity ID --email EMAIL --reason TEXT [--hr-person-id ID] [--redact-entry UUID]...",
		Short: "Erase a person's data in the control plane, then the knowledge service, under one request id",
		Long: "Erases in the control plane first (which refuses while the person has an instance that is not retired), " +
			"then in the knowledge service. Each prints its proof. If one service fails, re-run with the same --id: " +
			"a completed service returns its stored proof and changes nothing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}
			requestID := uuid.New()
			if id != "" {
				if requestID, err = uuid.Parse(id); err != nil {
					return fmt.Errorf("--id: %w", err)
				}
			}
			req := muistamov1.ErasureRequest{Id: requestID, Subject: sf.subject(), Reason: reason}
			cmd.Printf("erasure %s\n", requestID)

			res, err := client.ErasePersonalDataWithResponse(cmd.Context(), req)
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusCreated && res.StatusCode() != http.StatusOK {
				return fmt.Errorf("control plane: %w (nothing was erased in the knowledge service)", problem(res.StatusCode(), res.Body))
			}
			printProof(cmd, res.StatusCode(), res.Body)

			if len(redact) > 0 {
				ids := make([]uuid.UUID, len(redact))
				for i, r := range redact {
					if ids[i], err = uuid.Parse(r); err != nil {
						return fmt.Errorf("--redact-entry %q: %w", r, err)
					}
				}
				req.RedactEntries = &ids
			}
			body, err := json.Marshal(req)
			if err != nil {
				return err
			}
			status, out, err := opts.knowledgeCall(cmd.Context(), http.MethodPost, "/v1/knowledge/privacy/erasures", body)
			if err == nil && status != http.StatusCreated && status != http.StatusOK {
				err = problem(status, out)
			}
			if err != nil {
				return fmt.Errorf("knowledge service: %w (the control plane erasure is complete; re-run with --id %s)", err, requestID)
			}
			printProof(cmd, status, out)
			return nil
		},
	}
	sf.register(erase)
	erase.Flags().StringVar(&id, "id", "", "request id, to re-run a partly completed erasure (default: a new one)")
	erase.Flags().StringVar(&reason, "reason", "", "why, e.g. the data subject request reference; must not name the person")
	erase.Flags().StringSliceVar(&redact, "redact-entry", nil, "knowledge entry whose text is personal data (repeatable)")
	_ = erase.MarkFlagRequired("reason")

	var af subjectFlags
	var out string
	access := &cobra.Command{
		Use:   "access --identity ID --email EMAIL [--hr-person-id ID] -o FILE",
		Short: "Export everything both services hold about a person into one JSON file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}
			req := muistamov1.AccessRequest{Subject: af.subject()}
			res, err := client.ExportPersonalDataWithResponse(cmd.Context(), req)
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK {
				return fmt.Errorf("control plane: %w", problem(res.StatusCode(), res.Body))
			}
			body, err := json.Marshal(req)
			if err != nil {
				return err
			}
			status, kbody, err := opts.knowledgeCall(cmd.Context(), http.MethodPost, "/v1/knowledge/privacy/access", body)
			if err == nil && status != http.StatusOK {
				err = problem(status, kbody)
			}
			if err != nil {
				return fmt.Errorf("knowledge service: %w", err)
			}
			merged := map[string]json.RawMessage{"controlPlane": res.Body, "knowledge": kbody}
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetIndent("", "  ")
			if err := enc.Encode(merged); err != nil {
				return err
			}
			if err := os.WriteFile(out, buf.Bytes(), 0o600); err != nil {
				return err
			}
			cmd.Printf("wrote %s: control plane %s; knowledge %s\n", out, sectionSummary(res.Body), sectionSummary(kbody))
			return nil
		},
	}
	af.register(access)
	access.Flags().StringVarP(&out, "out", "o", "", "output file (written with mode 0600: it holds personal data)")
	_ = access.MarkFlagRequired("out")

	cmd.AddCommand(erase, access)
	return cmd
}

func printProof(cmd *cobra.Command, status int, body []byte) {
	var p muistamov1.ErasureProof
	if err := json.Unmarshal(body, &p); err != nil {
		cmd.Printf("  unreadable proof: %v\n", err)
		return
	}
	state := "erased"
	if status == http.StatusOK {
		state = "already erased (stored proof)"
	}
	var changed []string
	for k, n := range p.Counts {
		if n > 0 {
			changed = append(changed, fmt.Sprintf("%s=%d", k, n))
		}
	}
	cmd.Printf("  %s: %s at %s; pseudonym %s; changed %s\n", p.Service, state, p.CompletedAt.Format("2006-01-02T15:04:05Z"),
		p.Pseudonym, strings.Join(sorted(changed), ", "))
	for _, r := range p.Retained {
		cmd.Printf("    retained %s: %s\n", r.Data, r.Reason)
	}
	if p.Warnings != nil {
		for _, w := range *p.Warnings {
			cmd.Printf("    WARNING: %s\n", w)
		}
	}
}

func sectionSummary(body []byte) string {
	var e muistamov1.AccessExport
	if err := json.Unmarshal(body, &e); err != nil {
		return "unreadable"
	}
	var parts []string
	for table, rows := range e.Sections {
		if len(rows) > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", table, len(rows)))
		}
	}
	if len(parts) == 0 {
		return "nothing"
	}
	return strings.Join(sorted(parts), ", ")
}

func sorted(s []string) []string {
	slices.Sort(s)
	return s
}
