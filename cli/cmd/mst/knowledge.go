package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"muistamo.dev/muistamo/cli/internal/manifest"
	muistamov1 "muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// knowledgeCall sends a request to the knowledge service with the development identity headers.
// Bodies are contract-validated documents (manifest.Read), sent exactly as validated.
func (o *options) knowledgeCall(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	if o.tenant == "" || o.actor == "" {
		return 0, nil, fmt.Errorf("no tenant or actor: pass --tenant and --actor (MST_TENANT, MST_ACTOR)")
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(o.knowledgeServer, "/")+path, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Muistamo-Tenant", o.tenant)
	req.Header.Set("X-Muistamo-Actor", o.actor)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()
	out, err := io.ReadAll(res.Body)
	return res.StatusCode, out, err
}

// knowledgeKinds maps the kinds the knowledge service owns to their collection paths.
var knowledgeKinds = map[string]string{
	"KnowledgePack":   "/v1/knowledge/packs/",
	"KnowledgeSource": "/v1/knowledge/sources/",
}

func isKnowledgeKind(kind string) bool { _, ok := knowledgeKinds[kind]; return ok }

func applyKnowledge(cmd *cobra.Command, opts *options, doc manifest.Document) error {
	if doc.Kind == "KnowledgeSource" {
		return applySource(cmd, opts, doc)
	}
	status, body, err := opts.knowledgeCall(cmd.Context(), http.MethodPut, knowledgeKinds[doc.Kind]+url.PathEscape(doc.Name), doc.JSON)
	if err != nil {
		return err
	}
	var rec struct {
		LatestVersion string `json:"latestVersion"`
	}
	switch status {
	case http.StatusCreated:
		_ = json.Unmarshal(body, &rec)
		cmd.Printf("%s/%s: created (content version %s; content changes only through proposals)\n", doc.Kind, doc.Name, rec.LatestVersion)
	case http.StatusOK:
		_ = json.Unmarshal(body, &rec)
		cmd.Printf("%s/%s: applied (content version %s)\n", doc.Kind, doc.Name, rec.LatestVersion)
	default:
		return problem(status, body)
	}
	return nil
}

func applySource(cmd *cobra.Command, opts *options, doc manifest.Document) error {
	status, body, err := opts.knowledgeCall(cmd.Context(), http.MethodPut, knowledgeKinds[doc.Kind]+url.PathEscape(doc.Name), doc.JSON)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusCreated:
		cmd.Printf("%s/%s: created (run a sync to index it)\n", doc.Kind, doc.Name)
	case http.StatusOK:
		cmd.Printf("%s/%s: applied\n", doc.Kind, doc.Name)
	default:
		return problem(status, body)
	}
	return nil
}

func fetchKnowledge(ctx context.Context, opts *options, doc manifest.Document) ([]byte, error) {
	status, body, err := opts.knowledgeCall(ctx, http.MethodGet, knowledgeKinds[doc.Kind]+url.PathEscape(doc.Name), nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, problem(status, body)
	}
	var rec struct {
		Document json.RawMessage `json:"document"`
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, fmt.Errorf("decode pack: %w", err)
	}
	return rec.Document, nil
}

func knowledgeCmd(opts *options) *cobra.Command {
	cmd := &cobra.Command{Use: "knowledge", Short: "Work with the knowledge service"}
	var pack, version, out string
	export := &cobra.Command{
		Use:   "export-skills --pack P [--version V] -o FILE.zip",
		Short: "Download a published pack version as Agent Skills (SKILL.md folders)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := "/v1/knowledge/packs/" + url.PathEscape(pack) + "/versions/" + url.PathEscape(version) + "/skills.zip"
			status, body, err := opts.knowledgeCall(cmd.Context(), http.MethodGet, path, nil)
			if err != nil {
				return err
			}
			if status != http.StatusOK {
				return problem(status, body)
			}
			if err := os.WriteFile(out, body, 0o600); err != nil {
				return fmt.Errorf("write %s: %w", out, err)
			}
			sum := sha256.Sum256(body)
			cmd.Printf("wrote %s (%d bytes, sha256 %x)\n", out, len(body), sum)
			return nil
		},
	}
	export.Flags().StringVar(&pack, "pack", "", "pack name")
	export.Flags().StringVar(&version, "version", "latest", "published version, or latest")
	export.Flags().StringVarP(&out, "output", "o", "", "zip file to write")
	_ = export.MarkFlagRequired("pack")
	_ = export.MarkFlagRequired("output")
	cmd.AddCommand(export, verificationsCmd(opts), verifyEntryCmd(opts))
	return cmd
}

func verificationLine(v muistamov1.EntryVerification) string {
	timestamp := func(t *time.Time) string {
		if t == nil {
			return "unconfirmed"
		}
		return t.Format(time.RFC3339)
	}
	expires := timestamp(v.Decay.ExpiresAt)
	if v.Mandatory != nil && *v.Mandatory {
		expires = "never (mandatory)"
	}
	verifiedBy := "unconfirmed"
	if v.Decay.VerifiedBy != nil {
		verifiedBy = *v.Decay.VerifiedBy
	}
	return fmt.Sprintf("%s/%s\t%s\tentry %s\tversion %s\tdue %s\texpires %s\tlast verified by %s\tprovenance %d",
		v.Pack, v.Entry.Key, v.Decay.Status, v.Entry.Id, v.Version, timestamp(v.Decay.DueAt), expires, verifiedBy, v.Provenance.Score)
}

func verificationsCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "verifications",
		Short: "Entries due or expired in packs you may confirm (FR-307)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			status, body, err := opts.knowledgeCall(cmd.Context(), http.MethodGet, "/v1/knowledge/verifications", nil)
			if err != nil {
				return err
			}
			if status != http.StatusOK {
				return problem(status, body)
			}
			var page muistamov1.VerificationPage
			if err := json.Unmarshal(body, &page); err != nil {
				return fmt.Errorf("decode verifications: %w", err)
			}
			if len(page.Items) == 0 {
				cmd.Println("nothing to confirm")
			}
			for _, v := range page.Items {
				cmd.Println(verificationLine(v))
			}
			return nil
		},
	}
}

func verifyEntryCmd(opts *options) *cobra.Command {
	var reason, entryID string
	cmd := &cobra.Command{
		Use:   "verify PACK KEY --entry-id ID --reason TEXT",
		Short: "Confirm a pack entry is still right, restarting its decay clock",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(entryID)
			if err != nil {
				return fmt.Errorf("invalid --entry-id: %w", err)
			}
			payload, err := json.Marshal(muistamov1.VerificationInput{EntryId: id, Reason: reason})
			if err != nil {
				return err
			}
			path := "/v1/knowledge/packs/" + url.PathEscape(args[0]) + "/entries/" + url.PathEscape(args[1]) + "/verification"
			status, body, err := opts.knowledgeCall(cmd.Context(), http.MethodPost, path, payload)
			if err != nil {
				return err
			}
			if status != http.StatusOK {
				return problem(status, body)
			}
			var v muistamov1.EntryVerification
			if err := json.Unmarshal(body, &v); err != nil {
				return fmt.Errorf("decode verification: %w", err)
			}
			cmd.Println(verificationLine(v))
			return nil
		},
	}
	cmd.Flags().StringVar(&entryID, "entry-id", "", "immutable entry ID you inspected (from the verification queue)")
	_ = cmd.MarkFlagRequired("entry-id")
	cmd.Flags().StringVar(&reason, "reason", "", "why the entry is still right")
	_ = cmd.MarkFlagRequired("reason")
	return cmd
}
