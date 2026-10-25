package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/evidencechain"
)

func evidenceCmd(opts *options) *cobra.Command {
	cmd := &cobra.Command{Use: "evidence", Short: "Export and verify the evidence chain"}
	cmd.AddCommand(exportCmd(opts), verifyCmd())
	return cmd
}

func exportCmd(opts *options) *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "export -o FILE.jsonl",
		Short: "Write the tenant's whole evidence chain, one event per line",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}
			var buf bytes.Buffer
			count, after := 0, 0
			for {
				limit := 200
				res, err := client.ListEventsWithResponse(cmd.Context(), &muistamov1.ListEventsParams{AfterSeq: &after, Limit: &limit})
				if err != nil {
					return fmt.Errorf("list events: %w", err)
				}
				if res.StatusCode() != http.StatusOK {
					return problem(res.StatusCode(), res.Body)
				}
				// Keep each event exactly as the server sent it.
				var page struct {
					Items        []json.RawMessage `json:"items"`
					NextAfterSeq *int              `json:"nextAfterSeq"`
				}
				if err := json.Unmarshal(res.Body, &page); err != nil {
					return fmt.Errorf("decode events: %w", err)
				}
				for _, item := range page.Items {
					var compact bytes.Buffer
					if err := json.Compact(&compact, item); err != nil {
						return fmt.Errorf("encode event: %w", err)
					}
					buf.Write(compact.Bytes())
					buf.WriteByte('\n')
					count++
				}
				if page.NextAfterSeq == nil {
					break
				}
				after = *page.NextAfterSeq
			}
			if err := os.WriteFile(out, buf.Bytes(), 0o600); err != nil {
				return fmt.Errorf("write %s: %w", out, err)
			}
			cmd.Printf("exported %d events to %s\n", count, out)
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "file to write")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func verifyCmd() *cobra.Command {
	var file string
	var keyFiles []string
	cmd := &cobra.Command{
		Use:   "verify -f FILE.jsonl --public-key KEY.pub [--public-key ...]",
		Short: "Verify an exported chain offline against public keys you trust",
		Long: "Checks that the chain is complete from seq 1, every link is intact, every hash matches " +
			"its event, and every signature is valid under one of the given keys. Take the keys from " +
			"your own records, not from the system being audited.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			keys, err := readPublicKeys(keyFiles)
			if err != nil {
				return err
			}
			events, err := readExport(file)
			if err != nil {
				return err
			}
			if err := evidencechain.Verify(events, keys); err != nil {
				return fmt.Errorf("verification FAILED: %w", err)
			}
			last := events[len(events)-1]
			cmd.Printf("verified %d events for tenant %s; head seq %d hash %s\n", len(events), last.Tenant, last.Seq, last.Hash)
			return nil
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "exported chain (.jsonl)")
	cmd.Flags().StringArrayVar(&keyFiles, "public-key", nil, "trusted public key (PEM); repeatable")
	_ = cmd.MarkFlagRequired("file")
	_ = cmd.MarkFlagRequired("public-key")
	return cmd
}

func readPublicKeys(paths []string) (map[string]ed25519.PublicKey, error) {
	keys := map[string]ed25519.PublicKey{}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read public key: %w", err)
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("%s: expected a PEM PUBLIC KEY block", path)
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		pub, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%s: not an Ed25519 key", path)
		}
		keys[evidencechain.KeyID(pub)] = pub
	}
	return keys, nil
}

func readExport(path string) ([]evidencechain.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open export: %w", err)
	}
	defer func() { _ = f.Close() }()
	var events []evidencechain.Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 16<<20)
	for line := 1; scanner.Scan(); line++ {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var e evidencechain.Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, line, err)
		}
		events = append(events, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read export: %w", err)
	}
	if len(events) == 0 {
		return nil, errors.New("export contains no events")
	}
	return events, nil
}
