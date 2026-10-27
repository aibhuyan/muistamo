package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"go.temporal.io/sdk/client"

	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

// hrCmd is an operator recovery path using the normal scoped DB role and registered signer.
// It exposes no public administration endpoint and never prints retained HR payloads.
func hrCmd() *cobra.Command {
	root := &cobra.Command{Use: "hr", Short: "Recover durable HR workflow handoffs"}
	var tenant, actor string
	var limit int
	retry := &cobra.Command{
		Use: "retry --tenant ID --actor OPERATOR", Short: "Retry pending HR handoffs after a workflow-engine outage", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := uuid.Parse(tenant)
			if err != nil || id == uuid.Nil {
				return errors.New("a valid tenant id is required")
			}
			if strings.TrimSpace(actor) == "" {
				return errors.New("an operator actor is required")
			}
			if limit < 1 || limit > 1000 {
				return errors.New("limit must be between 1 and 1000")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Minute)
			defer cancel()
			db, err := store.Open(ctx, requireEnv("MUISTAMO_DATABASE_URL"))
			if err != nil {
				return err
			}
			defer db.Close()
			key, err := loadSigner(ctx, db, requireEnv("MUISTAMO_EVIDENCE_KEY_FILE"))
			if err != nil {
				return err
			}
			temporal, err := client.Dial(client.Options{HostPort: requireEnv("TEMPORAL_ADDRESS"), Namespace: envOr("TEMPORAL_NAMESPACE", "default")})
			if err != nil {
				return fmt.Errorf("connect to workflow engine: %w", err)
			}
			defer temporal.Close()
			in := &lifecycle.Intake{DB: db, Signer: key, Dispatcher: lifecycle.TemporalDispatcher{Client: temporal}}
			receipts, dispatchErr := in.RetryPending(ctx, id, actor, uuid.NewString(), limit)
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(receipts); err != nil {
				return fmt.Errorf("write HR recovery receipts: %w", err)
			}
			return dispatchErr
		},
	}
	retry.Flags().StringVar(&tenant, "tenant", "", "Muistamo tenant id")
	retry.Flags().StringVar(&actor, "actor", "", "operator identity recorded in evidence")
	retry.Flags().IntVar(&limit, "limit", 100, "maximum handoffs to attempt (1-1000)")
	_ = retry.MarkFlagRequired("tenant")
	_ = retry.MarkFlagRequired("actor")
	root.AddCommand(retry)
	return root
}
