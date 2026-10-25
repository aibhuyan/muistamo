package main

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

func modelsCmd(opts *options) *cobra.Command {
	cmd := &cobra.Command{Use: "models", Short: "Approve, reject or revoke catalogue models (privacy officers)"}
	for _, d := range []muistamov1.ModelApprovalDecisionDecision{
		muistamov1.ModelApprovalDecisionDecisionApprove, muistamov1.ModelApprovalDecisionDecisionReject, muistamov1.ModelApprovalDecisionDecisionRevoke,
	} {
		var reason string
		c := &cobra.Command{
			Use:   string(d) + " NAME --reason TEXT",
			Short: fmt.Sprintf("%s a catalogue model; never one you last changed", d),
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				client, err := opts.client()
				if err != nil {
					return err
				}
				res, err := client.DecideModelWithResponse(cmd.Context(), args[0], muistamov1.ModelApprovalDecision{Decision: d, Reason: reason})
				if err != nil {
					return err
				}
				if res.StatusCode() != http.StatusOK {
					return problem(res.StatusCode(), res.Body)
				}
				cmd.Printf("ModelCatalogueItem/%s: %s\n", args[0], res.JSON200.Approval.Status)
				return nil
			},
		}
		c.Flags().StringVar(&reason, "reason", "", "why")
		_ = c.MarkFlagRequired("reason")
		cmd.AddCommand(c)
	}
	return cmd
}

func rolloutCmd(opts *options) *cobra.Command {
	cmd := &cobra.Command{Use: "rollout", Short: "Switch a model alias to another approved model, or roll a switch back"}

	var to, reason string
	var accept bool
	start := &cobra.Command{
		Use:   "start ALIAS --to MODEL --reason TEXT --accept-unevaluated",
		Short: "Switch an alias (immediately; unevaluated until the gateway exists)",
		Long: "The evaluation gate (FR-603) needs the gateway, which is not built (D28), so no evaluation report can be produced. " +
			"--accept-unevaluated records that the switch was made without one.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !accept {
				return errors.New("this switch cannot be evaluated yet; pass --accept-unevaluated to make it anyway")
			}
			client, err := opts.client()
			if err != nil {
				return err
			}
			res, err := client.StartRolloutWithResponse(cmd.Context(), args[0], muistamov1.RolloutRequest{To: to, Reason: reason, AcknowledgeUnevaluated: true})
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusCreated {
				return problem(res.StatusCode(), res.Body)
			}
			r := res.JSON201
			cmd.Printf("rollout %s: %s %s -> %s (%s; evaluation %s)\n", r.Id, r.Alias, r.From, r.To, r.Status, r.Evaluation.Status)
			return nil
		},
	}
	start.Flags().StringVar(&to, "to", "", "the approved catalogue model to switch to")
	start.Flags().StringVar(&reason, "reason", "", "why")
	start.Flags().BoolVar(&accept, "accept-unevaluated", false, "acknowledge that no evaluation report exists")
	_ = start.MarkFlagRequired("to")
	_ = start.MarkFlagRequired("reason")

	var rbReason string
	rollback := &cobra.Command{
		Use:   "rollback ID --reason TEXT",
		Short: "Return the alias to the model it had before this rollout",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("rollout id: %w", err)
			}
			client, err := opts.client()
			if err != nil {
				return err
			}
			res, err := client.RollbackRolloutWithResponse(cmd.Context(), id, muistamov1.RollbackRequest{Reason: rbReason})
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK {
				return problem(res.StatusCode(), res.Body)
			}
			r := res.JSON200
			cmd.Printf("rollout %s: %s, %s back on %s\n", r.Id, r.Status, r.Alias, r.From)
			return nil
		},
	}
	rollback.Flags().StringVar(&rbReason, "reason", "", "why")
	_ = rollback.MarkFlagRequired("reason")

	cmd.AddCommand(start, rollback)
	return cmd
}
