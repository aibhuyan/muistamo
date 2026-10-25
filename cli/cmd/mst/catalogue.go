package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

func catalogueCmd(opts *options) *cobra.Command {
	cmd := &cobra.Command{Use: "catalogue", Short: "Publish templates to the catalogue, with approval by risk tier"}

	cmd.AddCommand(&cobra.Command{
		Use:   "request TEMPLATE VERSION",
		Short: "Ask for a template version to be published (low risk publishes at once)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}
			var version int
			if _, err := fmt.Sscan(args[1], &version); err != nil {
				return fmt.Errorf("version must be a number: %w", err)
			}
			res, err := client.RequestPublicationWithResponse(cmd.Context(), args[0], version)
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusCreated {
				return problem(res.StatusCode(), res.Body)
			}
			return printRequest(cmd, res.Body)
		},
	})

	decide := func(decision string) *cobra.Command {
		var reason string
		c := &cobra.Command{
			Use:   decision + " REQUEST_ID --reason TEXT",
			Short: fmt.Sprintf("%s a catalogue request (approvers only; never your own)", decision),
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				client, err := opts.client()
				if err != nil {
					return err
				}
				id, err := uuid.Parse(args[0])
				if err != nil {
					return fmt.Errorf("request id: %w", err)
				}
				res, err := client.DecideCatalogueRequestWithResponse(cmd.Context(), id,
					muistamov1.DecideCatalogueRequestJSONRequestBody{Decision: muistamov1.CatalogueDecisionDecision(decision), Reason: reason})
				if err != nil {
					return err
				}
				if res.StatusCode() != http.StatusOK {
					return problem(res.StatusCode(), res.Body)
				}
				return printRequest(cmd, res.Body)
			},
		}
		c.Flags().StringVar(&reason, "reason", "", "why")
		_ = c.MarkFlagRequired("reason")
		return c
	}
	cmd.AddCommand(decide("approve"), decide("reject"))

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "Show published templates and pending requests",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}
			published, err := client.ListCatalogueWithResponse(cmd.Context())
			if err != nil {
				return err
			}
			if published.StatusCode() != http.StatusOK {
				return problem(published.StatusCode(), published.Body)
			}
			cmd.Println("published:")
			for _, e := range published.JSON200.Items {
				cmd.Printf("  %s v%d (since %s)\n", e.Template, e.Version, e.PublishedAt.Format("2006-01-02 15:04"))
			}
			state := muistamov1.ListCatalogueRequestsParamsStatePending
			pending, err := client.ListCatalogueRequestsWithResponse(cmd.Context(), &muistamov1.ListCatalogueRequestsParams{State: &state})
			if err != nil {
				return err
			}
			if pending.StatusCode() != http.StatusOK {
				return problem(pending.StatusCode(), pending.Body)
			}
			cmd.Println("pending:")
			for _, r := range pending.JSON200.Items {
				cmd.Printf("  %s %s v%d %s risk, %d/%d approvals, requested by %s\n",
					r.Id, r.Template, r.Version, r.RiskTier, approvals(r.Approvals), r.NeededApprovals, r.RequestedBy)
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "withdraw TEMPLATE",
		Short: "Withdraw a template; new joiners stop receiving it (approvers only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}
			res, err := client.WithdrawFromCatalogueWithResponse(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusNoContent {
				return problem(res.StatusCode(), res.Body)
			}
			cmd.Printf("%s withdrawn from the catalogue\n", args[0])
			return nil
		},
	})
	return cmd
}

func approvals(list []muistamov1.CatalogueApproval) int {
	n := 0
	for _, a := range list {
		if a.Decision == muistamov1.CatalogueApprovalDecisionApprove {
			n++
		}
	}
	return n
}

func printRequest(cmd *cobra.Command, body []byte) error {
	var r muistamov1.CatalogueRequest
	if err := json.Unmarshal(body, &r); err != nil {
		var pretty bytes.Buffer
		_ = json.Indent(&pretty, body, "", "  ")
		cmd.Println(pretty.String())
		return nil
	}
	cmd.Printf("request %s: %s v%d, %s risk, %s (%d/%d approvals)\n",
		r.Id, r.Template, r.Version, r.RiskTier, r.State, approvals(r.Approvals), r.NeededApprovals)
	return nil
}
