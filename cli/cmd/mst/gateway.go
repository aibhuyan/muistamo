package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

func gatewayCmd(opts *options) *cobra.Command {
	cmd := &cobra.Command{Use: "gateway", Short: "Work with the model and tool gateway"}
	keys := &cobra.Command{Use: "keys", Short: "Issue, list and revoke virtual keys (gateway administrators)"}
	keys.AddCommand(keysListCmd(opts), keysGetCmd(opts), keysIssueCmd(opts), keysRevokeCmd(opts))
	cmd.AddCommand(keys)
	return cmd
}

func keyLine(k muistamov1.VirtualKey) string {
	expires := "never"
	if k.ExpiresAt != nil {
		expires = k.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("%s\t%s\t%s\taliases %s\tbudget %s %s/month\texpires %s",
		k.Id, k.Instance, k.Status, strings.Join(k.Aliases, ","), k.MonthlyBudget.Amount, k.MonthlyBudget.Currency, expires)
}

func keysListCmd(opts *options) *cobra.Command {
	var instance string
	c := &cobra.Command{
		Use:   "list [--instance NAME]",
		Short: "List virtual keys, never their secrets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}
			params := &muistamov1.ListVirtualKeysParams{}
			if instance != "" {
				params.Instance = &instance
			}
			res, err := client.ListVirtualKeysWithResponse(cmd.Context(), params)
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK {
				return problem(res.StatusCode(), res.Body)
			}
			if len(res.JSON200.Items) == 0 {
				cmd.Println("no virtual keys")
			}
			for _, k := range res.JSON200.Items {
				cmd.Println(keyLine(k))
			}
			return nil
		},
	}
	c.Flags().StringVar(&instance, "instance", "", "only this instance's keys")
	return c
}

func keysGetCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "get ID",
		Short: "Show one virtual key, never its secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("key id: %w", err)
			}
			client, err := opts.client()
			if err != nil {
				return err
			}
			res, err := client.GetVirtualKeyWithResponse(cmd.Context(), id)
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK {
				return problem(res.StatusCode(), res.Body)
			}
			cmd.Println(keyLine(*res.JSON200))
			return nil
		},
	}
}

func keysIssueCmd(opts *options) *cobra.Command {
	var instance, alias, budget, expires string
	c := &cobra.Command{
		Use:   "issue --instance NAME --alias ALIAS --budget EUR [--expires RFC3339]",
		Short: "Issue a virtual key; its secret is printed once and can never be shown again",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			req := muistamov1.VirtualKeyRequest{
				Instance:      instance,
				Aliases:       []string{alias},
				MonthlyBudget: muistamov1.Money{Amount: budget, Currency: muistamov1.MoneyCurrencyEUR},
			}
			if expires != "" {
				at, err := time.Parse(time.RFC3339, expires)
				if err != nil {
					return fmt.Errorf("--expires: %w", err)
				}
				req.ExpiresAt = &at
			}
			client, err := opts.client()
			if err != nil {
				return err
			}
			res, err := client.IssueVirtualKeyWithResponse(cmd.Context(), req)
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusCreated {
				return problem(res.StatusCode(), res.Body)
			}
			cmd.Println(keyLine(res.JSON201.Key))
			cmd.Println("secret (shown once; Muistamo keeps only its hash and cannot show it again):")
			cmd.Println(res.JSON201.Secret)
			return nil
		},
	}
	c.Flags().StringVar(&instance, "instance", "", "the agent instance")
	c.Flags().StringVar(&alias, "alias", "", "the model alias the key may call")
	c.Flags().StringVar(&budget, "budget", "", "monthly budget in EUR, e.g. 25.50")
	c.Flags().StringVar(&expires, "expires", "", "expiry time (RFC 3339)")
	for _, f := range []string{"instance", "alias", "budget"} {
		_ = c.MarkFlagRequired(f)
	}
	return c
}

func keysRevokeCmd(opts *options) *cobra.Command {
	var reason string
	c := &cobra.Command{
		Use:   "revoke ID --reason CODE",
		Short: "Revoke a virtual key; final",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("key id: %w", err)
			}
			client, err := opts.client()
			if err != nil {
				return err
			}
			res, err := client.RevokeVirtualKeyWithResponse(cmd.Context(), id, muistamov1.VirtualKeyRevocation{Reason: muistamov1.VirtualKeyRevocationReason(reason)})
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK {
				return problem(res.StatusCode(), res.Body)
			}
			cmd.Println(keyLine(*res.JSON200))
			return nil
		},
	}
	c.Flags().StringVar(&reason, "reason", "", "operator, compromised, rotation or leaver")
	_ = c.MarkFlagRequired("reason")
	return c
}
