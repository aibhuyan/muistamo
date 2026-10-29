package main

import (
	"fmt"
	"math/big"
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
	cmd.AddCommand(keys, usageCmd(opts))
	return cmd
}

func usageCmd(opts *options) *cobra.Command {
	var instance, from, to string
	var unmetered bool
	c := &cobra.Command{
		Use:   "usage [--instance NAME] [--from RFC3339] [--to RFC3339] [--unmetered]",
		Short: "Authorized gateway calls at provider cost; administrators see all, others their own",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			params := &muistamov1.ListUsageParams{}
			if instance != "" {
				params.Instance = &instance
			}
			for flag, dst := range map[string]**time.Time{from: &params.From, to: &params.To} {
				if flag == "" {
					continue
				}
				at, err := time.Parse(time.RFC3339, flag)
				if err != nil {
					return fmt.Errorf("time %q: %w", flag, err)
				}
				*dst = &at
			}
			if unmetered {
				params.Unmetered = &unmetered
			}
			client, err := opts.client()
			if err != nil {
				return err
			}
			totals := map[muistamov1.MoneyCurrency]*big.Rat{}
			calls, notMetered := 0, 0
			for {
				res, err := client.ListUsageWithResponse(cmd.Context(), params)
				if err != nil {
					return err
				}
				if res.StatusCode() != http.StatusOK {
					return problem(res.StatusCode(), res.Body)
				}
				for _, r := range res.JSON200.Items {
					calls++
					cmd.Println(usageLine(r))
					if r.Metered != nil && !*r.Metered {
						notMetered++
					}
					if r.Cost != nil {
						amount, ok := new(big.Rat).SetString(r.Cost.Amount)
						if !ok {
							return fmt.Errorf("cost %q of %s is not a decimal", r.Cost.Amount, r.RequestId)
						}
						if totals[r.Cost.Currency] == nil {
							totals[r.Cost.Currency] = new(big.Rat)
						}
						totals[r.Cost.Currency].Add(totals[r.Cost.Currency], amount)
					}
				}
				if res.JSON200.Next == nil {
					break
				}
				next := muistamov1.Cursor(*res.JSON200.Next)
				params.Cursor = &next
			}
			// Totals at provider prices, exactly; unmetered calls are counted, never estimated.
			for currency, total := range totals {
				cmd.Println(fmt.Sprintf("total %s %s at provider cost", strings.TrimRight(strings.TrimRight(total.FloatString(12), "0"), "."), currency))
			}
			cmd.Println(fmt.Sprintf("%d calls, %d unmetered", calls, notMetered))
			return nil
		},
	}
	c.Flags().StringVar(&instance, "instance", "", "only this instance's calls")
	c.Flags().StringVar(&from, "from", "", "calls authorized at or after this time (RFC 3339)")
	c.Flags().StringVar(&to, "to", "", "calls authorized before this time (RFC 3339)")
	c.Flags().BoolVar(&unmetered, "unmetered", false, "only model calls with no usage 15 minutes after authorization")
	return c
}

func usageLine(r muistamov1.UsageRecord) string {
	cost := "unmetered"
	switch {
	case r.Metered == nil:
		cost = "no tokens (" + string(r.Kind) + ")"
	case *r.Metered && r.Cost != nil:
		cost = fmt.Sprintf("%s %s (in %d, cached %d, out %d)", r.Cost.Amount, r.Cost.Currency, *r.InputTokens, *r.CachedInputTokens, *r.OutputTokens)
	}
	return strings.Join([]string{r.AuthorizedAt.UTC().Format(time.RFC3339), r.RequestId.String(), r.Instance, r.Person, cost}, "\t")
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
