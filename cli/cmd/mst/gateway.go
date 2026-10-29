package main

import (
	"fmt"
	"math/big"
	"net/http"
	"slices"
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
			for _, f := range []struct {
				value string
				dst   **time.Time
			}{{from, &params.From}, {to, &params.To}} {
				if f.value == "" {
					continue
				}
				at, err := time.Parse(time.RFC3339, f.value)
				if err != nil {
					return fmt.Errorf("time %q: %w", f.value, err)
				}
				*f.dst = &at
			}
			if unmetered {
				params.Unmetered = &unmetered
			}
			client, err := opts.client()
			if err != nil {
				return err
			}
			totals := map[muistamov1.MoneyCurrency]*big.Rat{}
			calls, notMetered, withoutUsage := 0, 0, 0
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
					cmd.Println(usageLine(r, time.Now()))
					switch {
					case r.FailedStatus != nil:
					case r.UsageMissing != nil && *r.UsageMissing:
						withoutUsage++
					case r.Metered != nil && !*r.Metered && !pending(r, time.Now()):
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
			currencies := make([]string, 0, len(totals))
			for currency := range totals {
				currencies = append(currencies, string(currency))
			}
			slices.Sort(currencies)
			for _, currency := range currencies {
				total := totals[muistamov1.MoneyCurrency(currency)]
				cmd.Println(fmt.Sprintf("total %s %s at provider cost", strings.TrimRight(strings.TrimRight(total.FloatString(12), "0"), "."), currency))
			}
			cmd.Println(fmt.Sprintf("%d calls, %d unmetered, %d ran without a usage report", calls, notMetered, withoutUsage))
			return nil
		},
	}
	c.Flags().StringVar(&instance, "instance", "", "only this instance's calls")
	c.Flags().StringVar(&from, "from", "", "calls authorized at or after this time (RFC 3339)")
	c.Flags().StringVar(&to, "to", "", "calls authorized before this time (RFC 3339)")
	c.Flags().BoolVar(&unmetered, "unmetered", false, "only model calls with no usage 15 minutes after authorization")
	return c
}

// unmeteredAfter matches the server's threshold: until then a call without usage is pending.
const unmeteredAfter = 15 * time.Minute

func pending(r muistamov1.UsageRecord, now time.Time) bool {
	return now.Sub(r.AuthorizedAt) < unmeteredAfter
}

func usageLine(r muistamov1.UsageRecord, now time.Time) string {
	cost := "unmetered: cost unknown, may have been incurred"
	switch {
	case r.FailedStatus != nil:
		cost = fmt.Sprintf("failed (HTTP %d): no cost", *r.FailedStatus)
	case r.Metered != nil && !*r.Metered && r.UsageMissing != nil && *r.UsageMissing:
		cost = "ran, no usage reported: cost unknown, likely incurred"
	case r.Metered != nil && !*r.Metered && pending(r, now):
		cost = "pending: usage not yet received"
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
	return fmt.Sprintf("%s\t%s\t%s\taliases %s\tbudget %s %s/month\tover %d without usage in 24h refuses, %d/min, %d in flight\texpires %s",
		k.Id, k.Instance, k.Status, strings.Join(k.Aliases, ","), k.MonthlyBudget.Amount, k.MonthlyBudget.Currency, k.MaxCallsWithoutUsage, k.MaxRequestsPerMinute, k.MaxCallsInFlight, expires)
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
	maxWithoutUsage, perMinute, inFlight := -1, -1, -1
	c := &cobra.Command{
		Use:   "issue --instance NAME --alias ALIAS --budget EUR [--expires RFC3339] [--max-calls-without-usage N]",
		Short: "Issue a virtual key; its secret is printed once and can never be shown again",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			req := muistamov1.VirtualKeyRequest{
				Instance:      instance,
				Aliases:       []string{alias},
				MonthlyBudget: muistamov1.Money{Amount: budget, Currency: muistamov1.MoneyCurrencyEUR},
			}
			switch {
			case maxWithoutUsage >= 0:
				req.MaxCallsWithoutUsage = &maxWithoutUsage
			case maxWithoutUsage != -1:
				return fmt.Errorf("--max-calls-without-usage must be 0 or more")
			}
			for _, f := range []struct {
				name  string
				value int
				dst   **int
			}{{"--max-requests-per-minute", perMinute, &req.MaxRequestsPerMinute}, {"--max-calls-in-flight", inFlight, &req.MaxCallsInFlight}} {
				switch {
				case f.value >= 1:
					v := f.value
					*f.dst = &v
				case f.value != -1:
					return fmt.Errorf("%s must be 1 or more", f.name)
				}
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
	c.Flags().IntVar(&maxWithoutUsage, "max-calls-without-usage", -1, "calls within 24 hours that may run without a usage report, e.g. aborted calls (default 10; 0 refuses after the first)")
	c.Flags().IntVar(&perMinute, "max-requests-per-minute", -1, "calls within any rolling minute (default 60)")
	c.Flags().IntVar(&inFlight, "max-calls-in-flight", -1, "model calls in flight at once (default 4)")
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
