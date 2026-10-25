package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// requestFlags builds a PolicyDecisionRequest from command-line flags.
type requestFlags struct {
	from, to, skill, actFor, agent, action string
	dataClasses, attributes                []string
	depth                                  int
}

func (f *requestFlags) register(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&f.from, "from", "", "call: the calling template")
	fl.StringVar(&f.to, "to", "", "call: the called template")
	fl.StringVar(&f.skill, "skill", "", "call: the skill used")
	fl.StringSliceVar(&f.dataClasses, "data-class", nil, "call: a data class the call carries (repeatable)")
	fl.IntVar(&f.depth, "depth", 0, "call: position in the delegation chain (default 1)")
	fl.StringVar(&f.actFor, "act-for", "", "call: same-user (default) or service")
	fl.StringVar(&f.agent, "agent", "", "action: the template taking the action")
	fl.StringVar(&f.action, "action", "", "action: the tool action, for example email.send")
	fl.StringSliceVar(&f.attributes, "attr", nil, "action: NAME=true|false, a fact rules can test (repeatable)")
}

func (f *requestFlags) request(kind string) (muistamov1.PolicyDecisionRequest, error) {
	req := muistamov1.PolicyDecisionRequest{Kind: muistamov1.PolicyDecisionRequestKind(kind)}
	set := func(dst **string, v string) {
		if v != "" {
			*dst = &v
		}
	}
	switch kind {
	case "call":
		set(&req.From, f.from)
		set(&req.To, f.to)
		set(&req.Skill, f.skill)
		if len(f.dataClasses) > 0 {
			req.DataClasses = &f.dataClasses
		}
		if f.depth != 0 {
			req.Depth = &f.depth
		}
		if f.actFor != "" {
			a := muistamov1.PolicyDecisionRequestActFor(f.actFor)
			req.ActFor = &a
		}
	case "action":
		set(&req.Agent, f.agent)
		set(&req.Action, f.action)
		if len(f.attributes) > 0 {
			attrs := map[string]bool{}
			for _, kv := range f.attributes {
				name, value, ok := strings.Cut(kv, "=")
				b, err := strconv.ParseBool(value)
				if !ok || err != nil {
					return req, fmt.Errorf("--attr %q: want NAME=true or NAME=false", kv)
				}
				attrs[name] = b
			}
			req.Attributes = &attrs
		}
	default:
		return req, fmt.Errorf("unknown request kind %q: use call or action", kind)
	}
	return req, nil
}

func policyCmd(opts *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Decide and simulate agent calls and tool actions (observe mode: nothing is enforced yet)",
	}

	var decideFlags requestFlags
	decide := &cobra.Command{
		Use:   "decide call|action [flags]",
		Short: "Ask whether a call or action is allowed; the decision is recorded as evidence",
		Example: "  mst policy decide call --from analyst-intern --to market-data-agent --skill get-quotes --data-class public\n" +
			"  mst policy decide action --agent analyst-intern --action email.send --attr recipients.allInternal=false",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"call", "action"},
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := decideFlags.request(args[0])
			if err != nil {
				return err
			}
			client, err := opts.client()
			if err != nil {
				return err
			}
			res, err := client.DecidePolicyWithResponse(cmd.Context(), req)
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK {
				return problem(res.StatusCode(), res.Body)
			}
			printDecision(cmd, "", *res.JSON200)
			return nil
		},
	}
	decideFlags.register(decide)

	var simFlags requestFlags
	var file string
	simulate := &cobra.Command{
		Use:   "simulate call|action -f PROPOSED.yaml [flags]",
		Short: "Decide a request under the current rules and under proposed AgentLink and ActionPolicy manifests; nothing is stored",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := simFlags.request(args[0])
			if err != nil {
				return err
			}
			docs, err := readManifests(file)
			if err != nil {
				return err
			}
			body := muistamov1.PolicySimulationRequest{Request: req}
			var links []muistamov1.AgentLink
			var policies []muistamov1.ActionPolicy
			for _, doc := range docs {
				switch doc.Kind {
				case "AgentLink":
					var l muistamov1.AgentLink
					if err := json.Unmarshal(doc.JSON, &l); err != nil {
						return err
					}
					links = append(links, l)
				case "ActionPolicy":
					var p muistamov1.ActionPolicy
					if err := json.Unmarshal(doc.JSON, &p); err != nil {
						return err
					}
					policies = append(policies, p)
				default:
					return fmt.Errorf("%s/%s: only AgentLink and ActionPolicy can be simulated", doc.Kind, doc.Name)
				}
			}
			if len(links) > 0 {
				body.Links = &links
			}
			if len(policies) > 0 {
				body.Policies = &policies
			}
			client, err := opts.client()
			if err != nil {
				return err
			}
			res, err := client.SimulatePolicyWithResponse(cmd.Context(), body)
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK {
				return problem(res.StatusCode(), res.Body)
			}
			printDecision(cmd, "current:  ", res.JSON200.Current)
			printDecision(cmd, "proposed: ", res.JSON200.Proposed)
			if res.JSON200.Changed {
				cmd.Println("the proposal changes this decision")
			} else {
				cmd.Println("the proposal does not change this decision")
			}
			return nil
		},
	}
	simFlags.register(simulate)
	simulate.Flags().StringVarP(&file, "file", "f", "", "proposed manifests (- for stdin)")
	_ = simulate.MarkFlagRequired("file")

	cedar := &cobra.Command{
		Use:   "cedar",
		Short: "Print the Cedar policy set the tenant's rules compile to",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}
			res, err := client.GetCompiledPoliciesWithResponse(cmd.Context())
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK {
				return problem(res.StatusCode(), res.Body)
			}
			if res.JSON200.Cedar == "" {
				cmd.Println("// no rules: every call and action is denied")
				return nil
			}
			cmd.Println(res.JSON200.Cedar)
			return nil
		},
	}

	del := &cobra.Command{
		Use:   "delete link|action-policy NAME",
		Short: "Remove a link or action policy; what it allowed is denied from then on",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}
			var status int
			var body []byte
			switch args[0] {
			case "link":
				res, err := client.DeleteLinkWithResponse(cmd.Context(), args[1])
				if err != nil {
					return err
				}
				status, body = res.StatusCode(), res.Body
			case "action-policy":
				res, err := client.DeleteActionPolicyWithResponse(cmd.Context(), args[1])
				if err != nil {
					return err
				}
				status, body = res.StatusCode(), res.Body
			default:
				return fmt.Errorf("unknown kind %q: use link or action-policy", args[0])
			}
			if status != http.StatusNoContent {
				return problem(status, body)
			}
			cmd.Printf("%s/%s: deleted\n", args[0], args[1])
			return nil
		},
	}

	cmd.AddCommand(decide, simulate, cedar, del)
	return cmd
}

func printDecision(cmd *cobra.Command, prefix string, d muistamov1.PolicyDecision) {
	block := "would not block"
	if d.WouldBlock {
		block = "would block"
	}
	cmd.Printf("%s%s (%s once enforced; not enforced yet): %s\n", prefix, strings.ToUpper(string(d.Decision)), block, d.Reason)
	if prefix == "" && len(d.NotEvaluated) > 0 {
		cmd.Printf("  not evaluated yet: %s\n", strings.Join(d.NotEvaluated, ", "))
	}
}
