// Command mst is the Muistamo CLI.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"muistamo.dev/muistamo/cli/internal/diff"
	"muistamo.dev/muistamo/cli/internal/manifest"
	"muistamo.dev/muistamo/cli/internal/version"
	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

type options struct {
	server, knowledgeServer, tenant, actor string
}

func main() {
	opts := &options{}
	root := &cobra.Command{Use: "mst", Short: "Muistamo CLI", SilenceUsage: true, SilenceErrors: true}
	// cobra's Print helpers default to stderr; command output belongs on stdout.
	root.SetOut(os.Stdout)
	flags := root.PersistentFlags()
	flags.StringVar(&opts.server, "server", envOr("MST_SERVER", "http://127.0.0.1:8080"), "control-plane URL (MST_SERVER)")
	flags.StringVar(&opts.knowledgeServer, "knowledge-server", envOr("MST_KNOWLEDGE_SERVER", "http://127.0.0.1:8001"), "knowledge service URL (MST_KNOWLEDGE_SERVER)")
	flags.StringVar(&opts.tenant, "tenant", os.Getenv("MST_TENANT"), "tenant id, development only (MST_TENANT)")
	flags.StringVar(&opts.actor, "actor", envOr("MST_ACTOR", os.Getenv("USER")), "acting person, development only (MST_ACTOR)")

	root.AddCommand(
		&cobra.Command{
			Use:   "version",
			Short: "Print the mst version",
			Run:   func(cmd *cobra.Command, _ []string) { cmd.Println(version.String()) },
		},
		applyCmd(opts), diffCmd(opts), getCmd(opts), evidenceCmd(opts), knowledgeCmd(opts), catalogueCmd(opts),
	)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "mst:", err)
		os.Exit(1)
	}
}

func applyCmd(opts *options) *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "apply -f FILE",
		Short: "Validate manifests locally, then apply them",
		RunE: func(cmd *cobra.Command, _ []string) error {
			docs, err := readManifests(file)
			if err != nil {
				return err
			}
			client, err := opts.client()
			if err != nil {
				return err
			}
			for _, doc := range docs {
				if isKnowledgeKind(doc.Kind) {
					if err := applyKnowledge(cmd, opts, doc); err != nil {
						return err
					}
					continue
				}
				if err := apply(cmd, client, doc); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "manifest file (- for stdin)")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func diffCmd(opts *options) *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "diff -f FILE",
		Short: "Show field-level changes against what the server holds",
		RunE: func(cmd *cobra.Command, _ []string) error {
			docs, err := readManifests(file)
			if err != nil {
				return err
			}
			client, err := opts.client()
			if err != nil {
				return err
			}
			for _, doc := range docs {
				var current []byte
				if isKnowledgeKind(doc.Kind) {
					current, err = fetchKnowledge(cmd.Context(), opts, doc)
				} else {
					current, _, err = fetch(cmd.Context(), client, doc)
				}
				if err != nil {
					return err
				}
				if current == nil {
					cmd.Printf("%s/%s: new\n", doc.Kind, doc.Name)
					continue
				}
				local, err := withServerState(doc, current)
				if err != nil {
					return err
				}
				changes, err := diff.JSON(current, local)
				if err != nil {
					return err
				}
				if len(changes) == 0 {
					cmd.Printf("%s/%s: unchanged\n", doc.Kind, doc.Name)
					continue
				}
				cmd.Printf("%s/%s:\n", doc.Kind, doc.Name)
				for _, c := range changes {
					cmd.Printf("  %s\n", c)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "manifest file (- for stdin)")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func getCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:       "get templates|instances [NAME]",
		Short:     "Print templates or instances as JSON",
		Args:      cobra.RangeArgs(1, 2),
		ValidArgs: []string{"templates", "instances"},
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			var res interface {
				StatusCode() int
			}
			var body []byte
			switch {
			case args[0] == "templates" && len(args) == 1:
				r, err := client.ListTemplatesWithResponse(ctx, &muistamov1.ListTemplatesParams{})
				if err != nil {
					return err
				}
				res, body = r, r.Body
			case args[0] == "templates":
				r, err := client.GetTemplateWithResponse(ctx, args[1])
				if err != nil {
					return err
				}
				res, body = r, r.Body
			case args[0] == "instances" && len(args) == 1:
				r, err := client.ListInstancesWithResponse(ctx, &muistamov1.ListInstancesParams{})
				if err != nil {
					return err
				}
				res, body = r, r.Body
			case args[0] == "instances":
				r, err := client.GetInstanceWithResponse(ctx, args[1])
				if err != nil {
					return err
				}
				res, body = r, r.Body
			default:
				return fmt.Errorf("unknown resource %q: use templates or instances", args[0])
			}
			if res.StatusCode() != http.StatusOK {
				return problem(res.StatusCode(), body)
			}
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, body, "", "  "); err != nil {
				return fmt.Errorf("format response: %w", err)
			}
			cmd.Println(pretty.String())
			return nil
		},
	}
}

func apply(cmd *cobra.Command, client *muistamov1.ClientWithResponses, doc manifest.Document) error {
	ctx := cmd.Context()
	switch doc.Kind {
	case "AgentTemplate":
		res, err := client.ApplyTemplateWithBodyWithResponse(ctx, doc.Name, "application/json", bytes.NewReader(doc.JSON))
		if err != nil {
			return fmt.Errorf("apply %s/%s: %w", doc.Kind, doc.Name, err)
		}
		switch res.StatusCode() {
		case http.StatusCreated:
			cmd.Printf("%s/%s: created version %d\n", doc.Kind, doc.Name, res.JSON201.Version)
		case http.StatusOK:
			cmd.Printf("%s/%s: unchanged (version %d)\n", doc.Kind, doc.Name, res.JSON200.Version)
		default:
			return problem(res.StatusCode(), res.Body)
		}
	case "AgentInstance":
		current, etag, err := fetch(ctx, client, doc)
		if err != nil {
			return err
		}
		body, params := doc.JSON, &muistamov1.ApplyInstanceParams{}
		if current != nil {
			if body, err = withServerState(doc, current); err != nil {
				return err
			}
			params.IfMatch = &etag
		}
		res, err := client.ApplyInstanceWithBodyWithResponse(ctx, doc.Name, params, "application/json", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("apply %s/%s: %w", doc.Kind, doc.Name, err)
		}
		switch res.StatusCode() {
		case http.StatusCreated:
			cmd.Printf("%s/%s: created (state requested)\n", doc.Kind, doc.Name)
		case http.StatusOK:
			cmd.Printf("%s/%s: applied (revision %d; state is changed only by transitions)\n", doc.Kind, doc.Name, res.JSON200.Revision)
		default:
			return problem(res.StatusCode(), res.Body)
		}
	default:
		return fmt.Errorf("%s/%s: the control plane does not serve %s yet", doc.Kind, doc.Name, doc.Kind)
	}
	return nil
}

// fetch returns the document the server holds (nil if none) and, for instances, its ETag.
func fetch(ctx context.Context, client *muistamov1.ClientWithResponses, doc manifest.Document) ([]byte, string, error) {
	switch doc.Kind {
	case "AgentTemplate":
		res, err := client.GetTemplateWithResponse(ctx, doc.Name)
		if err != nil {
			return nil, "", fmt.Errorf("get %s/%s: %w", doc.Kind, doc.Name, err)
		}
		if res.StatusCode() == http.StatusNotFound {
			return nil, "", nil
		}
		if res.StatusCode() != http.StatusOK {
			return nil, "", problem(res.StatusCode(), res.Body)
		}
		current, err := json.Marshal(res.JSON200.Document)
		return current, "", err
	case "AgentInstance":
		res, err := client.GetInstanceWithResponse(ctx, doc.Name)
		if err != nil {
			return nil, "", fmt.Errorf("get %s/%s: %w", doc.Kind, doc.Name, err)
		}
		if res.StatusCode() == http.StatusNotFound {
			return nil, "", nil
		}
		if res.StatusCode() != http.StatusOK {
			return nil, "", problem(res.StatusCode(), res.Body)
		}
		current, err := json.Marshal(res.JSON200.Document)
		return current, res.HTTPResponse.Header.Get("ETag"), err
	default:
		return nil, "", fmt.Errorf("%s/%s: the control plane does not serve %s yet", doc.Kind, doc.Name, doc.Kind)
	}
}

// withServerState replaces an instance manifest's spec.state with the server's, because state
// changes only through transitions. Other kinds are returned unchanged.
func withServerState(doc manifest.Document, current []byte) ([]byte, error) {
	if doc.Kind != "AgentInstance" {
		return doc.JSON, nil
	}
	var local, server map[string]any
	if err := json.Unmarshal(doc.JSON, &local); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(current, &server); err != nil {
		return nil, err
	}
	localSpec, _ := local["spec"].(map[string]any)
	serverSpec, _ := server["spec"].(map[string]any)
	if localSpec != nil && serverSpec != nil {
		localSpec["state"] = serverSpec["state"]
	}
	return json.Marshal(local)
}

func readManifests(file string) ([]manifest.Document, error) {
	var src []byte
	var err error
	if file == "-" {
		src, err = io.ReadAll(os.Stdin)
	} else {
		src, err = os.ReadFile(file)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", file, err)
	}
	return manifest.Read(src)
}

func (o *options) client() (*muistamov1.ClientWithResponses, error) {
	if o.tenant == "" {
		return nil, errors.New("no tenant: pass --tenant or set MST_TENANT")
	}
	if o.actor == "" {
		return nil, errors.New("no actor: pass --actor or set MST_ACTOR")
	}
	return muistamov1.NewClientWithResponses(o.server, muistamov1.WithRequestEditorFn(
		func(_ context.Context, req *http.Request) error {
			req.Header.Set("X-Muistamo-Tenant", o.tenant)
			req.Header.Set("X-Muistamo-Actor", o.actor)
			return nil
		}))
}

func problem(status int, body []byte) error {
	var p muistamov1.Problem
	if err := json.Unmarshal(body, &p); err != nil || p.Title == "" {
		return fmt.Errorf("server returned %d", status)
	}
	if p.Detail != nil {
		return fmt.Errorf("%d %s: %s", status, p.Title, *p.Detail)
	}
	return fmt.Errorf("%d %s", status, p.Title)
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
