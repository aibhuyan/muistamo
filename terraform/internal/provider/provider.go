// Package provider is the Muistamo Terraform/OpenTofu provider (FR-902).
//
// Every resource takes its spec as JSON (`spec = jsonencode({...})`) and validates it against
// contracts/ at plan time, so the provider never duplicates a type that the API already defines.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = (*muistamo)(nil)

type muistamo struct{ version string }

// New returns the provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &muistamo{version: version} }
}

type config struct {
	ControlPlaneURL types.String `tfsdk:"control_plane_url"`
	KnowledgeURL    types.String `tfsdk:"knowledge_url"`
	Tenant          types.String `tfsdk:"tenant"`
	Actor           types.String `tfsdk:"actor"`
}

func (p *muistamo) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "muistamo"
	resp.Version = p.version
}

func (p *muistamo) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage Muistamo templates, knowledge packs and sources as code. " +
			"INSECURE DEVELOPMENT AUTHENTICATION: tenant and actor are sent as development headers that the " +
			"services accept only when explicitly enabled; real authentication replaces them.",
		Attributes: map[string]schema.Attribute{
			"control_plane_url": schema.StringAttribute{Optional: true, Description: "Control-plane URL (MUISTAMO_CONTROL_PLANE_URL)."},
			"knowledge_url":     schema.StringAttribute{Optional: true, Description: "Knowledge service URL (MUISTAMO_KNOWLEDGE_URL)."},
			"tenant":            schema.StringAttribute{Optional: true, Description: "Tenant id (MUISTAMO_TENANT). Development only."},
			"actor":             schema.StringAttribute{Optional: true, Description: "Acting person (MUISTAMO_ACTOR). Development only."},
		},
	}
}

func (p *muistamo) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg config
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	pick := func(v types.String, env string) string {
		if !v.IsNull() && !v.IsUnknown() && v.ValueString() != "" {
			return v.ValueString()
		}
		return os.Getenv(env)
	}
	c := newClient(
		pick(cfg.ControlPlaneURL, "MUISTAMO_CONTROL_PLANE_URL"),
		pick(cfg.KnowledgeURL, "MUISTAMO_KNOWLEDGE_URL"),
		pick(cfg.Tenant, "MUISTAMO_TENANT"),
		pick(cfg.Actor, "MUISTAMO_ACTOR"),
	)
	if c.tenant == "" || c.actor == "" {
		resp.Diagnostics.AddError("Missing identity", "Set tenant and actor (or MUISTAMO_TENANT and MUISTAMO_ACTOR).")
		return
	}
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *muistamo) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		func() resource.Resource { return newDocumentResource(templateKind, "agent_template", templateDocs) },
		func() resource.Resource { return newDocumentResource(packKind, "knowledge_pack", packDocs) },
		func() resource.Resource { return newDocumentResource(sourceKind, "knowledge_source", sourceDocs) },
		func() resource.Resource { return newDocumentResource(cloneKind, "agent_clone", cloneDocs) },
		func() resource.Resource { return newDocumentResource(linkKind, "agent_link", linkDocs) },
		func() resource.Resource {
			return newDocumentResource(actionPolicyKind, "action_policy", actionPolicyDocs)
		},
	}
}

func (p *muistamo) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newCatalogueDataSource}
}

const (
	templateDocs = "An agent template. Each change to spec creates a new immutable version (version). " +
		"Destroy only removes it from state: template versions are retained; use mst catalogue withdraw to stop assignment."
	packDocs = "A knowledge pack definition. Content changes only through reviewed proposals; version is the latest published content version. " +
		"Destroy only removes it from state: pack history is retained."
	sourceDocs = "A knowledge source attached to a pack. Destroy only removes it from state."
	cloneDocs  = "A clone of a template: an overlay of knowledge packs, budget and HR assignment, with a sync policy. version is the revision. " +
		"Destroy only removes it from state: its instances depend on it."
	linkDocs = "A one-way agent link: agents of spec.from.template may call agents of spec.to.template with the listed skills and data classes. " +
		"version is the revision. Destroy deletes the link, so the calls it allowed are denied again; its history stays in the evidence log."
	actionPolicyDocs = "The action policy for one template (at most one per template). version is the revision. " +
		"Destroy deletes the policy, so the template's actions are denied by default again; its history stays in the evidence log."
)
