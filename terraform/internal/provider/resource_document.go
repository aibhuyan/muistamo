package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"muistamo.dev/muistamo/contracts"
)

// documentResource manages one YAML kind: metadata.name, metadata.owner and spec. The spec is
// JSON, validated against contracts/ at plan time and compared semantically, so formatting and
// key order never show as a diff while real server-side changes do (drift detection).
type documentResource struct {
	kind     kind
	typeName string
	docs     string
	client   *client
}

var (
	_ resource.ResourceWithConfigure      = (*documentResource)(nil)
	_ resource.ResourceWithImportState    = (*documentResource)(nil)
	_ resource.ResourceWithValidateConfig = (*documentResource)(nil)
)

func newDocumentResource(k kind, typeName, docs string) resource.Resource {
	return &documentResource{kind: k, typeName: typeName, docs: docs}
}

type documentModel struct {
	ID      types.String         `tfsdk:"id"`
	Name    types.String         `tfsdk:"name"`
	Owner   types.String         `tfsdk:"owner"`
	Spec    jsontypes.Normalized `tfsdk:"spec"`
	Version types.String         `tfsdk:"version"`
}

func (r *documentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.typeName
}

func (r *documentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: r.docs,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name": schema.StringAttribute{
				Required:      true,
				Description:   "metadata.name. Changing it replaces the resource.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"owner": schema.StringAttribute{Optional: true, Description: "metadata.owner."},
			"spec": schema.StringAttribute{
				Required:    true,
				CustomType:  jsontypes.NormalizedType{},
				Description: "The " + r.kind.name + " spec as JSON (use jsonencode). Validated against the Muistamo contract.",
			},
			"version": schema.StringAttribute{Computed: true, Description: "Server-assigned version, where the kind has one."},
		},
	}
}

func (r *documentResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	r.client = c
}

// document builds the YAML-kind document the API expects.
func (r *documentResource) document(m documentModel) ([]byte, error) {
	var spec any
	if err := json.Unmarshal([]byte(m.Spec.ValueString()), &spec); err != nil {
		return nil, fmt.Errorf("spec is not valid JSON: %w", err)
	}
	meta := map[string]any{"name": m.Name.ValueString()}
	if !m.Owner.IsNull() && m.Owner.ValueString() != "" {
		meta["owner"] = m.Owner.ValueString()
	}
	return json.Marshal(map[string]any{"apiVersion": "muistamo.dev/v1", "kind": r.kind.name, "metadata": meta, "spec": spec})
}

func (r *documentResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m documentModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || m.Spec.IsUnknown() || m.Spec.IsNull() || m.Name.IsUnknown() || m.Owner.IsUnknown() {
		return // values not known until apply; the server validates again
	}
	doc, err := r.document(m)
	if err == nil {
		err = contracts.Validate(doc)
	}
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("spec"), "Spec does not match the Muistamo contract", err.Error())
	}
}

func (r *documentResource) write(ctx context.Context, m *documentModel) error {
	doc, err := r.document(*m)
	if err != nil {
		return err
	}
	body, err := r.client.put(ctx, r.kind, m.Name.ValueString(), doc)
	if err != nil {
		return err
	}
	m.ID = m.Name
	m.Version = optional(r.kind.version(body))
	return nil
}

func (r *documentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m documentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.write(ctx, &m); err != nil {
		resp.Diagnostics.AddError("Create "+r.kind.name, err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *documentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m documentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.write(ctx, &m); err != nil {
		resp.Diagnostics.AddError("Update "+r.kind.name, err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// Read refreshes state from the server, which is how out-of-band changes surface as drift.
func (r *documentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m documentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := m.Name.ValueString()
	if name == "" {
		name = m.ID.ValueString()
	}
	body, err := r.client.get(ctx, r.kind, name)
	if errors.Is(err, errNotFound) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Read "+r.kind.name, err.Error())
		return
	}
	raw, err := r.kind.document(body)
	if err != nil {
		resp.Diagnostics.AddError("Read "+r.kind.name, err.Error())
		return
	}
	var doc struct {
		Metadata struct {
			Name  string  `json:"name"`
			Owner *string `json:"owner"`
		} `json:"metadata"`
		Spec json.RawMessage `json:"spec"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		resp.Diagnostics.AddError("Read "+r.kind.name, err.Error())
		return
	}
	m.ID = types.StringValue(doc.Metadata.Name)
	m.Name = types.StringValue(doc.Metadata.Name)
	if doc.Metadata.Owner != nil {
		m.Owner = types.StringValue(*doc.Metadata.Owner)
	} else {
		m.Owner = types.StringNull()
	}
	spec, err := canonicalJSON(doc.Spec)
	if err != nil {
		resp.Diagnostics.AddError("Read "+r.kind.name, err.Error())
		return
	}
	m.Spec = jsontypes.NewNormalizedValue(spec)
	m.Version = optional(r.kind.version(body))
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// Delete removes links and action policies, because keeping them would keep granting what they
// allow. Other kinds are history the product keeps, so Delete only forgets them, and says so.
func (r *documentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m documentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.kind.deletable {
		if err := r.client.delete(ctx, r.kind, m.Name.ValueString()); err != nil {
			resp.Diagnostics.AddError("Delete "+r.kind.name, err.Error())
		}
		return
	}
	detail := fmt.Sprintf("%s %q was removed from Terraform state but still exists in Muistamo: its history is retained.",
		r.kind.name, m.Name.ValueString())
	if r.kind.name == "AgentTemplate" {
		detail += " To stop new joiners receiving it, run: mst catalogue withdraw " + m.Name.ValueString()
	}
	resp.Diagnostics.AddWarning(r.kind.name+" not deleted", detail)
}

func (r *documentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}

// canonicalJSON re-encodes JSON the way jsonencode does (compact, keys sorted), so a value read
// from the server matches the configuration textually even when no prior state exists to compare
// semantically against, as after an import.
func canonicalJSON(raw json.RawMessage) (string, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("server returned invalid JSON: %w", err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func optional(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}
