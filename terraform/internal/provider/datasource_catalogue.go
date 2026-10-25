package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type catalogueDataSource struct{ client *client }

var _ datasource.DataSourceWithConfigure = (*catalogueDataSource)(nil)

func newCatalogueDataSource() datasource.DataSource { return &catalogueDataSource{} }

type catalogueModel struct {
	Templates []catalogueEntryModel `tfsdk:"templates"`
}

type catalogueEntryModel struct {
	Name    types.String `tfsdk:"name"`
	Version types.Int64  `tfsdk:"version"`
}

func (d *catalogueDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_catalogue"
}

func (d *catalogueDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Template versions published to the catalogue, and so assignable to joiners.",
		Attributes: map[string]schema.Attribute{
			"templates": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name":    schema.StringAttribute{Computed: true},
					"version": schema.Int64Attribute{Computed: true},
				}},
			},
		},
	}
}

func (d *catalogueDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	d.client = c
}

func (d *catalogueDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	status, body, err := d.client.do(ctx, http.MethodGet, d.client.controlPlane, "/v1/catalogue", nil)
	if err == nil && status != http.StatusOK {
		err = apiError(status, body)
	}
	if err != nil {
		resp.Diagnostics.AddError("Read catalogue", err.Error())
		return
	}
	var page struct {
		Items []struct {
			Template string `json:"template"`
			Version  int64  `json:"version"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		resp.Diagnostics.AddError("Read catalogue", err.Error())
		return
	}
	m := catalogueModel{Templates: []catalogueEntryModel{}}
	for _, e := range page.Items {
		m.Templates = append(m.Templates, catalogueEntryModel{Name: types.StringValue(e.Template), Version: types.Int64Value(e.Version)})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
