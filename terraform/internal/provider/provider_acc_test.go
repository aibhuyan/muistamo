package provider_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"muistamo.dev/muistamo/contracts"
	"muistamo.dev/muistamo/control-plane/controlplanetest"
	"muistamo.dev/muistamo/terraform/internal/provider"
)

var factories = map[string]func() (tfprotov6.ProviderServer, error){
	"muistamo": providerserver.NewProtocol6WithError(provider.New("test")()),
}

// requireTofu fails (never skips) when the acceptance prerequisites are missing.
func requireTofu(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" || os.Getenv("TF_ACC_TERRAFORM_PATH") == "" {
		t.Fatal("acceptance tests need TF_ACC=1 and TF_ACC_TERRAFORM_PATH pointing at an OpenTofu binary (make test sets both)")
	}
}

func providerBlock(controlPlane, knowledge, tenant string) string {
	return fmt.Sprintf(`
provider "muistamo" {
  control_plane_url = %q
  knowledge_url     = %q
  tenant            = %q
  actor             = "terraform@example.invalid"
}
`, controlPlane, knowledge, tenant)
}

func templateConfig(prefix, purpose string) string {
	return prefix + fmt.Sprintf(`
resource "muistamo_agent_template" "intern" {
  name  = "analyst-intern"
  owner = "team-equity-research"
  spec = jsonencode({
    purpose    = %q
    modelAlias = "reasoning-default"
    riskTier   = "low"
    assignment = { hrJobCodes = ["ANALYST_INTERN"] }
  })
}
`, purpose)
}

func put(t *testing.T, url, tenant, body string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Muistamo-Tenant", tenant)
	req.Header.Set("X-Muistamo-Actor", "someone-else@example.invalid")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode >= 300 {
		t.Fatalf("out-of-band PUT = %d", res.StatusCode)
	}
}

func TestAccAgentTemplate(t *testing.T) {
	requireTofu(t)
	cp := controlplanetest.New(t)
	prefix := providerBlock(cp.URL, "", cp.Tenant.String())
	tenant := cp.Tenant.String()

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: templateConfig(prefix, "Support interns"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("muistamo_agent_template.intern", "version", "1"),
					resource.TestCheckResourceAttr("muistamo_agent_template.intern", "id", "analyst-intern"),
				),
			},
			// The server stores the spec in a different key order; semantic equality means no diff.
			{Config: templateConfig(prefix, "Support interns"), PlanOnly: true},
			{
				Config: templateConfig(prefix, "Support interns and new analysts"),
				Check:  resource.TestCheckResourceAttr("muistamo_agent_template.intern", "version", "2"),
			},
			// An out-of-band change (mst apply, say) shows up as drift on the next plan.
			{
				PreConfig: func() {
					put(t, cp.URL+"/v1/templates/analyst-intern", tenant,
						`{"apiVersion":"muistamo.dev/v1","kind":"AgentTemplate","metadata":{"name":"analyst-intern","owner":"team-equity-research"},`+
							`"spec":{"purpose":"Changed by hand","modelAlias":"reasoning-default","riskTier":"low","assignment":{"hrJobCodes":["ANALYST_INTERN"]}}}`)
				},
				Config:             templateConfig(prefix, "Support interns and new analysts"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			// Applying restores the declared spec as a new version.
			{
				Config: templateConfig(prefix, "Support interns and new analysts"),
				Check:  resource.TestCheckResourceAttr("muistamo_agent_template.intern", "version", "4"),
			},
			{ResourceName: "muistamo_agent_template.intern", ImportState: true, ImportStateVerify: true},
			{
				Config: prefix + `
resource "muistamo_agent_template" "bad" {
  name = "bad"
  spec = jsonencode({ purpose = "x", modelAlias = "m", surprise = true })
}`,
				ExpectError: regexp.MustCompile(`does not match the Muistamo contract`),
			},
			{
				Config: prefix + `
resource "muistamo_agent_template" "bad" {
  name = "bad"
  spec = jsonencode({ modelAlias = "m" })
}`,
				ExpectError: regexp.MustCompile(`does not match the Muistamo contract`),
			},
			// End on a valid configuration: the framework destroys with the last config.
			{Config: templateConfig(prefix, "Support interns and new analysts")},
		},
		// Destroy keeps the template: its versions are retained history.
		CheckDestroy: func(*terraform.State) error {
			res, err := http.DefaultClient.Do(mustRequest(cp.URL+"/v1/templates/analyst-intern", tenant))
			if err != nil {
				return err
			}
			_ = res.Body.Close()
			if res.StatusCode != http.StatusOK {
				return fmt.Errorf("template after destroy = %d, want it retained", res.StatusCode)
			}
			return nil
		},
	})
}

func TestAccCatalogueDataSource(t *testing.T) {
	requireTofu(t)
	cp := controlplanetest.New(t)
	prefix := providerBlock(cp.URL, "", cp.Tenant.String())
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{Config: templateConfig(prefix, "Support interns")},
			{
				PreConfig: func() {
					// Low risk publishes on request.
					req := mustRequest(cp.URL+"/v1/templates/analyst-intern/versions/1/publication", cp.Tenant.String())
					req.Method = http.MethodPost
					res, err := http.DefaultClient.Do(req)
					if err != nil || res.StatusCode != http.StatusCreated {
						t.Fatalf("publish: %v %v", err, res)
					}
					_ = res.Body.Close()
				},
				Config: templateConfig(prefix, "Support interns") + `data "muistamo_catalogue" "all" {}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.muistamo_catalogue.all", "templates.#", "1"),
					resource.TestCheckResourceAttr("data.muistamo_catalogue.all", "templates.0.name", "analyst-intern"),
					resource.TestCheckResourceAttr("data.muistamo_catalogue.all", "templates.0.version", "1"),
				),
			},
		},
	})
}

// fakeKnowledge stands in for the Python knowledge service: it validates every document against
// the contract and stores it, as the real service does.
type fakeKnowledge struct {
	mu   sync.Mutex
	docs map[string]json.RawMessage
}

func (f *fakeKnowledge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("X-Muistamo-Tenant") == "" || r.Header.Get("X-Muistamo-Actor") == "" {
		http.Error(w, `{"title":"Unauthorized","status":401}`, http.StatusUnauthorized)
		return
	}
	key := r.URL.Path
	switch r.Method {
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		if err := contracts.Validate(body); err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = fmt.Fprintf(w, `{"title":"Invalid","status":422,"detail":%q}`, err.Error())
			return
		}
		status := http.StatusCreated
		if _, ok := f.docs[key]; ok {
			status = http.StatusOK
		}
		f.docs[key] = reformat(body)
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"document":%s,"latestVersion":"0.0.0","documentCount":0}`, f.docs[key])
	case http.MethodGet:
		doc, ok := f.docs[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"title":"Not found","status":404}`))
			return
		}
		_, _ = fmt.Fprintf(w, `{"document":%s,"latestVersion":"0.0.0","documentCount":0}`, doc)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestAccKnowledgePackAndSource(t *testing.T) {
	requireTofu(t)
	fake := &fakeKnowledge{docs: map[string]json.RawMessage{}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	prefix := providerBlock("", srv.URL, "00000000-0000-0000-0000-000000000001")
	config := prefix + `
resource "muistamo_knowledge_pack" "basics" {
  name = "equity-research-basics"
  spec = jsonencode({ layer = "role", reviewers = ["dev:reviewer-b@example.invalid"], mergePolicy = { requires = ["review"] } })
}
resource "muistamo_knowledge_source" "finance" {
  name = "finance-site"
  spec = jsonencode({ pack = muistamo_knowledge_pack.basics.name, connector = "sharepoint", sharepoint = { siteUrl = "https://example.invalid/sites/finance" } })
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("muistamo_knowledge_pack.basics", "version", "0.0.0"),
					resource.TestCheckNoResourceAttr("muistamo_knowledge_source.finance", "version"),
				),
			},
			{Config: config, PlanOnly: true},
			{ResourceName: "muistamo_knowledge_pack.basics", ImportState: true, ImportStateVerify: true},
			{ResourceName: "muistamo_knowledge_source.finance", ImportState: true, ImportStateVerify: true},
			{
				Config: prefix + `
resource "muistamo_knowledge_pack" "bad" {
  name = "bad"
  spec = jsonencode({ layer = "personal", reviewers = ["x"] })
}`,
				ExpectError: regexp.MustCompile(`does not match the Muistamo contract`),
			},
			{Config: config},
		},
	})
}

// reformat stores a document the way the real service returns it: spaced, keys not sorted. The
// provider must not report that as a difference, including right after an import.
func reformat(body []byte) json.RawMessage {
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)
	keys := []string{"spec", "metadata", "kind", "apiVersion"}
	var b strings.Builder
	b.WriteString("{ ")
	for i, k := range keys {
		v, _ := json.MarshalIndent(doc[k], "", "  ")
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q: %s", k, v)
	}
	b.WriteString(" }")
	return json.RawMessage(b.String())
}

func mustRequest(url, tenant string) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Muistamo-Tenant", tenant)
	req.Header.Set("X-Muistamo-Actor", "terraform@example.invalid")
	return req
}
