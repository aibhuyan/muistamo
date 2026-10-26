package provider_test

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/controlplanetest"
)

func catalogueClient(t *testing.T, cp controlplanetest.Server, actor string) *muistamov1.ClientWithResponses {
	t.Helper()
	client, err := muistamov1.NewClientWithResponses(cp.URL, muistamov1.WithRequestEditorFn(
		func(_ context.Context, req *http.Request) error {
			req.Header.Set("X-Muistamo-Tenant", cp.Tenant.String())
			req.Header.Set("X-Muistamo-Actor", actor)
			return nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func catalogueModelConfig(prefix, region string) string {
	return prefix + fmt.Sprintf(`
resource "muistamo_model" "test" {
  name = "catalogue-model"
  owner = "platform-team"
  spec = jsonencode({
    provider = "test-provider"
    model = "test-model"
    region = %q
    termsRef = "legal/test-terms"
    priceSheet = { currency = "EUR", inputPerMTok = 1, outputPerMTok = 2 }
  })
}
`, region)
}

func bindingConfig(prefix, target, description string) string {
	return prefix + fmt.Sprintf(`
resource "muistamo_model_binding" "role" {
  name = "role-reasoning"
  spec = jsonencode({ target = %q, description = %q })
}
`, target, description)
}

func TestAccModelCatalogue(t *testing.T) {
	requireTofu(t)
	cp := controlplanetest.New(t)
	cp.SetPrivacyOfficers(t, "dev:privacy@example.invalid")
	client := catalogueClient(t, cp, "terraform@example.invalid")
	officer := catalogueClient(t, cp, "privacy@example.invalid")
	prefix := providerBlock(cp.URL, "", cp.Tenant.String())
	approval := func(want muistamov1.ModelApprovalStatus) resource.TestCheckFunc {
		return func(*terraform.State) error {
			got, err := client.GetModelWithResponse(context.Background(), "catalogue-model")
			if err != nil {
				return err
			}
			if got.JSON200 == nil {
				return fmt.Errorf("model read = %d", got.StatusCode())
			}
			if got.JSON200.Approval.Status != want {
				return fmt.Errorf("approval = %s, want %s", got.JSON200.Approval.Status, want)
			}
			return nil
		}
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: catalogueModelConfig(prefix, "eu-test-1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("muistamo_model.test", "id", "catalogue-model"),
					resource.TestCheckResourceAttr("muistamo_model.test", "version", "1"),
					approval(muistamov1.ModelApprovalStatusPending)),
			},
			{
				PreConfig: func() {
					got, err := officer.DecideModelWithResponse(context.Background(), "catalogue-model",
						muistamov1.ModelApprovalDecision{Decision: muistamov1.ModelApprovalDecisionDecisionApprove, Reason: "independently reviewed"})
					if err != nil || got.JSON200 == nil {
						t.Fatalf("approve model: %v %v", err, got)
					}
				},
				Config: catalogueModelConfig(prefix, "eu-test-1"),
				Check:  approval(muistamov1.ModelApprovalStatusApproved),
			},
			{
				Config: catalogueModelConfig(prefix, "eu-test-2"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("muistamo_model.test", "version", "2"),
					approval(muistamov1.ModelApprovalStatusPending)),
			},
			{ResourceName: "muistamo_model.test", ImportState: true, ImportStateVerify: true},
			{
				PreConfig: func() {
					got, err := client.GetModelWithResponse(context.Background(), "catalogue-model")
					if err != nil || got.JSON200 == nil {
						t.Fatalf("read model: %v %v", err, got)
					}
					doc := got.JSON200.Document
					doc.Spec.Region = "changed-by-hand"
					updated, err := client.ApplyModelWithResponse(context.Background(), "catalogue-model", doc)
					if err != nil || updated.JSON200 == nil {
						t.Fatalf("manual change: %v %v", err, updated)
					}
				},
				Config:   catalogueModelConfig(prefix, "eu-test-2"),
				PlanOnly: true, ExpectNonEmptyPlan: true,
			},
			{
				Config: catalogueModelConfig(prefix, "eu-test-2"),
				Check:  resource.TestCheckResourceAttr("muistamo_model.test", "version", "4"),
			},
			{
				Config: prefix + `
resource "muistamo_model" "bad" {
  name = "invalid-model"
  spec = jsonencode({ provider = "test-provider", model = "test-model", region = "eu-test-1" })
}
`,
				ExpectError: regexp.MustCompile("does not match the Muistamo contract"),
			},
			{Config: catalogueModelConfig(prefix, "eu-test-2")},
		},
		CheckDestroy: approval(muistamov1.ModelApprovalStatusPending),
	})
}

func TestAccModelBinding(t *testing.T) {
	requireTofu(t)
	cp := controlplanetest.New(t)
	client := catalogueClient(t, cp, "terraform@example.invalid")
	existing, err := client.GetModelAliasWithResponse(context.Background(), "reasoning-default")
	if err != nil || existing.JSON200 == nil {
		t.Fatalf("seed alias: %v %v", err, existing)
	}
	target := existing.JSON200.Document.Spec.Target
	prefix := providerBlock(cp.URL, "", cp.Tenant.String())
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: bindingConfig(prefix, target, "initial"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("muistamo_model_binding.role", "id", "role-reasoning"),
					resource.TestCheckResourceAttr("muistamo_model_binding.role", "version", "1")),
			},
			{Config: bindingConfig(prefix, target, "initial"), PlanOnly: true},
			{
				Config: bindingConfig(prefix, target, "updated"),
				Check:  resource.TestCheckResourceAttr("muistamo_model_binding.role", "version", "2"),
			},
			{ResourceName: "muistamo_model_binding.role", ImportState: true, ImportStateVerify: true},
			{
				PreConfig: func() {
					got, err := client.GetModelAliasWithResponse(context.Background(), "role-reasoning")
					if err != nil || got.JSON200 == nil {
						t.Fatalf("read alias: %v %v", err, got)
					}
					doc := got.JSON200.Document
					description := "changed by hand"
					doc.Spec.Description = &description
					updated, err := client.ApplyModelAliasWithResponse(context.Background(), "role-reasoning", doc)
					if err != nil || updated.JSON200 == nil {
						t.Fatalf("manual alias change: %v %v", err, updated)
					}
				},
				Config: bindingConfig(prefix, target, "updated"), PlanOnly: true, ExpectNonEmptyPlan: true,
			},
			{
				Config: bindingConfig(prefix, target, "updated"),
				Check:  resource.TestCheckResourceAttr("muistamo_model_binding.role", "version", "4"),
			},
			{
				Config:      bindingConfig(prefix, "another-model", "updated"),
				ExpectError: regexp.MustCompile(`(?s)switch\s+it\s+with\s+a\s+rollout`),
			},
			{Config: bindingConfig(prefix, target, "updated")},
		},
		CheckDestroy: func(*terraform.State) error {
			got, err := client.GetModelAliasWithResponse(context.Background(), "role-reasoning")
			if err != nil {
				return err
			}
			if got.JSON200 == nil || got.JSON200.Document.Spec.Target != target {
				return fmt.Errorf("destroy changed or deleted the alias: %s", got.Body)
			}
			rollouts, err := client.ListRolloutsWithResponse(context.Background())
			if err != nil {
				return err
			}
			if rollouts.JSON200 == nil || len(rollouts.JSON200.Items) != 0 {
				return fmt.Errorf("provider started an implicit rollout: %s", rollouts.Body)
			}
			return nil
		},
	})
}

func TestAccModelBindingRefusesUnapprovedModel(t *testing.T) {
	requireTofu(t)
	cp := controlplanetest.New(t)
	client := catalogueClient(t, cp, "terraform@example.invalid")
	existing, err := client.GetModelAliasWithResponse(context.Background(), "reasoning-default")
	if err != nil || existing.JSON200 == nil {
		t.Fatalf("seed alias: %v %v", err, existing)
	}
	target := existing.JSON200.Document.Spec.Target
	// Reuse the approved fixture's valid document under a new name; a new model is pending.
	model, err := client.GetModelWithResponse(context.Background(), target)
	if err != nil || model.JSON200 == nil {
		t.Fatalf("seed model: %v %v", err, model)
	}
	doc := model.JSON200.Document
	doc.Metadata.Name = "unapproved-model"
	created, err := client.ApplyModelWithResponse(context.Background(), "unapproved-model", doc)
	if err != nil || created.JSON201 == nil {
		t.Fatalf("pending model: %v %v", err, created)
	}
	prefix := providerBlock(cp.URL, "", cp.Tenant.String())
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{Config: bindingConfig(prefix, "unapproved-model", "pending"), ExpectError: regexp.MustCompile("only approved models")},
			{Config: bindingConfig(prefix, target, "approved")},
		},
		CheckDestroy: func(*terraform.State) error {
			got, err := client.GetModelWithResponse(context.Background(), "unapproved-model")
			if err != nil {
				return err
			}
			if got.JSON200 == nil || got.JSON200.Approval.Status != muistamov1.ModelApprovalStatusPending {
				return fmt.Errorf("provider changed model approval: %s", got.Body)
			}
			return nil
		},
	})
}
