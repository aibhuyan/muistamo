// Command terraform-provider-muistamo is the Muistamo provider for Terraform and OpenTofu.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"muistamo.dev/muistamo/terraform/internal/provider"
)

// version is set at release time with -ldflags.
var version = "dev"

func main() {
	debug := flag.Bool("debug", false, "run with support for debuggers such as delve")
	flag.Parse()
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.opentofu.org/muistamo/muistamo",
		Debug:   *debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
