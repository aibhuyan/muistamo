// Command mst is the Muistamo CLI.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"muistamo.dev/muistamo/cli/internal/version"
)

func main() {
	root := &cobra.Command{
		Use:           "mst",
		Short:         "Muistamo CLI",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the mst version",
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Println(version.String())
		},
	})

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "mst:", err)
		os.Exit(1)
	}
}
