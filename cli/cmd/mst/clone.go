package main

import (
	"net/http"

	"github.com/spf13/cobra"
)

func cloneCmd(opts *options) *cobra.Command {
	cmd := &cobra.Command{Use: "clone", Short: "Work with clones of templates (apply them with mst apply)"}
	cmd.AddCommand(&cobra.Command{
		Use:   "sync NAME",
		Short: "Move a manual clone to its template's published version",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}
			res, err := client.SyncCloneWithResponse(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK {
				return problem(res.StatusCode(), res.Body)
			}
			cmd.Printf("AgentClone/%s: on template version %d (revision %d)\n", args[0], *res.JSON200.ResolvedVersion, res.JSON200.Revision)
			return nil
		},
	})
	return cmd
}
