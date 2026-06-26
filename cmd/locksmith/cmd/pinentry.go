package cmd

import (
	"github.com/bonjoski/locksmith/v2/pkg/agent"
	"github.com/spf13/cobra"
)

var pinentryCmd = &cobra.Command{
	Use:    "pinentry",
	Short:  "Internal GPG pinentry helper",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return agent.RunPinentry(ls)
	},
}

func init() {
	rootCmd.AddCommand(pinentryCmd)
}
