package cmd

import (
	"github.com/bonjoski/locksmith/v2/pkg/agent"
	"github.com/spf13/cobra"
)

var pinentryCmd = &cobra.Command{
	Use:    "pinentry",
	Short:  "Internal GPG pinentry helper",
	Hidden: true,
	PreRun: func(cmd *cobra.Command, args []string) {
		if ls != nil && ls.Options.AuditIdentity == "" {
			ls.Options.AuditIdentity = "gpg:pinentry"
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if ls != nil && ls.Options.AuditIdentity == "" {
			ls.Options.AuditIdentity = "gpg:pinentry"
		}
		return agent.RunPinentry(ls)
	},
}

func init() {
	rootCmd.AddCommand(pinentryCmd)
}
