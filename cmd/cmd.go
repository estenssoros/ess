package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	cmd.AddCommand(
		encryptCmd,
		decryptCmd,
	)
}

var cmd = &cobra.Command{
	Use:   "ess",
	Short: "estenssoro secret sharing",
}

func Execute() error {
	return cmd.Execute()
}
