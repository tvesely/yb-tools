package cmd

import "github.com/spf13/cobra"

var (
	rootCmd = &cobra.Command{
		Use:   "getlogs",
		Short: "A utility for gathering YugabyteDB logs across a Universe",
	}
)
