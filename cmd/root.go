package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "pqctl",
	Short: "OpenSSL for the post-quantum era",
	Long:  `pqctl makes post-quantum cryptography as accessible as OpenSSL. Uses NIST-standardized ML-DSA and ML-KEM algorithms.`,
}

// Execute runs pqctl.
func Execute() {
	setupKeygenFlags()
	rootCmd.AddCommand(keygenCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
