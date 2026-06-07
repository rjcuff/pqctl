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

// SetVersion sets the version string shown in --version output.
func SetVersion(v string) {
	rootCmd.Version = v
}

// Execute runs pqctl.
func Execute() {
	setupKeygenFlags()
	rootCmd.AddCommand(keygenCmd)

	setupSignFlags()
	rootCmd.AddCommand(signCmd)

	setupVerifyFlags()
	rootCmd.AddCommand(verifyCmd)

	setupEncryptFlags()
	rootCmd.AddCommand(encryptCmd)

	setupDecryptFlags()
	rootCmd.AddCommand(decryptCmd)

	setupInspectFlags()
	rootCmd.AddCommand(inspectCmd)

	setupCloudFlags()
	rootCmd.AddCommand(cloudCmd)

	rootCmd.AddCommand(completionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
