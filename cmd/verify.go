package cmd

import (
	"fmt"
	"os"

	"github.com/rjcuff/pqctl/crypto"
	"github.com/rjcuff/pqctl/keys"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a file signature using a post-quantum public key",
	Long:  `Verify a detached ML-DSA-65 signature against a file and public key.`,
	RunE:  runVerify,
}

func setupVerifyFlags() {
	verifyCmd.Flags().StringP("pubkey", "p", "", "public key PEM file (required)")
	verifyCmd.Flags().StringP("in", "i", "", "file that was signed (required)")
	verifyCmd.Flags().StringP("sig", "s", "", "signature file (required)")
	_ = verifyCmd.MarkFlagRequired("pubkey")
	_ = verifyCmd.MarkFlagRequired("in")
	_ = verifyCmd.MarkFlagRequired("sig")
}

func runVerify(cmd *cobra.Command, args []string) error {
	pubkeyPath, _ := cmd.Flags().GetString("pubkey")
	inPath, _ := cmd.Flags().GetString("in")
	sigPath, _ := cmd.Flags().GetString("sig")

	message, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("verify: read file %s: %w", inPath, err)
	}

	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("verify: read signature %s: %w", sigPath, err)
	}

	block, err := keys.ReadPEM(pubkeyPath)
	if err != nil {
		return err
	}

	if err := crypto.VerifyMLDSA65(block.Bytes, message, sig); err != nil {
		fmt.Printf("INVALID signature\n")
		return err
	}

	fmt.Printf("OK signature valid\n  file:   %s\n  key:    %s\n", inPath, pubkeyPath)
	return nil
}
