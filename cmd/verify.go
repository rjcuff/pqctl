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
	Short: "Verify file signatures using a post-quantum public key",
	Long:  `Verify one or more detached ML-DSA-65 signatures. Pass multiple --in files to verify in batch.`,
	RunE:  runVerify,
}

func setupVerifyFlags() {
	verifyCmd.Flags().StringP("pubkey", "p", "", "public key PEM file (required)")
	verifyCmd.Flags().StringArrayP("in", "i", nil, "file(s) to verify (repeatable; auto-detects <file>.sig)")
	verifyCmd.Flags().StringP("sig", "s", "", "signature file (optional; only valid with a single --in)")
	_ = verifyCmd.MarkFlagRequired("pubkey")
	_ = verifyCmd.MarkFlagRequired("in")
}

func runVerify(cmd *cobra.Command, args []string) error {
	pubkeyPath, _ := cmd.Flags().GetString("pubkey")
	inPaths, _ := cmd.Flags().GetStringArray("in")
	sigPath, _ := cmd.Flags().GetString("sig")

	block, err := keys.ReadPEM(pubkeyPath)
	if err != nil {
		return err
	}
	pubKeyBytes := block.Bytes

	if len(inPaths) > 1 && sigPath != "" {
		return fmt.Errorf("verify: --sig can only be used with a single --in file")
	}

	failed := 0
	for _, inPath := range inPaths {
		sig := sigPath
		if sig == "" {
			sig = inPath + ".sig"
		}
		if err := verifyOne(pubKeyBytes, inPath, sig); err != nil {
			fmt.Fprintf(os.Stderr, "INVALID %s: %v\n", inPath, err)
			failed++
		} else {
			fmt.Printf("OK  %s\n", inPath)
		}
	}

	if failed > 0 {
		return fmt.Errorf("%d of %d signatures invalid", failed, len(inPaths))
	}
	return nil
}

func verifyOne(pubKeyBytes []byte, inPath, sigPath string) error {
	message, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("read sig %s: %w", sigPath, err)
	}
	return crypto.VerifyMLDSA65(pubKeyBytes, message, sig)
}
