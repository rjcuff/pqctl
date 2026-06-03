package cmd

import (
	"fmt"
	"os"

	"github.com/rjcuff/pqctl/crypto"
	"github.com/spf13/cobra"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a file using a post-quantum private key",
	Long:  `Sign any file using ML-DSA-65. Outputs a detached signature file.`,
	RunE:  runSign,
}

func setupSignFlags() {
	signCmd.Flags().StringP("key", "k", "", "private key PEM file (required)")
	signCmd.Flags().StringP("in", "i", "", "file to sign (required)")
	signCmd.Flags().StringP("out", "o", "", "output signature file (default: <in>.sig)")
	_ = signCmd.MarkFlagRequired("key")
	_ = signCmd.MarkFlagRequired("in")
}

func runSign(cmd *cobra.Command, args []string) error {
	keyPath, _ := cmd.Flags().GetString("key")
	inPath, _ := cmd.Flags().GetString("in")
	outPath, _ := cmd.Flags().GetString("out")
	if outPath == "" {
		outPath = inPath + ".sig"
	}

	message, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("sign: read file %s: %w", inPath, err)
	}

	keyBytes, err := loadPrivateKey(keyPath)
	if err != nil {
		return err
	}

	sig, err := crypto.SignMLDSA65(keyBytes, message)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outPath, sig, 0644); err != nil {
		return fmt.Errorf("sign: write signature %s: %w", outPath, err)
	}

	fmt.Printf("signed %s\n  signature: %s\n", inPath, outPath)
	return nil
}
