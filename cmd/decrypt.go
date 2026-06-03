package cmd

import (
	"fmt"
	"os"

	"github.com/rjcuff/pqctl/crypto"
	"github.com/rjcuff/pqctl/keys"
	"github.com/spf13/cobra"
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a file using a ML-KEM-768 private key",
	Long:  `Decrypt a file encrypted with pqctl encrypt. Requires the ML-KEM-768 private key matching the recipient's public key.`,
	RunE:  runDecrypt,
}

func setupDecryptFlags() {
	decryptCmd.Flags().StringP("key", "k", "", "ML-KEM-768 private key PEM file (required)")
	decryptCmd.Flags().StringP("in", "i", "", "encrypted file to decrypt (required)")
	decryptCmd.Flags().StringP("out", "o", "", "output decrypted file (required)")
	_ = decryptCmd.MarkFlagRequired("key")
	_ = decryptCmd.MarkFlagRequired("in")
	_ = decryptCmd.MarkFlagRequired("out")
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	keyPath, _ := cmd.Flags().GetString("key")
	inPath, _ := cmd.Flags().GetString("in")
	outPath, _ := cmd.Flags().GetString("out")

	ciphertext, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("decrypt: read file %s: %w", inPath, err)
	}

	block, err := keys.ReadPEM(keyPath)
	if err != nil {
		return err
	}

	plaintext, err := crypto.DecryptMLKEM768(block.Bytes, ciphertext)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
		return fmt.Errorf("decrypt: write %s: %w", outPath, err)
	}

	fmt.Printf("decrypted %s\n  output: %s\n", inPath, outPath)
	return nil
}
