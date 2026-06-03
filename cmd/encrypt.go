package cmd

import (
	"fmt"
	"os"

	"github.com/rjcuff/pqctl/crypto"
	"github.com/rjcuff/pqctl/keys"
	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a file using a ML-KEM-768 public key",
	Long:  `Encrypt a file using ML-KEM-768 key encapsulation + AES-256-GCM. Requires a recipient's ML-KEM-768 public key.`,
	RunE:  runEncrypt,
}

func setupEncryptFlags() {
	encryptCmd.Flags().StringP("recipient", "r", "", "recipient ML-KEM-768 public key PEM file (required)")
	encryptCmd.Flags().StringP("in", "i", "", "file to encrypt (required)")
	encryptCmd.Flags().StringP("out", "o", "", "output encrypted file (default: <in>.enc)")
	_ = encryptCmd.MarkFlagRequired("recipient")
	_ = encryptCmd.MarkFlagRequired("in")
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	recipientPath, _ := cmd.Flags().GetString("recipient")
	inPath, _ := cmd.Flags().GetString("in")
	outPath, _ := cmd.Flags().GetString("out")
	if outPath == "" {
		outPath = inPath + ".enc"
	}

	plaintext, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("encrypt: read file %s: %w", inPath, err)
	}

	block, err := keys.ReadPEM(recipientPath)
	if err != nil {
		return err
	}

	ciphertext, err := crypto.EncryptMLKEM768(block.Bytes, plaintext)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outPath, ciphertext, 0644); err != nil {
		return fmt.Errorf("encrypt: write %s: %w", outPath, err)
	}

	fmt.Printf("encrypted %s\n  output: %s\n  algorithm: ML-KEM-768 + AES-256-GCM\n", inPath, outPath)
	return nil
}
