package cmd

import (
	"fmt"

	"github.com/rjcuff/pqctl/keys"
	"github.com/spf13/cobra"
)

var inspectCmd = &cobra.Command{
	Use:   "inspect <file>",
	Short: "Inspect a PEM key file",
	Long:  `Display human-readable information about a PEM key file: algorithm, key type, and size.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runInspect,
}

func runInspect(cmd *cobra.Command, args []string) error {
	path := args[0]

	block, err := keys.ReadPEM(path)
	if err != nil {
		return err
	}

	algo, keyType := parseAlgoFromPEMType(block.Type)

	fmt.Printf("file:      %s\n", path)
	fmt.Printf("type:      %s\n", block.Type)
	fmt.Printf("algorithm: %s\n", algo)
	fmt.Printf("key type:  %s\n", keyType)
	fmt.Printf("size:      %d bytes\n", len(block.Bytes))
	return nil
}

func parseAlgoFromPEMType(pemType string) (algo, keyType string) {
	switch pemType {
	case "ML-DSA-65 PRIVATE KEY":
		return "ML-DSA-65 (FIPS 204 — post-quantum signing)", "private"
	case "ML-DSA-65 PUBLIC KEY":
		return "ML-DSA-65 (FIPS 204 — post-quantum signing)", "public"
	case "ML-KEM-768 PRIVATE KEY":
		return "ML-KEM-768 (FIPS 203 — post-quantum key encapsulation)", "private"
	case "ML-KEM-768 PUBLIC KEY":
		return "ML-KEM-768 (FIPS 203 — post-quantum key encapsulation)", "public"
	case "ED25519 PRIVATE KEY":
		return "Ed25519 (classical signing, RFC 8032)", "private"
	case "ED25519 PUBLIC KEY":
		return "Ed25519 (classical signing, RFC 8032)", "public"
	default:
		return "unknown", "unknown"
	}
}
