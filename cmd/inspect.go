package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/rjcuff/pqctl/keys"
	"github.com/spf13/cobra"
)

var inspectCmd = &cobra.Command{
	Use:   "inspect <file>",
	Short: "Inspect a PEM key file",
	Long:  `Display human-readable information about a PEM key file: algorithm, key type, size, and fingerprint.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runInspect,
}

func setupInspectFlags() {
	inspectCmd.Flags().Bool("json", false, "output as JSON")
}

func runInspect(cmd *cobra.Command, args []string) error {
	path := args[0]
	jsonOut, _ := cmd.Flags().GetBool("json")

	block, err := keys.ReadPEM(path)
	if err != nil {
		return err
	}

	algo, keyType := parseAlgoFromPEMType(block.Type)
	sum := sha256.Sum256(block.Bytes)
	fingerprint := "SHA256:" + hex.EncodeToString(sum[:])

	if jsonOut {
		out := map[string]any{
			"file":        path,
			"type":        block.Type,
			"algorithm":   algo,
			"key_type":    keyType,
			"size":        len(block.Bytes),
			"fingerprint": fingerprint,
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	fmt.Printf("file:        %s\n", path)
	fmt.Printf("type:        %s\n", block.Type)
	fmt.Printf("algorithm:   %s\n", algo)
	fmt.Printf("key type:    %s\n", keyType)
	fmt.Printf("size:        %d bytes\n", len(block.Bytes))
	fmt.Printf("fingerprint: %s\n", fingerprint)
	return nil
}

func parseAlgoFromPEMType(pemType string) (algo, keyType string) {
	switch pemType {
	case "ML-DSA-65 PRIVATE KEY", "ENCRYPTED ML-DSA-65 PRIVATE KEY":
		return "ML-DSA-65 (FIPS 204 — post-quantum signing)", "private"
	case "ML-DSA-65 PUBLIC KEY":
		return "ML-DSA-65 (FIPS 204 — post-quantum signing)", "public"
	case "ML-KEM-768 PRIVATE KEY", "ENCRYPTED ML-KEM-768 PRIVATE KEY":
		return "ML-KEM-768 (FIPS 203 — post-quantum key encapsulation)", "private"
	case "ML-KEM-768 PUBLIC KEY":
		return "ML-KEM-768 (FIPS 203 — post-quantum key encapsulation)", "public"
	case "ED25519 PRIVATE KEY", "ENCRYPTED ED25519 PRIVATE KEY":
		return "Ed25519 (classical signing, RFC 8032)", "private"
	case "ED25519 PUBLIC KEY":
		return "Ed25519 (classical signing, RFC 8032)", "public"
	default:
		return "unknown", "unknown"
	}
}
