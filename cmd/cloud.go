package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rjcuff/pqctl/crypto"
	"github.com/rjcuff/pqctl/keys"
	"github.com/spf13/cobra"
)

const defaultCloudAPIURL = "https://api.moduli.dev"

var cloudCmd = &cobra.Command{
	Use:   "cloud",
	Short: "Hosted key management — store, retrieve, and audit keys via moduli",
	Long: `moduli is the paid hosted layer for pqctl: encrypted key storage,
rotation tracking, and a tamper-evident audit log. Keys are always
encrypted on your machine before upload — moduli never sees plaintext
key material. Requires a moduli account: https://moduli.dev`,
}

var cloudPushCmd = &cobra.Command{
	Use:   "push <key-file>",
	Short: "Encrypt a private key and upload it to moduli",
	Args:  cobra.ExactArgs(1),
	RunE:  runCloudPush,
}

var cloudPullCmd = &cobra.Command{
	Use:   "pull <id>",
	Short: "Download and decrypt a key from moduli",
	Args:  cobra.ExactArgs(1),
	RunE:  runCloudPull,
}

var cloudListCmd = &cobra.Command{
	Use:   "list",
	Short: "List keys stored in moduli",
	Args:  cobra.NoArgs,
	RunE:  runCloudList,
}

func setupCloudFlags() {
	cloudCmd.PersistentFlags().String("api-url", "", "moduli API URL (default: $MODULI_API_URL or "+defaultCloudAPIURL+")")
	cloudCmd.PersistentFlags().String("api-key", "", "moduli API key (default: $MODULI_API_KEY)")

	cloudPushCmd.Flags().Int("rotate-days", 0, "mark key due for rotation N days from now (0 = no rotation tracking)")
	cloudPullCmd.Flags().StringP("out", "o", "", "output filename (required)")
	cloudPullCmd.Flags().Bool("passphrase", false, "re-encrypt the downloaded key locally with a passphrase")
	_ = cloudPullCmd.MarkFlagRequired("out")

	cloudCmd.AddCommand(cloudPushCmd)
	cloudCmd.AddCommand(cloudPullCmd)
	cloudCmd.AddCommand(cloudListCmd)
}

// cloudClientFromFlags resolves API URL/key from flags, falling back to
// MODULI_API_URL / MODULI_API_KEY env vars. The key is required —
// there is no anonymous access to moduli.
func cloudClientFromFlags(cmd *cobra.Command) (*cloudClient, error) {
	apiURL, _ := cmd.Flags().GetString("api-url")
	if apiURL == "" {
		apiURL = os.Getenv("MODULI_API_URL")
	}
	if apiURL == "" {
		apiURL = defaultCloudAPIURL
	}
	apiURL = strings.TrimRight(apiURL, "/")

	apiKey, _ := cmd.Flags().GetString("api-key")
	if apiKey == "" {
		apiKey = os.Getenv("MODULI_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("moduli API key required — set $MODULI_API_KEY or pass --api-key (get one at https://moduli.dev)")
	}

	return newCloudClient(apiURL, apiKey), nil
}

// algoFromPEMType maps a private-key PEM type (encrypted or not) to the
// algo slug moduli stores and the canonical PEM type used to write it
// back out on pull.
func algoFromPEMType(pemType string) (slug, canonicalPEMType string, err error) {
	switch strings.TrimPrefix(pemType, "ENCRYPTED ") {
	case keys.PEMTypeMLDSA65Priv:
		return "ml-dsa-65", keys.PEMTypeMLDSA65Priv, nil
	case keys.PEMTypeEd25519Priv:
		return "ed25519", keys.PEMTypeEd25519Priv, nil
	case keys.PEMTypeMLKEM768Priv:
		return "ml-kem-768", keys.PEMTypeMLKEM768Priv, nil
	default:
		return "", "", fmt.Errorf("cloud: unsupported key type %q — only private keys can be pushed", pemType)
	}
}

func runCloudPush(cmd *cobra.Command, args []string) error {
	path := args[0]

	client, err := cloudClientFromFlags(cmd)
	if err != nil {
		return err
	}

	block, err := keys.ReadPEM(path)
	if err != nil {
		return err
	}
	slug, _, err := algoFromPEMType(block.Type)
	if err != nil {
		return err
	}

	// loadPrivateKey decrypts the file if it's locally passphrase-protected,
	// prompting for the local passphrase. Either way we end up with raw
	// key bytes that have never left this machine unencrypted.
	rawKey, err := loadPrivateKey(path)
	if err != nil {
		return err
	}

	cloudPass, err := readPassphrase("Cloud passphrase (encrypts this key for moduli storage): ")
	if err != nil {
		return err
	}
	confirmPass, err := readPassphrase("Confirm cloud passphrase: ")
	if err != nil {
		return err
	}
	if !bytes.Equal(cloudPass, confirmPass) {
		return fmt.Errorf("cloud: passphrases do not match")
	}

	ciphertext, err := crypto.EncryptKey(rawKey, cloudPass)
	if err != nil {
		return fmt.Errorf("cloud: encrypt for upload: %w", err)
	}

	sum := sha256.Sum256(rawKey)
	fingerprint := "SHA256:" + hex.EncodeToString(sum[:])

	req := pushRequest{
		Algo:          slug,
		Fingerprint:   fingerprint,
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	}
	if days, _ := cmd.Flags().GetInt("rotate-days"); days > 0 {
		due := time.Now().UTC().AddDate(0, 0, days).Format(time.RFC3339)
		req.RotationDueAt = &due
	}

	id, err := client.push(req)
	if err != nil {
		return err
	}

	fmt.Printf("uploaded to moduli\n  id:          %s\n  algorithm:   %s\n  fingerprint: %s\n", id, slug, fingerprint)
	if req.RotationDueAt != nil {
		fmt.Printf("  rotation due: %s\n", *req.RotationDueAt)
	}
	fmt.Println("\nRemember your cloud passphrase — moduli cannot recover it for you.")
	return nil
}

func runCloudPull(cmd *cobra.Command, args []string) error {
	id := args[0]
	out, _ := cmd.Flags().GetString("out")
	relock, _ := cmd.Flags().GetBool("passphrase")

	client, err := cloudClientFromFlags(cmd)
	if err != nil {
		return err
	}

	key, err := client.get(id)
	if err != nil {
		return err
	}

	var pemType string
	switch key.Algo {
	case "ml-dsa-65":
		pemType = keys.PEMTypeMLDSA65Priv
	case "ed25519":
		pemType = keys.PEMTypeEd25519Priv
	case "ml-kem-768":
		pemType = keys.PEMTypeMLKEM768Priv
	default:
		return fmt.Errorf("cloud: unknown algorithm %q returned by moduli", key.Algo)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(key.CiphertextB64)
	if err != nil {
		return fmt.Errorf("cloud: decode ciphertext: %w", err)
	}

	cloudPass, err := readPassphrase("Cloud passphrase (set when this key was pushed): ")
	if err != nil {
		return err
	}
	rawKey, err := crypto.DecryptKey(ciphertext, cloudPass)
	if err != nil {
		return err
	}

	if relock {
		localPass, err := readPassphrase("New local passphrase to protect the saved file: ")
		if err != nil {
			return err
		}
		confirmPass, err := readPassphrase("Confirm local passphrase: ")
		if err != nil {
			return err
		}
		if !bytes.Equal(localPass, confirmPass) {
			return fmt.Errorf("cloud: passphrases do not match")
		}
		encrypted, err := crypto.EncryptKey(rawKey, localPass)
		if err != nil {
			return fmt.Errorf("cloud: re-encrypt for local storage: %w", err)
		}
		if err := keys.WritePEM(out, "ENCRYPTED "+pemType, encrypted); err != nil {
			return err
		}
	} else {
		if err := keys.WritePEM(out, pemType, rawKey); err != nil {
			return err
		}
	}

	fmt.Printf("downloaded key %s -> %s\n  algorithm:   %s\n  fingerprint: %s\n", id, out, key.Algo, key.Fingerprint)
	return nil
}

func runCloudList(cmd *cobra.Command, args []string) error {
	client, err := cloudClientFromFlags(cmd)
	if err != nil {
		return err
	}

	list, err := client.list()
	if err != nil {
		return err
	}

	if len(list) == 0 {
		fmt.Println("no keys stored in moduli")
		return nil
	}

	fmt.Printf("%-36s  %-12s  %-20s  %s\n", "ID", "ALGORITHM", "FINGERPRINT", "ROTATION DUE")
	for _, k := range list {
		due := "-"
		if k.RotationDueAt != nil {
			due = *k.RotationDueAt
		}
		fmt.Printf("%-36s  %-12s  %-20s  %s\n", k.ID, k.Algo, k.Fingerprint, due)
	}
	return nil
}
