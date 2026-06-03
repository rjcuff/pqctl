package cmd

import (
	"fmt"

	"github.com/rjcuff/pqctl/crypto"
	"github.com/rjcuff/pqctl/keys"
	"github.com/spf13/cobra"
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a post-quantum keypair (default: ML-DSA-65)",
	Long:  `Generate a keypair using a NIST-standardized post-quantum algorithm. Outputs two PEM files: <out>.priv.pem and <out>.pub.pem`,
	RunE:  runKeygen,
}

func setupKeygenFlags() {
	keygenCmd.Flags().StringP("algo", "a", "ml-dsa-65", "algorithm: ml-dsa-65 | ed25519 | hybrid | ml-kem-768")
	keygenCmd.Flags().StringP("out", "o", "", "output filename prefix (required)")
	keygenCmd.Flags().Bool("passphrase", false, "encrypt private key with a passphrase")
	_ = keygenCmd.MarkFlagRequired("out")
}

func runKeygen(cmd *cobra.Command, args []string) error {
	algo, _ := cmd.Flags().GetString("algo")
	out, _ := cmd.Flags().GetString("out")
	usePassphrase, _ := cmd.Flags().GetBool("passphrase")

	switch algo {
	case "ml-dsa-65":
		if err := keygenMLDSA65(out, usePassphrase); err != nil {
			return err
		}
		fmt.Printf("generated ML-DSA-65 keypair\n  private: %s.priv.pem\n  public:  %s.pub.pem\n", out, out)
		return nil
	case "ed25519":
		if err := keygenEd25519(out, usePassphrase); err != nil {
			return err
		}
		fmt.Printf("generated ED25519 keypair\n  private: %s.priv.pem\n  public:  %s.pub.pem\n", out, out)
		return nil
	case "hybrid":
		if err := keygenMLDSA65(out+".mldsa65", usePassphrase); err != nil {
			return err
		}
		if err := keygenEd25519(out+".ed25519", usePassphrase); err != nil {
			return err
		}
		fmt.Printf("generated hybrid keypair\n  ML-DSA-65 private: %s.mldsa65.priv.pem\n  ML-DSA-65 public:  %s.mldsa65.pub.pem\n  ED25519 private:   %s.ed25519.priv.pem\n  ED25519 public:    %s.ed25519.pub.pem\n", out, out, out, out)
		return nil
	case "ml-kem-768":
		return keygenMLKEM768(out, usePassphrase)
	default:
		return fmt.Errorf("unknown algorithm %q — supported: ml-dsa-65, ed25519, hybrid, ml-kem-768", algo)
	}
}

func keygenMLDSA65(out string, usePassphrase bool) error {
	kp, err := crypto.GenerateMLDSA65()
	if err != nil {
		return err
	}
	return writeKeypair(out, "ML-DSA-65", kp.PrivateKey, kp.PublicKey, usePassphrase)
}

func keygenEd25519(out string, usePassphrase bool) error {
	kp, err := crypto.GenerateEd25519()
	if err != nil {
		return err
	}
	return writeKeypair(out, "ED25519", kp.PrivateKey, kp.PublicKey, usePassphrase)
}

func keygenMLKEM768(out string, usePassphrase bool) error {
	kp, err := crypto.GenerateMLKEM768()
	if err != nil {
		return err
	}
	if err := writeKeypair(out, "ML-KEM-768", kp.PrivateKey, kp.PublicKey, usePassphrase); err != nil {
		return err
	}
	fmt.Printf("generated ML-KEM-768 keypair\n  private: %s.priv.pem\n  public:  %s.pub.pem\n", out, out)
	return nil
}

func writeKeypair(out, algo string, privKey, pubKey []byte, usePassphrase bool) error {
	privPEMType := algo + " PRIVATE KEY"
	pubPEMType := algo + " PUBLIC KEY"

	privBytes := privKey
	if usePassphrase {
		pass, err := readPassphrase("Enter passphrase for private key: ")
		if err != nil {
			return err
		}
		confirm, err := readPassphrase("Confirm passphrase: ")
		if err != nil {
			return err
		}
		if string(pass) != string(confirm) {
			return fmt.Errorf("passphrases do not match")
		}
		privBytes, err = crypto.EncryptKey(privKey, pass)
		if err != nil {
			return err
		}
		privPEMType = "ENCRYPTED " + privPEMType
	}

	if err := keys.WritePEM(out+".priv.pem", privPEMType, privBytes); err != nil {
		return err
	}
	return keys.WritePEM(out+".pub.pem", pubPEMType, pubKey)
}
