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
	keygenCmd.Flags().StringP("algo", "a", "ml-dsa-65", "algorithm: ml-dsa-65 | ed25519 | hybrid")
	keygenCmd.Flags().StringP("out", "o", "", "output filename prefix (required)")
	_ = keygenCmd.MarkFlagRequired("out")
}

func runKeygen(cmd *cobra.Command, args []string) error {
	algo, _ := cmd.Flags().GetString("algo")
	out, _ := cmd.Flags().GetString("out")

	switch algo {
	case "ml-dsa-65":
		return keygenMLDSA65(out)
	case "ed25519":
		return keygenEd25519(out)
	default:
		return fmt.Errorf("unknown algorithm %q — supported: ml-dsa-65", algo)
	}
}

func keygenMLDSA65(out string) error {
	kp, err := crypto.GenerateMLDSA65()
	if err != nil {
		return err
	}

	privPath := out + ".priv.pem"
	pubPath := out + ".pub.pem"

	if err := keys.WritePEM(privPath, "ML-DSA-65 PRIVATE KEY", kp.PrivateKey); err != nil {
		return err
	}
	if err := keys.WritePEM(pubPath, "ML-DSA-65 PUBLIC KEY", kp.PublicKey); err != nil {
		return err
	}

	fmt.Printf("generated ML-DSA-65 keypair\n  private: %s\n  public:  %s\n", privPath, pubPath)
	return nil
}

func keygenEd25519(out string) error {
	kp, err := crypto.GenerateEd25519()
	if err != nil {
		return err
	}

	privPath := out + ".priv.pem"
	pubPath := out + ".pub.pem"

	if err := keys.WritePEM(privPath, "ED25519 PRIVATE KEY", kp.PrivateKey); err != nil {
		return err
	}
	if err := keys.WritePEM(pubPath, "ED25519 PUBLIC KEY", kp.PublicKey); err != nil {
		return err
	}

	fmt.Printf("generated ED25519 keypair\n  private: %s\n  public:  %s\n", privPath, pubPath)
	return nil
}
