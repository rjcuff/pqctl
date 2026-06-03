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
		if err := keygenMLDSA65(out); err != nil {
			return err
		}
		fmt.Printf("generated ML-DSA-65 keypair\n  private: %s.priv.pem\n  public:  %s.pub.pem\n", out, out)
		return nil

	case "ed25519":
		if err := keygenEd25519(out); err != nil {
			return err
		}
		fmt.Printf("generated ED25519 keypair\n  private: %s.priv.pem\n  public:  %s.pub.pem\n", out, out)
		return nil
	case "hybrid":
		if err := keygenMLDSA65(out + ".mldsa65"); err != nil {
			return err
		}
		if err := keygenEd25519(out + ".ed25519"); err != nil {
			return err
		}
		fmt.Printf("generated hybrid keypair\n  ML-DSA-65 private: %s.mldsa65.priv.pem\n  ML-DSA-65 public:  %s.mldsa65.pub.pem\n  ED25519 private:   %s.ed25519.priv.pem\n  ED25519 public:    %s.ed25519.pub.pem\n", out, out, out, out)
		return nil
	default:
		return fmt.Errorf("unknown algorithm %q — supported: ml-dsa-65, ed25519, hybrid", algo)
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

	return nil
}
