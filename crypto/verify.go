package crypto

import (
	"crypto/ed25519"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// VerifyMLDSA65 verifies an ML-DSA-65 signature over message using pubKeyBytes.
func VerifyMLDSA65(pubKeyBytes []byte, message []byte, sig []byte) error {
	var pub mldsa65.PublicKey
	if err := pub.UnmarshalBinary(pubKeyBytes); err != nil {
		return fmt.Errorf("verify: unmarshal public key: %w", err)
	}
	if !mldsa65.Verify(&pub, message, nil, sig) {
		return fmt.Errorf("verify: invalid signature")
	}
	return nil
}

// VerifyEd25519 verifies an Ed25519 signature over message using pubKeyBytes.
func VerifyEd25519(pubKeyBytes []byte, message []byte, sig []byte) error {
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("verify: ed25519: invalid public key size: got %d, want %d", len(pubKeyBytes), ed25519.PublicKeySize)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), message, sig) {
		return fmt.Errorf("verify: invalid signature")
	}
	return nil
}
