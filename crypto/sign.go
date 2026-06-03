package crypto

import (
	"crypto/ed25519"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)


func SignMLDSA65(privKeyBytes []byte, message []byte) ([]byte, error) {
	var priv mldsa65.PrivateKey
	if err := priv.UnmarshalBinary(privKeyBytes); err != nil {
		return nil, fmt.Errorf("sign: unmarshal private key: %w", err)
	}
	sig, err := priv.Sign(nil, message, nil)
	if err != nil {
		return nil, fmt.Errorf("sign: ml-dsa-65: %w", err)
	}
	return sig, nil
}

func SignEd25519(privKeyBytes []byte, message []byte) ([]byte, error) {
	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("sign: ed25519: invalid private key size: got %d, want %d", len(privKeyBytes), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(privKeyBytes)
	sig := ed25519.Sign(priv, message)
	return sig, nil
}