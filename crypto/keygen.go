package crypto

import (
	"crypto/ed25519"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// KeyPair holds raw DER-encoded private and public key bytes.
type KeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

// GenerateMLDSA65 generates an ML-DSA-65 keypair using crypto/rand.
func GenerateMLDSA65() (*KeyPair, error) {
	pub, priv, err := mldsa65.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("keygen: ml-dsa-65: %w", err)
	}

	privBytes, err := priv.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("keygen: marshal private key: %w", err)
	}

	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("keygen: marshal public key: %w", err)
	}

	return &KeyPair{
		PrivateKey: privBytes,
		PublicKey:  pubBytes,
	}, nil
}

func GenerateEd25519() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("keygen: ed25519: %w", err)
	}

	return &KeyPair{
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}
