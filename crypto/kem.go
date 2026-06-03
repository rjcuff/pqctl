package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// ML-KEM-768 ciphertext is always 1088 bytes.
const mlkem768CiphertextSize = 1088

// EncryptMLKEM768 encrypts plaintext using ML-KEM-768 + AES-256-GCM.
// Output format: [kem_ciphertext (1088 bytes)][aes_nonce (12 bytes)][aes_ciphertext]
func EncryptMLKEM768(pubKeyBytes []byte, plaintext []byte) ([]byte, error) {
	scheme := mlkem768.Scheme()

	pub, err := scheme.UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt: unmarshal public key: %w", err)
	}

	ct, ss, err := scheme.Encapsulate(pub)
	if err != nil {
		return nil, fmt.Errorf("encrypt: encapsulate: %w", err)
	}

	block, err := aes.NewCipher(ss)
	if err != nil {
		return nil, fmt.Errorf("encrypt: aes: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("encrypt: gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("encrypt: nonce: %w", err)
	}

	aesCiphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return append(ct, aesCiphertext...), nil
}

// DecryptMLKEM768 decrypts data produced by EncryptMLKEM768.
func DecryptMLKEM768(privKeyBytes []byte, data []byte) ([]byte, error) {
	if len(data) < mlkem768CiphertextSize {
		return nil, fmt.Errorf("decrypt: data too short")
	}

	scheme := mlkem768.Scheme()

	priv, err := scheme.UnmarshalBinaryPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("decrypt: unmarshal private key: %w", err)
	}

	kemCT := data[:mlkem768CiphertextSize]
	rest := data[mlkem768CiphertextSize:]

	ss, err := scheme.Decapsulate(priv, kemCT)
	if err != nil {
		return nil, fmt.Errorf("decrypt: decapsulate: %w", err)
	}

	block, err := aes.NewCipher(ss)
	if err != nil {
		return nil, fmt.Errorf("decrypt: aes: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("decrypt: gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(rest) < nonceSize {
		return nil, fmt.Errorf("decrypt: data too short for nonce")
	}

	nonce, ciphertext := rest[:nonceSize], rest[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: authentication failed — wrong key or corrupted data")
	}

	return plaintext, nil
}
