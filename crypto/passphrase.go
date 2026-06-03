package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
)

const (
	scryptN  = 32768
	scryptR  = 8
	scryptP  = 1
	saltSize = 32
)

// EncryptKey encrypts raw key bytes with a passphrase using scrypt + AES-256-GCM.
// Output format: salt (32 bytes) || nonce (12 bytes) || ciphertext || tag
func EncryptKey(keyBytes []byte, passphrase []byte) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("passphrase: salt: %w", err)
	}

	dk, err := scrypt.Key(passphrase, salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, fmt.Errorf("passphrase: derive key: %w", err)
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, fmt.Errorf("passphrase: aes: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("passphrase: gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("passphrase: nonce: %w", err)
	}

	encrypted := gcm.Seal(nonce, nonce, keyBytes, nil)
	return append(salt, encrypted...), nil
}

// DecryptKey decrypts key bytes encrypted by EncryptKey.
func DecryptKey(data []byte, passphrase []byte) ([]byte, error) {
	if len(data) < saltSize+12+16 {
		return nil, fmt.Errorf("passphrase: data too short")
	}

	salt := data[:saltSize]
	rest := data[saltSize:]

	dk, err := scrypt.Key(passphrase, salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, fmt.Errorf("passphrase: derive key: %w", err)
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, fmt.Errorf("passphrase: aes: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("passphrase: gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := rest[:nonceSize], rest[nonceSize:]

	keyBytes, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("passphrase: wrong passphrase or corrupted key")
	}

	return keyBytes, nil
}
