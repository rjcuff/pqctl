package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateMLDSA65(t *testing.T) {
	kp, err := GenerateMLDSA65()
	if err != nil {
		t.Fatalf("GenerateMLDSA65: %v", err)
	}
	if len(kp.PrivateKey) == 0 {
		t.Fatal("private key is empty")
	}
	if len(kp.PublicKey) == 0 {
		t.Fatal("public key is empty")
	}
	if bytes.Equal(kp.PrivateKey, kp.PublicKey) {
		t.Fatal("private and public keys are identical")
	}
}

func TestGenerateEd25519(t *testing.T) {
	kp, err := GenerateEd25519()
	if err != nil {
		t.Fatalf("GenerateEd25519: %v", err)
	}
	if len(kp.PrivateKey) == 0 {
		t.Fatal("private key is empty")
	}
	if len(kp.PublicKey) == 0 {
		t.Fatal("public key is empty")
	}
}

func TestGenerateMLKEM768(t *testing.T) {
	kp, err := GenerateMLKEM768()
	if err != nil {
		t.Fatalf("GenerateMLKEM768: %v", err)
	}
	if len(kp.PrivateKey) == 0 {
		t.Fatal("private key is empty")
	}
	if len(kp.PublicKey) == 0 {
		t.Fatal("public key is empty")
	}
}

func TestSignVerifyMLDSA65RoundTrip(t *testing.T) {
	kp, err := GenerateMLDSA65()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	msg := []byte("hello pqctl")

	sig, err := SignMLDSA65(kp.PrivateKey, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}

	if err := VerifyMLDSA65(kp.PublicKey, msg, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignVerifyMLDSA65TamperedMessage(t *testing.T) {
	kp, _ := GenerateMLDSA65()
	msg := []byte("original")
	sig, _ := SignMLDSA65(kp.PrivateKey, msg)

	tampered := []byte("tampered")
	if err := VerifyMLDSA65(kp.PublicKey, tampered, sig); err == nil {
		t.Fatal("expected verify to fail on tampered message")
	}
}

func TestSignVerifyMLDSA65WrongKey(t *testing.T) {
	kp1, _ := GenerateMLDSA65()
	kp2, _ := GenerateMLDSA65()
	msg := []byte("hello")
	sig, _ := SignMLDSA65(kp1.PrivateKey, msg)

	if err := VerifyMLDSA65(kp2.PublicKey, msg, sig); err == nil {
		t.Fatal("expected verify to fail with wrong public key")
	}
}

func TestEncryptDecryptMLKEM768RoundTrip(t *testing.T) {
	kp, err := GenerateMLKEM768()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	plaintext := []byte("secret message for post-quantum encryption")

	ciphertext, err := EncryptMLKEM768(kp.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decrypted, err := DecryptMLKEM768(kp.PrivateKey, ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted != original\ngot:  %q\nwant: %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptMLKEM768WrongKey(t *testing.T) {
	kp1, _ := GenerateMLKEM768()
	kp2, _ := GenerateMLKEM768()

	ciphertext, _ := EncryptMLKEM768(kp1.PublicKey, []byte("secret"))

	if _, err := DecryptMLKEM768(kp2.PrivateKey, ciphertext); err == nil {
		t.Fatal("expected decrypt to fail with wrong key")
	}
}

func TestEncryptDecryptMLKEM768LargeFile(t *testing.T) {
	kp, _ := GenerateMLKEM768()

	plaintext := make([]byte, 1024*1024) // 1MB
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := EncryptMLKEM768(kp.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("encrypt 1MB: %v", err)
	}

	decrypted, err := DecryptMLKEM768(kp.PrivateKey, ciphertext)
	if err != nil {
		t.Fatalf("decrypt 1MB: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("1MB round-trip failed")
	}
}
