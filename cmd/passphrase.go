package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/rjcuff/pqctl/crypto"
	"github.com/rjcuff/pqctl/keys"
	"golang.org/x/term"
)

// readPassphrase reads a passphrase from the terminal without echoing.
func readPassphrase(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	return pass, nil
}

// loadPrivateKey reads a PEM key file and decrypts it if passphrase-protected.
func loadPrivateKey(path string) ([]byte, error) {
	block, err := keys.ReadPEM(path)
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(block.Type, "ENCRYPTED ") {
		return block.Bytes, nil
	}

	pass, err := readPassphrase("Enter passphrase: ")
	if err != nil {
		return nil, err
	}

	keyBytes, err := crypto.DecryptKey(block.Bytes, pass)
	if err != nil {
		return nil, err
	}

	return keyBytes, nil
}
