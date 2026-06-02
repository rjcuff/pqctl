package keys

import (
	"encoding/pem"
	"fmt"
	"os"
)

// WritePEM encodes data as a PEM block and writes it to path.
func WritePEM(path, pemType string, data []byte) error {
	block := &pem.Block{
		Type:  pemType,
		Bytes: data,
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("pem: create %s: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, block); err != nil {
		return fmt.Errorf("pem: encode %s: %w", path, err)
	}
	return nil
}

// ReadPEM reads path and returns the first PEM block.
func ReadPEM(path string) (*pem.Block, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("pem: read %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("pem: no PEM data in %s", path)
	}
	return block, nil
}
