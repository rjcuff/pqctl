package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// cloudClient talks to a moduli API instance. It only ever sends/receives
// ciphertext + metadata — encryption and decryption happen on the caller's
// side using the user's cloud passphrase.
type cloudClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func newCloudClient(baseURL, apiKey string) *cloudClient {
	return &cloudClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

type cloudKey struct {
	ID            string  `json:"id"`
	Algo          string  `json:"algo"`
	Fingerprint   string  `json:"fingerprint"`
	CiphertextB64 string  `json:"ciphertext"`
	CreatedAt     string  `json:"created_at"`
	RotationDueAt *string `json:"rotation_due_at,omitempty"`
}

type pushRequest struct {
	Algo          string  `json:"algo"`
	Fingerprint   string  `json:"fingerprint"`
	CiphertextB64 string  `json:"ciphertext"`
	RotationDueAt *string `json:"rotation_due_at,omitempty"`
}

type pushResponse struct {
	ID string `json:"id"`
}

type apiError struct {
	Error string `json:"error"`
}

func (c *cloudClient) do(method, path string, body any, out any) error {
	var reqBody io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("cloud: encode request: %w", err)
		}
		reqBody = bytes.NewReader(payload)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("cloud: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cloud: request to %s failed: %w", c.baseURL, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("cloud: read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr apiError
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Error != "" {
			return fmt.Errorf("cloud: %s (HTTP %d)", apiErr.Error, resp.StatusCode)
		}
		return fmt.Errorf("cloud: unexpected response (HTTP %d)", resp.StatusCode)
	}

	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("cloud: decode response: %w", err)
		}
	}
	return nil
}

func (c *cloudClient) push(req pushRequest) (string, error) {
	var resp pushResponse
	if err := c.do(http.MethodPost, "/keys", req, &resp); err != nil {
		return "", err
	}
	return resp.ID, nil
}

func (c *cloudClient) get(id string) (*cloudKey, error) {
	var key cloudKey
	if err := c.do(http.MethodGet, "/keys/"+id, nil, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

func (c *cloudClient) list() ([]cloudKey, error) {
	var keysList []cloudKey
	if err := c.do(http.MethodGet, "/keys", nil, &keysList); err != nil {
		return nil, err
	}
	return keysList, nil
}
