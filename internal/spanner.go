package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	spanner "cloud.google.com/go/spanner"
)

func NewSpannerClient(ctx context.Context, db string) (*spanner.Client, error) {
	client, err := spanner.NewClient(ctx, db)
	if err != nil {
		return nil, err
	}
	return client, nil
}

type SpannerPayload struct {
	Table string   `json:"table"`
	Cols  []string `json:"cols"`
	Vals  []any    `json:"vals"`
}

func Send(token string, payload []SpannerPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	url := "https://api.alphaus.cloud/webhook/2f61f4e1-6bef-4b12-9b60-075a7c6f83f6/OfMdbxhgBviahkdZxwEJ/vortex"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	// req.Header.Set("Authorization", token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}

	return nil
}
