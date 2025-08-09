package internal

import (
	"context"

	spanner "cloud.google.com/go/spanner"
)

func NewSpannerClient(ctx context.Context, db string) (*spanner.Client, error) {
	client, err := spanner.NewClient(ctx, db)
	if err != nil {
		return nil, err
	}
	return client, nil
}
