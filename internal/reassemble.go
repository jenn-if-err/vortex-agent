package internal

import (
	"context"
	"strings"

	"cloud.google.com/go/spanner"
	"google.golang.org/api/iterator"
)

// ReassemblePrompt is a helper that wraps ReassembleSession and returns the reassembled string and error.
func ReassemblePrompt(ctx context.Context, client *spanner.Client, id string) (string, error) {
	resultCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go ReassembleSession(ctx, client, id, resultCh, errCh)
	select {
	case result := <-resultCh:
		return result, nil
	case err := <-errCh:
		return "", err
	}
}

func ReassembleSession(ctx context.Context, client *spanner.Client, id string, resultCh chan<- string, errCh chan<- error) {
	stmt := spanner.Statement{
		SQL:    `SELECT idx, content FROM llm_prompts WHERE id=@id ORDER BY idx ASC`,
		Params: map[string]interface{}{"id": id},
	}
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()

	var reassembled strings.Builder
	for {
		row, err := iter.Next()
		if err != nil {
			if err == iterator.Done {
				break
			}
			errCh <- err
			return
		}
		var idx int64
		var content string
		if err := row.Columns(&idx, &content); err != nil {
			errCh <- err
			return
		}
		reassembled.WriteString(content)
	}
	resultCh <- reassembled.String()
}
