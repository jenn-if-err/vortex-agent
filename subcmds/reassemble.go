package subcmds

import (
	"context"
	"fmt"
	"os"
	"strings"

	"cloud.google.com/go/spanner"
	"github.com/flowerinthenight/vortex-agent/internal"
	"github.com/spf13/cobra"
)

func ReassembleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reassemble",
		Short: "Reassemble packets or sessions from Spanner data",
		Long:  `Reassemble packets or sessions from Spanner data.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Example: reassemble for a given id (session/stream)
			if len(args) < 1 {
				fmt.Println("Usage: vortex-agent reassemble <id>")
				os.Exit(1)
			}
			id := args[0]
			ctx := context.Background()
			// TODO: Make DB string configurable
			db := "projects/alphaus-dashboard/instances/vortex-main/databases/main"
			client, err := internal.NewSpannerClient(ctx, db)
			if err != nil {
				fmt.Printf("Failed to create Spanner client: %v\n", err)
				os.Exit(1)
			}
			defer client.Close()

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
					if err.Error() == "iterator done" || strings.Contains(err.Error(), "StopIteration") {
						break
					}
					fmt.Printf("Query error: %v\n", err)
					os.Exit(1)
				}
				var idx, content string
				if err := row.Columns(&idx, &content); err != nil {
					fmt.Printf("Row parse error: %v\n", err)
					os.Exit(1)
				}
				reassembled.WriteString(content)
			}

			fmt.Println("Reassembled content:")
			fmt.Println(reassembled.String())
		},
	}

	cmd.Flags().SortFlags = false
	// TODO: Add flags as needed
	return cmd
}
