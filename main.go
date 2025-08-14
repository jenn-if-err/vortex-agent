//go:build linux

//go:generate sh bpf2go.sh

package main

import (
	goflag "flag"
	"log"
	"os"

	"github.com/flowerinthenight/vortex-agent/subcmds"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
)

var (
	rootCmd = &cobra.Command{
		Use:   "vortex-agent",
		Short: "Main agent for Vortex",
		Long:  `Main agent for Vortex.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			goflag.Parse() // for cobra + glog flags
		},
		Run: func(cmd *cobra.Command, args []string) {
			glog.Info("invalid cmd, please run -h")
		},
	}
)

func init() {
	rootCmd.Flags().SortFlags = false
	rootCmd.PersistentFlags().SortFlags = false
	rootCmd.AddCommand(
		subcmds.RunCmd(),
		subcmds.TestCmd(),
		subcmds.ReassembleCmd(),
	)

	// For cobra + glog flags.
	flag.CommandLine.AddGoFlagSet(goflag.CommandLine)
}

func main() {
	log.SetOutput(os.Stdout)
	cobra.EnableCommandSorting = false
	rootCmd.Execute()
}
