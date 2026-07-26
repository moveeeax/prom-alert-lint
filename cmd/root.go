// Package cmd wires the prom-alert-lint command-line interface.
package cmd

import (
	"github.com/spf13/cobra"
)

// version is overridable at build time with -ldflags.
var version = "dev"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "prom-alert-lint",
		Short: "Lint Prometheus alerting rules before they page (or fail to)",
		Long: "prom-alert-lint parses Prometheus rule files and flags broken or sloppy\n" +
			"alerting rules: unparseable or trivial PromQL, a missing `for`, missing\n" +
			"severity labels, missing summary/description annotations and duplicate\n" +
			"alert names. It exits non-zero on violations so it fits straight into CI.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newLintCmd())
	return root
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	if err := newRootCmd().Execute(); err != nil {
		return 2
	}
	return exitCode
}
