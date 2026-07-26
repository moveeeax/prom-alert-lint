package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/moveeeax/prom-alert-lint/internal/linter"
)

// exitCode is set by the lint command and read back by Execute.
var exitCode int

func newLintCmd() *cobra.Command {
	var (
		format      string
		requireFor  bool
		reqLabels   []string
		reqAnnots   []string
		sevValues   []string
		namePattern string
		strict      bool
		recordExpr  bool
	)

	cmd := &cobra.Command{
		Use:   "lint [flags] <file|glob>...",
		Short: "Lint one or more Prometheus rule files",
		Example: "  prom-alert-lint lint rules/*.yml --require-label severity\n" +
			"  prom-alert-lint lint examples/bad.yml --format json",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "text" && format != "json" {
				return fmt.Errorf("unknown --format %q (want text or json)", format)
			}

			cfg := linter.Config{
				RequireFor:          requireFor,
				RequiredLabels:      reqLabels,
				RequiredAnnotations: reqAnnots,
				SeverityValues:      sevValues,
				CheckRecordExpr:     recordExpr,
				Strict:              strict,
			}
			if namePattern != "" {
				re, err := regexp.Compile(namePattern)
				if err != nil {
					return fmt.Errorf("invalid --name-pattern: %w", err)
				}
				cfg.NamePattern = re
			}

			paths, err := expandPaths(args)
			if err != nil {
				return err
			}
			if len(paths) == 0 {
				return fmt.Errorf("no files matched %v", args)
			}

			l := linter.New(cfg)
			for _, p := range paths {
				_ = l.LintFile(p)
			}

			switch format {
			case "json":
				if err := l.WriteJSON(cmd.OutOrStdout()); err != nil {
					return err
				}
			default:
				l.WriteText(cmd.OutOrStdout())
			}
			exitCode = l.ExitCode()
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&format, "format", "text", "output format: text or json")
	f.BoolVar(&requireFor, "require-for", true, "require a `for` clause on alerts")
	f.StringArrayVar(&reqLabels, "require-label", []string{"severity"}, "label that must be present on every alert (repeatable)")
	f.StringArrayVar(&reqAnnots, "require-annotation", []string{"summary", "description"}, "annotation that must be present on every alert (repeatable)")
	f.StringArrayVar(&sevValues, "severity-value", nil, "allowed value for the severity label (repeatable); empty disables the check")
	f.StringVar(&namePattern, "name-pattern", "", "regexp every alert name must match (empty disables the check)")
	f.BoolVar(&recordExpr, "check-record-expr", true, "validate PromQL of recording rules too")
	f.BoolVar(&strict, "strict", false, "treat warnings as failures (non-zero exit)")
	return cmd
}

// expandPaths resolves shell-style globs and de-duplicates the result while
// preserving order. A literal path that does not exist is kept so the linter
// reports a read-error for it.
func expandPaths(args []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, a := range args {
		matches, err := filepath.Glob(a)
		if err != nil {
			return nil, fmt.Errorf("bad pattern %q: %w", a, err)
		}
		if len(matches) == 0 {
			if _, statErr := os.Stat(a); statErr == nil {
				add(a)
			} else if !hasMeta(a) {
				add(a) // literal miss: let the linter emit a read-error
			}
			continue
		}
		for _, m := range matches {
			add(m)
		}
	}
	return out, nil
}

func hasMeta(p string) bool {
	return regexp.MustCompile(`[*?[]`).MatchString(p)
}
