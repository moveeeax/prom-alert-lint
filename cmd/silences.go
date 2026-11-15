package cmd

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/common/model"
	"github.com/spf13/cobra"

	"github.com/moveeeax/prom-alert-lint/internal/linter"
	"github.com/moveeeax/prom-alert-lint/internal/silences"
)

func newSilencesCmd() *cobra.Command {
	var (
		alertmanager string
		prometheus   string
		format       string
		sortBy       string
		maxAge       string
		neverExpire  string
		lookback     string
		broadLabels  []string
		ignoreLabels []string
		headers      []string
		levels       []string
		timeout      time.Duration
		strict       bool
	)

	cmd := &cobra.Command{
		Use:   "silences --alertmanager <url> [flags]",
		Short: "Audit live Alertmanager silences",
		Long: "Read silences and alerts from the Alertmanager API v2 and report silences\n" +
			"that never expire, have been active longer than --max-age, use over-broad\n" +
			"matchers, mute more than their comment names, or match nothing. With\n" +
			"--prometheus, silences that match no current alert are also checked\n" +
			"against the ALERTS history over --lookback.",
		Example: "  prom-alert-lint silences --alertmanager http://localhost:9093\n" +
			"  prom-alert-lint silences --alertmanager http://am:9093 --prometheus http://prom:9090 --max-age 30d --format markdown",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if alertmanager == "" {
				return fmt.Errorf("--alertmanager is required")
			}
			switch format {
			case "text", "table", "json", "markdown":
			default:
				return fmt.Errorf("unknown --format %q (want table, json or markdown)", format)
			}
			if sortBy != "age" && sortBy != "creator" {
				return fmt.Errorf("unknown --sort %q (want age or creator)", sortBy)
			}
			lv, err := linter.ParseLevels(levels, silences.Codes)
			if err != nil {
				return err
			}
			cfg := silences.Config{
				Now:          time.Now(),
				BroadLabels:  broadLabels,
				Prometheus:   prometheus,
				IgnoreLabels: ignoreLabels,
				Levels:       lv,
				Strict:       strict,
				SortBy:       sortBy,
			}
			for _, d := range []struct {
				flag string
				val  string
				dst  *time.Duration
			}{
				{"--max-age", maxAge, &cfg.MaxAge},
				{"--never-expiring-after", neverExpire, &cfg.NeverExpiringAfter},
				{"--lookback", lookback, &cfg.Lookback},
			} {
				md, err := model.ParseDuration(d.val)
				if err != nil {
					return fmt.Errorf("invalid %s: %w", d.flag, err)
				}
				*d.dst = time.Duration(md)
			}
			hdr := http.Header{}
			for _, h := range headers {
				k, v, ok := strings.Cut(h, ":")
				if !ok || strings.TrimSpace(k) == "" {
					return fmt.Errorf("invalid --header %q (want \"Name: value\")", h)
				}
				hdr.Add(strings.TrimSpace(k), strings.TrimSpace(v))
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			client := &silences.Client{HTTP: &http.Client{}, Headers: hdr}
			rep, err := silences.Run(ctx, client, alertmanager, cfg)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			switch format {
			case "json":
				if err := rep.WriteJSON(out); err != nil {
					return err
				}
			case "markdown":
				rep.WriteMarkdown(out, cfg.Now)
			default:
				rep.WriteText(out, cfg.Now)
			}
			exitCode = rep.ExitCode()
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&alertmanager, "alertmanager", "", "Alertmanager base URL, e.g. http://localhost:9093 (userinfo is sent as basic auth)")
	f.StringVar(&prometheus, "prometheus", "", "Prometheus base URL for the never-fired check (optional)")
	f.StringVar(&format, "format", "table", "output format: table, json or markdown")
	f.StringVar(&sortBy, "sort", "age", "order silences by age (oldest first) or creator")
	f.StringVar(&maxAge, "max-age", "30d", "how long a silence may stay active before it is stale")
	f.StringVar(&neverExpire, "never-expiring-after", "1y", "flag silences ending further away than this; 0 disables")
	f.StringVar(&lookback, "lookback", "30d", "ALERTS history window for --prometheus")
	f.StringArrayVar(&broadLabels, "broad-label", silences.DefaultBroadLabels, "label that does not narrow a silence on its own (repeatable)")
	f.StringArrayVar(&ignoreLabels, "ignore-label", nil, "label left out of the ALERTS history query, e.g. an external label (repeatable)")
	f.StringArrayVar(&headers, "header", nil, "extra HTTP header \"Name: value\" for both APIs (repeatable)")
	f.StringArrayVar(&levels, "level", nil, "override a check's level: code=error|warning|info|off (repeatable)")
	f.DurationVar(&timeout, "timeout", 30*time.Second, "timeout for all API requests")
	f.BoolVar(&strict, "strict", false, "treat warnings as failures (non-zero exit); info never fails")
	return cmd
}
