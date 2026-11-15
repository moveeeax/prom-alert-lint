package silences

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// WriteJSON emits the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText emits one block per silence: a header line with id, state,
// creator, age, end and matchers, the alerts it currently mutes, then its
// findings with "fix:" hints.
func (r *Report) WriteText(w io.Writer, now time.Time) {
	for _, s := range r.Silences {
		fmt.Fprintf(w, "%s  %-7s %-16s age %-5s ends in %-5s %s\n",
			shortID(s.ID), s.State, orDash(s.CreatedBy), human(now.Sub(s.StartsAt)), human(s.EndsAt.Sub(now)), s.Matchers)
		if len(s.Suppressed) > 0 {
			fmt.Fprintf(w, "  mutes %s\n", suppressedText(s.Suppressed))
		}
		for _, f := range s.Findings {
			fmt.Fprintf(w, "  %-7s %s: %s\n", f.Level, f.Code, f.Message)
			if f.Suggestion != "" {
				fmt.Fprintf(w, "    fix: %s\n", f.Suggestion)
			}
		}
	}
	fmt.Fprintln(w, r.summaryLine())
}

// WriteMarkdown emits a table of silences followed by the findings, for
// pasting into an issue or a review.
func (r *Report) WriteMarkdown(w io.Writer, now time.Time) {
	fmt.Fprintln(w, "| Silence | State | Created by | Age | Ends in | Matchers | Mutes | Findings |")
	fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- | --- | --- |")
	for _, s := range r.Silences {
		codes := make([]string, len(s.Findings))
		for i, f := range s.Findings {
			codes[i] = fmt.Sprintf("%s (%s)", f.Code, f.Level)
		}
		fmt.Fprintf(w, "| `%s` | %s | %s | %s | %s | `%s` | %s | %s |\n",
			shortID(s.ID), s.State, mdEscape(orDash(s.CreatedBy)), human(now.Sub(s.StartsAt)), human(s.EndsAt.Sub(now)),
			strings.ReplaceAll(s.Matchers, "|", `\|`), mdEscape(orDash(suppressedText(s.Suppressed))), orDash(strings.Join(codes, ", ")))
	}
	var lines []string
	for _, s := range r.Silences {
		for _, f := range s.Findings {
			l := fmt.Sprintf("- `%s` **%s** %s: %s", shortID(s.ID), f.Level, f.Code, mdEscape(f.Message))
			if f.Suggestion != "" {
				l += "; fix: " + mdEscape(f.Suggestion)
			}
			lines = append(lines, l)
		}
	}
	if len(lines) > 0 {
		fmt.Fprintln(w, "\n### Findings")
		fmt.Fprintln(w)
		fmt.Fprintln(w, strings.Join(lines, "\n"))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, r.summaryLine())
}

func (r *Report) summaryLine() string {
	s := r.Summary
	return fmt.Sprintf("%d error(s), %d warning(s), %d info in %d active/pending silence(s) (%d expired skipped)",
		s.Errors, s.Warnings, s.Infos, s.Silences, s.Expired)
}

func suppressedText(sup []Suppressed) string {
	parts := make([]string, len(sup))
	for i, s := range sup {
		name := s.Alertname
		if name == "" {
			name = "(no alertname)"
		}
		parts[i] = fmt.Sprintf("%s x%d", name, s.Count)
	}
	return strings.Join(parts, ", ")
}

// shortID keeps the first 8 characters of a silence UUID to keep lines
// short; the JSON output carries the full id.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func mdEscape(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ").Replace(s)
}
