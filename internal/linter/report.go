package linter

import (
	"encoding/json"
	"fmt"
	"io"
)

// Summary is a machine-readable roll-up of a lint run.
type Summary struct {
	Files    int `json:"files"`
	Rules    int `json:"rules"`
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
}

// Report is the JSON document emitted with --format json.
type Report struct {
	Summary     Summary      `json:"summary"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

// Report builds a serialisable report from the current state.
func (l *Linter) Report() Report {
	ds := append([]Diagnostic(nil), l.diags...)
	SortDiagnostics(ds)
	return Report{
		Summary: Summary{
			Files:    l.files,
			Rules:    l.rules,
			Errors:   l.Errors(),
			Warnings: l.Warnings(),
		},
		Diagnostics: ds,
	}
}

// WriteJSON emits the report as indented JSON.
func (l *Linter) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(l.Report())
}

// WriteText emits a human-readable report and returns whether any diagnostics
// were printed.
func (l *Linter) WriteText(w io.Writer) {
	rep := l.Report()
	for _, d := range rep.Diagnostics {
		loc := d.File
		if d.Line > 0 {
			loc = fmt.Sprintf("%s:%d", d.File, d.Line)
		}
		rule := d.Rule
		if rule == "" {
			rule = "-"
		}
		fmt.Fprintf(w, "%-7s %s  [%s] %s: %s\n", d.Level, loc, rule, d.Code, d.Message)
	}
	s := rep.Summary
	if s.Errors == 0 && s.Warnings == 0 {
		fmt.Fprintf(w, "OK: %d rule(s) across %d file(s), no issues\n", s.Rules, s.Files)
		return
	}
	fmt.Fprintf(w, "%d error(s), %d warning(s) in %d rule(s) across %d file(s)\n",
		s.Errors, s.Warnings, s.Rules, s.Files)
}
