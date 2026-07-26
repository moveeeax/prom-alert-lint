package linter

import (
	"fmt"
	"os"
	"regexp"
	"sort"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/promql/parser"
)

// Level is the severity of a diagnostic.
type Level string

const (
	// Error marks a violation that fails the lint (non-zero exit).
	Error Level = "error"
	// Warning marks a soft issue; it fails the lint only with --strict.
	Warning Level = "warning"
)

// Diagnostic is a single finding tied to a file and, where possible, a rule.
type Diagnostic struct {
	File    string `json:"file"`
	Line    int    `json:"line,omitempty"`
	Group   string `json:"group,omitempty"`
	Rule    string `json:"rule,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Code    string `json:"code"`
	Level   Level  `json:"level"`
	Message string `json:"message"`
}

// Config controls which checks run and how strict they are.
type Config struct {
	// RequireFor flags alert rules that lack a `for` clause.
	RequireFor bool
	// RequiredLabels must be present (and non-empty) on every alert.
	RequiredLabels []string
	// RequiredAnnotations must be present (and non-empty) on every alert.
	RequiredAnnotations []string
	// SeverityValues, when non-empty, restricts the allowed values of the
	// `severity` label.
	SeverityValues []string
	// NamePattern, when set, is a regexp every alert name must match.
	NamePattern *regexp.Regexp
	// CheckRecordExpr also validates PromQL of recording rules.
	CheckRecordExpr bool
	// Strict makes warnings count towards a non-zero exit code.
	Strict bool
}

// DefaultConfig returns the conventional defaults: require `for`, a `severity`
// label and `summary`/`description` annotations, and validate recording-rule
// expressions too.
func DefaultConfig() Config {
	return Config{
		RequireFor:          true,
		RequiredLabels:      []string{"severity"},
		RequiredAnnotations: []string{"summary", "description"},
		CheckRecordExpr:     true,
	}
}

// Linter accumulates diagnostics across one or more rule files and tracks alert
// names so duplicates across files are caught.
type Linter struct {
	cfg   Config
	seen  map[string]string // alert name -> file:line first seen
	diags []Diagnostic
	files int
	rules int
}

// New returns a Linter using cfg.
func New(cfg Config) *Linter {
	return &Linter{cfg: cfg, seen: map[string]string{}}
}

// Diagnostics returns the accumulated findings, sorted for stable output.
func (l *Linter) Diagnostics() []Diagnostic { return l.diags }

// Files returns the number of files linted.
func (l *Linter) Files() int { return l.files }

// Rules returns the number of rules inspected.
func (l *Linter) Rules() int { return l.rules }

// Errors counts error-level diagnostics.
func (l *Linter) Errors() int { return l.count(Error) }

// Warnings counts warning-level diagnostics.
func (l *Linter) Warnings() int { return l.count(Warning) }

func (l *Linter) count(lv Level) int {
	n := 0
	for _, d := range l.diags {
		if d.Level == lv {
			n++
		}
	}
	return n
}

// ExitCode is 0 when clean, 1 when there are errors (or warnings under
// --strict).
func (l *Linter) ExitCode() int {
	if l.Errors() > 0 || (l.cfg.Strict && l.Warnings() > 0) {
		return 1
	}
	return 0
}

func (l *Linter) add(d Diagnostic) { l.diags = append(l.diags, d) }

// LintFile reads and lints a file by path.
func (l *Linter) LintFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		l.add(Diagnostic{File: path, Code: "read-error", Level: Error, Message: err.Error()})
		return err
	}
	l.LintBytes(path, data)
	return nil
}

// LintBytes lints an in-memory rule file. name is used for diagnostics; it does
// no I/O, which keeps the check set unit-testable without touching disk.
func (l *Linter) LintBytes(name string, data []byte) {
	l.files++
	rf, err := ParseRuleFile(data)
	if err != nil {
		l.add(Diagnostic{File: name, Code: "parse-error", Level: Error, Message: err.Error()})
		return
	}
	if len(rf.Groups) == 0 {
		l.add(Diagnostic{File: name, Code: "no-groups", Level: Warning,
			Message: "file contains no rule groups"})
	}
	for _, g := range rf.Groups {
		for _, r := range g.Rules {
			l.rules++
			l.checkRule(name, g, r)
		}
	}
}

func (l *Linter) checkRule(file string, g RuleGroup, r Rule) {
	base := Diagnostic{File: file, Line: r.Line, Group: g.Name, Rule: r.Name(), Kind: r.Kind()}
	emit := func(code string, lv Level, msg string) {
		d := base
		d.Code, d.Level, d.Message = code, lv, msg
		l.add(d)
	}

	kind := r.Kind()
	if kind == "" {
		emit("not-a-rule", Error, "rule is neither an alerting rule (`alert`) nor a recording rule (`record`), or sets both")
		return
	}

	// PromQL: must be present, parse, and (for alerts) be non-trivial.
	if r.Expr == "" {
		emit("missing-expr", Error, "rule has no `expr`")
	} else if kind == "alert" || l.cfg.CheckRecordExpr {
		if expr, err := parser.ParseExpr(r.Expr); err != nil {
			emit("invalid-promql", Error, fmt.Sprintf("PromQL does not parse: %v", err))
		} else if kind == "alert" && isTrivial(expr) {
			emit("trivial-expr", Error, "alert expression is a constant and will always or never fire")
		}
	}

	if kind == "record" {
		return
	}

	// Alert-only hygiene checks.
	if r.For == "" {
		if l.cfg.RequireFor {
			emit("missing-for", Error, "alert has no `for`; it fires on a single scrape")
		}
	} else if _, err := model.ParseDuration(r.For); err != nil {
		emit("invalid-for", Error, fmt.Sprintf("`for: %s` is not a valid duration: %v", r.For, err))
	}

	for _, lbl := range l.cfg.RequiredLabels {
		if r.Labels[lbl] == "" {
			emit("missing-label", Error, fmt.Sprintf("required label %q is missing or empty", lbl))
		}
	}
	for _, an := range l.cfg.RequiredAnnotations {
		if r.Annotations[an] == "" {
			emit("missing-annotation", Error, fmt.Sprintf("required annotation %q is missing or empty", an))
		}
	}

	if sev := r.Labels["severity"]; sev != "" && len(l.cfg.SeverityValues) > 0 && !contains(l.cfg.SeverityValues, sev) {
		emit("bad-severity", Warning, fmt.Sprintf("severity %q is not one of %v", sev, l.cfg.SeverityValues))
	}

	if l.cfg.NamePattern != nil && !l.cfg.NamePattern.MatchString(r.Alert) {
		emit("bad-name", Warning, fmt.Sprintf("alert name %q does not match %s", r.Alert, l.cfg.NamePattern))
	}

	if where, ok := l.seen[r.Alert]; ok {
		emit("duplicate-alert", Error, fmt.Sprintf("alert name %q already defined at %s", r.Alert, where))
	} else {
		l.seen[r.Alert] = fmt.Sprintf("%s:%d", file, r.Line)
	}
}

// isTrivial reports whether an expression is a bare constant (number or string
// literal), which makes an alert fire always or never.
func isTrivial(expr parser.Expr) bool {
	switch expr.(type) {
	case *parser.NumberLiteral, *parser.StringLiteral:
		return true
	default:
		return false
	}
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// SortDiagnostics orders diagnostics by file, line and code for deterministic
// output.
func SortDiagnostics(ds []Diagnostic) {
	sort.SliceStable(ds, func(i, j int) bool {
		if ds[i].File != ds[j].File {
			return ds[i].File < ds[j].File
		}
		if ds[i].Line != ds[j].Line {
			return ds[i].Line < ds[j].Line
		}
		return ds[i].Code < ds[j].Code
	})
}
