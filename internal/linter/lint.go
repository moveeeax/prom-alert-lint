package linter

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/promql/parser"
)

// promqlParser validates rule expressions. It uses the default (stable) PromQL
// feature set, matching a Prometheus server started without feature flags.
var promqlParser = parser.NewParser(parser.Options{})

// Level is the severity of a diagnostic.
type Level string

const (
	// Error marks a violation that fails the lint (non-zero exit).
	Error Level = "error"
	// Warning marks a soft issue; it fails the lint only with --strict.
	Warning Level = "warning"
	// Info marks a hint that is reported but never fails the lint.
	Info Level = "info"
	// Off drops a diagnostic entirely. It is only valid as an override.
	Off Level = "off"
)

// Codes lists every diagnostic code the rule linter can emit, in the order
// used by the README.
var Codes = []string{
	"invalid-promql", "trivial-expr", "missing-expr", "missing-for", "invalid-for",
	"missing-label", "missing-annotation", "missing-runbook", "duplicate-alert",
	"not-a-rule", "bad-severity", "bad-name", "parse-error", "read-error", "no-groups",
}

// ParseLevels parses repeated `code=level` overrides (level is error, warning,
// info or off). Codes not in known are rejected so a typo does not silently
// leave a check at its default level.
func ParseLevels(specs []string, known []string) (map[string]Level, error) {
	out := map[string]Level{}
	for _, s := range specs {
		code, lv, ok := strings.Cut(s, "=")
		if !ok {
			return nil, fmt.Errorf("level override %q: want code=error|warning|info|off", s)
		}
		code, lv = strings.TrimSpace(code), strings.TrimSpace(lv)
		if !contains(known, code) {
			return nil, fmt.Errorf("level override %q: unknown code %q", s, code)
		}
		switch Level(lv) {
		case Error, Warning, Info, Off:
			out[code] = Level(lv)
		default:
			return nil, fmt.Errorf("level override %q: unknown level %q (want error, warning, info or off)", s, lv)
		}
	}
	return out, nil
}

// Diagnostic is a single finding tied to a file and, where possible, a rule.
// Object is the "namespace/name" of the PrometheusRule the rule came from,
// empty for plain rule files. Suggestion is an optional hint on how to fix it.
type Diagnostic struct {
	File       string `json:"file"`
	Line       int    `json:"line,omitempty"`
	Object     string `json:"object,omitempty"`
	Group      string `json:"group,omitempty"`
	Rule       string `json:"rule,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Code       string `json:"code"`
	Level      Level  `json:"level"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion,omitempty"`
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
	// RequireRunbook flags alerts with neither a `runbook_url` nor a
	// `runbook` annotation.
	RequireRunbook bool
	// SkipNonRules drops the no-groups warning for valid YAML that holds no
	// rule groups, for globs over mixed config directories.
	SkipNonRules bool
	// Levels overrides the level of individual codes; Off drops the code.
	Levels map[string]Level
	// Strict makes warnings count towards a non-zero exit code. Info-level
	// diagnostics never do.
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
	seen  map[string]string // alert name + static labels -> file:line first seen
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

// Infos counts info-level diagnostics.
func (l *Linter) Infos() int { return l.count(Info) }

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
// --strict). Info-level diagnostics never affect it.
func (l *Linter) ExitCode() int {
	if l.Errors() > 0 || (l.cfg.Strict && l.Warnings() > 0) {
		return 1
	}
	return 0
}

// add records d after applying any level override for its code.
func (l *Linter) add(d Diagnostic) {
	if lv, ok := l.cfg.Levels[d.Code]; ok {
		if lv == Off {
			return
		}
		d.Level = lv
	}
	l.diags = append(l.diags, d)
}

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

// LintReader lints a rule stream such as stdin. name is used for diagnostics.
func (l *Linter) LintReader(name string, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		l.add(Diagnostic{File: name, Code: "read-error", Level: Error, Message: err.Error()})
		return err
	}
	l.LintBytes(name, data)
	return nil
}

// LintBytes lints an in-memory rule file, which may hold several YAML
// documents and PrometheusRule manifests. name is used for diagnostics; it
// does no I/O, which keeps the check set unit-testable without touching disk.
func (l *Linter) LintBytes(name string, data []byte) {
	l.files++
	docs, err := ParseDocuments(data)
	if err != nil {
		l.add(Diagnostic{File: name, Line: errLine(err), Code: "parse-error", Level: Error, Message: err.Error(),
			Suggestion: "fix the YAML syntax; Prometheus will refuse to load this file"})
	}
	groups, objects := 0, 0
	for _, doc := range docs {
		if doc.Kind == DocOtherObject {
			objects++
			continue
		}
		if doc.Kind == DocPrometheusRule {
			objects++
		}
		for _, g := range doc.Groups {
			groups++
			for _, r := range g.Rules {
				l.rules++
				l.checkRule(name, doc.Object, g, r)
			}
		}
	}
	// Kubernetes manifests without rules are expected in Helm output, so only
	// plain YAML without groups draws the warning.
	if err == nil && groups == 0 && objects == 0 && !l.cfg.SkipNonRules {
		l.add(Diagnostic{File: name, Code: "no-groups", Level: Warning,
			Message:    "file contains no rule groups",
			Suggestion: "pass --skip-non-rules if this is not meant to be a rule file"})
	}
}

func (l *Linter) checkRule(file, object string, g RuleGroup, r Rule) {
	base := Diagnostic{File: file, Line: r.Line, Object: object, Group: g.Name, Rule: r.Name(), Kind: r.Kind()}
	emit := func(code string, lv Level, msg, fix string) {
		d := base
		d.Code, d.Level, d.Message, d.Suggestion = code, lv, msg, fix
		l.add(d)
	}

	kind := r.Kind()
	if kind == "" {
		emit("not-a-rule", Error, "rule is neither an alerting rule (`alert`) nor a recording rule (`record`), or sets both",
			"set exactly one of `alert` or `record`")
		return
	}

	// PromQL: must be present, parse, and (for alerts) be non-trivial.
	if r.Expr == "" {
		emit("missing-expr", Error, "rule has no `expr`", "")
	} else if kind == "alert" || l.cfg.CheckRecordExpr {
		if expr, err := promqlParser.ParseExpr(r.Expr); err != nil {
			emit("invalid-promql", Error, fmt.Sprintf("PromQL does not parse: %v", err), "")
		} else if kind == "alert" && isTrivial(expr) {
			emit("trivial-expr", Error, "alert expression is a constant and will always or never fire",
				"compare a metric against the threshold, e.g. `up == 0`; use `vector(1)` for a deliberate always-firing watchdog")
		}
	}

	if kind == "record" {
		return
	}

	// Alert-only hygiene checks.
	if r.For == "" {
		if l.cfg.RequireFor {
			emit("missing-for", Error, "alert has no `for`; it fires on a single scrape",
				"add e.g. `for: 5m` so the condition must hold before firing")
		}
	} else if _, err := model.ParseDuration(r.For); err != nil {
		emit("invalid-for", Error, fmt.Sprintf("`for: %s` is not a valid duration: %v", r.For, err),
			"use a Prometheus duration such as `30s`, `5m` or `1h`")
	}

	for _, lbl := range l.cfg.RequiredLabels {
		if r.Labels[lbl] == "" {
			fix := fmt.Sprintf("add `labels: { %s: ... }`", lbl)
			if lbl == "severity" {
				fix = "add `labels: { severity: warning }` (or critical/info)"
			}
			emit("missing-label", Error, fmt.Sprintf("required label %q is missing or empty", lbl), fix)
		}
	}
	for _, an := range l.cfg.RequiredAnnotations {
		if r.Annotations[an] == "" {
			emit("missing-annotation", Error, fmt.Sprintf("required annotation %q is missing or empty", an),
				fmt.Sprintf("add `annotations: { %s: ... }`", an))
		}
	}
	if l.cfg.RequireRunbook && r.Annotations["runbook_url"] == "" && r.Annotations["runbook"] == "" {
		emit("missing-runbook", Error, "alert has no `runbook_url` (or `runbook`) annotation; responders have nothing to open",
			"add `annotations: { runbook_url: https://... }`")
	}

	if sev := r.Labels["severity"]; sev != "" && len(l.cfg.SeverityValues) > 0 && !contains(l.cfg.SeverityValues, sev) {
		emit("bad-severity", Warning, fmt.Sprintf("severity %q is not one of %v", sev, l.cfg.SeverityValues), "")
	}

	if l.cfg.NamePattern != nil && !l.cfg.NamePattern.MatchString(r.Alert) {
		emit("bad-name", Warning, fmt.Sprintf("alert name %q does not match %s", r.Alert, l.cfg.NamePattern), "")
	}

	// The same name with different static labels is legal tiering (e.g. a
	// warning and a critical variant), so the key includes the labels.
	key := alertKey(r)
	if where, ok := l.seen[key]; ok {
		emit("duplicate-alert", Error, fmt.Sprintf("alert %q with the same labels already defined at %s", r.Alert, where),
			"remove one copy, or give the variants different labels (e.g. severity)")
	} else {
		l.seen[key] = fmt.Sprintf("%s:%d", file, r.Line)
	}
}

// alertKey identifies an alert by its name and static labels.
func alertKey(r Rule) string {
	names := make([]string, 0, len(r.Labels))
	for k := range r.Labels {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString(r.Alert)
	for _, k := range names {
		fmt.Fprintf(&b, "\x00%s=%s", k, r.Labels[k])
	}
	return b.String()
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
