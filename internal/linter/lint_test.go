package linter

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// codes returns the set of diagnostic codes produced for a rule file.
func lintCodes(t *testing.T, cfg Config, yaml string) []string {
	t.Helper()
	l := New(cfg)
	l.LintBytes("test.yml", []byte(yaml))
	var out []string
	for _, d := range l.Diagnostics() {
		out = append(out, string(d.Level)+":"+d.Code)
	}
	return out
}

func has(codes []string, want string) bool {
	for _, c := range codes {
		if c == want {
			return true
		}
	}
	return false
}

func TestGoodRuleIsClean(t *testing.T) {
	const good = `
groups:
  - name: ok
    rules:
      - alert: HighErrorRate
        expr: sum(rate(errors_total[5m])) > 10
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "s"
          description: "d"
`
	l := New(DefaultConfig())
	l.LintBytes("good.yml", []byte(good))
	if got := l.Errors(); got != 0 {
		t.Fatalf("expected no errors, got %d: %+v", got, l.Diagnostics())
	}
	if l.ExitCode() != 0 {
		t.Fatalf("expected exit 0, got %d", l.ExitCode())
	}
	if l.Rules() != 1 {
		t.Fatalf("expected 1 rule, got %d", l.Rules())
	}
}

func TestMissingForLabelAnnotation(t *testing.T) {
	const bad = `
groups:
  - name: sloppy
    rules:
      - alert: NoMeta
        expr: up == 0
`
	codes := lintCodes(t, DefaultConfig(), bad)
	for _, want := range []string{"error:missing-for", "error:missing-label", "error:missing-annotation"} {
		if !has(codes, want) {
			t.Errorf("expected %s, got %v", want, codes)
		}
	}
	// summary and description are both required -> two missing-annotation.
	n := 0
	for _, c := range codes {
		if c == "error:missing-annotation" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("expected 2 missing-annotation diagnostics, got %d", n)
	}
}

func TestInvalidPromQL(t *testing.T) {
	const bad = `
groups:
  - name: g
    rules:
      - alert: Broken
        expr: rate(http_requests_total[5m]) >
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: s
          description: d
`
	codes := lintCodes(t, DefaultConfig(), bad)
	if !has(codes, "error:invalid-promql") {
		t.Fatalf("expected invalid-promql, got %v", codes)
	}
}

func TestTrivialExpr(t *testing.T) {
	const bad = `
groups:
  - name: g
    rules:
      - alert: AlwaysOn
        expr: "1"
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: s
          description: d
`
	codes := lintCodes(t, DefaultConfig(), bad)
	if !has(codes, "error:trivial-expr") {
		t.Fatalf("expected trivial-expr, got %v", codes)
	}
}

func TestDuplicateAlertName(t *testing.T) {
	const bad = `
groups:
  - name: g
    rules:
      - alert: Dup
        expr: up == 0
        for: 5m
        labels: {severity: warning}
        annotations: {summary: s, description: d}
      - alert: Dup
        expr: up == 1
        for: 5m
        labels: {severity: warning}
        annotations: {summary: s, description: d}
`
	codes := lintCodes(t, DefaultConfig(), bad)
	if !has(codes, "error:duplicate-alert") {
		t.Fatalf("expected duplicate-alert, got %v", codes)
	}
}

func TestDuplicateAcrossFiles(t *testing.T) {
	one := `
groups: [{name: a, rules: [{alert: Same, expr: up == 0, for: 5m, labels: {severity: warning}, annotations: {summary: s, description: d}}]}]
`
	two := `
groups: [{name: b, rules: [{alert: Same, expr: up == 1, for: 5m, labels: {severity: warning}, annotations: {summary: s, description: d}}]}]
`
	l := New(DefaultConfig())
	l.LintBytes("one.yml", []byte(one))
	l.LintBytes("two.yml", []byte(two))
	found := false
	for _, d := range l.Diagnostics() {
		if d.Code == "duplicate-alert" && d.File == "two.yml" {
			found = true
			if !strings.Contains(d.Message, "one.yml") {
				t.Errorf("duplicate message should point at the first file, got %q", d.Message)
			}
		}
	}
	if !found {
		t.Fatalf("expected cross-file duplicate-alert, got %+v", l.Diagnostics())
	}
}

func TestConfigurableLabels(t *testing.T) {
	const y = `
groups:
  - name: g
    rules:
      - alert: A
        expr: up == 0
        for: 5m
        labels: {severity: warning}
        annotations: {summary: s, description: d}
`
	cfg := DefaultConfig()
	cfg.RequiredLabels = []string{"severity", "team"}
	codes := lintCodes(t, cfg, y)
	if !has(codes, "error:missing-label") {
		t.Fatalf("expected missing-label for team, got %v", codes)
	}
	// Without the extra requirement it should be clean.
	if c := lintCodes(t, DefaultConfig(), y); c != nil {
		t.Fatalf("expected clean with default config, got %v", c)
	}
}

func TestRequireForToggle(t *testing.T) {
	const y = `
groups:
  - name: g
    rules:
      - alert: A
        expr: up == 0
        labels: {severity: warning}
        annotations: {summary: s, description: d}
`
	if c := lintCodes(t, DefaultConfig(), y); !has(c, "error:missing-for") {
		t.Fatalf("expected missing-for by default, got %v", c)
	}
	cfg := DefaultConfig()
	cfg.RequireFor = false
	if c := lintCodes(t, cfg, y); has(c, "error:missing-for") {
		t.Fatalf("did not expect missing-for when disabled, got %v", c)
	}
}

func TestInvalidForDuration(t *testing.T) {
	const y = `
groups:
  - name: g
    rules:
      - alert: A
        expr: up == 0
        for: 5minutes
        labels: {severity: warning}
        annotations: {summary: s, description: d}
`
	if c := lintCodes(t, DefaultConfig(), y); !has(c, "error:invalid-for") {
		t.Fatalf("expected invalid-for, got %v", c)
	}
}

func TestSeverityValuesWarning(t *testing.T) {
	const y = `
groups:
  - name: g
    rules:
      - alert: A
        expr: up == 0
        for: 5m
        labels: {severity: sev1}
        annotations: {summary: s, description: d}
`
	cfg := DefaultConfig()
	cfg.SeverityValues = []string{"info", "warning", "critical"}
	c := lintCodes(t, cfg, y)
	if !has(c, "warning:bad-severity") {
		t.Fatalf("expected bad-severity warning, got %v", c)
	}
}

func TestNamePattern(t *testing.T) {
	const y = `
groups:
  - name: g
    rules:
      - alert: bad_name
        expr: up == 0
        for: 5m
        labels: {severity: warning}
        annotations: {summary: s, description: d}
`
	cfg := DefaultConfig()
	cfg.NamePattern = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)
	if c := lintCodes(t, cfg, y); !has(c, "warning:bad-name") {
		t.Fatalf("expected bad-name warning, got %v", c)
	}
}

func TestStrictExitCode(t *testing.T) {
	const y = `
groups:
  - name: g
    rules:
      - alert: A
        expr: up == 0
        for: 5m
        labels: {severity: sev1}
        annotations: {summary: s, description: d}
`
	cfg := DefaultConfig()
	cfg.SeverityValues = []string{"warning", "critical"}
	cfg.Strict = true
	l := New(cfg)
	l.LintBytes("t.yml", []byte(y))
	if l.Errors() != 0 {
		t.Fatalf("expected no hard errors, got %d", l.Errors())
	}
	if l.ExitCode() != 1 {
		t.Fatalf("expected exit 1 under strict with a warning, got %d", l.ExitCode())
	}
}

func TestParseError(t *testing.T) {
	c := lintCodes(t, DefaultConfig(), "groups: [ this: is: not: valid")
	if !has(c, "error:parse-error") {
		t.Fatalf("expected parse-error, got %v", c)
	}
}

func TestNotARule(t *testing.T) {
	const y = `
groups:
  - name: g
    rules:
      - expr: up == 0
`
	if c := lintCodes(t, DefaultConfig(), y); !has(c, "error:not-a-rule") {
		t.Fatalf("expected not-a-rule, got %v", c)
	}
}

func TestRecordingRuleExprChecked(t *testing.T) {
	const y = `
groups:
  - name: g
    rules:
      - record: job:bad
        expr: sum(rate(x[5m]) >
`
	if c := lintCodes(t, DefaultConfig(), y); !has(c, "error:invalid-promql") {
		t.Fatalf("expected invalid-promql on recording rule, got %v", c)
	}
	// A valid recording rule must not draw alert-only diagnostics.
	const ok = `
groups:
  - name: g
    rules:
      - record: job:ok
        expr: sum(rate(x[5m]))
`
	l := New(DefaultConfig())
	l.LintBytes("t.yml", []byte(ok))
	if l.Errors() != 0 {
		t.Fatalf("recording rule should be clean, got %+v", l.Diagnostics())
	}
}

func TestJSONReport(t *testing.T) {
	const y = `
groups:
  - name: g
    rules:
      - alert: A
        expr: up == 0
`
	l := New(DefaultConfig())
	l.LintBytes("t.yml", []byte(y))
	var buf bytes.Buffer
	if err := l.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("json output does not round-trip: %v", err)
	}
	if rep.Summary.Errors == 0 {
		t.Fatalf("expected errors in summary, got %+v", rep.Summary)
	}
	if len(rep.Diagnostics) == 0 || rep.Diagnostics[0].File != "t.yml" {
		t.Fatalf("expected diagnostics referencing file, got %+v", rep.Diagnostics)
	}
}

func TestDiagnosticsIncludeFileAndAlert(t *testing.T) {
	const y = `
groups:
  - name: g
    rules:
      - alert: NeedsMeta
        expr: up == 0
`
	l := New(DefaultConfig())
	l.LintBytes("rules.yml", []byte(y))
	for _, d := range l.Diagnostics() {
		if d.File != "rules.yml" {
			t.Errorf("diagnostic missing file: %+v", d)
		}
		if d.Rule != "NeedsMeta" {
			t.Errorf("diagnostic missing alert name: %+v", d)
		}
		if d.Line == 0 {
			t.Errorf("diagnostic missing line: %+v", d)
		}
	}
}
