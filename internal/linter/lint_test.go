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

// TestPrometheus3Syntax pins PromQL behavior of the Prometheus 3.x parser.
// holt_winters was accepted by the 2.x parser; in 3.x it was renamed to the
// experimental double_exponential_smoothing, which the default (stable)
// parser rejects. Quoted UTF-8 metric and label names must keep parsing.
func TestPrometheus3Syntax(t *testing.T) {
	rule := func(expr string) string {
		return `
groups:
  - name: g
    rules:
      - alert: A
        expr: '` + expr + `'
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: s
          description: d
`
	}
	cases := []struct {
		name    string
		expr    string
		invalid bool
	}{
		{"utf8 metric name", `{"http.server.requests", job="api"} > 0`, false},
		{"utf8 label name", `up{"service.name"="api"} == 0`, false},
		{"holt_winters removed", `holt_winters(up[10m], 0.5, 0.5) > 0`, true},
		{"double_exponential_smoothing is experimental", `double_exponential_smoothing(up[10m], 0.5, 0.5) > 0`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			codes := lintCodes(t, DefaultConfig(), rule(tc.expr))
			if got := has(codes, "error:invalid-promql"); got != tc.invalid {
				t.Fatalf("invalid-promql = %v, want %v (codes %v)", got, tc.invalid, codes)
			}
		})
	}
}

func TestDuplicateTieringIsAllowed(t *testing.T) {
	const y = `
groups:
  - name: g
    rules:
      - alert: DiskFilling
        expr: disk_free < 0.2
        for: 5m
        labels: {severity: warning}
        annotations: {summary: s, description: d}
      - alert: DiskFilling
        expr: disk_free < 0.1
        for: 5m
        labels: {severity: critical}
        annotations: {summary: s, description: d}
`
	if c := lintCodes(t, DefaultConfig(), y); has(c, "error:duplicate-alert") {
		t.Fatalf("same name with different severity is tiering, not a duplicate: %v", c)
	}
}

func TestRequireRunbook(t *testing.T) {
	rule := func(annots string) string {
		return `
groups:
  - name: g
    rules:
      - alert: A
        expr: up == 0
        for: 5m
        labels: {severity: warning}
        annotations: {summary: s, description: d` + annots + `}
`
	}
	if c := lintCodes(t, DefaultConfig(), rule("")); has(c, "error:missing-runbook") {
		t.Fatalf("missing-runbook must be off by default, got %v", c)
	}
	cfg := DefaultConfig()
	cfg.RequireRunbook = true
	if c := lintCodes(t, cfg, rule("")); !has(c, "error:missing-runbook") {
		t.Fatalf("expected missing-runbook, got %v", c)
	}
	for _, a := range []string{", runbook_url: https://r/a", ", runbook: https://r/a"} {
		if c := lintCodes(t, cfg, rule(a)); c != nil {
			t.Fatalf("annotation %q should satisfy the check, got %v", a, c)
		}
	}
}

func TestLevelOverrides(t *testing.T) {
	const y = `
groups:
  - name: g
    rules:
      - alert: A
        expr: up == 0
        for: 5m
        labels: {severity: warning}
`
	lv, err := ParseLevels([]string{"missing-annotation=info", "missing-runbook=off"}, Codes)
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.RequireRunbook = true
	cfg.Levels = lv
	cfg.Strict = true
	l := New(cfg)
	l.LintBytes("t.yml", []byte(y))
	if l.Infos() != 2 || l.Errors() != 0 || l.Warnings() != 0 {
		t.Fatalf("want 2 info and nothing else, got %+v", l.Diagnostics())
	}
	if l.ExitCode() != 0 {
		t.Fatalf("info must not fail even under strict, got exit %d", l.ExitCode())
	}
	var buf bytes.Buffer
	l.WriteText(&buf)
	if !strings.Contains(buf.String(), "OK: 1 rule(s) across 1 file(s), 2 info") {
		t.Fatalf("unexpected summary:\n%s", buf.String())
	}
}

func TestParseLevelsRejectsBadInput(t *testing.T) {
	for _, s := range []string{"missing-for", "missing-for=fatal", "no-such-check=info"} {
		if _, err := ParseLevels([]string{s}, Codes); err == nil {
			t.Errorf("expected an error for %q", s)
		}
	}
}

func TestSuggestionInOutput(t *testing.T) {
	const y = `
groups:
  - name: g
    rules:
      - alert: A
        expr: up == 0
        labels: {severity: warning}
        annotations: {summary: s, description: d}
`
	l := New(DefaultConfig())
	l.LintBytes("t.yml", []byte(y))
	var text bytes.Buffer
	l.WriteText(&text)
	if !strings.Contains(text.String(), "\n  fix: add e.g. `for: 5m`") {
		t.Fatalf("text output lacks the fix line:\n%s", text.String())
	}
	var js bytes.Buffer
	if err := l.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(js.String(), `"suggestion": "add e.g.`) {
		t.Fatalf("json output lacks the suggestion:\n%s", js.String())
	}
}

func TestParseErrorLine(t *testing.T) {
	l := New(DefaultConfig())
	l.LintBytes("t.yml", []byte("groups:\n  - name: g\n    rules: [this is: not valid: mapping\n"))
	ds := l.Diagnostics()
	if len(ds) != 1 || ds[0].Code != "parse-error" {
		t.Fatalf("want one parse-error, got %+v", ds)
	}
	// yaml.v3 reports this error against line 2; the diagnostic must carry
	// the same line the parser names.
	if ds[0].Line != 2 || !strings.Contains(ds[0].Message, "line 2:") {
		t.Fatalf("parse-error line = %d, want 2 (%s)", ds[0].Line, ds[0].Message)
	}
}

func TestSkipNonRules(t *testing.T) {
	const y = "foo: bar\nbaz: [1, 2, 3]\n"
	if c := lintCodes(t, DefaultConfig(), y); !has(c, "warning:no-groups") {
		t.Fatalf("expected no-groups by default, got %v", c)
	}
	cfg := DefaultConfig()
	cfg.SkipNonRules = true
	if c := lintCodes(t, cfg, y); c != nil {
		t.Fatalf("expected silence with SkipNonRules, got %v", c)
	}
}

func TestMultiDocument(t *testing.T) {
	const y = `groups:
  - name: a
    rules:
      - alert: A
        expr: up == 0
        for: 5m
        labels: {severity: warning}
        annotations: {summary: s, description: d}
---
groups:
  - name: b
    rules:
      - alert: B
        expr: up == 0
`
	l := New(DefaultConfig())
	l.LintBytes("multi.yml", []byte(y))
	if l.Rules() != 2 {
		t.Fatalf("want 2 rules across both documents, got %d", l.Rules())
	}
	for _, d := range l.Diagnostics() {
		if d.Rule != "B" || d.Line != 13 {
			t.Fatalf("diagnostic should point at B on line 13 of the stream, got %+v", d)
		}
	}
}

const promRuleManifests = `# Source: chart/templates/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: unrelated
data:
  groups: "not rules"
---
# Source: chart/templates/rules.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: api
  namespace: monitoring
spec:
  groups:
    - name: api
      rules:
        - alert: ApiDown
          expr: up{job="api"} == 0
          labels:
            severity: critical
          annotations:
            summary: s
            description: d
---
`

func TestPrometheusRule(t *testing.T) {
	l := New(DefaultConfig())
	l.LintBytes("helm.yml", []byte(promRuleManifests))
	ds := l.Diagnostics()
	if l.Rules() != 1 || len(ds) != 1 {
		t.Fatalf("want one rule with one diagnostic, got %d rules: %+v", l.Rules(), ds)
	}
	d := ds[0]
	if d.Code != "missing-for" || d.Object != "monitoring/api" || d.Rule != "ApiDown" || d.Line != 19 {
		t.Fatalf("unexpected diagnostic %+v", d)
	}
	var buf bytes.Buffer
	l.WriteText(&buf)
	if !strings.Contains(buf.String(), "helm.yml:19  [monitoring/api ApiDown] missing-for") {
		t.Fatalf("text output should carry the object:\n%s", buf.String())
	}
}

func TestKubernetesListAndOtherKinds(t *testing.T) {
	const list = `apiVersion: v1
kind: List
items:
  - apiVersion: monitoring.coreos.com/v1
    kind: PrometheusRule
    metadata: {name: r1}
    spec:
      groups:
        - name: g
          rules:
            - alert: X
              expr: up == 0
              for: 5m
              labels: {severity: warning}
              annotations: {summary: s, description: d}
  - apiVersion: v1
    kind: Service
    metadata: {name: svc}
`
	l := New(DefaultConfig())
	l.LintBytes("list.yml", []byte(list))
	if l.Rules() != 1 || len(l.Diagnostics()) != 0 {
		t.Fatalf("want one clean rule from the List, got %d rules: %+v", l.Rules(), l.Diagnostics())
	}

	// Only non-rule Kubernetes objects: skipped without no-groups.
	if c := lintCodes(t, DefaultConfig(), "apiVersion: v1\nkind: Service\nmetadata: {name: s}\n"); c != nil {
		t.Fatalf("other kinds must be skipped silently, got %v", c)
	}
}

func TestLintReader(t *testing.T) {
	l := New(DefaultConfig())
	if err := l.LintReader("<stdin>", strings.NewReader(promRuleManifests)); err != nil {
		t.Fatal(err)
	}
	if l.Files() != 1 || l.Rules() != 1 || l.Diagnostics()[0].File != "<stdin>" {
		t.Fatalf("unexpected result: files=%d rules=%d %+v", l.Files(), l.Rules(), l.Diagnostics())
	}
}
