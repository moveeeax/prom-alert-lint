// Package linter loads Prometheus rule files and checks alerting rules for
// common mistakes: unparseable or trivial PromQL, a missing `for`, missing
// severity/team labels, missing summary/description annotations and duplicate
// alert names.
package linter

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// RuleFile is the top level of a Prometheus rule file.
type RuleFile struct {
	Groups []RuleGroup `yaml:"groups"`
}

// RuleGroup is a named collection of rules.
type RuleGroup struct {
	Name     string `yaml:"name"`
	Interval string `yaml:"interval"`
	Rules    []Rule `yaml:"rules"`
}

// Rule is a single alerting or recording rule. Line is the 1-based line of the
// rule in its source file, captured for precise diagnostics.
type Rule struct {
	Alert         string            `yaml:"alert"`
	Record        string            `yaml:"record"`
	Expr          string            `yaml:"expr"`
	For           string            `yaml:"for"`
	KeepFiringFor string            `yaml:"keep_firing_for"`
	Labels        map[string]string `yaml:"labels"`
	Annotations   map[string]string `yaml:"annotations"`

	Line int `yaml:"-"`
}

// UnmarshalYAML records the source line of each rule while decoding.
func (r *Rule) UnmarshalYAML(node *yaml.Node) error {
	type raw Rule
	if err := node.Decode((*raw)(r)); err != nil {
		return err
	}
	r.Line = node.Line
	return nil
}

// ParseRuleFile decodes a rule file's bytes into a RuleFile. A YAML syntax
// error is returned as a plain error so callers can turn it into a diagnostic.
func ParseRuleFile(data []byte) (*RuleFile, error) {
	var rf RuleFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	return &rf, nil
}

// Name returns the alert or record name of a rule, whichever is set.
func (r Rule) Name() string {
	if r.Alert != "" {
		return r.Alert
	}
	return r.Record
}

// Kind reports whether the rule is an "alert", a "record", or "" when neither
// (or both) of the discriminating keys are set.
func (r Rule) Kind() string {
	switch {
	case r.Alert != "" && r.Record == "":
		return "alert"
	case r.Record != "" && r.Alert == "":
		return "record"
	default:
		return ""
	}
}
