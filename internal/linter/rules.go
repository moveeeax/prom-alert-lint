// Package linter loads Prometheus rule files and checks alerting rules for
// common mistakes: unparseable or trivial PromQL, a missing `for`, missing
// severity/team labels, missing summary/description annotations and duplicate
// alert names.
package linter

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

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

// DocKind classifies one YAML document of an input stream.
type DocKind int

const (
	// DocRules is a plain Prometheus rule file (`groups:` at the top level).
	DocRules DocKind = iota
	// DocPrometheusRule is a prometheus-operator `kind: PrometheusRule` object;
	// its groups come from `spec.groups`.
	DocPrometheusRule
	// DocOtherObject is any other Kubernetes object. It is skipped silently.
	DocOtherObject
)

// Document is one decoded YAML document. Object is "namespace/name" (or just
// "name" without a namespace) for a PrometheusRule and empty otherwise.
type Document struct {
	Kind   DocKind
	Object string
	Groups []RuleGroup
}

// objectHeader holds the Kubernetes fields used to tell manifests from plain
// rule files.
type objectHeader struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Spec  RuleFile    `yaml:"spec"`
	Items []yaml.Node `yaml:"items"`
}

// ParseDocuments decodes every YAML document in data, as produced by
// `helm template` or `kubectl get -o yaml`. A document with a `kind` key is a
// Kubernetes object: `kind: PrometheusRule` yields its `spec.groups`, a
// `kind: List` (or `*List`) is expanded into its items, and any other kind is
// returned as DocOtherObject. Documents without `kind` are plain rule files.
// Empty documents (a bare `---` or comments only) are dropped.
//
// On a YAML error the documents decoded so far are returned together with the
// error, so callers can still lint them. Rule line numbers count from the
// start of data, not of the document.
func ParseDocuments(data []byte) ([]Document, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var docs []Document
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return docs, fmt.Errorf("invalid YAML: %w", err)
		}
		if docs, err = appendDocument(docs, &node); err != nil {
			return docs, fmt.Errorf("invalid YAML: %w", err)
		}
	}
}

func appendDocument(docs []Document, node *yaml.Node) ([]Document, error) {
	root := node
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			return docs, nil
		}
		root = root.Content[0]
	}
	if root.Kind == yaml.ScalarNode && root.Tag == "!!null" {
		return docs, nil
	}
	if root.Kind == yaml.MappingNode && hasKey(root, "kind") {
		var h objectHeader
		if err := root.Decode(&h); err != nil {
			return docs, err
		}
		switch {
		case h.Kind == "PrometheusRule":
			obj := h.Metadata.Name
			if h.Metadata.Namespace != "" {
				obj = h.Metadata.Namespace + "/" + obj
			}
			return append(docs, Document{Kind: DocPrometheusRule, Object: obj, Groups: h.Spec.Groups}), nil
		case strings.HasSuffix(h.Kind, "List"):
			for i := range h.Items {
				var err error
				if docs, err = appendDocument(docs, &h.Items[i]); err != nil {
					return docs, err
				}
			}
			return docs, nil
		default:
			return append(docs, Document{Kind: DocOtherObject}), nil
		}
	}
	var rf RuleFile
	if err := root.Decode(&rf); err != nil {
		return docs, err
	}
	return append(docs, Document{Kind: DocRules, Groups: rf.Groups}), nil
}

// hasKey reports whether mapping node n has the given key.
func hasKey(n *yaml.Node, key string) bool {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return true
		}
	}
	return false
}

var yamlErrLine = regexp.MustCompile(`\bline (\d+):`)

// errLine extracts the 1-based line number from a yaml.v3 error such as
// "yaml: line 3: did not find expected key". It returns 0 when the error
// carries no line.
func errLine(err error) int {
	if m := yamlErrLine.FindStringSubmatch(err.Error()); m != nil {
		if n, convErr := strconv.Atoi(m[1]); convErr == nil && n > 0 {
			return n
		}
	}
	return 0
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
