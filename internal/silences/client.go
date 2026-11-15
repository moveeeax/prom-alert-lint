// Package silences audits Alertmanager silences: silences that never expire,
// silences that have run for longer than a review window, over-broad matchers,
// silences that suppress more than their comment says, and silences that match
// nothing at all.
package silences

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Matcher is one silence matcher as returned by the Alertmanager API v2.
// IsEqual is a pointer because the API defaults it to true when absent.
type Matcher struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IsRegex bool   `json:"isRegex"`
	IsEqual *bool  `json:"isEqual,omitempty"`
}

// Equal reports whether the matcher is `=`/`=~` rather than `!=`/`!~`.
func (m Matcher) Equal() bool { return m.IsEqual == nil || *m.IsEqual }

// String renders the matcher in amtool syntax, e.g. `severity=~"crit.*"`.
func (m Matcher) String() string {
	op := "="
	if !m.Equal() {
		op = "!"
	}
	if m.IsRegex {
		op += "~"
	} else if !m.Equal() {
		op += "="
	}
	return fmt.Sprintf("%s%s%q", m.Name, op, m.Value)
}

// Silence is a gettableSilence from GET /api/v2/silences.
type Silence struct {
	ID     string `json:"id"`
	Status struct {
		State string `json:"state"` // expired, active or pending
	} `json:"status"`
	UpdatedAt time.Time `json:"updatedAt"`
	Matchers  []Matcher `json:"matchers"`
	StartsAt  time.Time `json:"startsAt"`
	EndsAt    time.Time `json:"endsAt"`
	CreatedBy string    `json:"createdBy"`
	Comment   string    `json:"comment"`
}

// Alert is a gettableAlert from GET /api/v2/alerts. Only the fields the audit
// uses are decoded.
type Alert struct {
	Labels      map[string]string `json:"labels"`
	Fingerprint string            `json:"fingerprint"`
	Status      struct {
		State      string   `json:"state"`
		SilencedBy []string `json:"silencedBy"`
	} `json:"status"`
}

// Client reads from the Alertmanager API v2 and, optionally, the Prometheus
// HTTP API. Headers are added to every request (e.g. Authorization).
type Client struct {
	HTTP    *http.Client
	Headers http.Header
}

// FetchSilences returns every silence known to the Alertmanager at base.
func (c *Client) FetchSilences(ctx context.Context, base string) ([]Silence, error) {
	var out []Silence
	err := c.getJSON(ctx, base, "api/v2/silences", nil, &out)
	return out, err
}

// FetchAlerts returns every alert, including silenced and inhibited ones (the
// API defaults all state filters to true).
func (c *Client) FetchAlerts(ctx context.Context, base string) ([]Alert, error) {
	var out []Alert
	err := c.getJSON(ctx, base, "api/v2/alerts", nil, &out)
	return out, err
}

// promResponse is the envelope of GET /api/v1/query.
type promResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
		} `json:"result"`
	} `json:"data"`
}

// QueryLabelSets runs an instant PromQL query at base and returns the label
// set of every series in the vector result.
func (c *Client) QueryLabelSets(ctx context.Context, base, query string) ([]map[string]string, error) {
	var resp promResponse
	if err := c.getJSON(ctx, base, "api/v1/query", url.Values{"query": {query}}, &resp); err != nil {
		return nil, err
	}
	if resp.Status != "success" {
		return nil, fmt.Errorf("prometheus query %q: %s", query, resp.Error)
	}
	if resp.Data.ResultType != "vector" {
		return nil, fmt.Errorf("prometheus query %q: unexpected result type %q", query, resp.Data.ResultType)
	}
	out := make([]map[string]string, 0, len(resp.Data.Result))
	for _, r := range resp.Data.Result {
		out = append(out, r.Metric)
	}
	return out, nil
}

func (c *Client) getJSON(ctx context.Context, base, path string, q url.Values, v any) error {
	u, err := url.JoinPath(base, path)
	if err != nil {
		return fmt.Errorf("bad URL %q: %w", base, err)
	}
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	for k, vs := range c.Headers {
		for _, hv := range vs {
			req.Header.Add(k, hv)
		}
	}
	req.Header.Set("Accept", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("GET %s: %w", redact(u), err)
	}
	// Prometheus answers failed queries with 4xx and a JSON error body, which
	// QueryLabelSets reports; anything else non-2xx is a transport failure.
	if resp.StatusCode/100 != 2 && !(path == "api/v1/query" && json.Valid(body)) {
		return fmt.Errorf("GET %s: %s", redact(u), resp.Status)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("GET %s: decoding response: %w", redact(u), err)
	}
	return nil
}

// redact drops userinfo from a URL before it goes into an error message.
func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Redacted()
}
