package silences

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/prom-alert-lint/internal/linter"
)

var now = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

// The fixtures follow the gettableSilence and gettableAlert shapes of the
// Alertmanager API v2 (api/v2/openapi.yaml).
const silencesJSON = `[
  {"id": "aaaaaaaa-0000-0000-0000-000000000001", "status": {"state": "active"},
   "updatedAt": "2025-01-01T00:00:00Z", "startsAt": "2025-01-01T00:00:00Z", "endsAt": "2099-01-01T00:00:00Z",
   "createdBy": "alice", "comment": "noisy during migration",
   "matchers": [{"name": "severity", "value": "warning", "isRegex": false, "isEqual": true}]},
  {"id": "bbbbbbbb-0000-0000-0000-000000000002", "status": {"state": "active"},
   "updatedAt": "2026-11-10T00:00:00Z", "startsAt": "2026-09-01T00:00:00Z", "endsAt": "2026-11-20T00:00:00Z",
   "createdBy": "bob", "comment": "DiskFilling on db-1 until the new volume lands",
   "matchers": [{"name": "instance", "value": "db-1", "isRegex": false}]},
  {"id": "cccccccc-0000-0000-0000-000000000003", "status": {"state": "active"},
   "updatedAt": "2026-11-11T00:00:00Z", "startsAt": "2026-11-11T00:00:00Z", "endsAt": "2026-11-13T00:00:00Z",
   "createdBy": "carol", "comment": "maintenance",
   "matchers": [{"name": "alertname", "value": "Gone", "isRegex": false}]},
  {"id": "dddddddd-0000-0000-0000-000000000004", "status": {"state": "expired"},
   "updatedAt": "2026-01-01T00:00:00Z", "startsAt": "2026-01-01T00:00:00Z", "endsAt": "2026-01-02T00:00:00Z",
   "createdBy": "dave", "comment": "old",
   "matchers": [{"name": "alertname", "value": "Old", "isRegex": false}]}
]`

const alertsJSON = `[
  {"labels": {"alertname": "DiskFilling", "instance": "db-1"}, "fingerprint": "1", "annotations": {}, "receivers": [],
   "startsAt": "2026-11-12T00:00:00Z", "updatedAt": "2026-11-12T00:00:00Z", "endsAt": "2026-11-12T13:00:00Z",
   "status": {"state": "suppressed", "silencedBy": ["bbbbbbbb-0000-0000-0000-000000000002"], "inhibitedBy": [], "mutedBy": []}},
  {"labels": {"alertname": "NodeDown", "instance": "db-1"}, "fingerprint": "2", "annotations": {}, "receivers": [],
   "startsAt": "2026-11-12T00:00:00Z", "updatedAt": "2026-11-12T00:00:00Z", "endsAt": "2026-11-12T13:00:00Z",
   "status": {"state": "suppressed", "silencedBy": ["bbbbbbbb-0000-0000-0000-000000000002"], "inhibitedBy": [], "mutedBy": []}},
  {"labels": {"alertname": "HighLatency", "severity": "warning"}, "fingerprint": "3", "annotations": {}, "receivers": [],
   "startsAt": "2026-11-12T00:00:00Z", "updatedAt": "2026-11-12T00:00:00Z", "endsAt": "2026-11-12T13:00:00Z",
   "status": {"state": "suppressed", "silencedBy": ["aaaaaaaa-0000-0000-0000-000000000001"], "inhibitedBy": [], "mutedBy": []}},
  {"labels": {"alertname": "Unsilenced"}, "fingerprint": "4", "annotations": {}, "receivers": [],
   "startsAt": "2026-11-12T00:00:00Z", "updatedAt": "2026-11-12T00:00:00Z", "endsAt": "2026-11-12T13:00:00Z",
   "status": {"state": "active", "silencedBy": [], "inhibitedBy": [], "mutedBy": []}}
]`

// fakeServers serves the fixtures from a fake Alertmanager and a fake
// Prometheus that reports no ALERTS history. queries collects PromQL seen.
func fakeServers(t *testing.T, queries *[]string) (am, prom *httptest.Server) {
	t.Helper()
	am = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer t0ken" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/am/api/v2/silences":
			w.Write([]byte(silencesJSON))
		case "/am/api/v2/alerts":
			w.Write([]byte(alertsJSON))
		default:
			http.NotFound(w, r)
		}
	}))
	prom = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			http.NotFound(w, r)
			return
		}
		*queries = append(*queries, r.URL.Query().Get("query"))
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	t.Cleanup(am.Close)
	t.Cleanup(prom.Close)
	return am, prom
}

func testConfig() Config {
	return Config{Now: now, MaxAge: days(30), NeverExpiringAfter: days(365), Lookback: days(30)}
}

func codesOf(r Result) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, string(f.Level)+":"+f.Code)
	}
	return out
}

func byID(t *testing.T, rep *Report, prefix string) Result {
	t.Helper()
	for _, s := range rep.Silences {
		if strings.HasPrefix(s.ID, prefix) {
			return s
		}
	}
	t.Fatalf("silence %s not in report", prefix)
	return Result{}
}

func has(codes []string, want string) bool {
	for _, c := range codes {
		if c == want {
			return true
		}
	}
	return false
}

func TestRunAgainstFakeAPIs(t *testing.T) {
	var queries []string
	am, prom := fakeServers(t, &queries)
	cfg := testConfig()
	cfg.Prometheus = prom.URL
	c := &Client{Headers: http.Header{"Authorization": {"Bearer t0ken"}}}
	rep, err := Run(context.Background(), c, am.URL+"/am/", cfg)
	if err != nil {
		t.Fatal(err)
	}

	if rep.Summary.Silences != 3 || rep.Summary.Expired != 1 {
		t.Fatalf("want 3 audited and 1 expired, got %+v", rep.Summary)
	}
	// Oldest first.
	if !strings.HasPrefix(rep.Silences[0].ID, "aaaaaaaa") || !strings.HasPrefix(rep.Silences[2].ID, "cccccccc") {
		t.Fatalf("unexpected order: %s, %s, %s", rep.Silences[0].ID, rep.Silences[1].ID, rep.Silences[2].ID)
	}

	a := codesOf(byID(t, rep, "aaaaaaaa"))
	for _, want := range []string{"error:never-expiring", "warning:stale-silence", "warning:broad-matcher"} {
		if !has(a, want) {
			t.Errorf("silence a: want %s, got %v", want, a)
		}
	}

	b := byID(t, rep, "bbbbbbbb")
	if bc := codesOf(b); !has(bc, "warning:extended-silence") || !has(bc, "warning:exceeds-comment") || len(bc) != 2 {
		t.Errorf("silence b: want extended-silence and exceeds-comment only, got %v", bc)
	}
	if len(b.Suppressed) != 2 {
		t.Errorf("silence b should mute 2 alertnames, got %+v", b.Suppressed)
	}
	for _, f := range b.Findings {
		if f.Code == "exceeds-comment" && !strings.Contains(f.Message, "NodeDown") {
			t.Errorf("exceeds-comment should name NodeDown, got %q", f.Message)
		}
	}

	cc := codesOf(byID(t, rep, "cccccccc"))
	if !has(cc, "info:matches-nothing") || !has(cc, "warning:never-fired") || len(cc) != 2 {
		t.Errorf("silence c: want matches-nothing and never-fired, got %v", cc)
	}
	if len(queries) != 1 || queries[0] != `group by (alertname) (last_over_time(ALERTS{alertstate="firing", alertname="Gone"}[2592000s]))` {
		t.Errorf("unexpected history queries: %q", queries)
	}

	if rep.ExitCode() != 1 {
		t.Errorf("never-expiring is an error, want exit 1, got %d", rep.ExitCode())
	}
}

func TestRunReportsHTTPErrors(t *testing.T) {
	var queries []string
	am, _ := fakeServers(t, &queries)
	_, err := Run(context.Background(), &Client{}, am.URL+"/am", testConfig())
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("want a 401 error without the token, got %v", err)
	}
}

func TestNarrows(t *testing.T) {
	f := false
	cases := []struct {
		name string
		ms   []Matcher
		want bool
	}{
		{"bare severity", []Matcher{{Name: "severity", Value: "critical"}}, false},
		{"namespace regex", []Matcher{{Name: "namespace", Value: "prod-.*", IsRegex: true}}, false},
		{"catch-all regex on alertname", []Matcher{{Name: "alertname", Value: ".+", IsRegex: true}}, false},
		{"empty-matching regex", []Matcher{{Name: "instance", Value: "db-1|", IsRegex: true}}, false},
		{"negative only", []Matcher{{Name: "alertname", Value: "Watchdog", IsEqual: &f}}, false},
		{"empty value", []Matcher{{Name: "alertname", Value: ""}}, false},
		{"alertname", []Matcher{{Name: "severity", Value: "warning"}, {Name: "alertname", Value: "DiskFilling"}}, true},
		{"specific regex", []Matcher{{Name: "instance", Value: "db-(1|2)", IsRegex: true}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := narrows(tc.ms, DefaultBroadLabels); got != tc.want {
				t.Fatalf("narrows = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHistoryQuery(t *testing.T) {
	f := false
	ms := []Matcher{
		{Name: "alertname", Value: "Disk.*", IsRegex: true},
		{Name: "instance", Value: `db"1`, IsEqual: &f},
		{Name: "service.name", Value: "api"},
		{Name: "cluster", Value: "prod"},
	}
	q, ok := historyQuery(ms, []string{"cluster"}, days(7))
	want := `group by (alertname) (last_over_time(ALERTS{alertstate="firing", alertname=~"Disk.*", instance!="db\"1", "service.name"="api"}[604800s]))`
	if !ok || q != want {
		t.Fatalf("got %q, want %q", q, want)
	}
	if _, ok := historyQuery([]Matcher{{Name: "cluster", Value: "prod"}}, []string{"cluster"}, days(7)); ok {
		t.Fatal("a query without matchers left must be skipped")
	}
}

func TestLevelsAndStrict(t *testing.T) {
	sils := []Silence{{ID: "x", Matchers: []Matcher{{Name: "severity", Value: "info"}},
		StartsAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour), EndsAt: now.Add(time.Hour)}}
	sils[0].Status.State = "active"
	alerts := []Alert{{Labels: map[string]string{"alertname": "A"}}}
	alerts[0].Status.SilencedBy = []string{"x"}

	cfg := testConfig()
	rep, err := Audit(context.Background(), sils, alerts, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Warnings != 1 || rep.ExitCode() != 0 {
		t.Fatalf("broad-matcher is a warning and must not fail by default: %+v", rep.Summary)
	}
	cfg.Strict = true
	if rep, _ = Audit(context.Background(), sils, alerts, nil, cfg); rep.ExitCode() != 1 {
		t.Fatal("strict must fail on warnings")
	}
	cfg.Levels = map[string]linter.Level{"broad-matcher": linter.Off}
	if rep, _ = Audit(context.Background(), sils, alerts, nil, cfg); len(rep.Silences[0].Findings) != 0 || rep.ExitCode() != 0 {
		t.Fatalf("off must drop the finding, got %+v", rep.Silences[0].Findings)
	}
}

func TestSortByCreator(t *testing.T) {
	mk := func(id, by string, age int) Silence {
		s := Silence{ID: id, CreatedBy: by, StartsAt: now.Add(-days(age)), UpdatedAt: now.Add(-days(age)), EndsAt: now.Add(time.Hour),
			Matchers: []Matcher{{Name: "alertname", Value: id}}}
		s.Status.State = "active"
		return s
	}
	cfg := testConfig()
	cfg.SortBy = "creator"
	rep, _ := Audit(context.Background(), []Silence{mk("1", "zoe", 9), mk("2", "adam", 1), mk("3", "adam", 5)}, nil, nil, cfg)
	var got []string
	for _, s := range rep.Silences {
		got = append(got, s.ID)
	}
	if strings.Join(got, ",") != "3,2,1" {
		t.Fatalf("want adam's oldest first, then zoe: got %v", got)
	}
}

func TestOutputs(t *testing.T) {
	var queries []string
	am, _ := fakeServers(t, &queries)
	c := &Client{Headers: http.Header{"Authorization": {"Bearer t0ken"}}}
	rep, err := Run(context.Background(), c, am.URL+"/am", testConfig())
	if err != nil {
		t.Fatal(err)
	}

	var text bytes.Buffer
	rep.WriteText(&text, now)
	for _, want := range []string{
		"aaaaaaaa  active  alice",
		"  mutes DiskFilling x1, NodeDown x1",
		"  error   never-expiring: ends 2099-01-01",
		"    fix: ",
		"(1 expired skipped)",
	} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text output lacks %q:\n%s", want, text.String())
		}
	}

	var md bytes.Buffer
	rep.WriteMarkdown(&md, now)
	if !strings.Contains(md.String(), "| `bbbbbbbb` | active | bob |") || !strings.Contains(md.String(), "### Findings") {
		t.Errorf("unexpected markdown:\n%s", md.String())
	}

	var js bytes.Buffer
	if err := rep.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(js.Bytes(), &back); err != nil {
		t.Fatalf("json does not round-trip: %v", err)
	}
	if back.Summary != rep.Summary || len(back.Silences) != 3 {
		t.Fatalf("json lost data: %+v", back.Summary)
	}
}
