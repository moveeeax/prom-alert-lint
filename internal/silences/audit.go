package silences

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/moveeeax/prom-alert-lint/internal/linter"
)

// Codes lists every finding code the silence audit can emit.
var Codes = []string{
	"never-expiring", "stale-silence", "extended-silence", "broad-matcher",
	"exceeds-comment", "matches-nothing", "never-fired",
}

// DefaultBroadLabels are labels that on their own select whole classes of
// alerts rather than one problem.
var DefaultBroadLabels = []string{"severity", "namespace", "cluster", "env", "environment", "region", "job"}

// Config controls the audit thresholds.
type Config struct {
	// Now is the reference time; zero means time.Now().
	Now time.Time
	// MaxAge is how long a silence may stay active before it needs a review.
	MaxAge time.Duration
	// NeverExpiringAfter flags silences ending further away than this; zero
	// disables the check.
	NeverExpiringAfter time.Duration
	// BroadLabels do not narrow a silence on their own.
	BroadLabels []string
	// Prometheus, when set, is queried for ALERTS over Lookback to find
	// silences whose matchers never matched a firing alert.
	Prometheus string
	// Lookback is the history window for the never-fired check.
	Lookback time.Duration
	// IgnoreLabels are dropped from the history query, for labels that exist
	// in Alertmanager but not on the ALERTS series (e.g. external labels).
	IgnoreLabels []string
	// Levels overrides finding levels per code; linter.Off drops the code.
	Levels map[string]linter.Level
	// Strict makes warnings count towards a non-zero exit code.
	Strict bool
	// SortBy is "age" (oldest first, the default) or "creator".
	SortBy string
}

// Finding is one problem with a silence.
type Finding struct {
	Code       string       `json:"code"`
	Level      linter.Level `json:"level"`
	Message    string       `json:"message"`
	Suggestion string       `json:"suggestion,omitempty"`
}

// Suppressed counts the current alerts a silence mutes, per alertname.
type Suppressed struct {
	Alertname string `json:"alertname"`
	Count     int    `json:"count"`
}

// Result is the audit of one active or pending silence.
type Result struct {
	ID         string       `json:"id"`
	State      string       `json:"state"`
	CreatedBy  string       `json:"createdBy"`
	Comment    string       `json:"comment"`
	Matchers   string       `json:"matchers"`
	StartsAt   time.Time    `json:"startsAt"`
	EndsAt     time.Time    `json:"endsAt"`
	UpdatedAt  time.Time    `json:"updatedAt"`
	Suppressed []Suppressed `json:"suppressed"`
	Findings   []Finding    `json:"findings"`
}

// Summary rolls up an audit run.
type Summary struct {
	Silences int `json:"silences"`
	Expired  int `json:"expired"`
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
	Infos    int `json:"infos"`
}

// Report is the outcome of an audit; it is also the JSON document.
type Report struct {
	Summary  Summary  `json:"summary"`
	Silences []Result `json:"silences"`
	strict   bool
}

// ExitCode is 0 when clean, 1 when there are errors (or warnings with Strict).
func (r *Report) ExitCode() int {
	if r.Summary.Errors > 0 || (r.strict && r.Summary.Warnings > 0) {
		return 1
	}
	return 0
}

// historyFunc returns the label sets of ALERTS series matching query.
type historyFunc func(ctx context.Context, query string) ([]map[string]string, error)

// Run fetches silences and alerts from the Alertmanager at am and audits them.
func Run(ctx context.Context, c *Client, am string, cfg Config) (*Report, error) {
	sils, err := c.FetchSilences(ctx, am)
	if err != nil {
		return nil, fmt.Errorf("fetching silences: %w", err)
	}
	alerts, err := c.FetchAlerts(ctx, am)
	if err != nil {
		return nil, fmt.Errorf("fetching alerts: %w", err)
	}
	var hist historyFunc
	if cfg.Prometheus != "" {
		hist = func(ctx context.Context, q string) ([]map[string]string, error) {
			return c.QueryLabelSets(ctx, cfg.Prometheus, q)
		}
	}
	return Audit(ctx, sils, alerts, hist, cfg)
}

// Audit checks sils against the current alerts. hist may be nil, in which
// case the never-fired check is skipped. Expired silences are only counted.
func Audit(ctx context.Context, sils []Silence, alerts []Alert, hist historyFunc, cfg Config) (*Report, error) {
	now := cfg.Now
	if now.IsZero() {
		now = time.Now()
	}
	broad := cfg.BroadLabels
	if broad == nil {
		broad = DefaultBroadLabels
	}

	// Alertmanager lists the silences muting each alert in status.silencedBy.
	muted := map[string]map[string]int{}
	for _, a := range alerts {
		for _, id := range a.Status.SilencedBy {
			if muted[id] == nil {
				muted[id] = map[string]int{}
			}
			muted[id][a.Labels["alertname"]]++
		}
	}

	rep := &Report{strict: cfg.Strict}
	for _, s := range sils {
		if s.Status.State == "expired" {
			rep.Summary.Expired++
			continue
		}
		res := Result{
			ID: s.ID, State: s.Status.State, CreatedBy: s.CreatedBy, Comment: s.Comment,
			Matchers: matcherString(s.Matchers), StartsAt: s.StartsAt, EndsAt: s.EndsAt, UpdatedAt: s.UpdatedAt,
			Suppressed: suppressedList(muted[s.ID]),
		}
		emit := func(code string, lv linter.Level, msg, fix string) {
			if o, ok := cfg.Levels[code]; ok {
				if o == linter.Off {
					return
				}
				lv = o
			}
			res.Findings = append(res.Findings, Finding{Code: code, Level: lv, Message: msg, Suggestion: fix})
		}
		active := s.Status.State == "active"

		if cfg.NeverExpiringAfter > 0 && s.EndsAt.Sub(now) > cfg.NeverExpiringAfter {
			emit("never-expiring", linter.Error,
				fmt.Sprintf("ends %s (in %s); this is a permanent blindfold, not a silence", s.EndsAt.Format(time.DateOnly), human(s.EndsAt.Sub(now))),
				"fix the alert or the routing instead, or set an end date and review it then")
		}

		if age := now.Sub(s.StartsAt); active && cfg.MaxAge > 0 && age > cfg.MaxAge {
			// Alertmanager keeps startsAt when an active silence is edited in
			// place, so updatedAt after startsAt means someone moved endsAt or
			// changed the comment while it was running.
			if s.UpdatedAt.After(s.StartsAt.Add(time.Minute)) {
				emit("extended-silence", linter.Warning,
					fmt.Sprintf("active for %s (over %s), last edited %s ago by an update that kept it running", human(age), human(cfg.MaxAge), human(now.Sub(s.UpdatedAt))),
					"check whether the underlying problem still exists before extending again")
			} else {
				emit("stale-silence", linter.Warning,
					fmt.Sprintf("active for %s (over %s) and never edited since %s created it", human(age), human(cfg.MaxAge), creator(s)),
					"review it with its creator; expire it if the incident is over")
			}
		}

		if !narrows(s.Matchers, broad) {
			emit("broad-matcher", linter.Warning,
				fmt.Sprintf("matchers %s select whole classes of alerts: no equality matcher on a specific label", res.Matchers),
				"add an `alertname` or `instance` matcher for the alert that is actually being silenced")
		}

		if active {
			if len(res.Suppressed) == 0 {
				emit("matches-nothing", linter.Info, "matches no current alert", "expire it if the work it covered is done")
			} else if extra := unmentioned(s.Comment, res.Suppressed); extra != nil {
				emit("exceeds-comment", linter.Warning,
					fmt.Sprintf("comment names some of the silenced alerts but it also mutes %s", strings.Join(extra, ", ")),
					"narrow the matchers to what the comment describes, or update the comment")
			}
		}

		if hist != nil && active && len(res.Suppressed) == 0 && cfg.Lookback > 0 {
			if q, ok := historyQuery(s.Matchers, cfg.IgnoreLabels, cfg.Lookback); ok {
				series, err := hist(ctx, q)
				if err != nil {
					return nil, fmt.Errorf("silence %s: %w", s.ID, err)
				}
				if len(series) == 0 {
					emit("never-fired", linter.Warning,
						fmt.Sprintf("no alert matching it fired in the last %s", human(cfg.Lookback)),
						"expire it; it is not silencing anything")
				}
			}
		}

		for _, f := range res.Findings {
			switch f.Level {
			case linter.Error:
				rep.Summary.Errors++
			case linter.Warning:
				rep.Summary.Warnings++
			case linter.Info:
				rep.Summary.Infos++
			}
		}
		rep.Silences = append(rep.Silences, res)
	}
	rep.Summary.Silences = len(rep.Silences)
	sortResults(rep.Silences, cfg.SortBy)
	return rep, nil
}

func creator(s Silence) string {
	if s.CreatedBy == "" {
		return "its creator"
	}
	return s.CreatedBy
}

// probe is a label value no real alert carries; a regex matching it would
// match any value.
const probe = "prom-alert-lint-probe-7f3c"

// narrows reports whether at least one matcher restricts the silence to a
// specific set of alerts: an equality (`=` or `=~`) matcher on a label that is
// not broad, with a non-empty value and, for regexes, not a catch-all.
// Negative matchers only exclude, so they never narrow.
func narrows(ms []Matcher, broad []string) bool {
	for _, m := range ms {
		if !m.Equal() || m.Value == "" || containsFold(broad, m.Name) {
			continue
		}
		if m.IsRegex {
			// Alertmanager anchors matcher regexes at both ends.
			re, err := regexp.Compile("^(?:" + m.Value + ")$")
			if err != nil || re.MatchString("") || re.MatchString(probe) {
				continue
			}
		}
		return true
	}
	return false
}

// unmentioned returns the suppressed alertnames the comment does not mention,
// but only when it mentions at least one of them: a comment that names no
// alert at all makes no claim about scope.
func unmentioned(comment string, sup []Suppressed) []string {
	lc := strings.ToLower(comment)
	var named, missing []string
	for _, s := range sup {
		if s.Alertname == "" {
			continue
		}
		if strings.Contains(lc, strings.ToLower(s.Alertname)) {
			named = append(named, s.Alertname)
		} else {
			missing = append(missing, s.Alertname)
		}
	}
	if len(named) == 0 || len(missing) == 0 {
		return nil
	}
	return missing
}

var legacyLabel = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// historyQuery builds a PromQL query returning one series per alertname that
// fired with labels matching ms within lookback. ok is false when no matcher
// is left after dropping ignored labels.
func historyQuery(ms []Matcher, ignore []string, lookback time.Duration) (string, bool) {
	sel := []string{`alertstate="firing"`}
	for _, m := range ms {
		if containsFold(ignore, m.Name) || m.Name == "alertstate" {
			continue
		}
		name := m.Name
		if !legacyLabel.MatchString(name) {
			name = strconv.Quote(name) // Prometheus 3 UTF-8 label name syntax
		}
		op := "="
		switch {
		case m.IsRegex && m.Equal():
			op = "=~"
		case m.IsRegex:
			op = "!~"
		case !m.Equal():
			op = "!="
		}
		sel = append(sel, name+op+strconv.Quote(m.Value))
	}
	if len(sel) == 1 {
		return "", false
	}
	return fmt.Sprintf("group by (alertname) (last_over_time(ALERTS{%s}[%s]))",
		strings.Join(sel, ", "), promDuration(lookback)), true
}

// promDuration renders d in whole seconds, which PromQL always accepts.
func promDuration(d time.Duration) string {
	return strconv.FormatInt(int64(d/time.Second), 10) + "s"
}

func matcherString(ms []Matcher) string {
	parts := make([]string, len(ms))
	for i, m := range ms {
		parts[i] = m.String()
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func suppressedList(byName map[string]int) []Suppressed {
	out := make([]Suppressed, 0, len(byName))
	for n, c := range byName {
		out = append(out, Suppressed{Alertname: n, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Alertname < out[j].Alertname
	})
	return out
}

func sortResults(rs []Result, by string) {
	sort.SliceStable(rs, func(i, j int) bool {
		if by == "creator" && rs[i].CreatedBy != rs[j].CreatedBy {
			return rs[i].CreatedBy < rs[j].CreatedBy
		}
		if !rs[i].StartsAt.Equal(rs[j].StartsAt) {
			return rs[i].StartsAt.Before(rs[j].StartsAt)
		}
		return rs[i].ID < rs[j].ID
	})
}

func containsFold(xs []string, v string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

// human renders a duration as whole days, hours or minutes.
func human(d time.Duration) string {
	switch {
	case d < 0:
		return "-" + human(-d)
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	default:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
}
