# prom-alert-lint

[![ci](https://github.com/moveeeax/prom-alert-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/prom-alert-lint/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Catch broken or sloppy Prometheus alerting rules **before** they page you (or,
worse, silently fail to). `prom-alert-lint` parses your rule files, validates the
PromQL, and enforces label/annotation hygiene — then exits non-zero so it slots
straight into CI.

## What it checks

| Code | Level | Meaning |
| --- | --- | --- |
| `invalid-promql` | error | the `expr` does not parse as PromQL |
| `trivial-expr` | error | an alert `expr` is a bare constant (always/never fires) |
| `missing-expr` | error | the rule has no `expr` |
| `missing-for` | error | an alert has no `for` (fires on a single scrape) |
| `invalid-for` | error | `for` is not a valid Prometheus duration |
| `missing-label` | error | a required label (default `severity`) is absent/empty |
| `missing-annotation` | error | a required annotation (default `summary`, `description`) is absent/empty |
| `missing-runbook` | error | no `runbook_url` or `runbook` annotation (only with `--require-runbook`) |
| `duplicate-alert` | error | the same alert name with the same static labels is defined twice (across all files) |
| `not-a-rule` | error | a rule sets neither `alert` nor `record` (or both) |
| `parse-error` | error | the file is not valid YAML or not a rule file shape; carries the parser's line |
| `read-error` | error | the file cannot be read |
| `bad-severity` | warning | the `severity` value is outside the allowed set (`--severity-value`) |
| `bad-name` | warning | the alert name does not match `--name-pattern` |
| `no-groups` | warning | valid YAML with no rule groups (silenced by `--skip-non-rules`) |

Every diagnostic carries the **file, line, and alert name**, and most carry a
`fix:` hint (`"suggestion"` in JSON).

`duplicate-alert` keys on the alert name plus its static labels, so a
`DiskFilling` at `severity: warning` next to a `DiskFilling` at
`severity: critical` is accepted as tiering.

### Levels

`error` fails the run, `warning` fails it only under `--strict`, and `info` is
reported but never fails. `--level code=error|warning|info|off` (repeatable)
sets the level of any check; `off` drops it:

```console
$ prom-alert-lint lint rules/*.yml --require-runbook \
    --level missing-annotation=info --level missing-runbook=info
```

## Install

```console
$ go install github.com/moveeeax/prom-alert-lint@latest
```

Or build from source:

```console
$ git clone https://github.com/moveeeax/prom-alert-lint.git
$ cd prom-alert-lint && make build
```

## Usage

```console
$ prom-alert-lint lint rules/*.yml --require-label severity
```

Against the bundled bad example:

```console
$ prom-alert-lint lint examples/bad.yml
error   examples/bad.yml:5  [DiskFilling] missing-annotation: required annotation "summary" is missing or empty
  fix: add `annotations: { summary: ... }`
error   examples/bad.yml:5  [DiskFilling] missing-annotation: required annotation "description" is missing or empty
  fix: add `annotations: { description: ... }`
error   examples/bad.yml:5  [DiskFilling] missing-for: alert has no `for`; it fires on a single scrape
  fix: add e.g. `for: 5m` so the condition must hold before firing
error   examples/bad.yml:5  [DiskFilling] missing-label: required label "severity" is missing or empty
  fix: add `labels: { severity: warning }` (or critical/info)
error   examples/bad.yml:9  [BrokenQuery] invalid-promql: PromQL does not parse: 1:32: parse error: unexpected end of input
error   examples/bad.yml:19  [AlwaysOn] trivial-expr: alert expression is a constant and will always or never fire
  fix: compare a metric against the threshold, e.g. `up == 0`; use `vector(1)` for a deliberate always-firing watchdog
error   examples/bad.yml:30  [BrokenQuery] duplicate-alert: alert "BrokenQuery" with the same labels already defined at examples/bad.yml:9
  fix: remove one copy, or give the variants different labels (e.g. severity)
7 error(s), 0 warning(s), 0 info in 4 rule(s) across 1 file(s)
$ echo $?
1
```

Machine-readable output for tooling:

```console
$ prom-alert-lint lint rules/*.yml --format json
```

### Kubernetes manifests and stdin

Every YAML document in a file is linted. A `kind: PrometheusRule` object
(prometheus-operator) is linted through its `spec.groups`, and its diagnostics
carry the object as `namespace/name`; `kind: List` output from
`kubectl get -o yaml` is expanded. Other Kubernetes kinds are skipped without a
warning. `-` reads from stdin:

```console
$ helm template ./chart | prom-alert-lint lint -
error   <stdin>:19  [monitoring/api ApiDown] missing-for: alert has no `for`; it fires on a single scrape
  fix: add e.g. `for: 5m` so the condition must hold before firing
```

### Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--format` | `text` | `text` or `json` output |
| `--require-for` | `true` | require a `for` clause on alerts |
| `--require-label` | `severity` | label that must be present (repeatable) |
| `--require-annotation` | `summary`, `description` | annotation that must be present (repeatable) |
| `--severity-value` | *(none)* | allowed value for the `severity` label (repeatable) |
| `--name-pattern` | *(none)* | regexp every alert name must match |
| `--check-record-expr` | `true` | also validate recording-rule PromQL |
| `--require-runbook` | `false` | require a `runbook_url` or `runbook` annotation |
| `--skip-non-rules` | `false` | skip valid YAML without rule groups instead of warning `no-groups` |
| `--level` | *(none)* | `code=error\|warning\|info\|off`, repeatable |
| `--strict` | `false` | treat warnings as failures (info never fails) |

Exit codes: `0` clean, `1` violations found (or warnings under `--strict`),
`2` usage error.

## Audit Alertmanager silences

`prom-alert-lint silences` reads `GET /api/v2/silences` and `GET /api/v2/alerts`
from a live Alertmanager and reports the silences that quietly turned into
permanent blindfolds. Expired silences are only counted.

```console
$ prom-alert-lint silences --alertmanager http://localhost:9093 --max-age 30d
aaaaaaaa  active  alice            age 680d  ends in 26347d {severity="warning"}
  mutes HighLatency x1
  error   never-expiring: ends 2099-01-01 (in 26347d); this is a permanent blindfold, not a silence
    fix: fix the alert or the routing instead, or set an end date and review it then
  warning stale-silence: active for 680d (over 30d) and never edited since alice created it
    fix: review it with its creator; expire it if the incident is over
  warning broad-matcher: matchers {severity="warning"} select whole classes of alerts: no equality matcher on a specific label
    fix: add an `alertname` or `instance` matcher for the alert that is actually being silenced
1 error(s), 2 warning(s), 0 info in 1 active/pending silence(s) (0 expired skipped)
```

| Code | Level | Meaning |
| --- | --- | --- |
| `never-expiring` | error | the silence ends more than `--never-expiring-after` (default `1y`) from now |
| `stale-silence` | warning | active for longer than `--max-age` and never edited since it started |
| `extended-silence` | warning | active for longer than `--max-age` and edited in place since it started (Alertmanager keeps `startsAt` on such edits, so this is usually a moved end date) |
| `broad-matcher` | warning | no matcher narrows the silence: only negative matchers, catch-all regexes, empty values, or labels from `--broad-label` |
| `exceeds-comment` | warning | the comment names some of the muted alerts, but the silence also mutes other alertnames |
| `matches-nothing` | info | the active silence mutes no current alert |
| `never-fired` | warning | with `--prometheus`: no `ALERTS{alertstate="firing"}` series matched the silence over `--lookback` |

The table output lists, per silence, every alertname it currently mutes (from
each alert's `status.silencedBy`), so the real scope is visible next to the
comment. `--format json` and `--format markdown` give the same data for tooling
or a review issue. Exit codes match `lint`, so a scheduled job can enforce a
review.

| Flag | Default | Purpose |
| --- | --- | --- |
| `--alertmanager` | *(required)* | Alertmanager base URL; userinfo in the URL is sent as basic auth |
| `--prometheus` | *(none)* | Prometheus base URL for `never-fired` |
| `--max-age` | `30d` | review window for `stale-silence` / `extended-silence` |
| `--never-expiring-after` | `1y` | threshold for `never-expiring`; `0` disables |
| `--lookback` | `30d` | ALERTS history window |
| `--broad-label` | `severity`, `namespace`, `cluster`, `env`, `environment`, `region`, `job` | labels that do not narrow a silence on their own (repeatable; replaces the default) |
| `--ignore-label` | *(none)* | labels left out of the history query (repeatable) |
| `--header` | *(none)* | extra `Name: value` HTTP header for both APIs, e.g. `Authorization: Bearer ...` |
| `--format` | `table` | `table`, `json` or `markdown` |
| `--sort` | `age` | `age` (oldest first) or `creator` |
| `--level`, `--strict` | | as for `lint` |
| `--timeout` | `30s` | timeout for all API requests |

Limits:

- An edit that changes the matchers or `startsAt` makes Alertmanager expire the
  old silence and create a new one with a new id, so such a chain of
  extensions shows up as a fresh silence.
- `never-fired` queries the `ALERTS` series in Prometheus. Labels that only
  Alertmanager sees, such as Prometheus `external_labels`, are not on that
  series; pass them with `--ignore-label` or the check reports false positives.
  History is bounded by the Prometheus retention.

## Migrating from prom-alert-linter

[prom-alert-linter](https://github.com/moveeeax/prom-alert-linter) is archived
and its checks live here. Replace
`go run github.com/moveeeax/prom-alert-linter/cmd/prom-alert-linter@latest rules/*.yml`
with the [GitHub Action](#use-it-in-ci) or with the binary:

```console
$ go run github.com/moveeeax/prom-alert-lint@latest lint rules/*.yml \
    --require-runbook --skip-non-rules \
    --level missing-annotation=info --level missing-runbook=info \
    --level missing-for=warning --level missing-label=warning \
    --level trivial-expr=warning --level duplicate-alert=warning \
    --level parse-error=warning --strict
```

The overrides turn the old WARN checks into warnings, which fail the run
through `--strict`, and the old INFO checks into info, which never fail. Checks
the old tool did not have (`invalid-promql`, `invalid-for`, `missing-expr`,
`not-a-rule`, recording-rule PromQL) stay errors.

| prom-alert-linter | prom-alert-lint |
| --- | --- |
| `missing-for` | `missing-for` |
| `missing-severity` | `missing-label` (default `--require-label severity`) |
| `missing-summary`, `missing-description` | `missing-annotation` |
| `missing-runbook` | `missing-runbook` (with `--require-runbook`) |
| `constant-expression` | `trivial-expr` (checked on the PromQL AST, not a regex) |
| `duplicate-name` | `duplicate-alert` (name plus static labels) |
| `invalid-yaml` | `parse-error` |
| skip of YAML without `groups:` | `--skip-non-rules` |

## How it works

Rule files are decoded with `gopkg.in/yaml.v3` into the standard Prometheus
`groups -> rules` shape, tracking each rule's source line for diagnostics. Every
`expr` is fed to Prometheus's own `promql/parser`, so a query is only accepted if
Prometheus itself would accept it — no reimplemented PromQL grammar to drift out
of date. Alert names are tracked across every file so duplicates are caught even
when they live in different rule files. Durations are validated with
`prometheus/common/model`.

## Use it in CI

This repo also ships a composite GitHub Action:

```yaml
- uses: moveeeax/prom-alert-lint@v1
  with:
    files: "rules/*.yml"
    args: "--strict --require-label team"
```

## Development

```console
$ make all      # gofmt check, vet, test, build
$ make race     # go test -race ./...
$ make smoke    # run the linter over examples/
```

## License

[MIT](LICENSE)
