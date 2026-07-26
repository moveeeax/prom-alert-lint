# prom-alert-lint

[![ci](https://github.com/moveeeax/prom-alert-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/prom-alert-lint/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8?logo=go)](https://go.dev/)
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
| `duplicate-alert` | error | the same alert name is defined twice (across all files) |
| `not-a-rule` | error | a rule sets neither `alert` nor `record` (or both) |
| `bad-severity` | warning | the `severity` value is outside the allowed set (`--severity-value`) |
| `bad-name` | warning | the alert name does not match `--name-pattern` |

Every diagnostic carries the **file, line, and alert name**.

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
error   examples/bad.yml:5  [DiskFilling] missing-for: alert has no `for`; it fires on a single scrape
error   examples/bad.yml:5  [DiskFilling] missing-label: required label "severity" is missing or empty
error   examples/bad.yml:9  [BrokenQuery] invalid-promql: PromQL does not parse: 1:32: parse error: unexpected end of input
error   examples/bad.yml:19 [AlwaysOn] trivial-expr: alert expression is a constant and will always or never fire
error   examples/bad.yml:29 [DiskFilling] duplicate-alert: alert name "DiskFilling" already defined at examples/bad.yml:5
7 error(s), 0 warning(s) in 4 rule(s) across 1 file(s)
$ echo $?
1
```

Machine-readable output for tooling:

```console
$ prom-alert-lint lint rules/*.yml --format json
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
| `--strict` | `false` | treat warnings as failures |

Exit codes: `0` clean, `1` violations found (or warnings under `--strict`),
`2` usage error.

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
