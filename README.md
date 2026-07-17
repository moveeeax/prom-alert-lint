# prom-alert-lint

> Catch broken or sloppy Prometheus alert rules before they page (or fail to).

**Status:** 🚧 In development

## Overview

Linter for Prometheus alerting rules: PromQL sanity plus label/annotation hygiene.

## Features

- Load rule files and parse each `alert` group
- Validate PromQL expressions parse and are non-trivial
- Enforce presence of `for`, severity label and summary/description annotations
- Configurable required labels/annotations and naming conventions
- Non-zero exit and precise diagnostics for CI

## Stack

Go 1.22, Prometheus `promql`/`rulefmt` libs, `cobra`.

## Usage

```bash
prom-alert-lint lint rules/*.yml --require-label severity
```

## License

MIT
