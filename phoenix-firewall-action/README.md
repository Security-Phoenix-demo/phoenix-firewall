# Phoenix Supply Chain Firewall -- GitHub Action

> Enforce Phoenix firewall rules on package installations in CI/CD workflows.

## Usage

```yaml
- uses: phoenix-security/firewall-action@v1
  with:
    api-key: ${{ secrets.PHOENIX_API_KEY }}
    mode: enforce
    fail-on: block
```

## Full Example

```yaml
name: Secure Build
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: phoenix-security/firewall-action@v1
        with:
          api-key: ${{ secrets.PHOENIX_API_KEY }}
          mode: enforce
          fail-on: block
          egress-policy: block
          allowed-endpoints: |
            registry.npmjs.org:443
            pypi.org:443

      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '22', cache: 'npm' }
      - run: npm ci  # Protected by Phoenix Firewall
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api-key` | Yes | - | Phoenix API key |
| `mode` | No | `enforce` | `enforce`, `warn`, or `audit` |
| `fail-on` | No | `block` | Fail on: `block`, `warn`, or `any` |
| `strict` | No | `false` | Fail-closed when API unreachable |
| `min-package-age-hours` | No | `0` | Quarantine threshold |
| `report-path` | No | `phoenix-firewall-report.json` | Report output |
| `egress-policy` | No | `off` | Harden-Runner: `block`, `audit`, `off` |

## License

Apache 2.0 -- Copyright 2026 Phoenix Security Ltd
