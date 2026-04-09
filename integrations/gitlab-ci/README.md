# Phoenix Firewall — GitLab CI Integration

## Quick Start

Add to your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Security-Phoenix-demo/phoenix-firewall/main/integrations/gitlab-ci/phoenix-firewall.yml'

stages:
  - test
  - build

# Phoenix Firewall runs automatically on lockfile changes
# Set PHOENIX_API_KEY in CI/CD → Variables (masked)

build:
  stage: build
  script:
    - npm ci  # Protected by Phoenix Firewall
```

## Configuration Variables

Set these in **Settings → CI/CD → Variables**:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PHOENIX_API_KEY` | Yes | — | Your Phoenix API key (mask this!) |
| `PHOENIX_MODE` | No | `enforce` | `enforce`, `warn`, or `audit` |
| `PHOENIX_FAIL_ON` | No | `block` | Fail pipeline on: `block`, `warn`, `any` |
| `PHOENIX_STRICT` | No | `false` | Fail-closed when API unreachable |
| `PHOENIX_MIN_AGE_HOURS` | No | `0` | Quarantine: block packages newer than N hours |

## Examples

### Basic (enforce mode)

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Security-Phoenix-demo/phoenix-firewall/main/integrations/gitlab-ci/phoenix-firewall.yml'

variables:
  PHOENIX_MODE: enforce
```

### Strict mode (air-gapped friendly)

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Security-Phoenix-demo/phoenix-firewall/main/integrations/gitlab-ci/phoenix-firewall.yml'

variables:
  PHOENIX_MODE: enforce
  PHOENIX_STRICT: "true"
  PHOENIX_MIN_AGE_HOURS: "24"
```

## Artifacts

The firewall report (`phoenix-firewall-report.json`) is saved as a pipeline artifact for 30 days. Download it from the job page.
