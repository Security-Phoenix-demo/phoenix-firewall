# Phoenix Supply Chain Firewall -- Bitbucket Pipelines Integration

## Quick Start

```yaml
pipelines:
  default:
    - step:
        name: 'Security'
        image: alpine:3.19
        script:
          - apk add --no-cache curl bash
          - curl -sfL https://github.com/Security-Phoenix-demo/phoenix-firewall/releases/latest/download/phoenix-firewall-linux-amd64 -o /usr/local/bin/phoenix-firewall
          - chmod +x /usr/local/bin/phoenix-firewall
          - eval $(phoenix-firewall --api-key $PHOENIX_API_KEY --ci)
        artifacts:
          - phoenix-firewall-report.json

    - step:
        name: 'Build'
        script:
          - npm ci  # Protected
```

## Setup

1. **Repository Settings > Pipelines > Repository variables**
2. Add `PHOENIX_API_KEY` as a **secured** variable
3. Add the firewall step to your `bitbucket-pipelines.yml`

## Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PHOENIX_API_KEY` | Yes | -- | Phoenix API key (secured) |
| `MODE` | No | `enforce` | `enforce`, `warn`, `audit` |
| `FAIL_ON` | No | `block` | `block`, `warn`, `any` |
| `STRICT` | No | `false` | Fail-closed when API unreachable |
| `MIN_AGE_HOURS` | No | `0` | Quarantine threshold |

## Pipe Usage

If using the published pipe image:

```yaml
- step:
    name: 'Security'
    script:
      - pipe: docker://phoenixsecurity/firewall-pipe:latest
        variables:
          PHOENIX_API_KEY: $PHOENIX_API_KEY
          MODE: 'enforce'
          FAIL_ON: 'block'
```

## License

Apache 2.0 -- Copyright 2026 Phoenix Security Ltd
