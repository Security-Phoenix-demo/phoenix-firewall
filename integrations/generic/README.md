# Phoenix Firewall — Generic CI Integration

For any CI system not explicitly supported (CircleCI, Drone, Buildkite, etc.).

## One-Line Install

```bash
curl -sfL https://raw.githubusercontent.com/Security-Phoenix-demo/phoenix-firewall/main/integrations/generic/install.sh | PHOENIX_API_KEY=your-key bash
```

## Standalone Lockfile Check (no proxy needed)

```bash
export PHOENIX_API_KEY=your-key
./check-lockfile.sh package-lock.json
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PHOENIX_API_KEY` | Yes | — | Phoenix API key |
| `PHOENIX_MODE` | No | `enforce` | `enforce`, `warn`, `audit` |
| `PHOENIX_FAIL_ON` | No | `block` | `block`, `warn`, `any` |
| `PHOENIX_STRICT` | No | `false` | Fail-closed |
| `PHOENIX_INSTALL_DIR` | No | `/usr/local/bin` | Binary install path |
| `PHOENIX_VERSION` | No | `latest` | Binary version |

## Examples

### CircleCI

```yaml
jobs:
  build:
    docker:
      - image: node:22
    steps:
      - checkout
      - run:
          name: Install Phoenix Firewall
          command: curl -sfL https://raw.githubusercontent.com/Security-Phoenix-demo/phoenix-firewall/main/integrations/generic/install.sh | bash
      - run: npm ci  # Protected
```

### Drone CI

```yaml
steps:
  - name: phoenix-firewall
    image: alpine
    commands:
      - apk add curl bash
      - curl -sfL https://raw.githubusercontent.com/Security-Phoenix-demo/phoenix-firewall/main/integrations/generic/install.sh | bash
  - name: build
    image: node:22
    commands:
      - npm ci  # Protected
```

### Buildkite

```yaml
steps:
  - label: ":shield: Phoenix Firewall"
    command: curl -sfL https://raw.githubusercontent.com/Security-Phoenix-demo/phoenix-firewall/main/integrations/generic/install.sh | bash
  - label: ":npm: Install"
    command: npm ci
```
