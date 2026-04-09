# Phoenix Supply Chain Firewall -- Azure DevOps Integration

## Quick Start

```yaml
resources:
  repositories:
    - repository: phoenix-firewall
      type: github
      name: Security-Phoenix-demo/phoenix-firewall
      endpoint: github-connection  # Your GitHub service connection

pool:
  vmImage: 'ubuntu-latest'

steps:
  - template: integrations/azure-devops/phoenix-firewall.yml@phoenix-firewall
    parameters:
      apiKey: $(PHOENIX_API_KEY)
      mode: enforce

  - script: npm ci
    displayName: 'Install Dependencies (Protected)'
```

## Setup

1. **Project Settings > Pipelines > Service Connections** -- add a GitHub service connection
2. **Pipelines > Library > Variable Groups** -- add `PHOENIX_API_KEY` as a secret variable
3. Reference the template in your `azure-pipelines.yml`

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `apiKey` | string | -- | Phoenix API key (required) |
| `apiUrl` | string | `https://api.cvedetails.io` | API endpoint |
| `mode` | string | `enforce` | `enforce`, `warn`, `audit` |
| `failOn` | string | `block` | `block`, `warn`, `any` |
| `strict` | boolean | `false` | Fail-closed when API unreachable |
| `minPackageAgeHours` | number | `0` | Quarantine threshold |
| `reportPath` | string | `phoenix-firewall-report.json` | Report output |

## Artifacts

The pipeline template automatically publishes the firewall report as a build artifact named `phoenix-firewall-report`. Blocked packages are logged as Azure DevOps errors visible in the build summary.

## License

Apache 2.0 -- Copyright 2026 Phoenix Security Ltd
