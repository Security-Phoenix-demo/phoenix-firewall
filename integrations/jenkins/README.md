# Phoenix Supply Chain Firewall -- Jenkins Integration

## Option 1: Shared Library (recommended)

1. Add this repo as a Jenkins shared library:
   - **Manage Jenkins > System > Global Pipeline Libraries**
   - Name: `phoenix-firewall`
   - Source: `https://github.com/Security-Phoenix-demo/phoenix-firewall.git`
   - Default version: `main`

2. Use in your Jenkinsfile:

```groovy
@Library('phoenix-firewall') _

pipeline {
    agent any
    environment {
        PHOENIX_API_KEY = credentials('phoenix-api-key')
    }
    stages {
        stage('Security') {
            steps {
                phoenixFirewall(apiKey: env.PHOENIX_API_KEY)
            }
        }
        stage('Build') {
            steps {
                sh 'npm ci'  // Protected
            }
        }
    }
    post {
        always {
            phoenixFirewall.report()
        }
    }
}
```

## Option 2: Inline (no shared library)

Copy the stage from `Jenkinsfile` into your pipeline.

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `apiKey` | `$PHOENIX_API_KEY` | Phoenix API key |
| `apiUrl` | `https://api.cvedetails.io` | API endpoint |
| `mode` | `enforce` | `enforce`, `warn`, `audit` |
| `failOn` | `block` | Fail on: `block`, `warn`, `any` |
| `strict` | `false` | Fail-closed when API unreachable |
| `minPackageAgeHours` | `0` | Quarantine threshold |
| `reportPath` | `phoenix-firewall-report.json` | Report output |

## Credentials Setup

1. **Manage Jenkins > Credentials > System > Global credentials**
2. Add **Secret text** with ID: `phoenix-api-key`
3. Paste your Phoenix API key from [cvedetails.io/admin](https://cvedetails.io/admin)

## License

Apache 2.0 -- Copyright 2026 Phoenix Security Ltd
