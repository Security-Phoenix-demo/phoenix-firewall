#!/usr/bin/env groovy
/**
 * Phoenix Supply Chain Firewall -- Jenkins Shared Library
 *
 * Usage in Jenkinsfile:
 *   @Library('phoenix-firewall') _
 *   phoenixFirewall(apiKey: env.PHOENIX_API_KEY)
 *
 * Or inline without shared library:
 *   load 'phoenixFirewall.groovy'
 */

def call(Map config = [:]) {
    def apiKey    = config.apiKey ?: env.PHOENIX_API_KEY
    def apiUrl    = config.apiUrl ?: env.PHOENIX_API_URL ?: 'https://api.cvedetails.io'
    def mode      = config.mode ?: 'enforce'
    def failOn    = config.failOn ?: 'block'
    def strict    = config.strict ?: false
    def minAgeHours = config.minPackageAgeHours ?: 0
    def reportPath  = config.reportPath ?: 'phoenix-firewall-report.json'
    def binaryUrl   = config.binaryUrl ?: 'https://github.com/Security-Phoenix-demo/phoenix-firewall/releases/latest/download'

    if (!apiKey) {
        error "Phoenix Firewall: PHOENIX_API_KEY is required. Set it in Jenkins credentials."
    }

    echo "Phoenix Supply Chain Firewall"
    echo "   Mode: ${mode} | Fail on: ${failOn} | Strict: ${strict}"

    // Download binary
    sh """
        ARCH=\$(uname -m)
        case "\$ARCH" in
            x86_64)  ARCH="amd64" ;;
            aarch64) ARCH="arm64" ;;
        esac
        OS=\$(uname -s | tr '[:upper:]' '[:lower:]')
        BINARY="phoenix-firewall-\${OS}-\${ARCH}"
        echo "Downloading Phoenix Firewall (\${BINARY})..."
        curl -sfL "${binaryUrl}/\${BINARY}" -o /tmp/phoenix-firewall
        chmod +x /tmp/phoenix-firewall
    """

    // Configure CI mode
    def extraFlags = ""
    if (strict) { extraFlags += " --strict" }
    if (minAgeHours > 0) { extraFlags += " --min-package-age-hours ${minAgeHours}" }

    sh """
        eval \$(/tmp/phoenix-firewall \
            --api-key '${apiKey}' \
            --api-url '${apiUrl}' \
            --ci \
            --mode '${mode}' \
            --fail-on '${failOn}' \
            --report-path '${reportPath}' \
            ${extraFlags})
    """

    echo "Phoenix Firewall configured -- package managers are now protected"
}

// Generate report summary (call in post block)
def report(String reportPath = 'phoenix-firewall-report.json') {
    if (fileExists(reportPath)) {
        def blocked = sh(
            script: "jq '[.[] | select(.action == \"block\")] | length' ${reportPath} 2>/dev/null || echo 0",
            returnStdout: true
        ).trim()
        def warned = sh(
            script: "jq '[.[] | select(.action == \"warn\")] | length' ${reportPath} 2>/dev/null || echo 0",
            returnStdout: true
        ).trim()
        def total = sh(
            script: "jq '. | length' ${reportPath} 2>/dev/null || echo 0",
            returnStdout: true
        ).trim()

        echo "Phoenix Firewall Report: ${total} evaluated, ${blocked} blocked, ${warned} warned"

        if (blocked.toInteger() > 0) {
            def details = sh(
                script: "jq '[.[] | select(.action == \"block\")]' ${reportPath}",
                returnStdout: true
            )
            echo "Blocked packages:\n${details}"
        }

        archiveArtifacts artifacts: reportPath, allowEmptyArchive: true
    }
}
