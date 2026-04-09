#!/usr/bin/env bash
# Phoenix Firewall — Lockfile Checker
# Checks all packages in a lockfile against Phoenix firewall API
# Usage: ./check-lockfile.sh [package-lock.json|yarn.lock|requirements.txt]

set -euo pipefail

API_KEY="${PHOENIX_API_KEY:-}"
API_URL="${PHOENIX_API_URL:-https://api.cvedetails.io}"

if [ -z "$API_KEY" ]; then
    echo "Error: PHOENIX_API_KEY is required" >&2
    exit 1
fi

LOCKFILE="${1:-}"

# Auto-detect lockfile
if [ -z "$LOCKFILE" ]; then
    for f in package-lock.json yarn.lock pnpm-lock.yaml requirements.txt Pipfile.lock poetry.lock Cargo.lock Gemfile.lock go.sum; do
        if [ -f "$f" ]; then
            LOCKFILE="$f"
            break
        fi
    done
fi

if [ -z "$LOCKFILE" ] || [ ! -f "$LOCKFILE" ]; then
    echo "Error: No lockfile found. Specify one as argument." >&2
    exit 1
fi

echo "Phoenix Firewall — checking $LOCKFILE"

# Extract packages based on lockfile type
case "$LOCKFILE" in
    package-lock.json)
        PACKAGES=$(node -e "
            const lock = require('./$LOCKFILE');
            const pkgs = Object.entries(lock.packages || lock.dependencies || {})
                .filter(([k]) => k && !k.startsWith('node_modules/'))
                .map(([name, info]) => ({
                    package_name: name.replace('node_modules/', ''),
                    package_version: info.version || '*',
                    ecosystem: 'npm'
                }))
                .slice(0, 500);
            console.log(JSON.stringify({packages: pkgs}));
        ")
        ;;
    requirements.txt)
        PACKAGES=$(python3 -c "
import re, json
pkgs = []
for line in open('$LOCKFILE'):
    line = line.strip()
    if line and not line.startswith('#') and not line.startswith('-'):
        m = re.match(r'^([a-zA-Z0-9._-]+)(?:==|>=|<=|~=|!=)?(.+)?', line)
        if m:
            pkgs.append({'package_name': m.group(1), 'package_version': (m.group(2) or '*').strip(), 'ecosystem': 'pypi'})
print(json.dumps({'packages': pkgs[:500]}))
        ")
        ;;
    *)
        echo "Unsupported lockfile format: $LOCKFILE" >&2
        echo "Supported: package-lock.json, requirements.txt" >&2
        exit 1
        ;;
esac

# Call batch-check API
RESPONSE=$(curl -sf -X POST "${API_URL}/api/v1/malware-intel/firewall/batch-check" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${API_KEY}" \
    -d "$PACKAGES")

BLOCKED=$(echo "$RESPONSE" | jq '.blocked // 0')
WARNED=$(echo "$RESPONSE" | jq '.warned // 0')
TOTAL=$(echo "$RESPONSE" | jq '.total // 0')

echo ""
echo "Results: $TOTAL checked, $BLOCKED blocked, $WARNED warned"

if [ "$BLOCKED" -gt 0 ]; then
    echo ""
    echo "Blocked packages:"
    echo "$RESPONSE" | jq -r '.results[] | select(.action == "block") | "  \(.package_name)@\(.package_version) — \(.reason)"'
    exit 1
fi

if [ "$WARNED" -gt 0 ]; then
    echo ""
    echo "Warned packages:"
    echo "$RESPONSE" | jq -r '.results[] | select(.action == "warn") | "  \(.package_name)@\(.package_version) — \(.reason)"'
fi

echo ""
echo "All packages passed"
