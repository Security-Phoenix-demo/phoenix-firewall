#!/usr/bin/env bash
# Phoenix Supply Chain Firewall — Universal Installer
# Usage: curl -sfL https://raw.githubusercontent.com/Security-Phoenix-demo/phoenix-firewall/main/integrations/generic/install.sh | bash
#
# Environment variables:
#   PHOENIX_API_KEY     - API key (required)
#   PHOENIX_MODE        - enforce | warn | audit (default: enforce)
#   PHOENIX_FAIL_ON     - block | warn | any (default: block)
#   PHOENIX_STRICT      - true | false (default: false)
#   PHOENIX_INSTALL_DIR - Binary install directory (default: /usr/local/bin)
#   PHOENIX_VERSION     - Binary version (default: latest)

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Phoenix Supply Chain Firewall — Installer${NC}"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)
        echo -e "${RED}Unsupported architecture: $ARCH${NC}" >&2
        exit 1
        ;;
esac

INSTALL_DIR="${PHOENIX_INSTALL_DIR:-/usr/local/bin}"
VERSION="${PHOENIX_VERSION:-latest}"
BINARY="phoenix-firewall-${OS}-${ARCH}"
BASE_URL="https://github.com/Security-Phoenix-demo/phoenix-firewall/releases"

# Resolve latest version
if [ "$VERSION" = "latest" ]; then
    VERSION=$(curl -sf "${BASE_URL}/latest" -o /dev/null -w '%{redirect_url}' | grep -oP 'tag/\K[^/]+' || echo "latest")
    DOWNLOAD_URL="${BASE_URL}/latest/download/${BINARY}"
else
    DOWNLOAD_URL="${BASE_URL}/download/${VERSION}/${BINARY}"
fi

echo -e "  Platform: ${OS}/${ARCH}"
echo -e "  Version:  ${VERSION}"
echo -e "  Target:   ${INSTALL_DIR}/phoenix-firewall"

# Download
echo -e "\n${YELLOW}Downloading...${NC}"
TMP=$(mktemp)
HTTP_CODE=$(curl -sfL -o "$TMP" -w '%{http_code}' "$DOWNLOAD_URL" || true)

if [ "$HTTP_CODE" != "200" ] || [ ! -s "$TMP" ]; then
    echo -e "${RED}Download failed (HTTP $HTTP_CODE)${NC}" >&2
    echo -e "URL: $DOWNLOAD_URL" >&2
    rm -f "$TMP"
    exit 1
fi

# Verify SHA256 (if available)
SHA_URL="${DOWNLOAD_URL}.sha256"
EXPECTED_SHA=$(curl -sf "$SHA_URL" 2>/dev/null | awk '{print $1}' || echo "")
if [ -n "$EXPECTED_SHA" ]; then
    if command -v sha256sum &>/dev/null; then
        ACTUAL_SHA=$(sha256sum "$TMP" | awk '{print $1}')
    elif command -v shasum &>/dev/null; then
        ACTUAL_SHA=$(shasum -a 256 "$TMP" | awk '{print $1}')
    fi
    if [ -n "${ACTUAL_SHA:-}" ] && [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
        echo -e "${RED}SHA256 verification failed!${NC}" >&2
        echo "Expected: $EXPECTED_SHA" >&2
        echo "Actual:   $ACTUAL_SHA" >&2
        rm -f "$TMP"
        exit 1
    fi
    echo -e "${GREEN}  SHA256 verified${NC}"
fi

# Install
chmod +x "$TMP"
if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP" "${INSTALL_DIR}/phoenix-firewall"
else
    sudo mv "$TMP" "${INSTALL_DIR}/phoenix-firewall"
fi

echo -e "${GREEN}  Installed to ${INSTALL_DIR}/phoenix-firewall${NC}"

# Configure if API key is set
if [ -n "${PHOENIX_API_KEY:-}" ]; then
    echo -e "\n${YELLOW}Configuring CI mode...${NC}"
    EXTRA_FLAGS=""
    [ "${PHOENIX_STRICT:-false}" = "true" ] && EXTRA_FLAGS="$EXTRA_FLAGS --strict"
    [ "${PHOENIX_MIN_AGE_HOURS:-0}" != "0" ] && EXTRA_FLAGS="$EXTRA_FLAGS --min-package-age-hours ${PHOENIX_MIN_AGE_HOURS}"

    eval $(phoenix-firewall \
        --api-key "$PHOENIX_API_KEY" \
        --ci \
        --mode "${PHOENIX_MODE:-enforce}" \
        --fail-on "${PHOENIX_FAIL_ON:-block}" \
        --report-path "${PHOENIX_REPORT_PATH:-phoenix-firewall-report.json}" \
        $EXTRA_FLAGS)

    echo -e "${GREEN}  Package managers are now protected${NC}"
else
    echo -e "\n${YELLOW}Set PHOENIX_API_KEY to enable CI mode automatically${NC}"
    echo -e "  Usage: phoenix-firewall --api-key YOUR_KEY --ci"
fi

echo -e "\n${GREEN}Phoenix Firewall ready${NC}"
