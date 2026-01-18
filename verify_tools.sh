#!/usr/bin/env bash
# Standalone tool verification script

set -euo pipefail

VENV_BIN="${VIRTUAL_ENV:-}/bin"
TOOLS_DIR="${TOOLS_DIR:-./tools}"

echo "=========================================="
echo "Guardian Tool Verification"
echo "=========================================="
echo ""

failed=()
success=0
total=0

test_tool() {
    local name="$1"
    local cmd="$2"
    local optional="${3:-false}"
    
    ((total++))
    
    if eval "$cmd" >/dev/null 2>&1; then
        echo "✓ $name"
        ((success++))
        return 0
    else
        if [[ "$optional" == "true" ]]; then
            echo "⚠ $name (optional)"
        else
            echo "✗ $name"
            failed+=("$name")
        fi
        return 1
    fi
}

echo "Core Network Tools:"
test_tool "nmap" "command -v nmap"
test_tool "enum4linux" "command -v enum4linux" "true"

echo ""
echo "ProjectDiscovery Suite:"
test_tool "httpx" "${VENV_BIN}/httpx -version"
test_tool "nuclei" "${VENV_BIN}/nuclei -version"
test_tool "katana" "${VENV_BIN}/katana -version"
test_tool "ffuf" "${VENV_BIN}/ffuf -version"

echo ""
echo "Web Tools:"
test_tool "whatweb" "command -v whatweb"
test_tool "testssl" "${VENV_BIN}/testssl --version"
test_tool "retire" "retire --version"

echo ""
echo "Docker & ZAP:"
test_tool "docker" "docker --version"
test_tool "docker-daemon" "docker ps"
test_tool "zap-image" "docker images ghcr.io/zaproxy/zaproxy:stable -q"

echo ""
echo "Kiterunner:"
test_tool "kiterunner-wordlist" "test -f ${TOOLS_DIR}/vendor/kiterunner/routes-small.kite"

echo ""
echo "=========================================="
echo "Summary"
echo "=========================================="

success_pct=$((success * 100 / total))
echo "✓ Success: $success/$total ($success_pct%)"

if [[ ${#failed[@]} -gt 0 ]]; then
    echo "✗ Failed: ${#failed[@]} tools"
    printf '  - %s\n' "${failed[@]}"
    exit 1
else
    echo ""
    echo "All tools verified! ✓"
    exit 0
fi
