#!/usr/bin/env bash
# Verify all enhancements are working

set -euo pipefail

VENV_BIN="${VIRTUAL_ENV:-}/bin"
TOOLS_DIR="${TOOLS_DIR:-./tools}"

echo "=========================================="
echo "Guardian Enhancement Verification"
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

echo "=== NEW RECONNAISSANCE TOOLS ==="
test_tool "interactsh-client" "command -v interactsh-client || test -x ${TOOLS_DIR}/.bin/interactsh-client"
test_tool "gau" "command -v gau"
test_tool "waybackurls" "command -v waybackurls"
test_tool "arjun" "${VENV_BIN}/arjun --help"
test_tool "CORScanner" "test -f ${TOOLS_DIR}/vendor/CORScanner/cors_scan.py"

echo ""
echo "=== ENHANCED EXISTING TOOLS ==="
test_tool "retire.js" "retire --version"
test_tool "ZAP (hybrid)" "${VENV_BIN}/guardian-zap"
test_tool "masscan" "command -v masscan" "true"
test_tool "smart-portscan" "test -x ${VENV_BIN}/guardian-portscan"

echo ""
echo "=== CORE TOOLS (SANITY CHECK) ==="
test_tool "nmap" "command -v nmap"
test_tool "httpx" "${VENV_BIN}/httpx -version"
test_tool "nuclei" "${VENV_BIN}/nuclei -version"

echo ""
echo "=========================================="
success_pct=$((success * 100 / total))
echo "Results: $success/$total ($success_pct%)"

if [[ ${#failed[@]} -gt 0 ]]; then
    echo ""
    echo "Failed tools:"
    printf '  - %s\n' "${failed[@]}"
    echo ""
    echo "Run ./setup.sh again to fix missing tools"
    exit 1
else
    echo ""
    echo "✓ All enhancements verified successfully!"
    exit 0
fi
