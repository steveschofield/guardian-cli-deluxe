#!/usr/bin/env bash
# Guardian CLI Deluxe - COMPLETE Setup (All Tools + Fixes + Enhancements)
# This version includes:
# - ALL original tools from setup.sh
# - Fixed dalfox (go install)
# - Fixed commix (safe git clone)
# - Enhanced retire.js
# - ZAP hybrid mode
# - New recon tools (interactsh, gau, CORScanner)
# - Smart port scanning
# - Made idempotent

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${BASE_DIR}/venv"
VENV_BIN=""
TOOLS_DIR="${BASE_DIR}/tools/vendor"

# Detect OS
if [[ "$(uname)" == "Darwin" ]]; then
    OS="macos"
elif [[ -f /etc/debian_version ]]; then
    OS="debian"
else
    OS="unknown"
fi

echo "Detected OS: ${OS}"

# Guard against unsupported Python versions (langchain requires < 3.13).
PYTHON_CHECK_BIN=""
if [[ -n "${VIRTUAL_ENV:-}" && -x "${VENV_BIN}/python" ]]; then
    PYTHON_CHECK_BIN="${VENV_BIN}/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_CHECK_BIN="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CHECK_BIN="$(command -v python)"
fi

if [[ -n "${PYTHON_CHECK_BIN}" ]]; then
    if ! "${PYTHON_CHECK_BIN}" - <<'PY'
import sys
sys.exit(0 if (sys.version_info.major, sys.version_info.minor) < (3, 13) else 1)
PY
    then
        echo "ERROR: Python 3.13+ is not supported. Use Python 3.11 or 3.12." >&2
        exit 1
    fi
fi

# ============================================================================
# HELPER FUNCTIONS (ENHANCED)
# ============================================================================

# Safe git clone - handles existing directories
safe_git_clone() {
    local repo_url="$1"
    local target_dir="$2"
    
    if [[ -d "$target_dir" ]]; then
        if [[ -d "${target_dir}/.git" ]]; then
            echo "Updating existing repo: $(basename "$target_dir")"
            (cd "$target_dir" && git pull --ff-only 2>/dev/null) || echo "WARN: Failed to update" >&2
        else
            echo "WARN: Directory exists but not a git repo: $target_dir" >&2
        fi
    else
        git clone "$repo_url" "$target_dir" || echo "WARN: Clone failed" >&2
    fi
}

# Copy ALL original helper functions from setup.sh
link_into_venv() {
    local src="$1"
    local name="$2"
    if [[ ! -x "${src}" ]]; then
        echo "WARN: ${src} is not executable"
    fi
    ln -sf "${src}" "${VENV_BIN}/${name}"
}

install_github_release_and_link() {
    local repo="$1"
    local bin="$2"
    local bin_dir="${BASE_DIR}/tools/.bin"
    mkdir -p "${bin_dir}"
    
    if [[ -x "${bin_dir}/${bin}" ]]; then
        link_into_venv "${bin_dir}/${bin}" "${bin}"
        return 0
    fi
    
    python "${BASE_DIR}/scripts/install_github_release_binary.py" "${repo}" "${bin}" || return 1
    
    if [[ -x "${bin_dir}/${bin}" ]]; then
        link_into_venv "${bin_dir}/${bin}" "${bin}"
    fi
}

go_install_and_link() {
    local pkg="$1"
    local bin="$2"
    
    if command -v "$bin" >/dev/null 2>&1; then
        link_into_venv "$(command -v "$bin")" "$bin"
        return 0
    fi
    
    if ! command -v go >/dev/null 2>&1; then
        echo "WARN: go not found; skipping ${bin}" >&2
        return 0
    fi
    
    echo "Installing ${bin}..."
    go install "${pkg}" || echo "WARN: ${bin} install failed" >&2
    
    local gobin
    gobin="$(go env GOBIN 2>/dev/null || true)"
    if [[ -z "${gobin}" ]]; then
        gobin="$(go env GOPATH 2>/dev/null || true)"
        gobin="${gobin:-${GOPATH:-$HOME/go}}/bin"
    fi
    
    if [[ -x "${gobin}/${bin}" ]]; then
        link_into_venv "${gobin}/${bin}" "${bin}"
    fi
}

write_python_wrapper_into_venv() {
    local script="$1"
    local name="$2"
    cat > "${VENV_BIN}/${name}" <<WRAPPER
#!/usr/bin/env bash
exec "${VENV_BIN}/python" "${script}" "\$@"
WRAPPER
    chmod +x "${VENV_BIN}/${name}"
}

# Original install_system_binary function
install_system_binary() {
    local bin="$1"
    local apt_pkg="$2"
    local brew_pkg="$3"
    
    if command -v "${bin}" >/dev/null 2>&1; then
        link_into_venv "$(command -v "${bin}")" "${bin}"
        return 0
    fi
    
    if [[ "${OS}" == "debian" ]]; then
        if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            echo "Installing ${bin}..."
            sudo apt-get update -qq && sudo apt-get install -y "${apt_pkg}"
            if command -v "${bin}" >/dev/null 2>&1; then
                link_into_venv "$(command -v "${bin}")" "${bin}"
            fi
        fi
    elif [[ "${OS}" == "macos" ]]; then
        if command -v brew >/dev/null 2>&1; then
            echo "Installing ${bin}..."
            brew install "${brew_pkg:-${bin}}"
            if command -v "${bin}" >/dev/null 2>&1; then
                link_into_venv "$(command -v "${bin}")" "${bin}"
            fi
        fi
    fi
}

# ============================================================================
# CORE SETUP (FROM ORIGINAL)
# ============================================================================

install_libpcap_dev() {
    if [[ "${OS}" == "macos" ]]; then
        if command -v brew >/dev/null 2>&1; then
            brew install libpcap 2>/dev/null || true
            export CPATH="/opt/homebrew/include:${CPATH:-}"
            export LIBRARY_PATH="/opt/homebrew/lib:${LIBRARY_PATH:-}"
        fi
    elif [[ "${OS}" == "debian" ]]; then
        if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            sudo apt-get update -qq && sudo apt-get install -y libpcap-dev
        fi
    fi
}

ensure_go() {
    command -v go >/dev/null 2>&1 && return
    
    if [[ "${OS}" == "debian" ]] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y golang-go
    elif [[ "${OS}" == "macos" ]] && command -v brew >/dev/null 2>&1; then
        brew install go
    fi
}

ensure_node_and_npm() {
    command -v npm >/dev/null 2>&1 && return
    
    if [[ "${OS}" == "macos" ]] && command -v brew >/dev/null 2>&1; then
        brew install node
    elif [[ "${OS}" == "debian" ]] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y nodejs npm
    fi
}

# Basic setup
install_libpcap_dev

if [[ -z "${VIRTUAL_ENV:-}" ]]; then
    if [[ -f "${VENV_DIR}/bin/activate" ]]; then
        echo "No virtualenv active; using ${VENV_DIR}"
        # shellcheck source=/dev/null
        source "${VENV_DIR}/bin/activate"
    else
        echo "ERROR: No virtualenv active." >&2
        echo "Create and activate one:" >&2
        echo "  python3.12 -m venv venv" >&2
        echo "  source venv/bin/activate" >&2
        exit 1
    fi
fi

VENV_BIN="${VIRTUAL_ENV}/bin"

ensure_go
ensure_node_and_npm

echo "Using virtualenv: ${VIRTUAL_ENV}"
mkdir -p "${TOOLS_DIR}"
"${VENV_BIN}/pip" install -e "${BASE_DIR}"
"${VENV_BIN}/pip" install -U "requests>=2.31.0" "urllib3>=2.0.7"

if [[ -f "${BASE_DIR}/package.json" ]] && command -v npm >/dev/null 2>&1; then
    (cd "${BASE_DIR}" && npm install)
fi

# ============================================================================
# ALL ORIGINAL TOOLS (KEEP EVERYTHING)
# ============================================================================

# ProjectDiscovery Tools
install_projectdiscovery_binaries() {
    local bin_dir="${BASE_DIR}/tools/.bin"
    mkdir -p "${bin_dir}"
    
    [[ ! -x "${bin_dir}/httpx" ]] && python "${BASE_DIR}/scripts/install_projectdiscovery_httpx.py" || true
    [[ ! -x "${bin_dir}/nuclei" ]] && python "${BASE_DIR}/scripts/install_projectdiscovery_nuclei.py" || true
}

# Core web tools (use safe_git_clone now)
install_testssl() {
    safe_git_clone "https://github.com/drwetter/testssl.sh.git" "${TOOLS_DIR}/testssl.sh"
    [[ -f "${TOOLS_DIR}/testssl.sh/testssl.sh" ]] && link_into_venv "${TOOLS_DIR}/testssl.sh/testssl.sh" "testssl"
}

install_xsstrike() {
    safe_git_clone "https://github.com/s0md3v/XSStrike.git" "${TOOLS_DIR}/XSStrike"
    [[ -f "${TOOLS_DIR}/XSStrike/requirements.txt" ]] && "${VENV_BIN}/pip" install -r "${TOOLS_DIR}/XSStrike/requirements.txt" --break-system-packages 2>/dev/null || true
    [[ -f "${TOOLS_DIR}/XSStrike/xsstrike.py" ]] && write_python_wrapper_into_venv "${TOOLS_DIR}/XSStrike/xsstrike.py" "xsstrike"
}

install_cmseek() {
    safe_git_clone "https://github.com/Tuhinshubhra/CMSeeK.git" "${TOOLS_DIR}/CMSeeK"
    [[ -f "${TOOLS_DIR}/CMSeeK/requirements.txt" ]] && "${VENV_BIN}/pip" install -r "${TOOLS_DIR}/CMSeeK/requirements.txt" --break-system-packages 2>/dev/null || true
    [[ -f "${TOOLS_DIR}/CMSeeK/cmseek.py" ]] && write_python_wrapper_into_venv "${TOOLS_DIR}/CMSeeK/cmseek.py" "cmseek"
}

install_whatweb() {
    safe_git_clone "https://github.com/urbanadventurer/WhatWeb.git" "${TOOLS_DIR}/WhatWeb"
    [[ -f "${TOOLS_DIR}/WhatWeb/whatweb" ]] && link_into_venv "${TOOLS_DIR}/WhatWeb/whatweb" "whatweb"
}

# FIXED: Dalfox - use go install
install_dalfox() {
    go_install_and_link "github.com/hahwul/dalfox/v2@latest" "dalfox"
}

# FIXED: Commix - use safe_git_clone
install_commix() {
    safe_git_clone "https://github.com/commixproject/commix.git" "${TOOLS_DIR}/commix"
    [[ -f "${TOOLS_DIR}/commix/commix.py" ]] && write_python_wrapper_into_venv "${TOOLS_DIR}/commix/commix.py" "commix"
}

# All other web tools
install_graphql_cop() {
    safe_git_clone "https://github.com/dolevf/graphql-cop.git" "${TOOLS_DIR}/graphql-cop"
    [[ -f "${TOOLS_DIR}/graphql-cop/requirements.txt" ]] && "${VENV_BIN}/pip" install -r "${TOOLS_DIR}/graphql-cop/requirements.txt" --break-system-packages 2>/dev/null || true
    [[ -f "${TOOLS_DIR}/graphql-cop/graphql-cop.py" ]] && write_python_wrapper_into_venv "${TOOLS_DIR}/graphql-cop/graphql-cop.py" "graphql-cop"
}

install_jsparser() {
    safe_git_clone "https://github.com/nahamsec/JSParser.git" "${TOOLS_DIR}/JSParser"
    [[ -f "${TOOLS_DIR}/JSParser/requirements.txt" ]] && "${VENV_BIN}/pip" install -r "${TOOLS_DIR}/JSParser/requirements.txt" --break-system-packages 2>/dev/null || true
    [[ -f "${TOOLS_DIR}/JSParser/JSParser.py" ]] && write_python_wrapper_into_venv "${TOOLS_DIR}/JSParser/JSParser.py" "jsparser"
}

install_jwt_tool() {
    safe_git_clone "https://github.com/ticarpi/jwt_tool.git" "${TOOLS_DIR}/jwt_tool"
    [[ -f "${TOOLS_DIR}/jwt_tool/requirements.txt" ]] && "${VENV_BIN}/pip" install -r "${TOOLS_DIR}/jwt_tool/requirements.txt" --break-system-packages 2>/dev/null || true
    [[ -f "${TOOLS_DIR}/jwt_tool/jwt_tool.py" ]] && write_python_wrapper_into_venv "${TOOLS_DIR}/jwt_tool/jwt_tool.py" "jwt_tool"
}

install_tplmap() {
    safe_git_clone "https://github.com/epinna/tplmap.git" "${TOOLS_DIR}/tplmap"
    [[ -f "${TOOLS_DIR}/tplmap/tplmap.py" ]] && write_python_wrapper_into_venv "${TOOLS_DIR}/tplmap/tplmap.py" "tplmap"
}

install_feroxbuster() {
    if ! install_github_release_and_link "epi052/feroxbuster" "feroxbuster"; then
        if command -v cargo >/dev/null 2>&1; then
            cargo install feroxbuster || true
            command -v feroxbuster >/dev/null 2>&1 && link_into_venv "$(command -v feroxbuster)" "feroxbuster"
        fi
    fi
}

install_nikto() {
    command -v nikto >/dev/null 2>&1 && return
    install_system_binary "nikto" "nikto" "nikto"
}

install_wpscan() {
    if command -v gem >/dev/null 2>&1; then
        gem install --user-install wpscan 2>/dev/null || echo "WARN: wpscan failed" >&2
    fi
}

# Go-based recon tools
install_go_recon_tools() {
    # Prefer GitHub release binaries when available.
    install_github_release_and_link "projectdiscovery/subfinder" "subfinder" || true
    install_github_release_and_link "projectdiscovery/dnsx" "dnsx" || true
    install_github_release_and_link "projectdiscovery/katana" "katana" || true
    install_github_release_and_link "projectdiscovery/naabu" "naabu" || true
    install_github_release_and_link "projectdiscovery/shuffledns" "shuffledns" || true
    install_github_release_and_link "projectdiscovery/asnmap" "asnmap" || true
    install_github_release_and_link "tomnomnom/waybackurls" "waybackurls" || true
    install_github_release_and_link "assetnote/kiterunner" "kr" || true
    install_github_release_and_link "zricethezav/gitleaks" "gitleaks" || true
    install_github_release_and_link "d3mondev/puredns" "puredns" || true

    command -v go >/dev/null 2>&1 || return
    
    go_install_and_link "github.com/ffuf/ffuf/v2@latest" "ffuf"
    go_install_and_link "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" "subfinder"
    go_install_and_link "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" "dnsx"
    go_install_and_link "github.com/projectdiscovery/katana/cmd/katana@latest" "katana"
    go_install_and_link "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" "naabu"
    go_install_and_link "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest" "shuffledns"
    go_install_and_link "github.com/projectdiscovery/asnmap/cmd/asnmap@latest" "asnmap"
    go_install_and_link "github.com/tomnomnom/waybackurls@latest" "waybackurls"
    go_install_and_link "github.com/assetnote/kiterunner@latest" "kr"
    go_install_and_link "github.com/zricethezav/gitleaks/v8@latest" "gitleaks"
    go_install_and_link "github.com/d3mondev/puredns/v2@latest" "puredns"
}

# Python tools
install_python_tools() {
    "${VENV_BIN}/pip" install --break-system-packages arjun || true
    "${VENV_BIN}/pip" install --break-system-packages dirsearch || true
    "${VENV_BIN}/pip" install --break-system-packages schemathesis || true
    "${VENV_BIN}/pip" install --break-system-packages wafw00f || true
    "${VENV_BIN}/pip" install --break-system-packages sqlmap || true
    "${VENV_BIN}/pip" install --break-system-packages sslyze || true
    "${VENV_BIN}/pip" install --break-system-packages dnsrecon || true
    "${VENV_BIN}/pip" install --break-system-packages trufflehog || true
    "${VENV_BIN}/pip" install --break-system-packages "py-altdns @ git+https://github.com/infosec-au/altdns.git" || true
    "${VENV_BIN}/pip" install --break-system-packages "linkfinder @ git+https://github.com/GerbenJavado/LinkFinder.git" || true
    "${VENV_BIN}/pip" install --break-system-packages xnlinkfinder || true
    "${VENV_BIN}/pip" install --break-system-packages "paramspider @ git+https://github.com/devanshbatham/ParamSpider.git" || true
}

# System binaries
install_system_binary "enum4linux" "enum4linux" "enum4linux"
install_system_binary "smbclient" "smbclient" "samba"
install_system_binary "showmount" "nfs-common" "nfs-utils"
install_system_binary "snmpwalk" "snmp" "net-snmp"
install_system_binary "onesixtyone" "onesixtyone" "onesixtyone"
install_system_binary "whois" "whois" "whois"
install_system_binary "hydra" "hydra" "hydra"
install_system_binary "seclists" "seclists" "seclists"

# Amass
install_amass() {
    command -v amass >/dev/null 2>&1 && link_into_venv "$(command -v amass)" "amass" && return
    install_system_binary "amass" "amass" "amass"
}

# Masscan
install_masscan() {
    command -v masscan >/dev/null 2>&1 && link_into_venv "$(command -v masscan)" "masscan" && return
    install_system_binary "masscan" "masscan" "masscan"
}

# Wappalyzer (npm)
install_wappalyzer() {
    command -v wappalyzer >/dev/null 2>&1 && return
    command -v npm >/dev/null 2>&1 || return
    
    npm install -g wappalyzer 2>/dev/null && command -v wappalyzer >/dev/null 2>&1 && link_into_venv "$(command -v wappalyzer)" "wappalyzer"
}

# UDP Proto Scanner
install_udp_proto_scanner() {
    safe_git_clone "https://github.com/portcullislabs/udp-proto-scanner.git" "${TOOLS_DIR}/udp-proto-scanner"
    if [[ -f "${TOOLS_DIR}/udp-proto-scanner/udp-proto-scanner.pl" ]]; then
        chmod +x "${TOOLS_DIR}/udp-proto-scanner/udp-proto-scanner.pl" 2>/dev/null || true
        link_into_venv "${TOOLS_DIR}/udp-proto-scanner/udp-proto-scanner.pl" "udp-proto-scanner.pl"
    fi
}

# Subjs
install_subjs() {
    command -v go >/dev/null 2>&1 || return
    safe_git_clone "https://github.com/lc/subjs.git" "${TOOLS_DIR}/subjs"
    (cd "${TOOLS_DIR}/subjs" && GOPROXY=direct GOSUMDB=off go build -o "${BASE_DIR}/tools/.bin/subjs" .) 2>/dev/null || true
    [[ -x "${BASE_DIR}/tools/.bin/subjs" ]] && link_into_venv "${BASE_DIR}/tools/.bin/subjs" "subjs"
}

# Kiterunner wordlists
install_kiterunner_wordlists() {
    local dest="${TOOLS_DIR}/kiterunner/routes-small.json"
    [[ -f "$dest" ]] && return
    mkdir -p "${TOOLS_DIR}/kiterunner"
    
    local url="https://wordlists-cdn.assetnote.io/rawdata/kiterunner/routes-small.json.tar.gz"
    curl -sL "$url" | tar -xz -C "${TOOLS_DIR}/kiterunner" 2>/dev/null || true
}

# ENHANCED: Retire.js with multi-method install
install_retire_enhanced() {
    command -v retire >/dev/null 2>&1 && retire --version >/dev/null 2>&1 && return
    command -v npm >/dev/null 2>&1 || return
    
    # Try global
    if npm install -g retire 2>/dev/null; then
        command -v retire >/dev/null 2>&1 && return
    fi
    
    # Try local prefix
    local prefix="${HOME}/.local"
    if npm install -g --prefix "${prefix}" retire 2>/dev/null; then
        [[ -x "${prefix}/bin/retire" ]] && ln -sf "${prefix}/bin/retire" "${VENV_BIN}/retire"
    fi
}

# Metasploit (optional)
install_metasploit() {
    command -v msfconsole >/dev/null 2>&1 && return
    
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo apt-get install -y metasploit-framework 2>/dev/null || true
    fi
}

# ============================================================================
# NEW ENHANCEMENTS
# ============================================================================

# NEW: Interactsh
install_interactsh() {
    go_install_and_link "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" "interactsh-client"
}

# NEW: GAU
install_gau() {
    go_install_and_link "github.com/lc/gau/v2/cmd/gau@latest" "gau"
}

# NEW: CORScanner
install_corscanner() {
    safe_git_clone "https://github.com/chenjj/CORScanner.git" "${TOOLS_DIR}/CORScanner"
    [[ -f "${TOOLS_DIR}/CORScanner/requirements.txt" ]] && "${VENV_BIN}/pip" install -r "${TOOLS_DIR}/CORScanner/requirements.txt" --break-system-packages 2>/dev/null || true
    [[ -f "${TOOLS_DIR}/CORScanner/cors_scan.py" ]] && write_python_wrapper_into_venv "${TOOLS_DIR}/CORScanner/cors_scan.py" "cors-scan"
}

# NEW: ZAP Hybrid Mode
install_zap_hybrid() {
    local has_docker=false
    local has_native=false
    
    if command -v docker >/dev/null 2>&1 && docker ps >/dev/null 2>&1; then
        docker pull ghcr.io/zaproxy/zaproxy:stable 2>/dev/null && has_docker=true
    fi
    
    command -v zap.sh >/dev/null 2>&1 && has_native=true
    
    cat > "${VENV_BIN}/guardian-zap" << 'ZAP'
#!/usr/bin/env bash
if command -v docker >/dev/null 2>&1 && docker ps >/dev/null 2>&1; then
    docker images ghcr.io/zaproxy/zaproxy:stable -q | grep -q . && echo "docker" && exit 0
fi
command -v zap.sh >/dev/null 2>&1 && echo "native" && exit 0
echo "none" >&2 && exit 1
ZAP
    chmod +x "${VENV_BIN}/guardian-zap"
}

# NEW: Smart Port Scanner
install_smart_scanner() {
    cat > "${VENV_BIN}/guardian-portscan" << 'SCAN'
#!/usr/bin/env bash
TARGET="$1"
OUT="${2:-.}"
if command -v masscan >/dev/null 2>&1; then
    sudo masscan "$TARGET" -p1-65535 --rate=10000 -oL "$OUT/masscan.txt" 2>/dev/null
    PORTS=$(awk '/open/{print $3}' "$OUT/masscan.txt" | cut -d'/' -f1 | paste -sd, || echo "1-65535")
else
    PORTS="1-65535"
fi
nmap -sV -sC -p "$PORTS" "$TARGET" -oX "$OUT/nmap.xml" --open
SCAN
    chmod +x "${VENV_BIN}/guardian-portscan"
}

# ============================================================================
# INSTALLATION EXECUTION
# ============================================================================

echo ""
echo "Installing all Guardian tools..."
echo ""

# Core
install_projectdiscovery_binaries
install_testssl
install_xsstrike
install_cmseek
install_whatweb

# Fixed
install_dalfox
install_commix

# Web tools
install_graphql_cop
install_jsparser
install_jwt_tool
install_tplmap
install_feroxbuster
install_nikto
install_wpscan

# Go tools
install_go_recon_tools

# Python tools
install_python_tools

# System tools
install_amass
install_masscan
install_wappalyzer
install_udp_proto_scanner
install_subjs

# Wordlists
install_kiterunner_wordlists

# Enhanced
install_retire_enhanced

# New
install_interactsh
install_gau
install_corscanner
install_zap_hybrid
install_smart_scanner

# Optional
install_metasploit

echo ""
echo "==========================================="
echo "Setup Complete!"
echo "==========================================="
echo ""
echo "All tools installed with fixes and enhancements"
echo "Ensure ${VENV_BIN} is in your PATH"
echo ""
