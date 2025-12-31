#!/usr/bin/env bash
# Guardian local setup helper (use inside your virtual environment)
# Installs Python deps and optional helper tools needed for full functionality.

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_BIN="${VIRTUAL_ENV:-}/bin"
TOOLS_DIR="${BASE_DIR}/tools/vendor"

install_libpcap_dev() {
  if command -v apt-get >/dev/null 2>&1; then
    if command -v sudo >/dev/null 2>&1; then
      echo "Installing libpcap-dev (required for naabu and other Go scanners)..."
      sudo apt-get update && sudo apt-get install -y libpcap-dev
    else
      echo "WARN: sudo not available; install libpcap-dev manually (apt-get install -y libpcap-dev)" >&2
    fi
  else
    echo "INFO: Non-apt system detected; ensure libpcap development headers are installed (e.g., brew install libpcap)" >&2
  fi
}

# Ensure libpcap headers are present before building Go scanners
install_libpcap_dev

if [[ -z "${VIRTUAL_ENV:-}" ]]; then
  echo "ERROR: Activate your virtual environment first (source venv/bin/activate)" >&2
  exit 1
fi

echo "Using virtualenv: ${VIRTUAL_ENV}"
mkdir -p "${TOOLS_DIR}"

pip install -e "${BASE_DIR}"

link_into_venv() {
  local src="$1"
  local name="$2"
  if [[ ! -x "${src}" ]]; then
    echo "WARN: ${src} is not executable"
  fi
  ln -sf "${src}" "${VENV_BIN}/${name}"
}

install_testssl() {
  local repo="${TOOLS_DIR}/testssl.sh"
  if [[ ! -d "${repo}/.git" ]]; then
    git clone https://github.com/drwetter/testssl.sh.git "${repo}"
  fi
  link_into_venv "${repo}/testssl.sh" "testssl"
}

install_xsstrike() {
  local repo="${TOOLS_DIR}/XSStrike"
  if [[ ! -d "${repo}/.git" ]]; then
    git clone https://github.com/s0md3v/XSStrike.git "${repo}"
  fi
  pip install -r "${repo}/requirements.txt"
  chmod +x "${repo}/xsstrike.py"
  link_into_venv "${repo}/xsstrike.py" "xsstrike"
}

install_cmseek() {
  local repo="${TOOLS_DIR}/CMSeeK"
  if [[ ! -d "${repo}/.git" ]]; then
    git clone https://github.com/Tuhinshubhra/CMSeeK.git "${repo}"
  fi
  pip install -r "${repo}/requirements.txt"
  link_into_venv "${repo}/cmseek.py" "cmseek"
}

install_gitleaks() {
  if command -v go >/dev/null 2>&1; then
    go install github.com/zricethezav/gitleaks/v8@latest
    # go installs into GOPATH/bin or ~/go/bin; if present, link into venv
    local gopath_bin="${GOPATH:-${HOME}/go}/bin"
    if [[ -x "${gopath_bin}/gitleaks" ]]; then
      link_into_venv "${gopath_bin}/gitleaks" "gitleaks"
    fi
  else
    echo "WARN: go not found; skipping gitleaks install" >&2
  fi
}

install_nikto() {
  if command -v nikto >/dev/null 2>&1; then
    echo "nikto already present on PATH"
    return
  fi
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    echo "Installing nikto via apt (requires sudo)..."
    sudo apt-get update -y && sudo apt-get install -y nikto
  else
    echo "WARN: nikto not found and sudo not available; install manually (e.g., apt install nikto)" >&2
  fi
}

echo "Installing optional tools: testssl, xsstrike, cmseek, gitleaks, nikto"
install_testssl
install_xsstrike
install_cmseek
install_gitleaks
install_nikto

# Fetch extra nuclei templates (CVE-heavy packs)
install_nuclei_templates() {
  mkdir -p "${HOME}/nuclei-templates-extra"
  clone_or_update() {
    local repo_url="$1"
    local dest="$2"
    if [[ -d "${dest}/.git" ]]; then
      git -C "${dest}" pull --ff-only || true
    else
      git clone --depth 1 "${repo_url}" "${dest}" || true
    fi
  }
  clone_or_update "https://github.com/ARPSyndicate/kenzer-templates" "${HOME}/nuclei-templates-extra/kenzer"
  clone_or_update "https://github.com/geeknik/the-nuclei-templates" "${HOME}/nuclei-templates-extra/geeknik"
}

# Install additional recon tools (Go/Pip/NPM) if available
install_recon_extras() {
  if command -v go >/dev/null 2>&1; then
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
    go install github.com/d3mondev/puredns/v2@latest
    go install github.com/hakluke/hakrawler@latest
    go install github.com/jaeles-project/gospider@latest
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install github.com/projectdiscovery/katana/cmd/katana@latest
    go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
    go install github.com/tomnomnom/waybackurls@latest
  else
    echo "WARN: go not found; skipping dnsx/shuffledns/puredns/hakrawler/gospider/naabu/katana/asnmap/waybackurls" >&2
  fi

  # altdns is no longer on PyPI; install from the maintained fork (package name py-altdns)
  pip install "py-altdns @ git+https://github.com/infosec-au/altdns.git"

  if command -v npm >/dev/null 2>&1; then
    npm install -g retire
  else
    echo "WARN: npm not found; skipping retire.js" >&2
  fi
}

install_libpcap_dev() {
  if command -v apt-get >/dev/null 2>&1; then
    if command -v sudo >/dev/null 2>&1; then
      echo "Installing libpcap-dev (required for naabu and other Go scanners)..."
      sudo apt-get update && sudo apt-get install -y libpcap-dev
    else
      echo "WARN: sudo not available; install libpcap-dev manually (apt-get install -y libpcap-dev)" >&2
    fi
  else
    echo "INFO: Non-apt system detected; ensure libpcap development headers are installed (e.g., brew install libpcap)" >&2
  fi
}

echo "Fetching extra nuclei templates (CVE packs)..."
install_nuclei_templates

echo "Installing recon extras (dnsx, shuffledns, puredns, altdns, hakrawler, gospider, retire, naabu, katana, asnmap, waybackurls)..."
install_recon_extras

echo "Setup complete. Ensure ${VENV_BIN} is in your PATH."
