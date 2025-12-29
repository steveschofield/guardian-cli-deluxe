#!/usr/bin/env bash
# Guardian local setup helper (use inside your virtual environment)
# Installs Python deps and optional helper tools needed for full functionality.

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_BIN="${VIRTUAL_ENV:-}/bin"
TOOLS_DIR="${BASE_DIR}/tools/vendor"

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

echo "Installing optional tools: testssl, xsstrike, cmseek, gitleaks"
install_testssl
install_xsstrike
install_cmseek
install_gitleaks

echo "Setup complete. Ensure ${VENV_BIN} is in your PATH."
