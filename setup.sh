#!/usr/bin/env bash
# Guardian local setup helper (use inside your virtual environment)
# Installs Python deps and optional helper tools needed for full functionality.

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_BIN="${VIRTUAL_ENV:-}/bin"
TOOLS_DIR="${BASE_DIR}/tools/vendor"

install_libpcap_dev() {
  if command -v apt-get >/dev/null 2>&1; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
      echo "Installing libpcap-dev (required for naabu and other Go scanners)..."
      sudo apt-get update && sudo apt-get install -y libpcap-dev || echo "WARN: libpcap-dev install failed; install manually if Go scanners fail to build" >&2
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

ensure_node_and_npm() {
  if command -v npm >/dev/null 2>&1; then
    return
  fi

  if command -v apt-get >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
    if sudo -n true 2>/dev/null; then
      echo "Installing nodejs/npm via apt (required for retire.js)..."
      sudo apt-get update && sudo apt-get install -y nodejs npm || echo "WARN: nodejs/npm install failed; install manually to enable retire.js" >&2
    else
      echo "WARN: npm not found and sudo requires a password; install nodejs/npm manually to enable retire.js" >&2
    fi
  else
    echo "WARN: npm not found; install nodejs/npm manually to enable retire.js" >&2
  fi
}

ensure_go() {
  if command -v go >/dev/null 2>&1; then
    return
  fi

  if command -v apt-get >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
    if sudo -n true 2>/dev/null; then
      echo "Installing Go via apt (required for several recon tools)..."
      sudo apt-get update && (sudo apt-get install -y golang-go || sudo apt-get install -y golang) || echo "WARN: Go install failed; install Go manually to enable Go-based recon tools" >&2
    else
      echo "WARN: go not found and sudo requires a password; install Go manually to enable Go-based recon tools" >&2
    fi
  else
    echo "WARN: go not found; install Go manually to enable Go-based recon tools" >&2
  fi
}

ensure_go
ensure_node_and_npm

echo "Using virtualenv: ${VIRTUAL_ENV}"
mkdir -p "${TOOLS_DIR}"

pip install -e "${BASE_DIR}"

install_npm_dependencies() {
  if [[ -f "${BASE_DIR}/package.json" ]]; then
    if command -v npm >/dev/null 2>&1; then
      echo "Installing Node dependencies (npm install)..."
      (cd "${BASE_DIR}" && npm install)
    else
      echo "WARN: package.json found but npm is not installed; skipping npm install" >&2
    fi
  fi
}

install_npm_dependencies

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

install_deb_binary_and_link() {
  local package="$1"
  local bin="$2"

  if ! command -v apt-get >/dev/null 2>&1; then
    return 1
  fi
  if ! command -v dpkg-deb >/dev/null 2>&1; then
    return 1
  fi

  local bin_dir="${BASE_DIR}/tools/.bin"
  mkdir -p "${bin_dir}"

  if [[ -x "${bin_dir}/${bin}" ]]; then
    link_into_venv "${bin_dir}/${bin}" "${bin}"
    return 0
  fi

  local tmp
  tmp="$(mktemp -d)"
  (cd "${tmp}" && apt-get download "${package}" >/dev/null 2>&1) || { rm -rf "${tmp}"; return 1; }

  local deb
  deb="$(ls -1 "${tmp}"/*.deb 2>/dev/null | head -n 1 || true)"
  if [[ -z "${deb}" ]]; then
    rm -rf "${tmp}"
    return 1
  fi

  local out
  out="$(mktemp -d)"
  dpkg-deb -x "${deb}" "${out}" >/dev/null 2>&1 || { rm -rf "${tmp}" "${out}"; return 1; }

  if [[ -x "${out}/usr/bin/${bin}" ]]; then
    cp -f "${out}/usr/bin/${bin}" "${bin_dir}/${bin}"
    chmod +x "${bin_dir}/${bin}"
    link_into_venv "${bin_dir}/${bin}" "${bin}"
    rm -rf "${tmp}" "${out}"
    return 0
  fi

  rm -rf "${tmp}" "${out}"
  return 1
}

go_install_and_link() {
  local pkg="$1"
  local bin="$2"

  if ! command -v go >/dev/null 2>&1; then
    echo "WARN: go not found; skipping ${bin} install" >&2
    return 0
  fi

  echo "Installing ${bin} (${pkg})..."
  if ! go install "${pkg}"; then
    echo "WARN: failed to install ${bin} via go (${pkg})" >&2
    return 0
  fi

  local gobin
  gobin="$(go env GOBIN 2>/dev/null || true)"
  if [[ -z "${gobin}" ]]; then
    local gopath_first
    gopath_first="$(go env GOPATH 2>/dev/null | cut -d: -f1 || true)"
    if [[ -n "${gopath_first}" ]]; then
      gobin="${gopath_first}/bin"
    else
      gobin="${GOPATH:-${HOME}/go}/bin"
    fi
  fi

  if [[ -x "${gobin}/${bin}" ]]; then
    link_into_venv "${gobin}/${bin}" "${bin}"
  else
    echo "WARN: ${bin} was installed but not found in ${gobin}; ensure your Go bin dir is on PATH" >&2
  fi
}

write_python_wrapper_into_venv() {
  local script="$1"
  local name="$2"
  cat > "${VENV_BIN}/${name}" <<EOF
#!/usr/bin/env bash
exec "${VENV_BIN}/python" "${script}" "\$@"
EOF
  chmod +x "${VENV_BIN}/${name}"
}

install_projectdiscovery_binaries() {
  # Prefer pinned, repo-local binaries to avoid PATH conflicts (e.g., Python httpx CLI shadowing PD httpx).
  local bin_dir="${BASE_DIR}/tools/.bin"
  mkdir -p "${bin_dir}"

  if [[ ! -x "${bin_dir}/httpx" ]]; then
    echo "Installing ProjectDiscovery httpx into ${bin_dir} ..."
    python "${BASE_DIR}/scripts/install_projectdiscovery_httpx.py" || echo "WARN: PD httpx install failed; install manually or set GUARDIAN_HTTPX_BIN" >&2
  fi

  if [[ ! -x "${bin_dir}/nuclei" ]]; then
    echo "Installing ProjectDiscovery nuclei into ${bin_dir} ..."
    python "${BASE_DIR}/scripts/install_projectdiscovery_nuclei.py" || echo "WARN: PD nuclei install failed; install manually or set GUARDIAN_NUCLEI_BIN" >&2
  fi
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
  write_python_wrapper_into_venv "${repo}/xsstrike.py" "xsstrike"
}

install_cmseek() {
  local repo="${TOOLS_DIR}/CMSeeK"
  if [[ ! -d "${repo}/.git" ]]; then
    git clone https://github.com/Tuhinshubhra/CMSeeK.git "${repo}"
  fi
  pip install -r "${repo}/requirements.txt"
  write_python_wrapper_into_venv "${repo}/cmseek.py" "cmseek"
}

install_gitleaks() {
  if install_github_release_and_link "zricethezav/gitleaks" "gitleaks"; then
    return
  fi
  go_install_and_link "github.com/zricethezav/gitleaks/v8@latest" "gitleaks"
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
install_projectdiscovery_binaries
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
  # Prefer GitHub release binaries where available (more reliable than `go install` on restricted networks/DNS).
  install_github_release_and_link "projectdiscovery/subfinder" "subfinder" || true
  install_github_release_and_link "projectdiscovery/dnsx" "dnsx" || true
  install_github_release_and_link "projectdiscovery/shuffledns" "shuffledns" || true
  install_github_release_and_link "projectdiscovery/naabu" "naabu" || true
  install_github_release_and_link "projectdiscovery/katana" "katana" || true
  install_github_release_and_link "projectdiscovery/asnmap" "asnmap" || true
  install_github_release_and_link "jaeles-project/gospider" "gospider" || true
  install_github_release_and_link "zricethezav/gitleaks" "gitleaks" || true
  install_github_release_and_link "d3mondev/puredns" "puredns" || true

  # hakrawler: Kali provides a package; extract without requiring sudo.
  install_deb_binary_and_link "hakrawler" "hakrawler" || true

  # waybackurls: no deps (stdlib only) and no release assets; build from source in GOPATH mode.
  install_waybackurls() {
    if [[ -x "${VENV_BIN}/waybackurls" ]]; then
      return 0
    fi
    if ! command -v go >/dev/null 2>&1; then
      echo "WARN: go not found; skipping waybackurls install" >&2
      return 0
    fi
    local gopath="${TOOLS_DIR}/.gopath"
    local repo="${gopath}/src/github.com/tomnomnom/waybackurls"
    mkdir -p "${repo}"
    if [[ ! -d "${repo}/.git" ]]; then
      rm -rf "${repo}"
      git clone https://github.com/tomnomnom/waybackurls.git "${repo}" || { echo "WARN: waybackurls clone failed" >&2; return 0; }
    fi
    (cd "${repo}" && GO111MODULE=off GOPATH="${gopath}" go install ./...) || { echo "WARN: waybackurls build failed" >&2; return 0; }
    if [[ -x "${gopath}/bin/waybackurls" ]]; then
      link_into_venv "${gopath}/bin/waybackurls" "waybackurls"
    fi
  }

  # subjs: build from source but avoid `golang.org` lookups by using GitHub mirrors for x/* modules.
  install_subjs() {
    if [[ -x "${VENV_BIN}/subjs" ]]; then
      return 0
    fi
    if ! command -v go >/dev/null 2>&1; then
      echo "WARN: go not found; skipping subjs install" >&2
      return 0
    fi
    local repo="${TOOLS_DIR}/subjs"
    if [[ ! -d "${repo}/.git" ]]; then
      git clone https://github.com/lc/subjs.git "${repo}" || { echo "WARN: subjs clone failed" >&2; return 0; }
    fi
    (
      cd "${repo}"
      go mod edit -replace=golang.org/x/net=github.com/golang/net@v0.0.0-20200202094626-16171245cfb2
      go mod edit -replace=golang.org/x/crypto=github.com/golang/crypto@v0.0.0-20190308221718-c2843e01d9a2
      go mod edit -replace=golang.org/x/sys=github.com/golang/sys@v0.0.0-20190215142949-d0b11bdaac8a
      go mod edit -replace=golang.org/x/text=github.com/golang/text@v0.3.0
      GOPROXY=direct GOSUMDB=off go mod tidy
      GOPROXY=direct GOSUMDB=off go build -o "${BASE_DIR}/tools/.bin/subjs" .
    ) || { echo "WARN: subjs build failed" >&2; return 0; }
    if [[ -x "${BASE_DIR}/tools/.bin/subjs" ]]; then
      link_into_venv "${BASE_DIR}/tools/.bin/subjs" "subjs"
    fi
  }

  install_waybackurls
  install_subjs

  install_retire_js() {
    if ! command -v npm >/dev/null 2>&1; then
      echo "INFO: npm not found; skipping retire.js" >&2
      return 0
    fi

    echo "Installing retire.js (npm)..."

    # First try plain global install (works if npm is already configured with a user-writable prefix).
    if npm install -g retire >/dev/null 2>&1; then
      return 0
    fi

    # Fall back to a user-local prefix and link into the venv so `retire` is on PATH when the venv is active.
    local prefix="${HOME}/.local"
    if npm install -g --prefix "${prefix}" retire; then
      local retire_bin="${prefix}/bin/retire"
      if [[ -x "${retire_bin}" ]]; then
        ln -sf "${retire_bin}" "${VENV_BIN}/retire"
      fi
      return 0
    fi

    echo "WARN: retire.js install failed (npm permissions/config); install manually or set npm prefix to a user-writable directory" >&2
    return 0
  }

  # altdns is no longer on PyPI; install from the maintained fork (package name py-altdns)
  pip install "py-altdns @ git+https://github.com/infosec-au/altdns.git"

  # Python-based discovery/analysis extras
  if command -v python >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
    pip install arjun
    pip install dirsearch
    pip install "linkfinder @ git+https://github.com/GerbenJavado/LinkFinder.git"
    pip install xnlinkfinder
    pip install "paramspider @ git+https://github.com/devanshbatham/ParamSpider.git"
    pip install schemathesis
    pip install trufflehog
  else
    echo "WARN: python/pip not found; skipping dirsearch/linkfinder/xnlinkfinder/paramspider/schemathesis/trufflehog" >&2
  fi

  install_retire_js
}

install_metasploit() {
  if command -v msfconsole >/dev/null 2>&1; then
    echo "Metasploit already present on PATH"
    return
  fi

  if command -v sudo >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    echo "Installing metasploit-framework via apt (requires sudo)..."
    if sudo -n true 2>/dev/null; then
      sudo apt-get update -y && sudo apt-get install -y metasploit-framework || echo "WARN: metasploit install failed; install manually from https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html" >&2
    else
      echo "WARN: sudo requires a password; skipping metasploit apt install" >&2
    fi
  else
    echo "WARN: metasploit not installed and apt/sudo not available; install manually from https://www.metasploit.com/" >&2
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

echo "Installing recon extras (dnsx, shuffledns, puredns, altdns, hakrawler, gospider, retire, naabu, katana, asnmap, waybackurls, subjs, dirsearch, linkfinder, xnlinkfinder, paramspider, schemathesis, trufflehog)..."
install_recon_extras

echo "Installing metasploit (optional, for MetasploitTool)..."
install_metasploit

echo "Setup complete. Ensure ${VENV_BIN} is in your PATH."
