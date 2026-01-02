# Multi-stage Dockerfile for Guardian CLI with Alpine Linux
# Installs all 15 security tools for comprehensive penetration testing

# ============================================================================
# Stage 1: Builder - Install Go tools and build dependencies
# ============================================================================
# Use a Go toolchain new enough for the latest ProjectDiscovery releases.
FROM golang:1.24.3-alpine AS builder

# Allow automatic toolchain download if modules require a newer Go.
ENV GOTOOLCHAIN=auto

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache \
    git \
    gcc \
    musl-dev

# Install Go-based security tools
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/OJ/gobuster/v3@v3.7.0 && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@master && \
    go install -v github.com/zricethezav/gitleaks/v8@latest

# ============================================================================
# Stage 2: Runtime - Python environment with all tools
# ============================================================================
FROM python:3.11-alpine

LABEL maintainer="Guardian Security Team"
LABEL description="AI-Powered Penetration Testing Automation Platform"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    GUARDIAN_HOME=/guardian

WORKDIR ${GUARDIAN_HOME}

# Install system dependencies and security tools
RUN apk add --no-cache \
    # Build dependencies
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    # Network tools
    nmap \
    nmap-scripts \
    git \
    curl \
    # Ruby for WhatWeb and WPScan
    ruby \
    ruby-dev \
    ruby-bundler \
    # Nikto dependencies
    perl \
    perl-net-ssleay \
    # Masscan build dependencies
    make \
    && \
    # Install Nikto
    git clone https://github.com/sullo/nikto /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto && \
    # Install Masscan
    git clone https://github.com/robertdavidgraham/masscan /opt/masscan && \
    cd /opt/masscan && make && make install && \
    cd ${GUARDIAN_HOME}

# Install Ruby-based tools (WhatWeb from source + WPScan gem)
RUN git clone https://github.com/urbanadventurer/WhatWeb /opt/whatweb && \
    cd /opt/whatweb && \
    bundle config set without 'development test' && \
    bundle install && \
    ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb && \
    chmod +x /usr/local/bin/whatweb && \
    gem install wpscan --no-document

# Copy Go tools from builder
COPY --from=builder /go/bin/* /usr/local/bin/

# Install Python-based security tools
RUN pip install --no-cache-dir \
    wafw00f \
    sqlmap \
    sslyze \
    arjun \
    dnsrecon

# Install JS and additional recon tools
RUN npm install -g retire && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest && \
    go install github.com/d3mondev/puredns@latest && \
    pip install altdns && \
    go install github.com/hakluke/hakrawler@latest && \
    go install github.com/jaeles-project/gospider@latest

# Install CMSeeK from source
RUN git clone https://github.com/Tuhinshubhra/CMSeeK.git /opt/cmseek && \
    pip install --no-cache-dir -r /opt/cmseek/requirements.txt && \
    ln -s /opt/cmseek/cmseek.py /usr/local/bin/cmseek && \
    chmod +x /usr/local/bin/cmseek

# Clean up build dependencies now that gems/pip installs are done
RUN apk del make gcc musl-dev

# Download TestSSL
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl

# Install XSStrike
RUN git clone https://github.com/s0md3v/XSStrike.git /opt/xsstrike && \
    pip install -r /opt/xsstrike/requirements.txt && \
    ln -s /opt/xsstrike/xsstrike.py /usr/local/bin/xsstrike && \
    chmod +x /usr/local/bin/xsstrike

# Copy Guardian application files
COPY pyproject.toml ./
COPY README.md ./
COPY ai/ ./ai/
COPY cli/ ./cli/
COPY core/ ./core/
COPY tools/ ./tools/
COPY reports/ ./reports/
COPY utils/ ./utils/
COPY workflows/ ./workflows/
COPY config/ ./config/

# Install Guardian and its dependencies
RUN pip install --no-cache-dir -e .

# Create directories for reports and logs
RUN mkdir -p /guardian/reports /guardian/logs && \
    chmod 777 /guardian/reports /guardian/logs

# Create non-root user for security
RUN addgroup -g 1000 guardian && \
    adduser -D -u 1000 -G guardian guardian && \
    chown -R guardian:guardian ${GUARDIAN_HOME}

# Switch to non-root user
USER guardian

# Update Nuclei templates on container start
RUN nuclei -update-templates || true

# Set entry point
ENTRYPOINT ["python", "-m", "cli.main"]
CMD ["--help"]
