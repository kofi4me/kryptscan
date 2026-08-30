FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    GO_VERSION=1.22.5 \
    GOPATH=/opt/go \
    PATH="/opt/go/bin:/usr/local/go/bin:${PATH}" \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    bsdextrautils \
    build-essential \
    curl \
    default-jre-headless \
    git \
    gnupg \
    jq \
    libxml-writer-perl \
    libpcap-dev \
    nmap \
    perl \
    python3-pip \
    ruby \
    unzip \
    wget \
    whatweb \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz \
    && tar -C /usr/local -xzf /tmp/go.tgz \
    && rm /tmp/go.tgz

RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/owasp-amass/amass/v4/...@latest

RUN pip install --no-cache-dir \
    checkov \
    prowler \
    scoutsuite \
    semgrep \
    sslyze \
    wafw00f

RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

RUN curl -fsSL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin \
    && curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

RUN wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz -O /tmp/gitleaks.tgz \
    && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm /tmp/gitleaks.tgz

RUN wget -q https://sourceforge.net/projects/zap.mirror/files/v2.17.0/ZAP_2.17.0_Linux.tar.gz/download -O /tmp/zap.tgz \
    && tar -xzf /tmp/zap.tgz -C /opt \
    && printf '%s\n' '#!/bin/sh' \
        'set -eu' \
        'for candidate in /opt/ZAP_*/zap-baseline.py /zap/zap-baseline.py; do' \
        '  if [ -f "$candidate" ]; then' \
        '    exec python3 "$candidate" "$@"' \
        '  fi' \
        'done' \
        'echo "OWASP ZAP baseline is not installed in this scanner image." >&2' \
        'exit 127' > /usr/local/bin/zap-baseline.py \
    && chmod +x /usr/local/bin/zap-baseline.py \
    && rm /tmp/zap.tgz

WORKDIR /workspace

COPY requirements.txt requirements-greenbone.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-greenbone.txt

COPY app ./app
COPY scanner-worker/app ./scanner_worker_app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"

CMD ["python", "-m", "uvicorn", "scanner_worker_app.main:app", "--host", "0.0.0.0", "--port", "8000"]
