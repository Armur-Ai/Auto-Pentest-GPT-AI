# syntax=docker/dockerfile:1.7
#
# Pentest Swarm AI — single-image distribution.
#
# Three-stage build:
#   1. swarm-build  — compiles the pentestswarm binary
#   2. tools-build  — installs the Go-based security tools (subfinder, nuclei,
#                     httpx, naabu, etc.) into a single bin directory
#   3. runtime      — slim Debian with apt + binary security tools, plus
#                     the artefacts copied from stages 1 and 2
#
# Why this shape:
#   - Stages 1 + 2 keep the Go toolchain (~150 MB) out of the final image.
#   - The runtime layer holds only the binaries the operator actually invokes.
#   - Final image is ~700 MB — large by web-app standards, normal for a
#     pentesting toolbox image (Kali base is ~3 GB for comparison).
#
# Usage:
#   docker build -t pentest-swarm-ai .
#   docker run --rm -e PENTESTSWARM_ORCHESTRATOR_API_KEY=$KEY \
#     -v "$PWD/reports:/reports" \
#     pentest-swarm-ai scan example.com

# ───────────────────────────────────────────────────────────────────────────
# Stage 1: build the swarm binary
# ───────────────────────────────────────────────────────────────────────────
FROM golang:1.25-bookworm AS swarm-build

WORKDIR /src

# Layer the build so dependency downloads are cached separately from the
# source tree — incremental rebuilds only repay the compile step.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO is on because some adapters (e.g. naabu's libpcap link) need it.
# -s -w strips debug info to keep the binary small (~30 MB).
RUN CGO_ENABLED=1 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=docker -X main.commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /out/pentestswarm \
    ./cmd/pentestswarm

# ───────────────────────────────────────────────────────────────────────────
# Stage 2: build the Go-based security tools
# ───────────────────────────────────────────────────────────────────────────
# A separate stage so we can throw away the Go toolchain at the end. Each
# `go install` writes to /out/bin; the runtime stage scoops up that whole
# directory into /usr/local/bin.
FROM golang:1.25-bookworm AS tools-build

# libpcap-dev is required at COMPILE time for naabu's raw-socket port scan.
# The runtime stage installs libpcap0.8 for the runtime ABI.
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpcap-dev \
      git \
    && rm -rf /var/lib/apt/lists/*

# GOTOOLCHAIN=auto lets Go fetch a newer toolchain on-demand when a tool's
# go.mod requires it. Without this, a single upstream bump (e.g. gowitness
# requiring Go 1.26) would force us to re-tag the base image. Auto handles
# the whole class of "tool X now needs Go Y.Z" failures transparently.
ENV GOTOOLCHAIN=auto
ENV GOBIN=/out/bin
RUN mkdir -p /out/bin

# ProjectDiscovery toolchain (8 tools)
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/lc/gau/v2/cmd/gau@latest \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/ffuf/ffuf/v2@latest

# Evidence + reporting helpers
RUN go install github.com/sensepost/gowitness@latest

# Dalfox — reflected/DOM XSS finder (Go module). Adapter at
# internal/tools/dalfox.go (2.1.9); registered in NewCoordinator.
RUN go install github.com/hahwul/dalfox/v2@latest

# Interactsh-client — out-of-band callback listener (Go module). Adapter
# at internal/tools/interactsh.go (2.1.26); enables blind injection
# detection across XSS/SSRF/RCE/SQLi by capturing DNS/HTTP/SMTP/LDAP
# interactions from server-controlled subdomains.
RUN go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# crlfuzz — CRLF injection fuzzer (Go module). Adapter at
# internal/tools/crlfuzz.go (2.1.14).
RUN go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest

# Gxss — fast reflected-XSS pre-screener (Go module). Adapter at
# internal/tools/gxss.go (2.1.27); pairs with dalfox for confirmation.
RUN go install github.com/KathanP19/Gxss@latest

# Amass is no longer in Debian's main repo — install from upstream Go module.
RUN go install -v github.com/owasp-amass/amass/v4/...@master

# ───────────────────────────────────────────────────────────────────────────
# Stage 3: runtime
# ───────────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# System security tools (apt-installable):
#   nmap        — port + service scanner
#   sqlmap      — SQL-injection exploitation
#   gobuster    — content discovery (alternative to ffuf)
#   nikto       — web server misconfiguration / signature scanner
#   dnsutils    — dig/nslookup, used by some adapters
#   libpcap0.8  — naabu runtime dependency
#   ca-certificates, curl, git — basic networking + tool downloads
#   chromium    — gowitness needs a headless browser; without it screenshot
#                 capture silently no-ops (we want it to work out of the box)
#
# Note: amass dropped from Debian's main repo as of Bookworm; we install
# it via `go install` in the tools-build stage instead.
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap \
      sqlmap \
      gobuster \
      nikto \
      dnsutils \
      libpcap0.8 \
      testssl.sh \
      ca-certificates \
      curl \
      git \
      python3 \
      python3-pip \
      python3-venv \
      chromium \
    && rm -rf /var/lib/apt/lists/*

# Semgrep + arjun via pip in a venv (Debian's PEP 668 forbids
# system-wide pip). Arjun (2.1.13, internal/tools/arjun.go) needs a
# Python runtime; bundling it in the same venv keeps the layer small.
# Drop the venv's `httpx` script — semgrep pulls in the python-httpx
# library which installs a CLI of the same name, shadowing the
# ProjectDiscovery `httpx` we want on PATH (the recon tool, not the
# HTTP client). Reported in #13.
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir \
       semgrep arjun checkov \
       prowler pacu scoutsuite cloudsplaining \
       kube-hunter droopescan \
    && rm -f /opt/venv/bin/httpx
ENV PATH="/opt/venv/bin:${PATH}"

# Trufflehog: pinned release binary (not the curl|sh installer — auditability).
ARG TRUFFLEHOG_VERSION=3.83.7
RUN curl -sSfL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin trufflehog

# Gitleaks: pinned release binary.
ARG GITLEAKS_VERSION=8.21.2
RUN curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks

# Pull in the Go-based tools from stage 2 + the swarm binary from stage 1.
COPY --from=tools-build /out/bin/. /usr/local/bin/
COPY --from=swarm-build /out/pentestswarm /usr/local/bin/pentestswarm

# Pre-cache nuclei templates so the first scan doesn't pay the download cost.
# `|| true` because template fetch occasionally rate-limits on the
# unauthenticated GitHub API and we don't want that to break the build.
RUN nuclei -update-templates -silent 2>/dev/null || true

# Non-root user for the actual scan. Naabu's raw-socket scan needs CAP_NET_RAW
# which docker grants by default to root inside the container; if you run as
# non-root and need raw sockets, pass --cap-add=NET_RAW.
RUN useradd -ms /bin/bash pentester \
    && mkdir -p /reports /home/pentester/.pentestswarm \
    && chown -R pentester:pentester /reports /home/pentester
USER pentester

# Reports land here; mount a host directory at /reports to persist them.
WORKDIR /reports

# `pentestswarm` as the entrypoint means `docker run <image> scan <target>`
# works just like the host install. Default to --help so a bare `docker run`
# is informative rather than failing.
ENTRYPOINT ["pentestswarm"]
CMD ["--help"]
