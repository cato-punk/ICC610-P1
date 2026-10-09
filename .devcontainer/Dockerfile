FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm

# Ajusta a las versiones que obtuviste arriba (sin la "v")
ARG CODEQL_VERSION=2.26.4
ARG SYFT_VERSION=1.52.0
ARG GRYPE_VERSION=0.120.0

# La imagen base trae el repo apt de Yarn con una clave GPG caducada.
# No usamos Yarn, así que se elimina para que apt-get update funcione.
RUN set -eux; \
    grep -rl "dl.yarnpkg.com" /etc/apt/sources.list.d/ 2>/dev/null | xargs -r rm -f; \
    apt-get update; \
    apt-get install -y --no-install-recommends unzip curl ca-certificates git; \
    rm -rf /var/lib/apt/lists/*

# CodeQL CLI (las query packs las descarga el Miner con --fetch-packs)
RUN set -eux; \
    curl -fsSL -o /tmp/codeql.zip \
      "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip"; \
    unzip -q /tmp/codeql.zip -d /opt; \
    rm /tmp/codeql.zip; \
    ln -s /opt/codeql/codeql /usr/local/bin/codeql

# Syft y Grype con versión fija
RUN set -eux; \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
      | sh -s -- -b /usr/local/bin "v${SYFT_VERSION}"
RUN set -eux; \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
      | sh -s -- -b /usr/local/bin "v${GRYPE_VERSION}"
