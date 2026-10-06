FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends unzip curl git \
 && rm -rf /var/lib/apt/lists/*

# CodeQL CLI (las query packs las descarga el Miner con --fetch-packs)
RUN curl -fsSL -o /tmp/codeql.zip \
      https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip \
 && unzip -q /tmp/codeql.zip -d /opt \
 && rm /tmp/codeql.zip \
 && ln -s /opt/codeql/codeql /usr/local/bin/codeql

# Syft y Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh  | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
