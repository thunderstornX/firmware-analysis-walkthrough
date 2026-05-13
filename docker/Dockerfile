# syntax=docker/dockerfile:1.7
# ─────────────────────────────────────────────────────────────────
# Reproducible firmware-analysis environment.
#
# Stage 1: cargo-build the Rust rewrite of binwalk 3.x (PyPI's
#          `binwalk` package is broken/squatted, so we go via cargo).
# Stage 2: minimal runtime carrying the tools needed by every script
#          under scripts/, plus pinned Python deps. Ghidra itself is
#          NOT bundled — it is several hundred MiB and is fetched at
#          run-time via docker/install_ghidra.sh if the user opts in.
# ─────────────────────────────────────────────────────────────────

ARG  PYTHON_VERSION=3.11
ARG  BINWALK_VERSION=3.1.0

# ─── stage 1: binwalk build ──────────────────────────────────────
FROM rust:1.83-bookworm AS binwalk-build
ARG BINWALK_VERSION
WORKDIR /src

# Native deps binwalk's `compressed_data` extractor needs at build time.
RUN apt-get update \
 && apt-get install --no-install-recommends -y \
        libfontconfig1-dev=2.14.* \
        pkg-config=1.8.* \
 && rm -rf /var/lib/apt/lists/*

RUN cargo install binwalk \
        --version "${BINWALK_VERSION}" \
        --locked \
        --root /opt/binwalk

# ─── stage 2: runtime ────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim-bookworm
ARG  PYTHON_VERSION

LABEL org.opencontainers.image.title="firmware-analysis-walkthrough" \
      org.opencontainers.image.source="https://github.com/thunderstornX/firmware-analysis-walkthrough" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System packages: squashfs tooling, git (for firmwalker clone), ca-certs,
# tini for proper PID-1 signal handling.
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install --no-install-recommends -y \
        squashfs-tools \
        ca-certificates \
        git \
        tini \
 && rm -rf /var/lib/apt/lists/*

# Carry the cargo-built binwalk binary over.
COPY --from=binwalk-build /opt/binwalk/bin/binwalk /usr/local/bin/binwalk

# Non-root analyst account.
RUN groupadd --gid 1000 analyst \
 && useradd  --uid 1000 --gid analyst --create-home --shell /bin/bash analyst

# firmwalker — upstream has no tagged release, so we clone the default
# branch shallowly and drop the .git directory to keep the layer lean.
# Override FIRMWALKER_BRANCH=<sha> at build-time to pin to a commit.
ARG FIRMWALKER_BRANCH=master
RUN install -d -o analyst -g analyst /home/analyst/.local/share/firmwalker \
 && git clone --depth 1 --branch "${FIRMWALKER_BRANCH}" \
        https://github.com/craigz28/firmwalker.git \
        /home/analyst/.local/share/firmwalker \
 && rm -rf /home/analyst/.local/share/firmwalker/.git \
 && chown -R analyst:analyst /home/analyst/.local

# Python deps — copied first for cache locality.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes=false \
        -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

# Repo bind-mounted at /work by callers (`docker run -v "$PWD:/work"`).
WORKDIR /work
USER analyst

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash"]
