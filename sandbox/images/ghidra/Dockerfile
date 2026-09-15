# Deep RE analyzer (S4): Ghidra headless, xrefs to flagged strings.
#
# Ghidra is not ours. It is an Apache-2.0 distribution published by the NSA at
# github.com/NationalSecurityAgency/ghidra, and this image consumes it the way
# a package manager consumes a release: by pinned version, from the vendor's
# own URL, verified against the SHA-256 the vendor published in the release
# notes. Nothing of Ghidra is committed to this repository — `git ls-files`
# holds a URL and a digest. See sandbox/images/ghidra/NOTICE.md and ADR-0031.
#
# The ARG defaults below are duplicated in ghidra.lock.json, which is the file
# a human edits to bump. tests/unit/test_ghidra_pin.py fails if they disagree,
# so the pin cannot rot in one place while the other moves.
#
#   docker build -f sandbox/images/ghidra/Dockerfile -t bare/ghidra:dev .
#
# Air-gapped: fetch the archive on a connected machine with
#   uv run python scripts/fetch_ghidra.py --output /media/transfer
# serve it from an internal mirror, and build with
#   --build-arg GHIDRA_URL=https://mirror.internal/ghidra_12.1.3_PUBLIC_20260817.zip
# The digest check is unconditional, so a mirror is verified exactly as
# stringently as the upstream URL is.

ARG GHIDRA_VERSION=12.1.3
ARG GHIDRA_ARCHIVE=ghidra_12.1.3_PUBLIC_20260817.zip
ARG GHIDRA_SHA256=93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54
ARG GHIDRA_DIR=ghidra_12.1.3_PUBLIC
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.3_build/ghidra_12.1.3_PUBLIC_20260817.zip

# Ghidra 12.x requires a JDK 21 — a JRE is not enough, because analyzeHeadless
# compiles the scripts handed to -scriptPath at runtime and needs javac.
FROM eclipse-temurin@sha256:2fc8306f51cd8c1582b972213f3115300074084ec4f9060448454f04ecbd941b AS fetch

ARG GHIDRA_ARCHIVE
ARG GHIDRA_SHA256
ARG GHIDRA_DIR
ARG GHIDRA_URL

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*

# Verified before it is unzipped, and the build dies if it does not match. A
# 569 MB download over a proxy that returns an HTML error page is the ordinary
# failure here, and it must not become "Ghidra is missing a class".
RUN set -eu; \
    curl --fail --location --show-error --silent --retry 3 \
         --output "/tmp/${GHIDRA_ARCHIVE}" "${GHIDRA_URL}"; \
    echo "${GHIDRA_SHA256}  /tmp/${GHIDRA_ARCHIVE}" | sha256sum --check --strict -; \
    unzip -q "/tmp/${GHIDRA_ARCHIVE}" -d /opt; \
    rm "/tmp/${GHIDRA_ARCHIVE}"; \
    mv "/opt/${GHIDRA_DIR}" /opt/ghidra

# Documentation and the Eclipse integration are ~200 MB of an image that runs
# one headless command and never renders a page. `licenses/`, `LICENSE` and
# `NOTICE` are deliberately NOT among them: upstream's licensing material ships
# as upstream wrote it, which is a condition of using it at all.
RUN rm -rf /opt/ghidra/docs /opt/ghidra/GhidraDocs /opt/ghidra/Extensions/Eclipse

# ---------------------------------------------------------------------------
FROM eclipse-temurin@sha256:2fc8306f51cd8c1582b972213f3115300074084ec4f9060448454f04ecbd941b

ARG GHIDRA_VERSION

# Ghidra's launcher is a bash script and the decompiler is a native ELF; python3
# is the analyzer entrypoint. Nothing else — this container opens untrusted
# binaries and every package in it is attack surface.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 analyzer \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin analyzer \
 && mkdir -p /input /output /work /scripts

COPY --from=fetch --chown=root:root /opt/ghidra /opt/ghidra

COPY --chown=root:root core/__init__.py /opt/bare/core/__init__.py
COPY --chown=root:root core/vocab.py    /opt/bare/core/vocab.py
COPY --chown=root:root core/analyzers/ghidra_result.py /opt/bare/core/analyzers/ghidra_result.py
COPY --chown=root:root core/analyzers/__init__.py      /opt/bare/core/analyzers/__init__.py
COPY --chown=root:root sandbox/ghidra_scripts/ /scripts/
COPY --chown=root:root sandbox/images/ghidra/analyzer.py /opt/bare/analyzer.py
COPY --chown=root:root sandbox/images/ghidra/NOTICE.md   /opt/ghidra/BARE-NOTICE.md

# The whole Ghidra tree is read-only, which is both a hardening measure and the
# honest statement: BARE runs Ghidra as shipped and cannot have modified it.
RUN chmod -R a-w /opt/ghidra /opt/bare /scripts

USER 10001:10001
WORKDIR /work

# HOME and the JVM temp directory both land on the /work tmpfs, because the
# rootfs is read-only and Ghidra writes a user-settings directory, a project
# directory, and compiled scripts before it analyses anything. /work rather
# than /tmp: /tmp is mounted noexec and the JVM extracts native helpers.
ENV HOME=/work \
    TMPDIR=/work \
    GHIDRA_HOME=/opt/ghidra \
    BARE_GHIDRA_VERSION=${GHIDRA_VERSION} \
    JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=/work -Djna.tmpdir=/work" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0

ENTRYPOINT ["python3", "/opt/bare/analyzer.py"]

LABEL org.opencontainers.image.title="bare-ghidra" \
      org.opencontainers.image.description="Ghidra headless cross-referencing of flagged strings" \
      org.opencontainers.image.licenses="Apache-2.0" \
      bare.thirdparty.ghidra.version="${GHIDRA_VERSION}" \
      bare.thirdparty.ghidra.upstream="https://github.com/NationalSecurityAgency/ghidra" \
      bare.thirdparty.ghidra.license="Apache-2.0"
