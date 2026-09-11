# Unpack analyzer: recursive container extraction.
#
# Build context is the repo root, because the image shares core/unpack with the
# host so the extraction logic under test is the extraction logic that runs.
#
#   docker build -f sandbox/images/unpack/Dockerfile -t bare/unpack:dev .
#
# This container opens untrusted archives, which makes it the most exposed
# component in the pipeline. It gets the same boundary as every other analyzer
# — no network, read-only rootfs, uid 10001, cap_drop ALL, seccomp allowlist —
# plus hard extraction budgets enforced in core/unpack/budget.py.
FROM python@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134

# p7zip covers 7z, zip, cab, MSI, ISO, NSIS and (partially) InnoSetup, which is
# most of what a Windows installer turns out to be. squashfs-tools and
# cabextract cover the firmware and CAB cases p7zip handles poorly.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      p7zip-full \
      squashfs-tools \
      cabextract \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 analyzer \
 && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin analyzer \
 && mkdir -p /input /output /work \
 && chown analyzer:analyzer /work

COPY --chown=root:root core/__init__.py  /opt/bare/core/__init__.py
COPY --chown=root:root core/vocab.py     /opt/bare/core/vocab.py
COPY --chown=root:root core/unpack/      /opt/bare/core/unpack/
COPY --chown=root:root sandbox/images/unpack/analyzer.py /opt/bare/analyzer.py
RUN chmod -R a-w /opt/bare

USER 10001:10001
WORKDIR /work

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0

ENTRYPOINT ["python3", "/opt/bare/analyzer.py"]

LABEL org.opencontainers.image.title="bare-unpack" \
      org.opencontainers.image.description="Recursive container extraction with hard budgets" \
      org.opencontainers.image.licenses="Apache-2.0"
