# BARE reference analyzer image.
#
# Base is digest-pinned, not tag-pinned: the run manifest claims byte-identical
# results for identical tool versions (§2.5), and `python:3.12-slim-bookworm`
# silently changes underneath a tag. Refresh with `make refresh-digests`.
FROM python@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134

# uid/gid must match core.sandbox.spec.ANALYZER_UID/GID. The driver forces this
# user at runtime regardless, but creating it here means $HOME and file
# ownership behave sanely instead of landing on a nonexistent account.
RUN groupadd --gid 10001 analyzer \
 && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin analyzer \
 && mkdir -p /input /output /work \
 && chown analyzer:analyzer /work

COPY --chown=root:root analyzer.py /opt/bare/analyzer.py
RUN chmod 0555 /opt/bare/analyzer.py

USER 10001:10001
WORKDIR /work

# Unbuffered so the orchestrator sees progress from a container it may have to
# kill; no .pyc writes because the rootfs is read-only anyway.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0

ENTRYPOINT ["python3", "/opt/bare/analyzer.py"]

LABEL org.opencontainers.image.title="bare-hello" \
      org.opencontainers.image.description="Reference analyzer and sandbox isolation probe" \
      org.opencontainers.image.licenses="Apache-2.0"
