# Static scan analyzer: strings, rule matching, entropy, file identification.
#
# Build context is the repo root (not this directory) because the image shares
# core/rules with the host. That sharing is deliberate: the scanner that
# produces findings in production is the exact source the unit tests exercise,
# rather than a reimplementation that drifts.
#
#   docker build -f sandbox/images/static/Dockerfile -t bare/static:dev .
FROM python@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134

# PyYAML is the only third-party dependency. core.rules is kept free of
# SQLAlchemy and Pydantic precisely so this stays true — a sandboxed scanner
# should not carry an ORM.
RUN pip install --no-cache-dir pyyaml==6.0.2

RUN groupadd --gid 10001 analyzer \
 && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin analyzer \
 && mkdir -p /input /rules /output /work \
 && chown analyzer:analyzer /work

COPY --chown=root:root core/__init__.py /opt/bare/core/__init__.py
COPY --chown=root:root core/vocab.py    /opt/bare/core/vocab.py
COPY --chown=root:root core/rules/      /opt/bare/core/rules/
COPY --chown=root:root core/composition/ /opt/bare/core/composition/
COPY --chown=root:root sandbox/images/static/analyzer.py /opt/bare/analyzer.py
RUN chmod -R a-w /opt/bare

USER 10001:10001
WORKDIR /work

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0

ENTRYPOINT ["python3", "/opt/bare/analyzer.py"]

LABEL org.opencontainers.image.title="bare-static" \
      org.opencontainers.image.description="String extraction and rule matching over binary artifacts" \
      org.opencontainers.image.licenses="Apache-2.0"
