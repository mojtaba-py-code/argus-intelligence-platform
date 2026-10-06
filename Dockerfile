# syntax=docker/dockerfile:1.10
#
# One image, three process roles (api | worker | scheduler) selected by the command.
# * build stage: uv resolves the *locked* environment (uv.lock) into /app/.venv; the project is
#   installed as a regular wheel (migrations, prompts and configs are packaged inside it).
# * runtime stage: no compiler, no uv, no shell tools beyond the slim base; non-root UID 10001;
#   the virtual environment is owned by root, so the application cannot modify its own code.
# Base images are pinned by digest; Dependabot proposes updates.

ARG PYTHON_IMAGE=python:3.12.15-slim-trixie@sha256:6b1f85a08c199d29d5b6d71ab9c27bd5b3b393492e01216a15758ff69c4be8b8
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.23@sha256:61d393e44e249f2e4b526b6c7ddcecce245946826e608e11c93ad4f5bba55b21

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /src
# Dependencies first: this layer is reused until uv.lock changes.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --locked --no-dev --no-install-project --extra anthropic --extra openai --extra s3
COPY src ./src
COPY migrations ./migrations
COPY prompts ./prompts
COPY configs ./configs
RUN uv sync --locked --no-dev --no-editable --extra anthropic --extra openai --extra s3

FROM ${PYTHON_IMAGE} AS runtime
# Set by the release workflow; local builds keep the defaults.
ARG VERSION=0.0.0-dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="argus" \
      org.opencontainers.image.description="Argus - enterprise AI intelligence & research platform" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="https://github.com/mojtaba-py-code/argus-intelligence-platform"
# DejaVu Sans: Unicode coverage for PDF report exports (Persian, Arabic, Cyrillic, Greek ...).
RUN apt-get update \
 && apt-get install --yes --no-install-recommends fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 argus \
 && useradd --system --uid 10001 --gid argus --home-dir /nonexistent --no-create-home \
      --shell /usr/sbin/nologin argus \
 && mkdir -p /var/lib/argus/storage \
 && chown argus:argus /var/lib/argus/storage
COPY --from=build --chown=root:root /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PYTHONFAULTHANDLER=1 \
    ARGUS_STORAGE__LOCAL_ROOT=/var/lib/argus/storage \
    ARGUS_REPORTS__PDF_FONT_PATH=/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf
WORKDIR /app
USER 10001:10001
# 8000: API. 9100: /metrics of worker and scheduler (ARGUS_OBSERVABILITY__METRICS_PORT).
EXPOSE 8000 9100
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2).status == 200 else 1)"]
ENTRYPOINT ["argus"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
