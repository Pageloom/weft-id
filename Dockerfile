# Production multi-stage Dockerfile
# Dev Dockerfile: app/Dockerfile (used by dev/docker-compose.yml)

# --- Stage 1: Docs builder ---
FROM python:3.12-slim AS docs-builder
WORKDIR /build
RUN pip install --no-cache-dir 'zensical>=0.0.28' 'pygments>=2.16,<2.20'
COPY mkdocs.yml .
COPY docs/ docs/
RUN zensical build

# --- Stage 2: Asset builder ---
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl \
    pkg-config libxmlsec1-dev libxmlsec1-openssl libcairo2-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY deploy/prod_requirements.lock.txt ./
RUN pip install --no-cache-dir -r prod_requirements.lock.txt

# Build Tailwind CSS
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      TAILWIND_ARCH="arm64"; \
    else \
      TAILWIND_ARCH="x64"; \
    fi \
 && curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/tailwindcss-linux-${TAILWIND_ARCH} \
 && chmod +x tailwindcss-linux-${TAILWIND_ARCH} \
 && mv tailwindcss-linux-${TAILWIND_ARCH} /usr/local/bin/tailwindcss

COPY dev/tailwind.config.js /build/
COPY app/templates/ /build/app/templates/
COPY static/css/input.css /build/static/css/
RUN mkdir -p /build/static/css \
 && tailwindcss -i /build/static/css/input.css -o /build/static/css/output.css --minify

# --- Stage 3: Runtime ---
FROM python:3.12-slim

ARG VERSION=dev
ARG BUILD_DATE
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/pageloom/weft-id" \
      org.opencontainers.image.description="Multi-tenant identity federation platform" \
      org.opencontainers.image.created="${BUILD_DATE}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends libxmlsec1-openssl libcairo2 \
 && rm -rf /var/lib/apt/lists/* \
 && addgroup --system --gid 1000 weftid \
 && adduser --system --uid 1000 --ingroup weftid weftid

# Copy installed Python packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

WORKDIR /app
ENV PYTHONPATH=/app

# Copy app code (exclude dev-only files)
COPY app/ /app/
RUN rm -rf /app/dev/ /app/Dockerfile /app/dev-docker-entrypoint.sh

# Bake version into a file for runtime access (importlib.metadata fallback).
# Extract from pyproject.toml so the build is self-sufficient; the VERSION
# build arg overrides this when set to something other than "dev".
COPY pyproject.toml /tmp/pyproject.toml
RUN if [ "${VERSION}" != "dev" ]; then \
      echo "${VERSION}" > /app/VERSION; \
    else \
      python3 -c "import tomllib; print(tomllib.load(open('/tmp/pyproject.toml','rb'))['tool']['poetry']['version'])" > /app/VERSION; \
    fi \
 && rm /tmp/pyproject.toml

# Copy static assets
COPY --from=builder /build/static/css/output.css /app/static/css/output.css
COPY static/js/ /app/static/js/
COPY static/svgs/ /app/static/svgs/

# Copy documentation site (built in docs-builder stage)
COPY --from=docs-builder /build/site/ /site/

# Copy migration runner
COPY db-init/ /db-init/

# Ensure the non-root user can write to storage (volume mount point)
RUN mkdir -p /app/storage && chown weftid:weftid /app/storage

USER weftid
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
