FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.8.3 \
    POETRY_HOME=/opt/poetry \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_CREATE=false

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential ca-certificates curl \
    pkg-config libxmlsec1-dev libxmlsec1-openssl \
 && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 - \
 && ln -s /opt/poetry/bin/poetry /usr/local/bin/poetry

WORKDIR /app
ENV PYTHONPATH=/app

# Copy dependency files from root
COPY pyproject.toml poetry.lock* /tmp/

# Install dependencies
RUN cd /tmp && poetry install --no-root && rm -rf /tmp/pyproject.toml /tmp/poetry.lock

# Copy app code
COPY app/ /app/

# Install Tailwind CLI and build CSS
# Use TARGETARCH to download the correct binary for the build platform
# Using v3.4.17 (stable) instead of v4 which is still in beta
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      TAILWIND_ARCH="arm64"; \
    else \
      TAILWIND_ARCH="x64"; \
    fi \
 && curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/tailwindcss-linux-${TAILWIND_ARCH} \
 && chmod +x tailwindcss-linux-${TAILWIND_ARCH} \
 && mv tailwindcss-linux-${TAILWIND_ARCH} /usr/local/bin/tailwindcss

# Copy Tailwind config and CSS source from root
COPY tailwind.config.js /app/
COPY static/css/input.css /app/static/css/

# Build CSS
RUN mkdir -p /app/static/css \
 && tailwindcss -i /app/static/css/input.css -o /app/static/css/output.css --minify

EXPOSE 8000
ENTRYPOINT ["./dev-docker-entrypoint.sh"]
