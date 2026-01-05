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

EXPOSE 8000
ENTRYPOINT ["./dev-docker-entrypoint.sh"]
