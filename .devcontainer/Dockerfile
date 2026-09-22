FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        postgresql-client \
    && rm -rf /var/lib/apt/lists/*

COPY backend /tmp/ai-security-analyst-backend

RUN python -m pip install --upgrade pip \
    && python -m pip install "/tmp/ai-security-analyst-backend[dev]" \
    && rm -rf /tmp/ai-security-analyst-backend

WORKDIR /workspace
