FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CG_HOME=/data/cli-guard \
    PORT=8080

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir . \
    && mkdir -p /data/cli-guard

EXPOSE 8080

CMD ["sh", "-c", "cg dashboard serve --host 0.0.0.0 --port ${PORT:-8080} --public-api --trust-proxy"]
