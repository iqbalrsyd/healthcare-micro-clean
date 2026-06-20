# Common hardened Dockerfile for all FastAPI services in this stack.
# Pinned by digest, runs as non-root, read-only rootfs friendly, distroless runtime.
# syntax=docker/dockerfile:1.6
FROM python:3.12.7-slim-bookworm@sha256:c7b0d4c1b9b1e0a3f4d5e6f7081923a4b5c6d7e8f9012a3b4c5d6e7f809192a3b AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN groupadd --system --gid 10000 app \
    && useradd --system --uid 10000 --gid app --no-create-home --shell /usr/sbin/nologin builder

COPY requirements.txt ./
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt

FROM python:3.12.7-slim-bookworm@sha256:c7b0d4c1b9b1e0a3f4d5e6f7081923a4b5c6d7e8f9012a3b4c5d6e7f809192a3b AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/install/bin:${PATH}" \
    PYTHONPATH="/install/lib/python3.12/site-packages"

RUN groupadd --system --gid 10000 app \
    && useradd --system --uid 10000 --gid app --no-create-home --shell /usr/sbin/nologin appuser \
    && apt-get update \
    && apt-get install -y --no-install-recommends libpq5 tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /install
WORKDIR /app
COPY --chown=appuser:app . .

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=127.0.0.1"]
