FROM python:3.12-slim

LABEL org.opencontainers.image.title="Netwide" \
      org.opencontainers.image.version="4.6.0" \
      org.opencontainers.image.description="Sovereign Network Intelligence, 802.11 TSF De-Cloaker & RF Reconnaissance Suite"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    iw \
    wireless-tools \
    tshark \
    nmap \
    mtr-tiny \
    bluez \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/netwide
COPY . /app/netwide/

RUN pip install --no-cache-dir fastapi "uvicorn[standard]" pydantic rich qrcode

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8765/api/health || exit 1

CMD ["python3", "-m", "netwide", "serve", "--host", "0.0.0.0", "--port", "8765"]
