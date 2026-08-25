# SecuraIQ — local / on-prem security AI
# Nmap + Nuclei always; OWASP ZAP when INSTALL_ZAP=true (default).
FROM python:3.11-slim

WORKDIR /app

ARG NUCLEI_VERSION=3.11.1
ARG ZAP_VERSION=2.16.1
ARG INSTALL_ZAP=true
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    nmap \
    unzip \
    wget \
    && ARCH="${TARGETARCH:-amd64}" \
    && case "$ARCH" in \
         amd64|x86_64) NARCH=amd64 ;; \
         arm64|aarch64) NARCH=arm64 ;; \
         arm|arm/v7) NARCH=arm ;; \
         *) NARCH=amd64 ;; \
       esac \
    && curl -fsSL \
         "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NARCH}.zip" \
         -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /tmp/nuclei \
    && install -m 0755 /tmp/nuclei/nuclei /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei /tmp/nuclei.zip \
    && nuclei -version \
    && nmap --version | head -n 1 \
    && nuclei -update-templates \
    && if [ "$INSTALL_ZAP" = "true" ]; then \
         apt-get install -y --no-install-recommends default-jre-headless python3 \
         && wget -q "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
              -O /tmp/zap.tgz \
         && mkdir -p /opt/zaproxy \
         && tar -xzf /tmp/zap.tgz -C /opt/zaproxy --strip-components=1 \
         && rm -f /tmp/zap.tgz \
         && ln -sf /opt/zaproxy/zap.sh /usr/local/bin/zap \
         && ln -sf /opt/zaproxy/zap.sh /usr/local/bin/zaproxy \
         && if [ -f /opt/zaproxy/zap-baseline.py ]; then \
              printf '#!/bin/sh\nexec python3 /opt/zaproxy/zap-baseline.py "$@"\n' > /usr/local/bin/zap-baseline.py \
              && chmod +x /usr/local/bin/zap-baseline.py; \
            fi \
         && zap.sh -cmd -version || true; \
       fi \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir 'psycopg[binary]>=3.1.0' 'alembic>=1.13.0' 'sqlalchemy>=2.0.0' 'redis>=5.0.0'

COPY app ./app
COPY static ./static
COPY data/knowledge ./data/knowledge
COPY data/frameworks ./data/frameworks
COPY alembic ./alembic
COPY alembic.ini .
COPY scripts ./scripts
COPY run.py .
COPY .env.example .

ENV HOST=0.0.0.0
ENV PORT=8080
ENV AUTH_ENABLED=true
ENV DATA_DIR=/data
ENV CHROMA_PERSIST_DIR=/data/chroma
ENV HOME=/root
ENV UVICORN_RELOAD=0
ENV DEPLOYMENT_MODE=production
# ZAP needs a writable home for its DB when running as non-root later
ENV ZAP_PATH=/opt/zaproxy

VOLUME ["/data"]
EXPOSE 8080

CMD ["python", "run.py"]
