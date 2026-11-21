# ---- Stage 1: React/Vite build ----
FROM node:20-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --frozen-lockfile 2>/dev/null || npm install
COPY frontend/ .
RUN npm run build

# ---- Stage 2: Python runtime ----
FROM python:3.12-slim AS runtime
LABEL org.opencontainers.image.title="BIG-IP Protocol Performance Tuner"
LABEL org.opencontainers.image.source="https://github.com/gregcoward/automated_protocol_tuning"

ARG UID=1001
ARG GID=1001
RUN groupadd -g ${GID} tuner && useradd -u ${UID} -g tuner -m -s /bin/sh tuner

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY backend/ ./backend/
COPY run_server.py .

# Inject built frontend
COPY --from=frontend-build /app/frontend/dist ./frontend/dist

# Config dir — group-writable for OpenShift arbitrary UIDs (GID 0)
RUN mkdir -p /config && chown -R tuner:tuner /config && chmod 770 /config

ENV TUNER_CONFIG_DIR=/config
ENV PORT=8000
ENV LOG_LEVEL=INFO

EXPOSE 8000

# Non-root user; OpenShift overrides UID but keeps GID 0 → /config still writable
USER ${UID}

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost:${PORT}/api/health || exit 1

CMD ["python", "run_server.py"]
