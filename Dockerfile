FROM python:3.12-slim

WORKDIR /app

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./

ENV APP_HOST=0.0.0.0 \
    APP_PORT=8000 \
    PORT=8000 \
    SQLITE_PATH=/data/vendorguard.db

EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s CMD curl -fsS "http://127.0.0.1:${PORT:-8000}/health" || exit 1

# Railway, Fly, Render all inject $PORT — honour it if set, otherwise default to 8000.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
