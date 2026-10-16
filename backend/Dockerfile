# ==============================================================================
# Sentinova ThreatLens Backend Dockerfile
# Lightweight Python 3.12-slim base image for high-performance CTI processing
# ==============================================================================

FROM python:3.12-slim

# Set environment flags: unbuffered I/O and disable bytecode creation
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install minimal OS dependencies for network requests and build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install pinned Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY app/ /app/app/

# Expose FastAPI HTTP port
EXPOSE 8000

# Healthcheck endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Start Uvicorn ASGI server with production defaults
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
