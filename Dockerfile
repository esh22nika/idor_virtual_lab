# Multi-stage / secure production Dockerfile for IDOR Virtual Lab
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    DATABASE_PATH=/home/labuser/app/instance/idor_lab.sqlite \
    LAB_MODE=secure

# Install curl for health check
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Create a dedicated non-root runtime group and user
RUN groupadd -g 1000 labgroup && \
    useradd -u 1000 -g labgroup -m -s /bin/bash labuser

# Set working directory
WORKDIR /home/labuser/app

# Copy dependency definition and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY --chown=labuser:labgroup . .

# Ensure instance directory exists and has proper permissions
RUN mkdir -p /home/labuser/app/instance && \
    chown -R labuser:labgroup /home/labuser/app

# Switch to the non-root user
USER labuser

# Expose internal application port
EXPOSE 5000

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Start using Gunicorn WSGI server (honoring dynamic PORT on Render or default 5000)
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 2 --threads 2 'app:create_app()'"]
