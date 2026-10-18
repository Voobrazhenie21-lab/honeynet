FROM python:3.12-slim

WORKDIR /app

# Ensure non-buffered console output and bind dashboard to 0.0.0.0 for container networking
ENV PYTHONUNBUFFERED=1 \
    HONEYNET_DASHBOARD_HOST=0.0.0.0

COPY pyproject.toml README.md ./
COPY honeynet/ ./honeynet/

# Install honeynet with SSH (paramiko) support included
RUN pip install --no-cache-dir ".[ssh]"

# Expose HTTP honeypot (8080), SSH honeypot (2222), and SOC Dashboard (8888)
EXPOSE 8080 2222 8888

ENTRYPOINT ["honeynet", "run"]
