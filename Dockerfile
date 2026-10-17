FROM python:3.12-slim

WORKDIR /app

# Ensure non-buffered console output
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml README.md ./
COPY honeynet/ ./honeynet/

RUN pip install --no-cache-dir .

# Expose HTTP honeypot (8080), SSH honeypot (2222), and SOC Dashboard (8888)
EXPOSE 8080 2222 8888

ENTRYPOINT ["honeynet", "run"]
