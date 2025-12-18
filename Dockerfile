FROM python:3.11-slim

LABEL org.opencontainers.image.title="k3s-metadata-backup"
LABEL org.opencontainers.image.description="k3s Metadata Backup and Verification Tool with native Kubernetes API access"
LABEL org.opencontainers.image.source="https://github.com/YOUR_USERNAME/k3s-metadata-backup"
LABEL org.opencontainers.image.licenses="MIT"

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget \
    unzip \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install Bitwarden Secrets CLI
RUN wget -q https://github.com/bitwarden/sdk/releases/download/bws-v0.4.0/bws-x86_64-unknown-linux-gnu-0.4.0.zip && \
    unzip bws-x86_64-unknown-linux-gnu-0.4.0.zip && \
    mv bws /usr/local/bin/bws && \
    chmod +x /usr/local/bin/bws && \
    rm bws-x86_64-unknown-linux-gnu-0.4.0.zip

# Install Python dependencies
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

# Copy application
COPY k3s-metadata-backup.py /app/k3s-metadata-backup.py
RUN chmod +x /app/k3s-metadata-backup.py

WORKDIR /app

# Non-root user for security
RUN useradd -r -u 1000 -g root k3s-metadata-backup && \
    chown -R k3s-metadata-backup:root /app
USER k3s-metadata-backup

# Set entrypoint
ENTRYPOINT ["python3", "/app/k3s-metadata-backup.py"]
CMD ["--help"]
