FROM python:3.9-slim

WORKDIR /app

# Create non-root user
RUN useradd -m -u 1000 attacker && \
    mkdir -p /app/logs && \
    chown -R attacker:attacker /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy attack scripts
COPY attack_scripts/ ./attack_scripts/

# Change ownership
RUN chown -R attacker:attacker /app

# Switch to non-root user
USER attacker

# Keep container running
CMD ["tail", "-f", "/dev/null"]
