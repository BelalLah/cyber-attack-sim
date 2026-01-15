FROM python:3.9-slim

WORKDIR /app

# Create non-root user
RUN useradd -m -u 1000 victim && \
    mkdir -p /app/logs && \
    chown -R victim:victim /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY vulnerable_app.py .

# Change ownership
RUN chown -R victim:victim /app

# Switch to non-root user
USER victim

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:5000/')" || exit 1

# Run application
CMD ["python", "vulnerable_app.py"]
