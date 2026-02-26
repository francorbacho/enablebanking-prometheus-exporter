FROM python:3.11-slim

WORKDIR /app

# Install curl for healthcheck
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY server.py .

# Create directory for data
RUN mkdir -p /app/data

# Expose the server port
EXPOSE 8080

# Set environment variable for port
ENV PORT=8080

# Run the server
CMD ["python", "server.py"]
