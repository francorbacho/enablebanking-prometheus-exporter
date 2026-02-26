FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY server.py .
COPY config.yml .

# Create volume mount points for sensitive data
VOLUME ["/app/data"]

# Expose the server port
EXPOSE 8080

# Set environment variable for port
ENV PORT=8080

# Run the server
CMD ["python", "server.py"]
