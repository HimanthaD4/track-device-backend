FROM python:3.10-slim

WORKDIR /app

# Install system dependencies for geospatial and ML libraries
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    python3-dev \
    libssl-dev \
    libffi-dev \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create models directory
RUN mkdir -p models && chmod 755 models

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV FLASK_ENV=production
ENV EVENTLET_NO_GREENDNS=yes

# Create non-root user
RUN useradd -m -u 1000 render && chown -R render:render /app
USER render

# Run the application with gunicorn and eventlet
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--threads", "2", "--timeout", "120", "--bind", "0.0.0.0:10000", "app:app"]