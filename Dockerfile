# Dockerfile
FROM python:3.11-slim-bullseye

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set work directory
WORKDIR /app

# Install dependencies
COPY requirements.txt /app/
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends gcc libpq-dev \
	&& pip install --upgrade pip && pip install -r requirements.txt \
	&& apt-get purge -y --auto-remove gcc libpq-dev \
	&& rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . /app/

# Expose port 8000
EXPOSE 8000

# Default command
CMD ["gunicorn", "passmanager.wsgi:application", "--bind", "0.0.0.0:8000"]
