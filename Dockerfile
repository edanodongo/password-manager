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

# Copy the wait script and make it executable
COPY wait-for-postgres.sh /app/wait-for-postgres.sh
RUN chmod +x /app/wait-for-postgres.sh

# Expose port 8000
EXPOSE 8000

# Default command
CMD ["./wait-for-postgres.sh", "gunicorn", "passmanager.wsgi:application", "--bind", "0.0.0.0:8000"]

