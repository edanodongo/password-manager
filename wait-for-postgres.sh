#!/bin/sh

# Wait for PostgreSQL
echo "Waiting for PostgreSQL..."

while ! nc -z $DB_DEFAULT_HOST $DB_DEFAULT_PORT; do
  sleep 1
done

echo "PostgreSQL started"

exec "$@"
