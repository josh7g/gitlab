#!/bin/bash
set -e

echo "=== Starting AWS CIS Benchmark Scanner Service ==="


# Function to wait for RDS connection (simplified)
wait_for_database() {
    if [ -z "$DB_HOST" ]; then
        echo "⚠️ DB_HOST not set, skipping database check"
        return 0
    fi
    
    echo "Waiting for PostgreSQL database to be ready..."
    pg_isready -h "$DB_HOST" -p "${DB_PORT:-5432}" || true
}


# Continue with application startup
wait_for_database
echo "Initializing application database..."
if [ -f create_tables.py ]; then
    python create_tables.py
else
    echo "⚠️ create_tables.py not found, skipping database initialization"
fi


echo "=== Starting application ==="
exec gunicorn --config gunicorn_config.py "app:app"