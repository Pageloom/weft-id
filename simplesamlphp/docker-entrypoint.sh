#!/bin/bash
set -e

CERT_DIR="/var/www/simplesamlphp/cert"
CERT_FILE="$CERT_DIR/idp.crt"
KEY_FILE="$CERT_DIR/idp.pem"

# Generate certificates if they don't exist
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "Generating IdP certificates..."
    mkdir -p "$CERT_DIR"
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -days 3650 \
        -nodes \
        -subj "/CN=Local Dev IdP/O=Development"
    echo "Certificates generated successfully"
fi

# Ensure proper permissions for Apache to read
chown -R www-data:www-data "$CERT_DIR"
chmod 644 "$CERT_FILE"
chmod 600 "$KEY_FILE"

# Run the original entrypoint
exec apache2-foreground
