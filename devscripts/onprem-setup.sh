#!/usr/bin/env bash
#
# On-Prem Setup Script
# Generates Let's Encrypt certificates and configures the app for on-prem deployment.
#
# Usage: ./devscripts/onprem-setup.sh [domain]
#   domain: Optional. If not provided, will prompt interactively.
#
# Example: ./devscripts/onprem-setup.sh dev.pageloom.com

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Get domain from argument or prompt
DOMAIN="${1:-}"
if [[ -z "$DOMAIN" ]]; then
    read -rp "Enter your domain (e.g., dev.pageloom.com): " DOMAIN
fi

if [[ -z "$DOMAIN" ]]; then
    error "Domain is required"
fi

info "Setting up on-prem deployment for: $DOMAIN"

# Check for certbot
if ! command -v certbot &> /dev/null; then
    warn "certbot not found. Installing..."
    if command -v apt &> /dev/null; then
        sudo apt update && sudo apt install -y certbot
    elif command -v yum &> /dev/null; then
        sudo yum install -y certbot
    elif command -v brew &> /dev/null; then
        brew install certbot
    else
        error "Could not install certbot. Please install it manually."
    fi
fi

# Check if certificate already exists
CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
if [[ -f "$CERT_PATH" ]]; then
    info "Certificate already exists at $CERT_PATH"
    read -rp "Do you want to skip certificate generation? [Y/n]: " SKIP_CERT
    SKIP_CERT="${SKIP_CERT:-Y}"
else
    SKIP_CERT="n"
fi

# Generate certificate using DNS-01 challenge
if [[ "${SKIP_CERT,,}" != "y" ]]; then
    info "Generating Let's Encrypt certificate using DNS-01 challenge..."
    info "You will be prompted to create a TXT record in your DNS."
    echo ""
    warn "IMPORTANT: When prompted, create the TXT record and wait for DNS propagation"
    warn "before pressing Enter. You can verify propagation with:"
    warn "  dig TXT _acme-challenge.$DOMAIN"
    echo ""

    # Generate cert with wildcard for future tenant subdomains
    sudo certbot certonly \
        --manual \
        --preferred-challenges dns \
        -d "$DOMAIN" \
        -d "*.$DOMAIN" \
        --agree-tos \
        --no-eff-email

    if [[ $? -ne 0 ]]; then
        error "Certificate generation failed"
    fi

    info "Certificate generated successfully!"
fi

# Generate nginx config from template
info "Generating nginx configuration..."
NGINX_TEMPLATE="$PROJECT_DIR/nginx/conf.d/app.onprem.conf.template"
NGINX_OUTPUT="$PROJECT_DIR/nginx/conf.d/app.onprem.conf"

if [[ ! -f "$NGINX_TEMPLATE" ]]; then
    error "Nginx template not found at $NGINX_TEMPLATE"
fi

sed "s/{{DOMAIN}}/$DOMAIN/g" "$NGINX_TEMPLATE" > "$NGINX_OUTPUT"
info "Nginx config written to: $NGINX_OUTPUT"

# Generate .env file
info "Generating environment configuration..."
ENV_TEMPLATE="$PROJECT_DIR/.env.onprem.example"
ENV_OUTPUT="$PROJECT_DIR/.env"

if [[ -f "$ENV_OUTPUT" ]]; then
    warn ".env file already exists"
    read -rp "Overwrite existing .env? [y/N]: " OVERWRITE_ENV
    OVERWRITE_ENV="${OVERWRITE_ENV:-N}"
else
    OVERWRITE_ENV="y"
fi

if [[ "${OVERWRITE_ENV,,}" == "y" ]]; then
    if [[ ! -f "$ENV_TEMPLATE" ]]; then
        error "Environment template not found at $ENV_TEMPLATE"
    fi

    sed "s/{{DOMAIN}}/$DOMAIN/g" "$ENV_TEMPLATE" > "$ENV_OUTPUT"
    info ".env file written to: $ENV_OUTPUT"
    warn "IMPORTANT: Review and update .env with secure passwords before starting!"
else
    info "Skipping .env generation"
fi

echo ""
info "=========================================="
info "On-prem setup complete!"
info "=========================================="
echo ""
info "Next steps:"
echo "  1. Review and update .env with secure passwords"
echo "  2. Start the application:"
echo "     docker compose -f docker-compose.onprem.yml up -d"
echo ""
echo "  3. Access your application at:"
echo "     https://$DOMAIN"
echo ""
info "To view logs:"
echo "     docker compose -f docker-compose.onprem.yml logs -f"
echo ""
