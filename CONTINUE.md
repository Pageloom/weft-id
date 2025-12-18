# On-Prem Deployment Instructions

## Files Created
- `docker-compose.onprem.yml` - On-prem docker compose config
- `nginx/conf.d/app.onprem.conf.template` - Nginx template with `{{DOMAIN}}` placeholder
- `devscripts/onprem-setup.sh` - Interactive setup script
- `.env.onprem.example` - Environment template for on-prem

## Files Modified
- `app/settings.py` - Added `DEFAULT_SUBDOMAIN` env var
- `app/dependencies.py` - Base domain now routes to default tenant
- `.env.dev.example` - Added `DEFAULT_SUBDOMAIN` for consistency

## To Deploy on Your Droplet

```bash
# Run the setup script (it will prompt for domain)
./devscripts/onprem-setup.sh dev.pageloom.com

# Or run interactively
./devscripts/onprem-setup.sh
```

The script will:
1. Install certbot if needed
2. Generate Let's Encrypt certs (you'll need to add TXT records for DNS-01 challenge)
3. Generate nginx config from template
4. Generate `.env` from template

Then:
```bash
# Review .env and update passwords!
vi .env

# Start the app
docker compose -f docker-compose.onprem.yml up -d
```

Access at: `https://dev.pageloom.com`
