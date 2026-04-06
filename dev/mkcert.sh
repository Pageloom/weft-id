#!/usr/bin/env bash
# Generate a local development TLS certificate using mkcert.
# Installs a local CA if not already present.
# Skips generation if existing cert is valid and not near expiry.
# Requires: mkcert, openssl, date
# Usage: RENEW_DAYS=30 ./scripts/mkcert.sh
set -euo pipefail

CERT_DIR=".devcerts"
KEY_FILE="$CERT_DIR/dev.key"
CRT_FILE="$CERT_DIR/dev.crt"

# Adjust how early to renew (in days). Default 0 = only renew if already expired.
RENEW_DAYS="${RENEW_DAYS:-0}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "❌ Required command not found: $1" >&2
    exit 1
  }
}

# Convert "notAfter" from openssl to epoch in a cross-platform way (GNU/BSD date)
expiry_epoch() {
  local enddate="$1"        # e.g. "Aug 30 12:00:00 2026 GMT"
  local epoch=""

  # Try GNU date
  if date -d "$enddate" +%s >/dev/null 2>&1; then
    epoch="$(date -d "$enddate" +%s)"
    echo "$epoch"
    return 0
  fi

  # Try BSD/macOS date
  if date -j -f "%b %e %T %Y %Z" "$enddate" +%s >/dev/null 2>&1; then
    epoch="$(date -j -f "%b %e %T %Y %Z" "$enddate" +%s)"
    echo "$epoch"
    return 0
  fi

  echo "❌ Could not parse certificate end date: $enddate" >&2
  return 1
}

is_cert_still_good() {
  # Returns 0 if cert exists and is not within RENEW_DAYS of expiry, else 1
  [[ -f "$CRT_FILE" && -f "$KEY_FILE" ]] || return 1

  # Read notAfter from cert
  local end_raw
  end_raw="$(openssl x509 -enddate -noout -in "$CRT_FILE" | sed 's/^notAfter=//')" || return 1

  local end_epoch now_epoch renew_cutoff_epoch
  end_epoch="$(expiry_epoch "$end_raw")" || return 1
  now_epoch="$(date +%s)"

  # Seconds until expiry
  local remaining=$(( end_epoch - now_epoch ))

  # Renew threshold in seconds
  local renew_threshold=$(( RENEW_DAYS * 24 * 3600 ))

  if (( remaining > renew_threshold )); then
    return 0
  else
    return 1
  fi
}

need_cmd mkcert
need_cmd openssl
need_cmd date
mkdir -p "$CERT_DIR"

# One-time (idempotent): install local CA into OS/browser trust stores
mkcert -install

if is_cert_still_good; then
  echo "✅ Existing certificate is valid and not within $RENEW_DAYS day(s) of expiry, skipping."
  exit 0
fi

echo "🔑 Generating new certificate..."
mkcert -key-file "$KEY_FILE" -cert-file "$CRT_FILE" \
  "weftid.localhost" "*.weftid.localhost" 127.0.0.1 ::1

echo "🎉 Certificate created/renewed at $CERT_DIR"

# Optional: show new expiry
new_end="$(openssl x509 -enddate -noout -in "$CRT_FILE" | sed 's/^notAfter=//')"
echo "📅 Not After: $new_end"
