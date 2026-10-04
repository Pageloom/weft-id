#!/usr/bin/env bash
# Self-hosting smoke test
#
# Follows docs/self-hosting/index.md on a throwaway install: run the
# installer non-interactively, start the stack, verify email, provision a
# tenant, then check HTTPS through Caddy, the certificate gate, the
# invitation email, and that data survives a restart. With --upgrade-from,
# it installs the older release first and upgrades it the documented way.
#
# Images are pulled anonymously from ghcr.io, exactly as a self-hoster would.
# With "local" as the version, the image is built from this checkout and the
# repo's deploy/ files replace the released ones, so a branch can be tested
# before it is released.
#
# Test-only deviations from a real install (applied in a compose override):
#   - Caddy issues certificates from its internal CA (local_certs), since
#     there is no public DNS for the ACME HTTP-01 challenge
#   - Caddy listens on high localhost ports so a dev stack can keep 80/443
#   - A Mailpit container receives the outbound email
#
# Usage:
#   dev/selfhost-smoke.sh <version|local> [--upgrade-from <older-version>] [--keep]
#
#   make selfhost-smoke                                     # this checkout
#   make selfhost-smoke VERSION=2.0.0                       # a release
#   make selfhost-smoke ARGS="--upgrade-from 2.0.0"         # release -> checkout
#
# Environment:
#   SMOKE_HTTPS_PORT  Host port for Caddy HTTPS (default 18443)
#   SMOKE_MAIL_PORT   Host port for the Mailpit API (default 18025)
#   SMOKE_INSTALLER   Installer to run (default: this repo's deploy/install.sh)

set -euo pipefail

usage() {
    echo "Usage: $0 <version|local> [--upgrade-from <older-version>] [--keep]" >&2
    exit 2
}

[ $# -ge 1 ] || usage
VERSION="${1#v}"
shift
FROM_VERSION=""
KEEP=false
while [ $# -gt 0 ]; do
    case "$1" in
        --upgrade-from) [ $# -ge 2 ] || usage; FROM_VERSION="${2#v}"; shift 2 ;;
        --keep) KEEP=true; shift ;;
        *) usage ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOCAL=false
TARGET_TAG="$VERSION"
if [ "$VERSION" = local ]; then
    LOCAL=true
    TARGET_TAG="smoke-local"
fi
INSTALLER="${SMOKE_INSTALLER:-${REPO_ROOT}/deploy/install.sh}"
HTTPS_PORT="${SMOKE_HTTPS_PORT:-18443}"
MAIL_PORT="${SMOKE_MAIL_PORT:-18025}"

DOMAIN="selfhost.test"
SUBDOMAIN="acme"
TENANT_HOST="${SUBDOMAIN}.${DOMAIN}"
ADMIN_EMAIL="admin@example.com"

export COMPOSE_PROJECT_NAME="weftid-selfhost-smoke"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/weftid-selfhost-smoke.XXXXXX")"

# --- Helpers ----------------------------------------------------------------

step() { printf '\n==> %s\n' "$*"; }
fail() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }

compose() {
    docker compose -f docker-compose.yml -f compose.smoke.yml "$@"
}

cleanup() {
    status=$?
    cd "$WORKDIR" 2>/dev/null || return
    if [ "$status" -ne 0 ] && [ -f docker-compose.yml ]; then
        printf '\n==> Logs (last 60 lines per service)\n'
        compose ps -a || true
        compose logs --no-color --tail=60 || true
    fi
    if [ "$KEEP" = true ]; then
        echo "Kept install in ${WORKDIR} (project ${COMPOSE_PROJECT_NAME})"
        return
    fi
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# Poll until a command succeeds or the timeout (seconds) runs out
wait_for() {
    timeout="$1"; shift
    deadline=$(( $(date +%s) + timeout ))
    until "$@" >/dev/null 2>&1; do
        [ "$(date +%s)" -lt "$deadline" ] || return 1
        sleep 3
    done
}

app_healthy() {
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q app)")" = healthy ]
}

# curl a host served by Caddy, resolved to localhost
tenant_curl() {
    host="$1"; shift
    curl -sS --cacert caddy-root.crt --resolve "${host}:${HTTPS_PORT}:127.0.0.1" "$@" \
        "https://${host}:${HTTPS_PORT}/login"
}

start_stack() {
    compose up -d
    wait_for 240 app_healthy || fail "app did not become healthy"
    [ "$(docker inspect -f '{{.State.ExitCode}}' "$(compose ps -aq migrate)")" = 0 ] \
        || fail "migrate service failed"
}

check_running_version() {
    expected="ghcr.io/pageloom/weft-id:$1"
    actual="$(docker inspect -f '{{.Config.Image}}' "$(compose ps -q app)")"
    [ "$actual" = "$expected" ] || fail "app runs ${actual}, expected ${expected}"
    echo "app runs ${actual}"
}

check_tenant_served() {
    # Caddy's root CA appears once it has issued its first certificate
    wait_for 60 compose exec -T caddy test -f /data/caddy/pki/authorities/local/root.crt \
        || fail "Caddy did not create its local CA"
    compose exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > caddy-root.crt

    # Caddy starts after the app turns healthy, so give it a moment to listen
    login_ok() { [ "$(tenant_curl "$TENANT_HOST" -o login.html -w '%{http_code}')" = 200 ]; }
    if ! wait_for 60 login_ok; then
        tenant_curl "$TENANT_HOST" -o /dev/null -w 'last status %{http_code}\n' || true
        fail "GET https://${TENANT_HOST}/login did not return 200"
    fi
    grep -qi "<form" login.html || fail "login page has no form"
    echo "https://${TENANT_HOST}/login returned 200 with a trusted certificate"
}

# --- Install ----------------------------------------------------------------

install_version() {
    step "Install ${1:-the latest release} with the non-interactive installer"
    WEFT_NONINTERACTIVE=1 \
    WEFT_VERSION="$1" \
    BASE_DOMAIN="$DOMAIN" \
    SMTP_HOST=mailpit \
    SMTP_PORT=1025 \
    SMTP_TLS=false \
        bash "$INSTALLER" </dev/null

    for f in docker-compose.yml Caddyfile .env; do
        [ -s "$f" ] || fail "installer did not create ${f}"
    done
    if [ -n "$1" ]; then
        grep -qx "WEFT_VERSION=$1" .env || fail ".env does not pin WEFT_VERSION=$1"
    fi
    for key in SECRET_KEY POSTGRES_PASSWORD APPUSER_PASSWORD; do
        grep -qE "^${key}=.{20,}" .env || fail "installer did not generate ${key}"
    done
}

caddy_local_certs() {
    # Insert local_certs into the Caddyfile's global options block
    awk '!done && /^\{$/ { print; print "\tlocal_certs"; done = 1; next } { print }' \
        Caddyfile > Caddyfile.tmp && mv Caddyfile.tmp Caddyfile
    grep -q "local_certs" Caddyfile || fail "Caddyfile has no global options block"
}

write_test_overrides() {
    step "Apply test-only overrides (local CA, ports, mail catcher)"
    caddy_local_certs

    cat > compose.smoke.yml <<EOF
services:
  caddy:
    ports: !override
      - "127.0.0.1:${HTTPS_PORT}:443"
  mailpit:
    image: axllent/mailpit:v1.31
    ports:
      - "127.0.0.1:${MAIL_PORT}:8025"
    networks:
      - prodnet
EOF
}

# Swap in this checkout's image and deploy files, keeping the generated .env
use_local_build() {
    step "Use this checkout's image and deploy files"
    cp "${REPO_ROOT}/deploy/docker-compose.yml" "${REPO_ROOT}/deploy/Caddyfile" .
    caddy_local_certs
    sed "s/^WEFT_VERSION=.*/WEFT_VERSION=${TARGET_TAG}/" .env > .env.tmp && mv .env.tmp .env
    chmod 600 .env
}

if [ "$LOCAL" = true ]; then
    step "Build the image from this checkout"
    docker build -q -t "ghcr.io/pageloom/weft-id:${TARGET_TAG}" -f "${REPO_ROOT}/Dockerfile" "$REPO_ROOT"
fi

cd "$WORKDIR"
echo "Working directory: ${WORKDIR}"

if [ -n "$FROM_VERSION" ]; then
    install_version "$FROM_VERSION"
elif [ "$LOCAL" = true ]; then
    install_version ""
else
    install_version "$VERSION"
fi
write_test_overrides
if [ "$LOCAL" = true ] && [ -z "$FROM_VERSION" ]; then
    use_local_build
fi

step "Start the services"
start_stack
check_running_version "${FROM_VERSION:-$TARGET_TAG}"

step "Verify email delivery"
compose exec -T app python -m cli.verify_email --to "$ADMIN_EMAIL" \
    || fail "verify_email failed"

step "Provision the first tenant"
compose exec -T app python -m cli.provision_tenant \
    --subdomain "$SUBDOMAIN" \
    --tenant-name "Acme Corp" \
    --email "$ADMIN_EMAIL" \
    --first-name Jane \
    --last-name Smith | tee provision.log
grep -q "Invitation sent to ${ADMIN_EMAIL}" provision.log \
    || fail "provisioning did not send the invitation"

step "Check the invitation email"
mail_api() { curl -fsS "http://127.0.0.1:${MAIL_PORT}/api/v1/$1"; }
invitation_received() {
    ids="$(mail_api "search?query=to:${ADMIN_EMAIL}" \
        | python3 -c 'import json, sys; [print(m["ID"]) for m in json.load(sys.stdin)["messages"]]')"
    for id in $ids; do
        mail_api "message/${id}" | grep -q "https://${TENANT_HOST}/" && return 0
    done
    return 1
}
wait_for 30 invitation_received || fail "no email to ${ADMIN_EMAIL} links to https://${TENANT_HOST}/"
echo "invitation to ${ADMIN_EMAIL} links to https://${TENANT_HOST}/"

step "Check HTTPS and the certificate gate"
check_tenant_served
if tenant_curl "nope.${DOMAIN}" -o /dev/null 2>/dev/null; then
    fail "Caddy issued a certificate for an unknown tenant"
fi
echo "unknown tenant nope.${DOMAIN} was refused a certificate"

if [ -n "$FROM_VERSION" ]; then
    step "Upgrade ${FROM_VERSION} -> ${VERSION} (documented procedure)"
    if [ "$LOCAL" = true ]; then
        use_local_build
    else
        sed "s/^WEFT_VERSION=.*/WEFT_VERSION=${VERSION}/" .env > .env.tmp && mv .env.tmp .env
        chmod 600 .env
        compose pull --quiet
    fi
    start_stack
    check_running_version "$TARGET_TAG"
    check_tenant_served
fi

step "Restart the stack and check data survived"
compose down
start_stack
check_tenant_served

step "PASS: self-hosted ${VERSION}${FROM_VERSION:+ (upgraded from ${FROM_VERSION})}"
