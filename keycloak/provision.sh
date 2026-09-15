#!/usr/bin/env bash
# Idempotent Keycloak provisioning via kcadm.sh
# Run after Keycloak is healthy (called from docker-compose healthcheck or Makefile)
set -euo pipefail

KC_URL="${KC_URL:-http://localhost:8080}"
KC_ADMIN="${KC_ADMIN_USER:-admin}"
KC_PASS="${KC_ADMIN_PASSWORD:-admin_secret_local}"
KCADM="docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh"

echo "==> Provisioning Keycloak at $KC_URL"

# Authenticate kcadm
$KCADM config credentials \
  --server "$KC_URL" \
  --realm master \
  --user "$KC_ADMIN" \
  --password "$KC_PASS"

# Verify realms imported
for REALM in openbanking-b0 openbanking-fapi2; do
  if $KCADM get realms/$REALM > /dev/null 2>&1; then
    echo "  [OK] Realm $REALM already exists"
  else
    echo "  [WARN] Realm $REALM not found — check import"
  fi
done

echo "==> Provisioning complete"
