#!/usr/bin/env bash
set -euo pipefail

# -------------------------
# Config (override via env)
# -------------------------
VAULT_CONT="${VAULT_CONT:-vault-new}"
PG_CONT="${PG_CONT:-keycloak-postgres}"

VAULT_ADDR_URL="${VAULT_ADDR_URL:-https://127.0.0.1:8200}"

# These file paths are for *host-side* checks/copy.
VAULT_CACERT="${VAULT_CACERT:-./certs/ca.pem}"
VAULT_CLIENT_CERT="${VAULT_CLIENT_CERT:-./certs/client-admin.pem}"
VAULT_CLIENT_KEY="${VAULT_CLIENT_KEY:-./certs/client-admin.key}"

# Bundle output
BUNDLE_DIR="${BUNDLE_DIR:-bundle-preloaded}"

# Files to include
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
CONFIG_DIR="${CONFIG_DIR:-config}"
CERTS_DIR="${CERTS_DIR:-certs}"
VAULT_SNAPSHOT_HOST_PATH="${VAULT_SNAPSHOT_HOST_PATH:-file/vault.snap}"

# Vault auth:
# - Prefer VAULT_TOKEN with sufficient privileges to do raft snapshot
# - Alternatively you can use a tokenless flow if your Vault is configured for cert auth,
#   but typically snapshot requires a token.
# Provide via env: VAULT_TOKEN="..."
VAULT_TOKEN="${VAULT_TOKEN:-}"

# -------------------------
# Helpers
# -------------------------
die() { echo "ERROR: $*" >&2; exit 1; }
req() { command -v "$1" >/dev/null || die "Missing required command: $1"; }

req docker

echo "[0/6] Preflight..."
test -f "$COMPOSE_FILE" || die "$COMPOSE_FILE missing"
test -d "$CONFIG_DIR" || die "$CONFIG_DIR missing"
test -d "$CERTS_DIR" || die "$CERTS_DIR missing"
test -f "$VAULT_CACERT" || die "$VAULT_CACERT missing"

mkdir -p "${BUNDLE_DIR}"/{config,certs,file}

echo "[1/6] Freeze image versions and save images..."
docker compose pull
IMGS="$(docker compose images -q | sort -u)"
test -n "$IMGS" || die "No images found via 'docker compose images -q'"
docker save ${IMGS} -o "${BUNDLE_DIR}/images.tar"

echo "[2/6] Copy compose + config + certs..."
cp -a "$COMPOSE_FILE" "${BUNDLE_DIR}/"
cp -a "${CONFIG_DIR}/"* "${BUNDLE_DIR}/config/" 2>/dev/null || true
cp -a "${CERTS_DIR}/"* "${BUNDLE_DIR}/certs/" 2>/dev/null || true

echo "[3/6] Create a Vault Raft snapshot..."
if [ -z "$VAULT_TOKEN" ]; then
  # If running interactively, prompt; otherwise fail with instruction.
  if [ -t 0 ]; then
    read -rsp "Enter VAULT_TOKEN (needs permission for raft snapshot): " VAULT_TOKEN
    echo
  else
    die "VAULT_TOKEN not set. Run: export VAULT_TOKEN='...'; then re-run."
  fi
fi

# Snapshot is written inside container to /vault/file/vault.snap (bind-mounted to ./file)
docker exec \
  -e VAULT_ADDR="${VAULT_ADDR_URL}" \
  -e VAULT_CACERT="/certs/ca.pem" \
  -e VAULT_TOKEN="${VAULT_TOKEN}" \
  "${VAULT_CONT}" \
  sh -lc 'vault operator raft snapshot save /vault/file/vault.snap'

test -f "$VAULT_SNAPSHOT_HOST_PATH" || die "Snapshot not found at ${VAULT_SNAPSHOT_HOST_PATH}"
cp -a "$VAULT_SNAPSHOT_HOST_PATH" "${BUNDLE_DIR}/file/vault.snap"

echo "[4/6] Dump Postgres (logical)..."
docker exec -t "${PG_CONT}" pg_dump -U keycloak keycloak | gzip -9 > "${BUNDLE_DIR}/postgres-keycloak.sql.gz"

echo "[5/6] Write restore README..."
cat > "${BUNDLE_DIR}/README-RESTORE.md" <<'EOF'
Restore steps are automated by ./restore-bundle.sh

Notes:
- You need the ORIGINAL Vault unseal key(s) from the source environment to unseal after snapshot restore.
- Snapshot restore overwrites cluster state; Vault will seal and then require the ORIGINAL unseal keys.
EOF

echo "[6/6] Optional: encrypt the bundle (recommended)"
echo "Examples:"
echo "  zip -r -e bundle-preloaded.zip ${BUNDLE_DIR}/"
echo "  tar cz ${BUNDLE_DIR} | gpg -c -o ${BUNDLE_DIR}.tgz.gpg"
echo "Done. Bundle at: ${BUNDLE_DIR}"
