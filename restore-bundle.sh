#!/usr/bin/env bash
set -euo pipefail

# -------------------------
# Config (override via env)
# -------------------------
VAULT_CONT="${VAULT_CONT:-vault-new}"
PG_CONT="${PG_CONT:-keycloak-postgres}"

# Try hostname first (matches cert SAN), fallback to 127.0.0.1
VAULT_ADDR_HOST="${VAULT_ADDR_HOST:-https://vault1.poc.itproject.com:8200}"
VAULT_ADDR_IP="${VAULT_ADDR_IP:-https://127.0.0.1:8200}"
VAULT_ADDR_URL="${VAULT_ADDR_URL:-$VAULT_ADDR_HOST}"

# mTLS certs (host paths)
VAULT_CACERT="${VAULT_CACERT:-./certs/ca.pem}"
VAULT_CLIENT_CERT="${VAULT_CLIENT_CERT:-./certs/client.pem}"
VAULT_CLIENT_KEY="${VAULT_CLIENT_KEY:-./certs/client.key}"

# Secrets (DO NOT hardcode)
# Provide via env or interactive prompt:
#   export VAULT_TOKEN="..."
#   export VAULT_UNSEAL_KEY="..."
VAULT_TOKEN="${VAULT_TOKEN:-}"
VAULT_UNSEAL_KEY="${VAULT_UNSEAL_KEY:-}"

# Bundle artifacts
IMAGES_TAR="${IMAGES_TAR:-images.tar}"
PG_DUMP_GZ="${PG_DUMP_GZ:-postgres-keycloak.sql.gz}"
SNAPSHOT_PATH_HOST="${SNAPSHOT_PATH_HOST:-./file/vault.snap}"

# -------------------------
# Helpers
# -------------------------
req() { command -v "$1" >/dev/null || { echo "Missing required command: $1" >&2; exit 1; }; }
die() { echo "ERROR: $*" >&2; exit 1; }

probe_addr() {
  local addr="$1"
  docker exec \
    -e VAULT_ADDR="$addr" \
    -e VAULT_CACERT="/certs/ca.pem" \
    -e VAULT_CLIENT_CERT="/certs/client.pem" \
    -e VAULT_CLIENT_KEY="/certs/client.key" \
    "$VAULT_CONT" sh -lc '
      vault status -format=json >/dev/null 2>&1; rc=$?;
      test "$rc" = "0" -o "$rc" = "2"
    '
}

prompt_secret_if_missing() {
  local var_name="$1"
  local prompt="$2"
  local silent="${3:-true}"

  local val="${!var_name:-}"
  if [ -n "$val" ]; then return 0; fi

  if [ -t 0 ]; then
    if [ "$silent" = "true" ]; then
      read -rsp "$prompt" val
      echo
    else
      read -rp "$prompt" val
    fi
    export "$var_name"="$val"
  else
    return 1
  fi
}

req docker
req gunzip

echo "[0/9] Preflight..."
test -f "$PG_DUMP_GZ" || die "$PG_DUMP_GZ missing"
test -f "$SNAPSHOT_PATH_HOST" || die "$SNAPSHOT_PATH_HOST missing"
test -f "$VAULT_CACERT" || die "$VAULT_CACERT missing"
test -f "$VAULT_CLIENT_CERT" || die "$VAULT_CLIENT_CERT missing"
test -f "$VAULT_CLIENT_KEY" || die "$VAULT_CLIENT_KEY missing"
test -f ./config/config.hcl || die "./config/config.hcl missing"

mkdir -p config data file certs logs

echo "[0b/9] Fix perms for Vault volumes (Vault runs as uid:gid 100:100)..."
sudo chown -R 100:100 ./config ./data ./file ./certs ./logs
sudo chmod 755 ./config ./data ./file ./certs ./logs
sudo chmod 644 ./config/config.hcl
sudo chmod 640 ./certs/*.key 2>/dev/null || true
sudo chmod 644 ./certs/*.pem 2>/dev/null || true

echo "[1/9] (Optional) Load images tar if present..."
if [ -f "$IMAGES_TAR" ]; then
  docker load -i "$IMAGES_TAR"
else
  echo "  No $IMAGES_TAR found; assuming images are already available."
fi

echo "[2/9] Start only Postgres..."
docker compose up -d postgres

echo "[3/9] Wait for Postgres to be healthy..."
for i in {1..60}; do
  if docker exec "$PG_CONT" pg_isready -U keycloak >/dev/null 2>&1; then break; fi
  sleep 2
  [[ $i -eq 60 ]] && die "Postgres not healthy in time"
done

echo "[4/9] Reset schema and restore Keycloak DB..."
docker exec -i "$PG_CONT" psql -U keycloak -d keycloak -v ON_ERROR_STOP=1 \
  -c 'DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO keycloak;'
gunzip -c "$PG_DUMP_GZ" | docker exec -i "$PG_CONT" psql -U keycloak -d keycloak -v ON_ERROR_STOP=1

echo "[5/9] Start Vault..."
docker compose up -d vault

echo "[6/9] Probe Vault reachability (hostname → fallback to 127.0.0.1)…"
if probe_addr "$VAULT_ADDR_HOST"; then
  echo "  ✓ Hostname reachable: $VAULT_ADDR_HOST"
  VAULT_ADDR_URL="$VAULT_ADDR_HOST"
else
  echo "  ! Hostname unreachable; using IP: $VAULT_ADDR_IP"
  VAULT_ADDR_URL="$VAULT_ADDR_IP"
fi

echo "[7/9] Ensure Vault is initialized/unsealed enough to restore snapshot..."
# If Vault is uninitialized, we can initialize it temporarily to be able to restore the snapshot.
# Snapshot restore will seal Vault again and then it MUST be unsealed with the ORIGINAL unseal key.
docker exec \
  -e VAULT_ADDR="$VAULT_ADDR_URL" \
  -e VAULT_CACERT="/certs/ca.pem" \
  -e VAULT_CLIENT_CERT="/certs/client.pem" \
  -e VAULT_CLIENT_KEY="/certs/client.key" \
  "$VAULT_CONT" sh -lc '
set -euo pipefail
json="$(vault status -format=json || true)"
init="$(printf "%s" "$json" | sed -n "s/.*\"initialized\":\\s*\\(true\\|false\\).*/\\1/p")"
sealed="$(printf "%s" "$json" | sed -n "s/.*\"sealed\":\\s*\\(true\\|false\\).*/\\1/p")"
echo "  initialized=${init:-unknown}, sealed=${sealed:-unknown}"
if [ "$init" = "false" ]; then
  echo "  Vault not initialized; initializing 1-of-1 so we can restore snapshot..."
  out="$(vault operator init -key-shares=1 -key-threshold=1)"
  printf "%s\n" "$out" > /vault/file/init-temp.txt
  token="$(printf "%s\n" "$out" | awk "/Initial Root Token/ {print \$NF}")"
  key="$(printf "%s\n" "$out" | awk "/Unseal Key 1/ {print \$NF}")"
  printf "%s\n" "$token" > /vault/file/token-temp.txt
  printf "%s\n" "$key" > /vault/file/unseal-temp.txt
  vault operator unseal "$key" >/dev/null
  echo "  Temp init done (token/unseal stored in /vault/file/*-temp.txt)."
fi
'

echo "[8/9] Restore the raft snapshot (Vault will seal afterwards)..."
# Need a token to perform snapshot restore:
# - Use VAULT_TOKEN if provided
# - Otherwise, use temp token if we just initialized
if [ -z "$VAULT_TOKEN" ]; then
  VAULT_TOKEN="$(docker exec "$VAULT_CONT" sh -lc 'test -f /vault/file/token-temp.txt && cat /vault/file/token-temp.txt || true')"
fi
if [ -z "$VAULT_TOKEN" ]; then
  prompt_secret_if_missing VAULT_TOKEN "Enter VAULT_TOKEN (needs permission for raft snapshot restore): " true || true
fi
[ -n "$VAULT_TOKEN" ] || die "No VAULT_TOKEN available (set VAULT_TOKEN env var)."

docker exec \
  -e VAULT_ADDR="$VAULT_ADDR_URL" \
  -e VAULT_CACERT="/certs/ca.pem" \
  -e VAULT_CLIENT_CERT="/certs/client.pem" \
  -e VAULT_CLIENT_KEY="/certs/client.key" \
  -e VAULT_TOKEN="$VAULT_TOKEN" \
  "$VAULT_CONT" sh -lc '
  test -f /vault/file/vault.snap || { echo "/vault/file/vault.snap missing"; exit 1; }
  vault operator raft snapshot restore -force /vault/file/vault.snap
  echo "  Snapshot applied."
'

echo "[8b/9] Unseal with ORIGINAL unseal key (required after restore)..."
if [ -z "$VAULT_UNSEAL_KEY" ]; then
  prompt_secret_if_missing VAULT_UNSEAL_KEY "Enter ORIGINAL Vault unseal key: " true || true
fi
[ -n "$VAULT_UNSEAL_KEY" ] || die "Missing VAULT_UNSEAL_KEY. Set env var or run interactively."

docker exec \
  -e VAULT_ADDR="$VAULT_ADDR_URL" \
  -e VAULT_CACERT="/certs/ca.pem" \
  -e VAULT_CLIENT_CERT="/certs/client.pem" \
  -e VAULT_CLIENT_KEY="/certs/client.key" \
  "$VAULT_CONT" sh -lc "vault operator unseal '${VAULT_UNSEAL_KEY}' >/dev/null"

echo
echo "[9/9] Done: DB restored, Vault snapshot restored, Vault unsealed."
