# TokenizationService – Keycloak + Vault (mTLS) Stack

## Overview

This repository provides a complete local authentication and secrets stack:

* **PostgreSQL** – Keycloak database
* **Keycloak** – Identity Provider (HTTPS + mTLS)
* **HashiCorp Vault** – Secrets management (HTTPS + mTLS, Raft storage)

The stack supports:

* TLS-secured communication
* Mutual TLS (client certificate authentication)
* Database backup & restore
* Vault snapshot backup & restore
* Full environment migration via bundle scripts

---

# Architecture Overview

![architecture.svg](./architecture.svg)

---

# Requirements

* Docker + Docker Compose
* `curl`
* `jq` (optional)
* `gunzip`
* Vault CLI (optional)

---

# Project Structure

```
.
├─ docker-compose.yml
├─ certs/
├─ config/
│  └─ config.hcl
├─ file/
├─ logs/
├─ make-bundle.sh
├─ restore-bundle.sh
```

---

# 1. Start the Stack

```bash
docker compose up -d
```

Services:

| Service  | URL                                              |
| -------- | ------------------------------------------------ |
| Keycloak | [https://localhost:8443](https://localhost:8443) |
| Vault    | [https://127.0.0.1:8200](https://127.0.0.1:8200) |

---

# 2. Certificates (mTLS)

Both Keycloak and Vault require TLS certificates.

Expected in `./certs`:

```
ca.pem
server.pem
server.key
client.pem
client.key
client.p12
```

### Important

* Browser must present a valid client certificate.
* Keycloak is configured with:

  ```
  KC_HTTPS_CLIENT_AUTH=required
  ```

If no client certificate is presented → TLS handshake fails.

---

# 3. Keycloak Setup

## Admin Login

```
https://localhost:8443
```

Credentials:

```
Username: admin
Password: admin_password
```

---

## Create Realm

Create realm:

```
demo
```

---

## Create Test User

```
Username: alice
Password: alice_password
Temporary: OFF
```

---

## Create Roles

Create:

```
user
admin
```

Assign `user` role to `alice`.

---

## Create Clients

### SPA (Public)

```
Client ID: demo-spa
Client authentication: OFF
Standard flow: ON
```

Redirect URIs:

```
https://localhost:3000/*
```

---

### Backend (Confidential)

```
Client ID: demo-api
Client authentication: ON
Direct access grants: ON
```

Copy the **Client Secret**.

---

# 4. Test Token (CLI)

### Password Grant

```bash
curl --cacert ./certs/ca.pem \
     --cert ./certs/client.pem \
     --key ./certs/client.key \
     -X POST \
     -d "grant_type=password" \
     -d "client_id=demo-api" \
     -d "client_secret=<CLIENT_SECRET>" \
     -d "username=alice" \
     -d "password=alice_password" \
     https://localhost:8443/realms/demo/protocol/openid-connect/token | jq
```

---

# 5. Vault Setup

## Set Environment Variables (Local CLI)

```bash
export VAULT_ADDR="https://127.0.0.1:8200"
export VAULT_CACERT="./certs/ca.pem"
export VAULT_CLIENT_CERT="./certs/client.pem"
export VAULT_CLIENT_KEY="./certs/client.key"
```

---

## Check Status

```bash
vault status
```

---

# 6. Vault Initialization (First Time Only)

### Initialize

```bash
vault operator init -key-shares=1 -key-threshold=1
```

Save:

* Unseal key
* Root token

---

### Unseal

```bash
vault operator unseal <UNSEAL_KEY>
```

---

### Login

```bash
vault login <ROOT_TOKEN>
```

---

# 7. Backup & Migration

This project provides two helper scripts:

| Script              | Purpose                    |
| ------------------- | -------------------------- |
| `make-bundle.sh`    | Creates full backup bundle |
| `restore-bundle.sh` | Restores full environment  |

---

# Create Backup Bundle

```bash
chmod +x make-bundle.sh
./make-bundle.sh
```

The script creates:

```
bundle/
├─ postgres-keycloak.sql.gz
├─ file/vault.snap
├─ certs/
├─ config/config.hcl
└─ images.tar (optional)
```

Included:

* PostgreSQL dump
* Vault Raft snapshot
* TLS certificates
* Vault config
* Optional Docker images

---

# Restore Full Environment

```bash
chmod +x restore-bundle.sh
./restore-bundle.sh
```

The restore script:

1. Starts Postgres
2. Restores Keycloak DB
3. Starts Vault
4. Initializes (if needed)
5. Unseals Vault
6. Restores Vault snapshot
7. Unseals again

---

# Full Migration Workflow

## On Source Machine

```bash
./make-bundle.sh
```

Transfer bundle to new host.

---

## On Target Machine

```bash
./restore-bundle.sh
```

Stack fully restored.

---

# Troubleshooting

## Keycloak TLS Fails

* Check client certificate installed
* Verify `ca.pem` matches server cert

---

## Vault Permission Errors

Vault runs as UID/GID `100:100`.

Ensure:

```bash
sudo chown -R 100:100 ./data ./file ./logs
```

---

## Port Already in Use

```bash
lsof -i :8443
lsof -i :8200
```

---

## Reset Environment

```bash
docker compose down -v
```

---

# Security Notes

⚠ This setup is for development/testing.

Do NOT:

* Hardcode unseal keys
* Commit root tokens
* Store bundle unencrypted

Recommended improvements:

* Use environment variables
* Encrypt backup bundles
* Use Vault auto-unseal (KMS/HSM)
* Rotate secrets after restore
* Enable proper TLS hostname validation

---

# Summary

This repository provides:

* Secure Keycloak setup with mTLS
* Secure Vault setup with Raft
* Automated backup & restore
* Full migration capability
* Local development security simulation

## Credits

Architecture diagram icons by [Icons8](https://icons8.com) (used under free license).