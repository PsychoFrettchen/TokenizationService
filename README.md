# Vault-Backed Tokenization Service

A secure, production-oriented gRPC-based tokenization service supporting
format-preserving encryption (FPE), HMAC, hashing, and AES-GCM encryption.

The service integrates with Vault for key management and supports
tenant-aware key rotation and deterministic field-level key derivation.

The service is based on `netstandard 2.0` to compatible with a majority of versions
used in legacy environments.

---

## Features

- gRPC API (Unary + Bidirectional Streaming)
- Multi-tenant key management
- HKDF-based per-field key derivation
- AES-256-GCM encryption
- SHA-256 hashing
- HMAC-SHA256 tokenization
- Format-Preserving Encryption (FF1 / FF3-1)
- Optional reversible token storage
- Key rotation support
- Vault-backed key provider
- Keycloak JWT validation (Authorization Interceptor)
- Full integration and unit tests

---

## Architecture

The service follows clean separation of concerns:

- `IKeyProvider` – abstraction for key management
- `ITokenStore` – abstraction for token persistence
- `IFpeEngine` – pluggable FPE engine
- gRPC service layer
- Crypto abstraction layer

Key derivation is performed per:

tenant + keyId + field

using HKDF to ensure strict cryptographic isolation.

---

## Technology Stack

- .NET 8
- gRPC
- BouncyCastle (Crypto)
- Vault (Key management)
- Keycloak (JWT validation)
- xUnit (Testing)

---

## Supported Token Types

| Type      | Reversible | Store Required |
|-----------|------------|----------------|
| Random    | Yes        | Yes            |
| Hash      | No         | Optional       |
| HMAC      | No         | Optional       |
| FPE       | Yes        | No             |
| Encrypted | Yes        | No             |

---

## Key Rotation

Keys can be rotated per tenant.  
New tokens use the active key ID while older tokens remain valid
as long as their key material is retained.

---

## Testing

The project includes:

- Unit tests
- Integration tests
- End-to-end tests (Vault + Keycloak)

Run:

```bash
dotnet test
