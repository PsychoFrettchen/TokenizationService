using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Grpc.Core;

namespace TokenizationService.Authorization
{
    /// <summary>
    ///     Validates JWTs issued by Keycloak (RS256):
    ///     - Loads and caches JWKS (RSA keys) via OIDC discovery.
    ///     - Verifies signature, issuer (iss), audience (aud), not-before (nbf), and expiration (exp).
    ///     - Derives permissions from "scope" (space-separated or array) and client-specific roles.
    /// </summary>
    public sealed class KeycloakAccessTokenValidator : IAccessTokenValidator, IDisposable
    {
        private readonly string audience; // Expected audience (API clientId), e.g. "tokenization-api"
        private readonly string discoveryUrl;
        private readonly HttpClient http;
        private readonly string issuer; // Expected issuer, e.g. https://keycloak.local:8443/realms/poc
        private readonly TimeSpan jwksTtl;
        private DateTimeOffset jwksExpiry = DateTimeOffset.MinValue;

        // Very simple in-memory cache for JWKS keys by kid
        private Dictionary<string, RSA> keysByKid = new Dictionary<string, RSA>(StringComparer.Ordinal);

        public KeycloakAccessTokenValidator(HttpClient http, string issuer, string audience, TimeSpan? jwksTtl = null)
        {
            this.http = http ?? throw new ArgumentNullException(nameof(http));
            this.issuer = issuer?.TrimEnd('/') ?? throw new ArgumentNullException(nameof(issuer));
            this.audience = audience ?? "";
            discoveryUrl = this.issuer + "/.well-known/openid-configuration";
            this.jwksTtl = jwksTtl ?? TimeSpan.FromMinutes(10); // Duration JWKS remain cached
        }

        public async Task<IReadOnlyCollection<string>> ValidateAsync(string bearerToken)
        {
            // 1) Validate input
            if (string.IsNullOrWhiteSpace(bearerToken))
                throw new RpcException(new Status(StatusCode.Unauthenticated, "Missing bearer token"));

            // Remove "Bearer " prefix (if present)
            var token = bearerToken.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                ? bearerToken.Substring(7).Trim()
                : bearerToken.Trim();

            // JWT must consist of three Base64URL parts: header.payload.signature
            var parts = token.Split('.');
            if (parts.Length != 3)
                throw new RpcException(new Status(StatusCode.Unauthenticated, "Malformed JWT"));

            // 2) Decode header & payload (without validation yet)
            var header = JsonDocument.Parse(FromB64Url(parts[0])).RootElement;
            var payload = JsonDocument.Parse(FromB64Url(parts[1])).RootElement;
            var kid = header.TryGetProperty("kid", out var kidEl) ? kidEl.GetString() : null;

            // 3) Retrieve RSA key for the given kid (from cache/JWKS if necessary)
            var rsa = await GetKeyForKidAsync(kid).ConfigureAwait(false);

            // 4) Verify signature (RS256)
            var signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
            var sig = FromB64UrlRaw(parts[2]);
            var ok = rsa.VerifyData(signingInput, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            if (!ok)
                throw new RpcException(new Status(StatusCode.Unauthenticated, "Invalid token signature"));

            // 5) Validate standard claims: iss / aud / nbf / exp
            if (payload.TryGetProperty("iss", out var issEl))
                if (!string.Equals(issEl.GetString(), issuer, StringComparison.Ordinal))
                    throw new RpcException(new Status(StatusCode.Unauthenticated, "Issuer mismatch"));

            if (!string.IsNullOrEmpty(audience) && payload.TryGetProperty("aud", out var audEl))
                // Keycloak commonly sets a single string audience in access tokens
                if (!string.Equals(audEl.GetString(), audience, StringComparison.Ordinal))
                    throw new RpcException(new Status(StatusCode.Unauthenticated, "Audience mismatch"));

            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            if (payload.TryGetProperty("nbf", out var nbfEl) && nbfEl.ValueKind == JsonValueKind.Number)
            {
                var nbf = nbfEl.GetInt64();
                // Small tolerance of 5 seconds
                if (nbf > now + 5)
                    throw new RpcException(new Status(StatusCode.Unauthenticated, "Token not yet valid"));
            }

            if (payload.TryGetProperty("exp", out var expEl) && expEl.ValueKind == JsonValueKind.Number)
            {
                var exp = expEl.GetInt64();
                if (exp < now - 5)
                    throw new RpcException(new Status(StatusCode.Unauthenticated, "Token expired"));
            }

            // 6) Extract scopes/permissions:
            //    a) Directly from "scope" (space-separated or array)
            //    b) From client-specific roles: resource_access[<audience>].roles
            var result = new HashSet<string>(StringComparer.Ordinal);

            // a) "scope" may be a string or an array (depending on Keycloak mapper configuration)
            if (payload.TryGetProperty("scope", out var scopeEl))
            {
                if (scopeEl.ValueKind == JsonValueKind.String)
                    foreach (var s in (scopeEl.GetString() ?? "")
                             .Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
                        result.Add(s);
                else if (scopeEl.ValueKind == JsonValueKind.Array)
                    foreach (var item in scopeEl.EnumerateArray())
                        if (item.ValueKind == JsonValueKind.String)
                            result.Add(item.GetString());
            }

            // b) Map client roles to scopes (mapping strategy)
            if (payload.TryGetProperty("resource_access", out var ra) &&
                ra.ValueKind == JsonValueKind.Object &&
                ra.TryGetProperty(audience, out var clientSec) &&
                clientSec.ValueKind == JsonValueKind.Object &&
                clientSec.TryGetProperty("roles", out var roles) &&
                roles.ValueKind == JsonValueKind.Array)
                foreach (var r in roles.EnumerateArray())
                    if (r.ValueKind == JsonValueKind.String)
                        // Assumption: role name equals required scope (e.g., "tokenize", "detokenize")
                        result.Add(r.GetString());

            return result;
        }

        public void Dispose()
        {
            http?.Dispose();
        }

        private async Task<RSA> GetKeyForKidAsync(string kid, CancellationToken ct = default)
        {
            // If we have a matching key in cache and it has not expired → use it
            if (!string.IsNullOrEmpty(kid) &&
                keysByKid.TryGetValue(kid, out var cached) &&
                DateTimeOffset.UtcNow < jwksExpiry)
                return cached;

            // 1) Load OIDC discovery document (contains jwks_uri)
            var disco = await http.GetStringAsync(discoveryUrl).ConfigureAwait(false);
            var jwksUri = JsonDocument.Parse(disco).RootElement.GetProperty("jwks_uri").GetString();

            // 2) Fetch JWKS and store all RSA keys in a map
            var jwks = await http.GetStringAsync(jwksUri).ConfigureAwait(false);
            var keys = JsonDocument.Parse(jwks).RootElement.GetProperty("keys");

            var map = new Dictionary<string, RSA>(StringComparer.Ordinal);
            foreach (var k in keys.EnumerateArray())
                if (k.TryGetProperty("kty", out var kty) && kty.GetString() == "RSA")
                {
                    // Base64URL-decode modulus (n) and exponent (e)
                    var n = FromB64Url(k.GetProperty("n").GetString());
                    var e = FromB64Url(k.GetProperty("e").GetString());
                    var rp = new RSAParameters { Modulus = n, Exponent = e };
                    var r = RSA.Create();
                    r.ImportParameters(rp);
                    var kkid = k.TryGetProperty("kid", out var kidEl) ? kidEl.GetString() : "";
                    map[kkid ?? ""] = r;
                }

            // Replace cache and set expiration
            keysByKid = map;
            jwksExpiry = DateTimeOffset.UtcNow.Add(jwksTtl);

            // Preferred: exact kid match found?
            if (!string.IsNullOrEmpty(kid) && keysByKid.TryGetValue(kid, out var rsa))
                return rsa;

            // Fallback: If no kid in token but exactly one key available → use that
            if (string.IsNullOrEmpty(kid) && keysByKid.Count == 1)
                return keysByKid.Values.First();

            // Otherwise: no suitable signing key found
            throw new RpcException(new Status(StatusCode.Unauthenticated, "Signing key not found"));
        }

        // ---- Base64URL helpers ----
        private static byte[] FromB64Url(string s)
        {
            // Converts Base64URL (RFC 7515) to regular Base64 and decodes it
            if (string.IsNullOrEmpty(s)) return Array.Empty<byte>();
            var p = s.Replace('-', '+').Replace('_', '/');
            switch (p.Length % 4)
            {
                case 2: p += "=="; break;
                case 3: p += "="; break;
            }

            return Convert.FromBase64String(p);
        }

        private static byte[] FromB64UrlRaw(string s)
        {
            return FromB64Url(s);
        }
    }
}