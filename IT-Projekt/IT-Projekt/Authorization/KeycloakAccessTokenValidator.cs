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

namespace IT_Projekt.Authorization
{
    /// <summary>
    /// Validiert von Keycloak ausgestellte JWTs (RS256):
    ///  - Lädt und cached die JWKS (RSA-Schlüssel) per OIDC-Discovery.
    ///  - Prüft Signatur, Issuer (iss), Audience (aud), Not-Before (nbf) und Ablauf (exp).
    ///  - Leitet Berechtigungen aus "scope" (space-separiert oder Array) und client-spezifischen Rollen ab.
    /// </summary>
    public sealed class KeycloakAccessTokenValidator : IAccessTokenValidator, IDisposable
    {
        private readonly HttpClient http;
        private readonly string issuer;   // Erwarteter Issuer, z.B. https://keycloak.local:8443/realms/poc
        private readonly string audience; // Erwartete Audience (clientId der API), z.B. "tokenization-api"
        private readonly string discoveryUrl;

        // Sehr einfacher In-Memory-Cache für JWKS-Schlüssel nach kid
        private Dictionary<string, RSA> keysByKid = new Dictionary<string, RSA>(StringComparer.Ordinal);
        private DateTimeOffset jwksExpiry = DateTimeOffset.MinValue;
        private readonly TimeSpan jwksTtl;

        public KeycloakAccessTokenValidator(HttpClient http, string issuer, string audience, TimeSpan? jwksTtl = null)
        {
            this.http = http ?? throw new ArgumentNullException(nameof(http));
            this.issuer = issuer?.TrimEnd('/') ?? throw new ArgumentNullException(nameof(issuer));
            this.audience = audience ?? "";
            discoveryUrl = this.issuer + "/.well-known/openid-configuration";
            this.jwksTtl = jwksTtl ?? TimeSpan.FromMinutes(10); // wie lange JWKS im Cache bleiben
        }

        public void Dispose() => http?.Dispose();

        public async Task<IReadOnlyCollection<string>> ValidateAsync(string bearerToken)
        {
            // 1) Eingabe validieren
            if (string.IsNullOrWhiteSpace(bearerToken))
                throw new RpcException(new Status(StatusCode.Unauthenticated, "Missing bearer token"));

            // "Bearer " Präfix entfernen (falls vorhanden)
            string token = bearerToken.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                ? bearerToken.Substring(7).Trim()
                : bearerToken.Trim();

            // JWT sollte aus drei Base64URL-Teilen bestehen: header.payload.signature
            var parts = token.Split('.');
            if (parts.Length != 3)
                throw new RpcException(new Status(StatusCode.Unauthenticated, "Malformed JWT"));

            // 2) Header & Payload dekodieren (noch ohne Prüfung)
            JsonElement header   = JsonDocument.Parse(FromB64Url(parts[0])).RootElement;
            JsonElement payload  = JsonDocument.Parse(FromB64Url(parts[1])).RootElement;
            string kid = header.TryGetProperty("kid", out var kidEl) ? kidEl.GetString() : null;

            // 3) RSA-Schlüssel zum kid besorgen (ggf. aus Cache/JWKS)
            RSA rsa = await GetKeyForKidAsync(kid).ConfigureAwait(false);

            // 4) Signatur prüfen (RS256)
            var signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
            var sig = FromB64UrlRaw(parts[2]);
            bool ok = rsa.VerifyData(signingInput, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            if (!ok)
                throw new RpcException(new Status(StatusCode.Unauthenticated, "Invalid token signature"));

            // 5) Standard-Claims prüfen: iss / aud / nbf / exp
            if (payload.TryGetProperty("iss", out var issEl))
            {
                if (!string.Equals(issEl.GetString(), issuer, StringComparison.Ordinal))
                    throw new RpcException(new Status(StatusCode.Unauthenticated, "Issuer mismatch"));
            }

            if (!string.IsNullOrEmpty(audience) && payload.TryGetProperty("aud", out var audEl))
            {
                // Keycloak setzt bei Access Tokens häufig eine einzelne String-Audience
                if (!string.Equals(audEl.GetString(), audience, StringComparison.Ordinal))
                    throw new RpcException(new Status(StatusCode.Unauthenticated, "Audience mismatch"));
            }

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (payload.TryGetProperty("nbf", out var nbfEl) && nbfEl.ValueKind == JsonValueKind.Number)
            {
                var nbf = nbfEl.GetInt64();
                // kleine Toleranz von 5s
                if (nbf > now + 5)
                    throw new RpcException(new Status(StatusCode.Unauthenticated, "Token not yet valid"));
            }
            if (payload.TryGetProperty("exp", out var expEl) && expEl.ValueKind == JsonValueKind.Number)
            {
                var exp = expEl.GetInt64();
                if (exp < now - 5)
                    throw new RpcException(new Status(StatusCode.Unauthenticated, "Token expired"));
            }

            // 6) Scopes/Berechtigungen extrahieren:
            //    a) direkt aus "scope" (Space-separiert oder als Array)
            //    b) aus client-spezifischen Rollen: resource_access[<audience>].roles
            var result = new HashSet<string>(StringComparer.Ordinal);

            // a) "scope" kann String oder Array sein (je nach Mapper-Konfiguration in Keycloak)
            if (payload.TryGetProperty("scope", out var scopeEl))
            {
                if (scopeEl.ValueKind == JsonValueKind.String)
                {
                    foreach (var s in (scopeEl.GetString() ?? "")
                             .Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
                        result.Add(s);
                }
                else if (scopeEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in scopeEl.EnumerateArray())
                        if (item.ValueKind == JsonValueKind.String)
                            result.Add(item.GetString());
                }
            }

            // b) Rollen des adressierten Clients als Scopes übernehmen (Mapping-Strategie)
            if (payload.TryGetProperty("resource_access", out var ra) &&
                ra.ValueKind == JsonValueKind.Object &&
                ra.TryGetProperty(audience, out var clientSec) &&
                clientSec.ValueKind == JsonValueKind.Object &&
                clientSec.TryGetProperty("roles", out var roles) &&
                roles.ValueKind == JsonValueKind.Array)
            {
                foreach (var r in roles.EnumerateArray())
                    if (r.ValueKind == JsonValueKind.String)
                        // Annahme: Rollenname == benötigter Scope (z.B. "tokenize", "detokenize")
                        result.Add(r.GetString());
            }

            return result;
        }

        private async Task<RSA> GetKeyForKidAsync(string kid, CancellationToken ct = default(CancellationToken))
        {
            // Falls wir einen passenden Key im Cache haben und er nicht abgelaufen ist → verwenden
            if (!string.IsNullOrEmpty(kid) &&
                keysByKid.TryGetValue(kid, out var cached) &&
                DateTimeOffset.UtcNow < jwksExpiry)
                return cached;

            // 1) OIDC Discovery-Dokument laden (enthält u.a. jwks_uri)
            string disco = await http.GetStringAsync(discoveryUrl).ConfigureAwait(false);
            string jwksUri = JsonDocument.Parse(disco).RootElement.GetProperty("jwks_uri").GetString();

            // 2) JWKS abrufen und alle RSA-Schlüssel in Map legen
            string jwks = await http.GetStringAsync(jwksUri).ConfigureAwait(false);
            var keys = JsonDocument.Parse(jwks).RootElement.GetProperty("keys");

            var map = new Dictionary<string, RSA>(StringComparer.Ordinal);
            foreach (var k in keys.EnumerateArray())
            {
                if (k.TryGetProperty("kty", out var kty) && kty.GetString() == "RSA")
                {
                    // Modulus (n) und Exponent (e) base64url-dekodieren
                    var n = FromB64Url(k.GetProperty("n").GetString());
                    var e = FromB64Url(k.GetProperty("e").GetString());
                    var rp = new RSAParameters { Modulus = n, Exponent = e };
                    var r = RSA.Create();
                    r.ImportParameters(rp);
                    string kkid = k.TryGetProperty("kid", out var kidEl) ? kidEl.GetString() : "";
                    map[kkid ?? ""] = r;
                }
            }

            // Cache ersetzen und Ablauf setzen
            keysByKid = map;
            jwksExpiry = DateTimeOffset.UtcNow.Add(jwksTtl);

            // Bevorzugt: exaktes kid gefunden?
            if (!string.IsNullOrEmpty(kid) && keysByKid.TryGetValue(kid, out var rsa))
                return rsa;

            // Fallback: Wenn kein kid im Token, aber exakt ein Schlüssel vorhanden → diesen nehmen
            if (string.IsNullOrEmpty(kid) && keysByKid.Count == 1)
                return keysByKid.Values.First();

            // Andernfalls: keinen passenden Signierschlüssel gefunden
            throw new RpcException(new Status(StatusCode.Unauthenticated, "Signing key not found"));
        }

        // ---- Base64URL-Helfer ----
        private static byte[] FromB64Url(string s)
        {
            // Wandelt Base64URL (RFC 7515) in reguläres Base64 um und dekodiert
            if (string.IsNullOrEmpty(s)) return Array.Empty<byte>();
            var p = s.Replace('-', '+').Replace('_', '/');
            switch (p.Length % 4) { case 2: p += "=="; break; case 3: p += "="; break; }
            return Convert.FromBase64String(p);
        }

        private static byte[] FromB64UrlRaw(string s) => FromB64Url(s);
    }
}
