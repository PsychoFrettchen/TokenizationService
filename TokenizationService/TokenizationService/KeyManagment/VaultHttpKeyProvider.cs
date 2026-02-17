using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TokenizationService.Provider;

namespace TokenizationService.KeyManagment
{
    /// <summary>
    ///     Implements an <see cref="IKeyProvider" /> for Vault KV v2 over HTTP.
    ///     This class manages symmetric keys (AES-256, 32 bytes)
    ///     that are stored and retrieved per tenant in Vault.
    ///     - Keys are stored under <c>tokenization/keys/&lt;tenant&gt;/&lt;keyId&gt;</c>.
    ///     - The active key ID for a tenant is stored under <c>tokenization/meta/&lt;tenant&gt;</c>.
    ///     Supports:
    ///     - Fetching existing keys or creating new ones on demand.
    ///     - Rotation: setting a new active key ID.
    ///     - Reading the active key ID.
    /// </summary>
    public sealed class VaultHttpKeyProvider : IKeyProvider, IDisposable
    {
        private readonly HttpClient _http;
        private readonly string _keyRoot = "tokenization/keys";
        private readonly string _metaRoot = "tokenization/meta";
        private readonly string _mount;

        /// <summary>
        ///     Creates a new provider using the given <paramref name="http" /> and KV mount.
        /// </summary>
        /// <param name="http">A prepared <see cref="HttpClient" /> with BaseAddress and X-Vault-Token.</param>
        /// <param name="kvMount">Name of the KV mount (e.g., "kv").</param>
        public VaultHttpKeyProvider(HttpClient http, string kvMount)
        {
            _http = http ?? throw new ArgumentNullException(nameof(http));
            _mount = (kvMount ?? "kv").Trim('/');
        }

        /// <summary>
        ///     Optional Dispose (only used if this instance owns the HttpClient).
        /// </summary>
        public void Dispose()
        {
            /* Optionally dispose if you own http */
        }

        /// <summary>
        ///     Retrieves the key (32 bytes) for a tenant and key ID.
        ///     If it does not exist yet, a new one is generated and written to Vault.
        /// </summary>
        /// <param name="tenantId">Tenant ID (may be null, then "").</param>
        /// <param name="keyId">Key ID (may be null, then "default").</param>
        /// <returns>32-byte key material.</returns>
        public byte[] GetKey(string tenantId, string keyId)
        {
            tenantId = tenantId ?? "";
            keyId = keyId ?? "default";
            var path = $"/v1/{_mount}/data/{_keyRoot}/{Escape(tenantId)}/{Escape(keyId)}";

            // 1) Try to read
            var read = _http.GetAsync(path).GetAwaiter().GetResult();
            if (read.IsSuccessStatusCode)
            {
                var json = read.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                using (var doc = JsonDocument.Parse(json))
                {
                    var b64 = doc.RootElement.GetProperty("data").GetProperty("data").GetProperty("k").GetString();
                    if (!string.IsNullOrEmpty(b64))
                        return Convert.FromBase64String(b64);
                }
            }

            // 2) If not present → generate new 32B key and store it
            var key = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }

            var payload = new
            {
                data = new { k = Convert.ToBase64String(key) },
                options = new { cas = 0 } // create-if-not-exists
            };
            var body = new StringContent(
                JsonSerializer.Serialize(payload),
                Encoding.UTF8,
                "application/json");

            var write = _http.PostAsync(path, body).GetAwaiter().GetResult();
            if (!write.IsSuccessStatusCode)
            {
                // Race: someone else just created the key → read again
                var read2 = _http.GetAsync(path).GetAwaiter().GetResult();
                read2.EnsureSuccessStatusCode();
                var json2 = read2.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                using (var doc2 = JsonDocument.Parse(json2))
                {
                    var b642 = doc2.RootElement.GetProperty("data").GetProperty("data").GetProperty("k").GetString();
                    return Convert.FromBase64String(b642);
                }
            }

            return key;
        }

        /// <summary>
        ///     Sets a new active key ID for the specified tenant.
        /// </summary>
        /// <param name="tenantId">Tenant ID (may be null).</param>
        /// <param name="newKeyId">New key ID (may be null → "default").</param>
        public void Rotate(string tenantId, string newKeyId)
        {
            SetActiveKeyId(tenantId ?? "", newKeyId ?? "default");
        }

        /// <summary>
        ///     Returns the currently active key ID for a tenant.
        /// </summary>
        /// <param name="tenantId">Tenant ID (may be null).</param>
        /// <returns>
        ///     The active key ID, or <c>"default"</c> if no entry exists in Vault.
        /// </returns>
        public string GetActiveKeyId(string tenantId)
        {
            tenantId = tenantId ?? "";
            var path = $"/v1/{_mount}/data/{_metaRoot}/{Escape(tenantId)}";
            var resp = _http.GetAsync(path).GetAwaiter().GetResult();
            if (!resp.IsSuccessStatusCode) return "default";

            var json = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            using (var doc = JsonDocument.Parse(json))
            {
                var kid = doc.RootElement.GetProperty("data").GetProperty("data").GetProperty("active").GetString();
                return string.IsNullOrEmpty(kid) ? "default" : kid;
            }
        }

        /// <summary>
        ///     Writes the active key ID for a tenant to Vault.
        /// </summary>
        private void SetActiveKeyId(string tenantId, string keyId)
        {
            var path = $"/v1/{_mount}/data/{_metaRoot}/{Escape(tenantId)}";
            var payload = new { data = new { active = keyId } };
            var body = new StringContent(
                JsonSerializer.Serialize(payload),
                Encoding.UTF8,
                "application/json");

            var write = _http.PostAsync(path, body).GetAwaiter().GetResult();
            write.EnsureSuccessStatusCode();
        }

        /// <summary>
        ///     Helper method: replaces "/" with "_" for Vault-compatible secret paths.
        /// </summary>
        private static string Escape(string s)
        {
            return (s ?? "").Replace("/", "_");
        }
    }
}