using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using em.Tokenization.V1;
using TokenizationService.CryptoImpl;

namespace TokenizationService.KeyManagement
{
    /// <summary>
    ///     Vault KV v2-based token store (detokenization store).
    ///     Each token is stored in Vault under a hash-based path:
    ///     <c>/v1/{mount}/data/tokenization/tokens/{h2}/{h64}</c>
    ///     Where:
    ///     - <c>h64</c> = SHA-256(token) in hex (64 characters)
    ///     - <c>h2</c>  = the first 2 characters (shard directory, distributes load)
    ///     This allows tokens to be stored and retrieved deterministically by their hash.
    /// </summary>
    public sealed class VaultHttpTokenStore : ITokenStore, IDisposable
    {
        private readonly HttpClient _http;
        private readonly string _mount;

        /// <summary>
        ///     Creates a new TokenStore for a Vault KV mount.
        /// </summary>
        /// <param name="http">A prepared <see cref="HttpClient" /> (with BaseAddress + X-Vault-Token).</param>
        /// <param name="kvMount">Name of the KV mount (default: "kv").</param>
        public VaultHttpTokenStore(HttpClient http, string kvMount = "kv")
        {
            _http = http ?? throw new ArgumentNullException(nameof(http));
            _mount = string.IsNullOrWhiteSpace(kvMount) ? "kv" : kvMount.Trim('/');
        }

        /// <summary>
        ///     Releases the <see cref="HttpClient" /> used by this instance.
        /// </summary>
        public void Dispose()
        {
            _http?.Dispose();
        }

        /// <summary>
        ///     Stores a token record in Vault.
        ///     If the key already exists, it will be overwritten.
        /// </summary>
        /// <param name="record">The TokenRecord to store (must not be null).</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="record" /> is null.</exception>
        /// <exception cref="HttpRequestException">Thrown if the Vault operation fails.</exception>
        public void Save(TokenRecord record)
        {
            if (record == null) throw new ArgumentNullException(nameof(record));
            var h = Crypto.Sha256Hex(record.Token ?? "");
            var dataPath = BuildDataPath(h);

            var doc = new
            {
                data = new
                {
                    token = record.Token ?? "",
                    tenantId = record.TenantId ?? "",
                    field = record.Field ?? "",
                    plaintext = record.Plaintext ?? "",
                    type = (int)record.Type,
                    keyId = record.KeyId ?? "",
                    dataClass = (int)record.DataClass,
                    attributes = record.Attributes ?? new Dictionary<string, string>()
                }
            };

            var json = JsonSerializer.Serialize(doc);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var resp = _http.PostAsync(dataPath, content).GetAwaiter().GetResult();
            resp.EnsureSuccessStatusCode();
        }

        /// <summary>
        ///     Attempts to load a stored token record from Vault.
        /// </summary>
        /// <param name="token">The token to look up.</param>
        /// <param name="record">The retrieved TokenRecord (or null if not found).</param>
        /// <returns><c>true</c> if the token was found, otherwise <c>false</c>.</returns>
        /// <exception cref="HttpRequestException">Thrown if the Vault request fails.</exception>
        public bool TryGet(string token, out TokenRecord record)
        {
            record = null;
            if (string.IsNullOrEmpty(token)) return false;

            var h = Crypto.Sha256Hex(token);
            var dataPath = BuildDataPath(h);

            var resp = _http.GetAsync(dataPath).GetAwaiter().GetResult();
            if (resp.StatusCode == HttpStatusCode.NotFound) return false;
            resp.EnsureSuccessStatusCode();

            var json = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            var doc = JsonDocument.Parse(json);
            var data = doc.RootElement.GetProperty("data").GetProperty("data");

            // Sanity check: stored token must match the hash basis
            var tok = data.GetProperty("token").GetString();
            if (!string.Equals(tok, token, StringComparison.Ordinal)) return false;

            record = new TokenRecord
            {
                Token = tok,
                TenantId = data.GetProperty("tenantId").GetString(),
                Field = data.GetProperty("field").GetString(),
                Plaintext = data.GetProperty("plaintext").GetString(),
                Type = (TokenType)data.GetProperty("type").GetInt32(),
                KeyId = data.GetProperty("keyId").GetString(),
                DataClass = (DataClass)data.GetProperty("dataClass").GetInt32(),
                Attributes =
                    JsonToDict(data.TryGetProperty("attributes", out var attrs) ? attrs : default(JsonElement?))
            };
            return true;
        }

        /// <summary>
        ///     Deletes a stored token completely from Vault.
        /// </summary>
        /// <param name="token">The token to delete.</param>
        /// <remarks>
        ///     Performs a delete on the <c>metadata/</c> path so that old versions are removed as well.
        /// </remarks>
        /// <exception cref="HttpRequestException">Thrown if deletion fails.</exception>
        public void Delete(string token)
        {
            if (string.IsNullOrEmpty(token)) return;
            var h = Crypto.Sha256Hex(token);
            var metaPath = BuildMetadataPath(h);

            var resp = _http.DeleteAsync(metaPath).GetAwaiter().GetResult();
            if (resp.StatusCode != HttpStatusCode.NotFound)
                resp.EnsureSuccessStatusCode();
        }

        // ---------- Private path helpers (no tenant segment) ----------

        /// <summary>
        ///     Builds the data path (JSON contains the actual token data).
        /// </summary>
        private string BuildDataPath(string tokenHashHex)
        {
            var shard = tokenHashHex.Substring(0, 2); // directory sharding
            var secretPath = $"tokenization/tokens/{shard}/{tokenHashHex}";
            return $"/v1/{_mount}/data/{secretPath}";
        }

        /// <summary>
        ///     Builds the metadata path (used for delete operations).
        /// </summary>
        private string BuildMetadataPath(string tokenHashHex)
        {
            var shard = tokenHashHex.Substring(0, 2);
            var secretPath = $"tokenization/tokens/{shard}/{tokenHashHex}";
            return $"/v1/{_mount}/metadata/{secretPath}";
        }

        /// <summary>
        ///     Helper method: converts a JSON object into a dictionary.
        /// </summary>
        private static Dictionary<string, string> JsonToDict(JsonElement? e)
        {
            var dict = new Dictionary<string, string>(StringComparer.Ordinal);
            if (e.HasValue && e.Value.ValueKind == JsonValueKind.Object)
                foreach (var p in e.Value.EnumerateObject())
                    dict[p.Name] = p.Value.GetString();

            return dict;
        }
    }
}