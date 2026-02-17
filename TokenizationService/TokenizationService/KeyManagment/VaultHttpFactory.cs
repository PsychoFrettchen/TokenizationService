using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace TokenizationService.KeyManagment
{
    /// <summary>
    ///     Helper class for accessing Vault KV v2 via <see cref="HttpClient" />.
    ///     Provides methods to create, read, and delete secrets,
    ///     as well as helper functions for building the correct API paths.
    /// </summary>
    public class VaultHttpFactory
    {
        /// <summary>
        ///     Writes a secret to Vault (KV v2) at the specified <paramref name="dataPath" />.
        /// </summary>
        /// <param name="client">Prepared <see cref="HttpClient" /> with BaseAddress and X-Vault-Token.</param>
        /// <param name="dataPath">Path to <c>/v1/&lt;mount&gt;/data/... </c></param>
        /// <param name="valueB64">The value to store (Base64-encoded).</param>
        /// <param name="ct">Optional CancellationToken.</param>
        /// <remarks>
        ///     A JSON document of the form <c>{ "data": { "k": "&lt;b64&gt;" } }</c> is sent to Vault.
        /// </remarks>
        public static async Task CreateAsync(HttpClient client, string dataPath, string valueB64,
            CancellationToken ct = default)
        {
            var writeDoc = new { data = new { k = valueB64 } };
            var writeJson = JsonSerializer.Serialize(writeDoc);
            var content = new StringContent(writeJson, Encoding.UTF8, "application/json");

            var resp = await client.PostAsync(dataPath, content, ct);
            resp.EnsureSuccessStatusCode();
        }

        /// <summary>
        ///     Reads a secret from Vault (KV v2) at the specified <paramref name="dataPath" />.
        /// </summary>
        /// <param name="client">Prepared <see cref="HttpClient" />.</param>
        /// <param name="dataPath">Path to <c>/v1/&lt;mount&gt;/data/... </c></param>
        /// <param name="ct">Optional CancellationToken.</param>
        /// <returns>The stored Base64-encoded value.</returns>
        /// <exception cref="HttpRequestException">If the request fails.</exception>
        public static async Task<string> ReadAsync(HttpClient client, string dataPath, CancellationToken ct = default)
        {
            var resp = await client.GetAsync(dataPath, ct);
            resp.EnsureSuccessStatusCode();

            var readJson = await resp.Content.ReadAsStringAsync();
            var doc = JsonDocument.Parse(readJson);

            // Vault KV v2: data → data → k
            return doc.RootElement
                .GetProperty("data")
                .GetProperty("data")
                .GetProperty("k")
                .GetString();
        }

        /// <summary>
        ///     Deletes a secret in Vault (KV v2) completely.
        /// </summary>
        /// <param name="client">Prepared <see cref="HttpClient" />.</param>
        /// <param name="metadataPath">Path to <c>/v1/&lt;mount&gt;/metadata/... </c> (delete-all endpoint).</param>
        /// <param name="dataPath">Path to <c>/v1/&lt;mount&gt;/data/... </c> (verified after deletion).</param>
        /// <param name="ct">Optional CancellationToken.</param>
        /// <exception cref="HttpRequestException">
        ///     Thrown if the secret still exists after deletion.
        /// </exception>
        public static async Task DeleteAsync(HttpClient client, string metadataPath, string dataPath,
            CancellationToken ct = default)
        {
            // KV v2: full deletion via metadata endpoint
            var del = await client.DeleteAsync(metadataPath, ct);
            del.EnsureSuccessStatusCode();

            // Verify: subsequent GET must return 404
            var readAgain = await client.GetAsync(dataPath, ct);
            if (readAgain.StatusCode != HttpStatusCode.NotFound)
                throw new HttpRequestException($"Secret still present after delete: {readAgain.StatusCode}");
        }

        /// <summary>
        ///     Builds the Vault data path (KV v2) for a secret under <c>tokenization/keys</c>.
        /// </summary>
        /// <param name="tenant">Tenant ID.</param>
        /// <param name="keyId">Key ID.</param>
        /// <param name="mount">Vault KV mount name (e.g., "kv").</param>
        /// <returns>
        ///     Path in the form <c>/v1/&lt;mount&gt;/data/tokenization/keys/&lt;tenant&gt;/&lt;keyId&gt;</c>.
        /// </returns>
        public static string BuildDataPath(string tenant, string keyId, string mount)
        {
            var secretPath = $"tokenization/keys/{tenant}/{keyId}";
            return $"/v1/{mount}/data/{secretPath}";
        }

        /// <summary>
        ///     Builds the Vault metadata path (KV v2) for a secret under <c>tokenization/keys</c>.
        /// </summary>
        /// <param name="tenant">Tenant ID.</param>
        /// <param name="keyId">Key ID.</param>
        /// <param name="mount">Vault KV mount name.</param>
        /// <returns>
        ///     Path in the form <c>/v1/&lt;mount&gt;/metadata/tokenization/keys/&lt;tenant&gt;/&lt;keyId&gt;</c>.
        /// </returns>
        public static string BuildMetadataPath(string tenant, string keyId, string mount)
        {
            var secretPath = $"tokenization/keys/{tenant}/{keyId}";
            return $"/v1/{mount}/metadata/{secretPath}";
        }
    }
}