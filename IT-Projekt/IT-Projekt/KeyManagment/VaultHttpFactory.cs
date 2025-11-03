using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace IT_Projekt.KeyManagment
{
    /// <summary>
    /// Hilfsklasse für den Zugriff auf Vault KV v2 über <see cref="HttpClient"/>.
    /// Stellt Methoden bereit, um Secrets zu erzeugen, auszulesen und zu löschen,
    /// sowie Hilfsfunktionen zum Bauen der richtigen API-Pfade.
    /// </summary>
    public class VaultHttpFactory
    {
        /// <summary>
        /// Schreibt ein Secret in Vault (KV v2) an den angegebenen <paramref name="dataPath"/>.
        /// </summary>
        /// <param name="client">Vorbereiteter <see cref="HttpClient"/> mit BaseAddress und X-Vault-Token.</param>
        /// <param name="dataPath">Pfad zu <c>/v1/&lt;mount&gt;/data/... </c></param>
        /// <param name="valueB64">Der zu speichernde Wert (Base64-kodiert).</param>
        /// <param name="ct">Optionaler CancellationToken.</param>
        /// <remarks>
        /// Es wird ein JSON-Dokument der Form <c>{ "data": { "k": "&lt;b64&gt;" } }</c> an Vault gesendet.
        /// </remarks>
        public static async Task CreateAsync(HttpClient client, string dataPath, string valueB64, CancellationToken ct = default)
        {
            var writeDoc  = new { data = new { k = valueB64 } };
            var writeJson = JsonSerializer.Serialize(writeDoc);
            var content   = new StringContent(writeJson, Encoding.UTF8, "application/json");

            var resp = await client.PostAsync(dataPath, content, ct);
            resp.EnsureSuccessStatusCode();
        }

        /// <summary>
        /// Liest ein Secret von Vault (KV v2) am angegebenen <paramref name="dataPath"/>.
        /// </summary>
        /// <param name="client">Vorbereiteter <see cref="HttpClient"/>.</param>
        /// <param name="dataPath">Pfad zu <c>/v1/&lt;mount&gt;/data/... </c></param>
        /// <param name="ct">Optionaler CancellationToken.</param>
        /// <returns>Den gespeicherten Base64-kodierten Wert.</returns>
        /// <exception cref="HttpRequestException">Wenn der Request fehlschlägt.</exception>
        public static async Task<string> ReadAsync(HttpClient client, string dataPath, CancellationToken ct = default)
        {
            var resp = await client.GetAsync(dataPath, ct);
            resp.EnsureSuccessStatusCode();

            var readJson = await resp.Content.ReadAsStringAsync();
            var doc = JsonDocument.Parse(readJson);

            // Vault-KV v2: data → data → k
            return doc.RootElement.GetProperty("data").GetProperty("data").GetProperty("k").GetString();
        }

        /// <summary>
        /// Löscht ein Secret in Vault (KV v2) vollständig.
        /// </summary>
        /// <param name="client">Vorbereiteter <see cref="HttpClient"/>.</param>
        /// <param name="metadataPath">Pfad zu <c>/v1/&lt;mount&gt;/metadata/... </c> (delete-all Endpoint).</param>
        /// <param name="dataPath">Pfad zu <c>/v1/&lt;mount&gt;/data/... </c> (wird nach Löschung überprüft).</param>
        /// <param name="ct">Optionaler CancellationToken.</param>
        /// <exception cref="HttpRequestException">Wenn das Secret nach der Löschung noch existiert.</exception>
        public static async Task DeleteAsync(HttpClient client, string metadataPath, string dataPath, CancellationToken ct = default)
        {
            // KV v2: vollständige Löschung über metadata-Endpoint
            var del = await client.DeleteAsync(metadataPath, ct);
            del.EnsureSuccessStatusCode();

            // Verifizieren: erneuter GET muss 404 zurückgeben
            var readAgain = await client.GetAsync(dataPath, ct);
            if (readAgain.StatusCode != HttpStatusCode.NotFound)
                throw new HttpRequestException($"Secret still present after delete: {readAgain.StatusCode}");
        }

        /// <summary>
        /// Baut den Vault-Datenpfad (KV v2) für ein Secret unterhalb von <c>tokenization/keys</c>.
        /// </summary>
        /// <param name="tenant">Tenant-ID.</param>
        /// <param name="keyId">Key-ID.</param>
        /// <param name="mount">Vault-KV-Mount-Name (z. B. "kv").</param>
        /// <returns>Pfad der Form <c>/v1/&lt;mount&gt;/data/tokenization/keys/&lt;tenant&gt;/&lt;keyId&gt;</c>.</returns>
        public static string BuildDataPath(string tenant, string keyId, string mount)
        {
            var secretPath = $"tokenization/keys/{tenant}/{keyId}";
            return $"/v1/{mount}/data/{secretPath}";
        }

        /// <summary>
        /// Baut den Vault-Metadatenpfad (KV v2) für ein Secret unterhalb von <c>tokenization/keys</c>.
        /// </summary>
        /// <param name="tenant">Tenant-ID.</param>
        /// <param name="keyId">Key-ID.</param>
        /// <param name="mount">Vault-KV-Mount-Name.</param>
        /// <returns>Pfad der Form <c>/v1/&lt;mount&gt;/metadata/tokenization/keys/&lt;tenant&gt;/&lt;keyId&gt;</c>.</returns>
        public static string BuildMetadataPath(string tenant, string keyId, string mount)
        {
            var secretPath = $"tokenization/keys/{tenant}/{keyId}";
            return $"/v1/{mount}/metadata/{secretPath}";
        }
    }
}
