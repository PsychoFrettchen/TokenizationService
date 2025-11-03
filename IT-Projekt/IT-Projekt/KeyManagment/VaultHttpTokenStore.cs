using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using em.Tokenization.V1;
using IT_Projekt.CryptoImpl;

namespace IT_Projekt.KeyManagement
{
    /// <summary>
    /// Vault KV v2-basierter Token-Store (Detokenization-Store).
    /// 
    /// Jeder Token wird im Vault unter einem Hash-Pfad gespeichert:
    ///   <c>/v1/{mount}/data/tokenization/tokens/{h2}/{h64}</c>
    ///   
    /// Dabei ist:
    /// - <c>h64</c> = SHA-256(token) in Hex (64 Zeichen)
    /// - <c>h2</c> = die ersten 2 Zeichen (Shard-Verzeichnis, verteilt Last)
    /// 
    /// Dadurch können Tokens anhand ihres Hashes deterministisch gespeichert und wiedergefunden werden.
    /// </summary>
    public sealed class VaultHttpTokenStore : ITokenStore, IDisposable
    {
        private readonly HttpClient _http;
        private readonly string _mount;

        /// <summary>
        /// Erstellt einen neuen TokenStore für einen Vault-KV-Mount.
        /// </summary>
        /// <param name="http">Ein vorbereiteter <see cref="HttpClient"/> (mit BaseAddress + X-Vault-Token).</param>
        /// <param name="kvMount">Name des KV-Mounts (Standard: "kv").</param>
        public VaultHttpTokenStore(HttpClient http, string kvMount = "kv")
        {
            _http   = http ?? throw new ArgumentNullException(nameof(http));
            _mount  = string.IsNullOrWhiteSpace(kvMount) ? "kv" : kvMount.Trim('/');
        }

        /// <summary>
        /// Gibt den verwendeten <see cref="HttpClient"/> frei.
        /// </summary>
        public void Dispose() => _http?.Dispose();

        /// <summary>
        /// Speichert einen Token-Record in Vault.
        /// Falls der Schlüssel bereits existiert, wird er überschrieben.
        /// </summary>
        /// <param name="record">Der zu speichernde TokenRecord (darf nicht null sein).</param>
        /// <exception cref="ArgumentNullException">Wenn <paramref name="record"/> null ist.</exception>
        /// <exception cref="HttpRequestException">Wenn die Vault-Operation fehlschlägt.</exception>
        public void Save(TokenRecord record)
        {
            if (record == null) throw new ArgumentNullException(nameof(record));
            var h = Crypto.Sha256Hex(record.Token ?? "");
            var dataPath = BuildDataPath(h);

            var doc = new
            {
                data = new
                {
                    token      = record.Token ?? "",
                    tenantId   = record.TenantId ?? "",
                    field      = record.Field ?? "",
                    plaintext  = record.Plaintext ?? "",
                    type       = (int)record.Type,
                    keyId      = record.KeyId ?? "",
                    dataClass  = (int)record.DataClass,
                    attributes = record.Attributes ?? new System.Collections.Generic.Dictionary<string, string>()
                }
            };

            var json    = JsonSerializer.Serialize(doc);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var resp    = _http.PostAsync(dataPath, content).GetAwaiter().GetResult();
            resp.EnsureSuccessStatusCode();
        }

        /// <summary>
        /// Versucht, einen gespeicherten Token aus Vault zu laden.
        /// </summary>
        /// <param name="token">Der zu suchende Token.</param>
        /// <param name="record">Ausgelesener TokenRecord (oder null, wenn nicht vorhanden).</param>
        /// <returns><c>true</c>, wenn der Token gefunden wurde, andernfalls <c>false</c>.</returns>
        /// <exception cref="HttpRequestException">Wenn die Vault-Abfrage fehlschlägt.</exception>
        public bool TryGet(string token, out TokenRecord record)
        {
            record = null;
            if (string.IsNullOrEmpty(token)) return false;

            var h        = Crypto.Sha256Hex(token);
            var dataPath = BuildDataPath(h);

            var resp = _http.GetAsync(dataPath).GetAwaiter().GetResult();
            if (resp.StatusCode == HttpStatusCode.NotFound) return false;
            resp.EnsureSuccessStatusCode();

            var json = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            var doc  = JsonDocument.Parse(json);
            var data = doc.RootElement.GetProperty("data").GetProperty("data");

            // Sanity-Check: gespeicherter Token muss zur Hash-Basis passen
            var tok = data.GetProperty("token").GetString();
            if (!string.Equals(tok, token, StringComparison.Ordinal)) return false;

            record = new TokenRecord
            {
                Token      = tok,
                TenantId   = data.GetProperty("tenantId").GetString(),
                Field      = data.GetProperty("field").GetString(),
                Plaintext  = data.GetProperty("plaintext").GetString(),
                Type       = (TokenType)data.GetProperty("type").GetInt32(),
                KeyId      = data.GetProperty("keyId").GetString(),
                DataClass  = (DataClass)data.GetProperty("dataClass").GetInt32(),
                Attributes = JsonToDict(data.TryGetProperty("attributes", out var attrs) ? attrs : default(JsonElement?))
            };
            return true;
        }

        /// <summary>
        /// Löscht einen gespeicherten Token vollständig aus Vault.
        /// </summary>
        /// <param name="token">Der zu löschende Token.</param>
        /// <remarks>
        /// Führt ein Delete auf den <c>metadata/</c>-Pfad aus, sodass auch alte Versionen entfernt werden.
        /// </remarks>
        /// <exception cref="HttpRequestException">Wenn das Löschen fehlschlägt.</exception>
        public void Delete(string token)
        {
            if (string.IsNullOrEmpty(token)) return;
            var h        = Crypto.Sha256Hex(token);
            var metaPath = BuildMetadataPath(h);

            var resp = _http.DeleteAsync(metaPath).GetAwaiter().GetResult();
            if (resp.StatusCode != HttpStatusCode.NotFound)
                resp.EnsureSuccessStatusCode();
        }

        // ---------- Private Pfad-Helfer (kein Tenant-Segment) ----------

        /// <summary>
        /// Baut den Data-Pfad (JSON enthält die eigentlichen Token-Daten).
        /// </summary>
        private string BuildDataPath(string tokenHashHex)
        {
            var shard      = tokenHashHex.Substring(0, 2); // Verzeichnis-Sharding
            var secretPath = $"tokenization/tokens/{shard}/{tokenHashHex}";
            return $"/v1/{_mount}/data/{secretPath}";
        }

        /// <summary>
        /// Baut den Metadata-Pfad (für Löschoperationen).
        /// </summary>
        private string BuildMetadataPath(string tokenHashHex)
        {
            var shard      = tokenHashHex.Substring(0, 2);
            var secretPath = $"tokenization/tokens/{shard}/{tokenHashHex}";
            return $"/v1/{_mount}/metadata/{secretPath}";
        }

        /// <summary>
        /// Hilfsmethode: wandelt ein JSON-Objekt in ein Dictionary um.
        /// </summary>
        private static System.Collections.Generic.Dictionary<string, string> JsonToDict(JsonElement? e)
        {
            var dict = new System.Collections.Generic.Dictionary<string, string>(StringComparer.Ordinal);
            if (e.HasValue && e.Value.ValueKind == JsonValueKind.Object)
            {
                foreach (var p in e.Value.EnumerateObject())
                    dict[p.Name] = p.Value.GetString();
            }
            return dict;
        }
    }
}
