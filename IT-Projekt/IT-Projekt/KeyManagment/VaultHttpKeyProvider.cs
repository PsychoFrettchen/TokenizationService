using System;
using System.Net.Http;
using System.Text;
using IT_Projekt.Provider;

namespace IT_Projekt.KeyManagment
{
    /// <summary>
    /// Implementiert einen <see cref="IKeyProvider"/> für Vault KV v2 über HTTP.
    /// 
    /// Diese Klasse verwaltet symmetrische Schlüssel (AES-256, 32 Bytes),
    /// die für Tenants in Vault gespeichert und abgerufen werden.
    /// 
    /// - Schlüssel werden im Pfad <c>tokenization/keys/&lt;tenant&gt;/&lt;keyId&gt;</c> gespeichert.
    /// - Die aktive Key-ID eines Tenants wird unter <c>tokenization/meta/&lt;tenant&gt;</c> abgelegt.
    /// 
    /// unterstützt:
    /// - Abrufen existierender Schlüssel oder Erzeugen neuer (on-demand).
    /// - Rotation: Setzen einer neuen aktiven Key-ID.
    /// - Lesen der aktiven Key-ID.
    /// </summary>
    public sealed class VaultHttpKeyProvider : IKeyProvider, IDisposable
    {
        private readonly HttpClient _http;
        private readonly string _mount;
        private readonly string _keyRoot = "tokenization/keys";
        private readonly string _metaRoot = "tokenization/meta";

        /// <summary>
        /// Erstellt einen neuen Provider mit einem gegebenen <paramref name="http"/> und dem KV-Mount.
        /// </summary>
        /// <param name="http">Ein vorbereiteter <see cref="HttpClient"/> mit BaseAddress und X-Vault-Token.</param>
        /// <param name="kvMount">Name des KV-Mounts (z. B. "kv").</param>
        public VaultHttpKeyProvider(HttpClient http, string kvMount)
        {
            _http   = http ?? throw new ArgumentNullException(nameof(http));
            _mount  = (kvMount ?? "kv").Trim('/');
        }

        /// <summary>
        /// Optionaler Dispose (wird nur genutzt, wenn die Instanz den HttpClient verwaltet).
        /// </summary>
        public void Dispose() { /* Optionally dispose if you own http */ }

        /// <summary>
        /// Holt den Schlüssel (32 Bytes) für einen Tenant und eine Key-ID.
        /// Existiert noch keiner, wird ein neuer generiert und in Vault geschrieben.
        /// </summary>
        /// <param name="tenantId">Tenant-Id (darf null sein, dann "").</param>
        /// <param name="keyId">Key-ID (darf null sein, dann "default").</param>
        /// <returns>32-Byte Schlüsselmaterial.</returns>
        public byte[] GetKey(string tenantId, string keyId)
        {
            tenantId = tenantId ?? "";
            keyId    = keyId ?? "default";
            var path = $"/v1/{_mount}/data/{_keyRoot}/{Escape(tenantId)}/{Escape(keyId)}";

            // 1) Versuchen zu lesen
            var read = _http.GetAsync(path).GetAwaiter().GetResult();
            if (read.IsSuccessStatusCode)
            {
                var json = read.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                using (var doc = System.Text.Json.JsonDocument.Parse(json))
                {
                    var b64 = doc.RootElement.GetProperty("data").GetProperty("data").GetProperty("k").GetString();
                    if (!string.IsNullOrEmpty(b64))
                        return Convert.FromBase64String(b64);
                }
            }

            // 2) Falls nicht vorhanden → neuen 32B Schlüssel erzeugen und speichern
            var key = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                rng.GetBytes(key);

            var payload = new
            {
                data = new { k = Convert.ToBase64String(key) },
                options = new { cas = 0 } // create-if-not-exists
            };
            var body = new StringContent(System.Text.Json.JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

            var write = _http.PostAsync(path, body).GetAwaiter().GetResult();
            if (!write.IsSuccessStatusCode)
            {
                // Race: jemand anderes hat den Schlüssel gerade erzeugt → nochmal lesen
                var read2 = _http.GetAsync(path).GetAwaiter().GetResult();
                read2.EnsureSuccessStatusCode();
                var json2 = read2.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                using (var doc2 = System.Text.Json.JsonDocument.Parse(json2))
                {
                    var b642 = doc2.RootElement.GetProperty("data").GetProperty("data").GetProperty("k").GetString();
                    return Convert.FromBase64String(b642);
                }
            }
            return key;
        }

        /// <summary>
        /// Setzt eine neue aktive Key-ID für den angegebenen Tenant.
        /// </summary>
        /// <param name="tenantId">Tenant-Id (darf null sein).</param>
        /// <param name="newKeyId">Neue Key-ID (darf null sein → "default").</param>
        public void Rotate(string tenantId, string newKeyId)
        {
            SetActiveKeyId(tenantId ?? "", newKeyId ?? "default");
        }

        /// <summary>
        /// Gibt die aktuell aktive Key-ID für einen Tenant zurück.
        /// </summary>
        /// <param name="tenantId">Tenant-Id (darf null sein).</param>
        /// <returns>
        /// Die aktive Key-ID oder <c>"default"</c>, wenn kein Eintrag in Vault existiert.
        /// </returns>
        public string GetActiveKeyId(string tenantId)
        {
            tenantId = tenantId ?? "";
            var path = $"/v1/{_mount}/data/{_metaRoot}/{Escape(tenantId)}";
            var resp = _http.GetAsync(path).GetAwaiter().GetResult();
            if (!resp.IsSuccessStatusCode) return "default";

            var json = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            using (var doc = System.Text.Json.JsonDocument.Parse(json))
            {
                var kid = doc.RootElement.GetProperty("data").GetProperty("data").GetProperty("active").GetString();
                return string.IsNullOrEmpty(kid) ? "default" : kid;
            }
        }

        /// <summary>
        /// Schreibt die aktive Key-ID für einen Tenant in Vault.
        /// </summary>
        private void SetActiveKeyId(string tenantId, string keyId)
        {
            var path = $"/v1/{_mount}/data/{_metaRoot}/{Escape(tenantId)}";
            var payload = new { data = new { active = keyId } };
            var body = new StringContent(System.Text.Json.JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

            var write = _http.PostAsync(path, body).GetAwaiter().GetResult();
            write.EnsureSuccessStatusCode();
        }

        /// <summary>
        /// Hilfsmethode: ersetzt "/" durch "_" für Vault-kompatible Schlüsselpfade.
        /// </summary>
        private static string Escape(string s) => (s ?? "").Replace("/", "_");
    }
}
