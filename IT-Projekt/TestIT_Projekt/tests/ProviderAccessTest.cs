using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IT_Projekt.KeyManagment;

namespace TestIT_Projekt;

/// <summary>
/// Integrationstest für Vault-Zugriff über mTLS.
/// Verifiziert, dass man mit einem Client-Zertifikat einen Key in Vault
/// schreiben, lesen und anschließend wieder löschen kann.
/// </summary>
public class ProviderAccessTest
{
    /// <summary>
    /// Hilfsfunktion, um Dateipfade relativ zum Testverzeichnis aufzulösen.
    /// </summary>
    private static string P(string rel) =>
        Path.Combine(AppContext.BaseDirectory, rel.Replace('/', Path.DirectorySeparatorChar));

    [Fact]
    public async Task Write_Read_Delete_Key_Over_mTLS()
    {
        // ---------- Trust Anchor (Server-CA) laden ----------
        var serverCaPem = await File.ReadAllTextAsync(P("tests/Certs/ca.pem"));
        var serverCa = X509Certificate2.CreateFromPem(serverCaPem);
        var anchors = new X509Certificate2Collection { serverCa };

        // ---------- Client-Zertifikat für mTLS laden ----------
        var flags =
            OperatingSystem.IsWindows()
                ? X509KeyStorageFlags.MachineKeySet   // or UserKeySet for non-service apps
                  | X509KeyStorageFlags.PersistKeySet
                  | X509KeyStorageFlags.Exportable
                : X509KeyStorageFlags.EphemeralKeySet // fine on Linux/macOS
                  | X509KeyStorageFlags.Exportable;

        var client = new X509Certificate2("tests/Certs/client.p12", "changeit", flags);


        // ---------- HttpClient mit mTLS gegen Vault bauen ----------
        var http = IT_Projekt.Factory.HttpClientFactory.Build(
            trustAnchors: anchors,
            protocols: SslProtocols.Tls12 | SslProtocols.Tls13,
            clientCertificate: client);

        http.BaseAddress = new Uri("https://127.0.0.1:8200");
        http.DefaultRequestHeaders.Add("X-Vault-Token",
            Environment.GetEnvironmentVariable("VAULT_TOKEN") 
            ?? "hvs.pb8h7f1TX7vDEMmLnbkpq9CA"); // Default-Token für Tests

        // ---------- Testdaten vorbereiten ----------
        string mount = "kv";
        string tenant = "devtenant";
        string keyId = "k-unit-" + Guid.NewGuid().ToString("N")[..8]; // zufällige ID

        // Pfade für Vault KV v2 (Daten + Metadaten)
        var dataPath = VaultHttpFactory.BuildDataPath(tenant, keyId, mount);
        var metadataPath = VaultHttpFactory.BuildMetadataPath(tenant, keyId, mount);

        // Testwert (Base64-kodiert)
        var valueB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("hello-vault-" + keyId));

        // ---------- WRITE ----------
        // Speichert den Schlüssel unter dem Datenpfad in Vault
        await VaultHttpFactory.CreateAsync(http, dataPath, valueB64);

        // ---------- READ ----------
        // Liest den Wert zurück und prüft, dass er identisch ist
        var got = await VaultHttpFactory.ReadAsync(http, dataPath);
        Assert.Equal(valueB64, got);

        // ---------- DELETE ----------
        // Löscht den Eintrag über den Metadata-Endpunkt
        // und prüft, dass ein anschließender Read 404 liefert
        await VaultHttpFactory.DeleteAsync(http, metadataPath, dataPath);
    }
}
