using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TokenizationService.Factory;
using TokenizationService.KeyManagment;

namespace TokenizationService_Tests.tests;

/// <summary>
///     Integration test for Vault access via mTLS.
///     Verifies that using a client certificate, a key can be written to Vault,
///     read back, and then deleted again.
/// </summary>
public class ProviderAccessTest
{
    /// <summary>
    ///     Helper function to resolve file paths relative to the test directory.
    /// </summary>
    private static string P(string rel)
    {
        return Path.Combine(AppContext.BaseDirectory, rel.Replace('/', Path.DirectorySeparatorChar));
    }

    [Fact]
    public async Task Write_Read_Delete_Key_Over_mTLS()
    {
        // ---------- Load trust anchor (server CA) ----------
        var serverCaPem = await File.ReadAllTextAsync(P("tests/Certs/ca.pem"));
        var serverCa = X509Certificate2.CreateFromPem(serverCaPem);
        var anchors = new X509Certificate2Collection { serverCa };

        // ---------- Load client certificate for mTLS ----------
        var flags =
            OperatingSystem.IsWindows()
                ? X509KeyStorageFlags.MachineKeySet // or UserKeySet for non-service apps
                  | X509KeyStorageFlags.PersistKeySet
                  | X509KeyStorageFlags.Exportable
                : X509KeyStorageFlags.EphemeralKeySet // fine on Linux/macOS
                  | X509KeyStorageFlags.Exportable;

        var client = new X509Certificate2("tests/Certs/client.p12", "changeit", flags);

        // ---------- Build HttpClient with mTLS for Vault ----------
        var http = HttpClientFactory.Build(
            anchors,
            SslProtocols.Tls12 | SslProtocols.Tls13,
            client);

        http.BaseAddress = new Uri("https://127.0.0.1:8200");
        http.DefaultRequestHeaders.Add("X-Vault-Token",
            Environment.GetEnvironmentVariable("VAULT_TOKEN")
            ?? "hvs.pb8h7f1TX7vDEMmLnbkpq9CA"); // default token for tests

        // ---------- Prepare test data ----------
        var mount = "kv";
        var tenant = "devtenant";
        var keyId = "k-unit-" + Guid.NewGuid().ToString("N")[..8]; // random ID

        // Paths for Vault KV v2 (data + metadata)
        var dataPath = VaultHttpFactory.BuildDataPath(tenant, keyId, mount);
        var metadataPath = VaultHttpFactory.BuildMetadataPath(tenant, keyId, mount);

        // Test value (Base64-encoded)
        var valueB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("hello-vault-" + keyId));

        // ---------- WRITE ----------
        // Stores the key under the data path in Vault
        await VaultHttpFactory.CreateAsync(http, dataPath, valueB64);

        // ---------- READ ----------
        // Reads the value back and verifies it matches
        var got = await VaultHttpFactory.ReadAsync(http, dataPath);
        Assert.Equal(valueB64, got);

        // ---------- DELETE ----------
        // Deletes the entry via the metadata endpoint
        // and verifies that a subsequent read returns 404
        await VaultHttpFactory.DeleteAsync(http, metadataPath, dataPath);
    }
}