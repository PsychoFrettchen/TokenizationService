using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using em.Tokenization.V1;
using Google.Protobuf;
using IT_Projekt;
using IT_Projekt.CryptoImpl;
using IT_Projekt.KeyManagement;
using IT_Projekt.KeyManagment;

namespace TestIT_Projekt;

/// <summary>
/// Integrationstests für den TokenizationService mit Vault-gestütztem KeyProvider und TokenStore.
/// Es wird ein echter Vault (KV v2) sowie mTLS (Server- und Client-Zertifikate) verwendet.
/// </summary>
public class VaultBackedTokenizationTests
{
    /// <summary>
    /// Hilfsfunktion: Baut Pfade relativ zum Test-Verzeichnis.
    /// </summary>
    private static string P(string rel) =>
        Path.Combine(AppContext.BaseDirectory, rel.Replace('/', Path.DirectorySeparatorChar));

    /// <summary>
    /// Erstellt einen gRPC-Context für die Tokenization-Requests,
    /// mit Tenant-ID, Purpose und optionalem Tweak (ByteString).
    /// </summary>
    private static Context MakeCtx(byte[] tweak, string tenant = "devtenant") =>
        new Context
        {
            TenantId = tenant,
            Purpose  = "tests",
            Tweak    = ByteString.CopyFrom(tweak ?? Array.Empty<byte>())
        };

    /// <summary>
    /// Baut einen HttpClient, der per mTLS gegen Vault spricht:
    /// - Lädt das CA-Zertifikat (Servertrust)
    /// - Lädt das Clientzertifikat (PEM + Key → PFX)
    /// - Erstellt einen HttpClient mit diesen Parametern
    /// - Setzt X-Vault-Token im Header
    /// </summary>
    private static async Task<HttpClient> BuildVaultHttpClientAsync()
    {
        // ---- TLS Trust Anchor (CA des Servers) ----
        var serverCaPem = await File.ReadAllTextAsync(P("tests/Certs/ca.pem"));
        var serverCa    = X509Certificate2.CreateFromPem(serverCaPem);
        var anchors     = new X509Certificate2Collection { serverCa };

        // ---- Client-Zertifikat aus PEM + Key laden ----
        var flags =
            OperatingSystem.IsWindows()
                ? X509KeyStorageFlags.MachineKeySet   // or UserKeySet for non-service apps
                  | X509KeyStorageFlags.PersistKeySet
                  | X509KeyStorageFlags.Exportable
                : X509KeyStorageFlags.EphemeralKeySet // fine on Linux/macOS
                  | X509KeyStorageFlags.Exportable;

        var client = new X509Certificate2("tests/Certs/client.p12", "changeit", flags);

        // ---- HttpClient mit mTLS bauen ----
        var http = IT_Projekt.Factory.HttpClientFactory.Build(
            trustAnchors: anchors,
            protocols: SslProtocols.Tls12 | SslProtocols.Tls13,
            clientCertificate: client);

        // Vault-Adresse → Hostname/IP muss SAN des Serverzertifikats entsprechen
        http.BaseAddress = new Uri("https://127.0.0.1:8200");

        // Vault-Token aus Environment oder Fallback
        var token = Environment.GetEnvironmentVariable("VAULT_TOKEN") ?? "hvs.pb8h7f1TX7vDEMmLnbkpq9CA";
        http.DefaultRequestHeaders.Add("X-Vault-Token", token);

        return http;
    }

    /// <summary>
    /// Testet einen vollständigen Roundtrip mit FF1-FPE (Format Preserving Encryption) 
    /// unter Verwendung des Vault-gestützten KeyProviders.
    /// 
    /// Ablauf:
    ///  - Eine Kreditkartennummer (nur Ziffern) wird mit FPE tokenisiert.
    ///  - Der erzeugte Token wird überprüft (Präfix, Länge, Ziffern-Domäne).
    ///  - Anschließend wird detokenisiert und der ursprüngliche Plaintext erwartet.
    /// 
    /// Zweck:
    ///  - Sicherstellen, dass FPE mit Vault-Keys korrekt funktioniert
    ///    und die Format-Eigenschaften (nur Ziffern, Länge) erhalten bleiben.
    /// </summary>
    [Fact]
    public async Task FF1_Roundtrip_Digits_With_Vault_KeyProvider()
    {
        using var http = await BuildVaultHttpClientAsync();

        // Vault-basierter KeyProvider: Schlüssel liegen unter kv/data/tokenization/keys/<tenant>/<keyId>
        using var keys  = new VaultHttpKeyProvider(http, kvMount: "kv");

        // Vault-basierter TokenStore: speichert reversible Tokens (hier für Vollständigkeit)
        using var store = new VaultHttpTokenStore(http, "kv");

        // Reelle FF1-FPE-Engine (Format-preserving encryption)
        var fpe = new BcFpeEngine(BcFpeEngine.Mode.FF1);

        // Tokenization-Service mit Vault-Backends
        var svc = new TokenizationServiceImpl(keys, store, fpe);

        var pt    = "4111111111111111"; // 16-stellige Kreditkartennummer
        var tweak = Encoding.UTF8.GetBytes("order-42");

        // --- Tokenize ---
        var tok = await svc.Tokenize(new TokenizeRequest
        {
            TokenType = TokenType.Fpe,
            Context   = MakeCtx(tweak),
            Items     =
            {
                new FieldPayload
                {
                    Field = "credit_card",
                    Plaintext = pt,
                    DataClass = DataClass.CreditCard,
                    PreserveFormat = true
                }
            }
        }, null);

        Assert.Empty(tok.Errors);
        Assert.Single(tok.Items);

        var token = tok.Items[0].Token;
        Assert.StartsWith("v1.f.", token);

        // Das Payload-Teil des Tokens sollte nur Ziffern enthalten und die Länge behalten
        var payload = token.Split('.').Skip(3).First();
        Assert.True(payload.All(char.IsDigit));
        Assert.Equal(pt.Length, payload.Length);

        // --- Detokenize ---
        var det = await svc.Detokenize(new DetokenizeRequest
        {
            Context = MakeCtx(tweak),
            Items   = { new TokenizedField { Field = "credit_card", Token = token } }
        }, null);

        Assert.Empty(det.Errors);
        Assert.Single(det.Items);
        Assert.Equal(pt, det.Items[0].Plaintext);
    }
    
  
    /// <summary>
    /// Testet einen vollständigen Roundtrip mit RANDOM-Tokens unter Verwendung
    /// sowohl des Vault-KeyProviders als auch des Vault-TokenStores.
    /// 
    /// Ablauf:
    ///  - Ein Plaintext (E-Mail) wird als RANDOM-Token gespeichert.
    ///  - Der Token wird auf Präfix geprüft ("v1.r.").
    ///  - Anschließend wird der Token über den Vault-gestützten TokenStore 
    ///    detokenisiert und der ursprüngliche Plaintext erwartet.
    /// 
    /// Zweck:
    ///  - Sicherstellen, dass nicht-deterministische RANDOM-Tokens korrekt
    ///    persistiert und über Vault wieder aufgelöst werden können.
    /// </summary>
    [Fact]
    public async Task RANDOM_Roundtrip_With_Vault_KeyProvider_And_Vault_TokenStore()
    {
        using var http = await BuildVaultHttpClientAsync();

        // KeyProvider (Vault), auch wenn RANDOM den Key nicht direkt braucht
        using var keys = new VaultHttpKeyProvider(http, kvMount: "kv");

        // TokenStore (Vault), notwendig für spätere Detokenization von RANDOM
        using var store = new VaultHttpTokenStore(http, kvMount: "kv");

        // FPE-Engine (wird für RANDOM nicht genutzt, aber Service erwartet eine Instanz)
        var fpe = new BcFpeEngine(BcFpeEngine.Mode.FF1);

        // Service mit Option: speichere auch nicht-reversible Tokens (hier RANDOM)
        var svc = new TokenizationServiceImpl(keys, store, fpe, storeNonReversible: true);

        var pt    = "alice@example.com";
        var tweak = Encoding.UTF8.GetBytes("demo");

        // --- Tokenize ---
        var tok = await svc.Tokenize(new TokenizeRequest
        {
            TokenType = TokenType.Random,
            Context   = MakeCtx(tweak),
            Items     =
            {
                new FieldPayload
                {
                    Field = "email",
                    Plaintext = pt,
                    DataClass = DataClass.Email
                }
            }
        }, null);

        Assert.Empty(tok.Errors);
        Assert.Single(tok.Items);

        var token = tok.Items[0].Token;
        Assert.StartsWith("v1.r.", token);

        // --- Detokenize (holt Plaintext aus Vault Store) ---
        var det = await svc.Detokenize(new DetokenizeRequest
        {
            Context = MakeCtx(tweak),
            Items   = { new TokenizedField { Field = "email", Token = token } }
        }, null);

        Assert.Empty(det.Errors);
        Assert.Single(det.Items);
        Assert.Equal(pt, det.Items[0].Plaintext);
    }
}
