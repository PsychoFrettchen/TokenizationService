using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using em.Tokenization.V1;
using Google.Protobuf;
using TokenizationService.CryptoImpl;
using TokenizationService.Factory;
using TokenizationService.KeyManagement;
using TokenizationService.KeyManagment;
using TokenizationService.Tokenization;

namespace TokenizationService_Tests.tests;

/// <summary>
///     Integration tests for the TokenizationService using a Vault-backed KeyProvider and TokenStore.
///     A real Vault (KV v2) as well as mTLS (server and client certificates) are used.
/// </summary>
public class VaultBackedTokenizationTests
{
    /// <summary>
    ///     Helper: builds paths relative to the test directory.
    /// </summary>
    private static string P(string rel)
    {
        return Path.Combine(AppContext.BaseDirectory, rel.Replace('/', Path.DirectorySeparatorChar));
    }

    /// <summary>
    ///     Creates a gRPC context for tokenization requests,
    ///     with tenant ID, purpose, and an optional tweak (ByteString).
    /// </summary>
    private static Context MakeCtx(byte[] tweak, string tenant = "devtenant")
    {
        return new Context
        {
            TenantId = tenant,
            Purpose = "tests",
            Tweak = ByteString.CopyFrom(tweak ?? Array.Empty<byte>())
        };
    }

    /// <summary>
    ///     Builds an HttpClient that talks to Vault via mTLS:
    ///     - loads the CA certificate (server trust)
    ///     - loads the client certificate (PEM + key → PFX)
    ///     - creates an HttpClient with these parameters
    ///     - sets X-Vault-Token in the header
    /// </summary>
    private static async Task<HttpClient> BuildVaultHttpClientAsync()
    {
        // ---- TLS trust anchor (server CA) ----
        var serverCaPem = await File.ReadAllTextAsync(P("tests/Certs/ca.pem"));
        var serverCa = X509Certificate2.CreateFromPem(serverCaPem);
        var anchors = new X509Certificate2Collection { serverCa };

        // ---- Load client certificate from PEM + key ----
        var flags =
            OperatingSystem.IsWindows()
                ? X509KeyStorageFlags.MachineKeySet // or UserKeySet for non-service apps
                  | X509KeyStorageFlags.PersistKeySet
                  | X509KeyStorageFlags.Exportable
                : X509KeyStorageFlags.EphemeralKeySet // fine on Linux/macOS
                  | X509KeyStorageFlags.Exportable;

        var client = new X509Certificate2("tests/Certs/client.p12", "changeit", flags);

        // ---- Build HttpClient with mTLS ----
        var http = HttpClientFactory.Build(
            anchors,
            SslProtocols.Tls12 | SslProtocols.Tls13,
            client);

        // Vault address → hostname/IP must match the SAN of the server certificate
        http.BaseAddress = new Uri("https://127.0.0.1:8200");

        // Vault token from environment or fallback
        var token = Environment.GetEnvironmentVariable("VAULT_TOKEN") ?? "hvs.pb8h7f1TX7vDEMmLnbkpq9CA";
        http.DefaultRequestHeaders.Add("X-Vault-Token", token);

        return http;
    }

    /// <summary>
    ///     Tests a full roundtrip with FF1-FPE (format-preserving encryption)
    ///     using the Vault-backed KeyProvider.
    ///     Flow:
    ///     - A credit card number (digits only) is tokenized using FPE.
    ///     - The generated token is checked (prefix, length, digit domain).
    ///     - Then it is detokenized and the original plaintext is expected.
    ///     Purpose:
    ///     - Ensure FPE works correctly with Vault keys
    ///     and format properties (digits only, length) are preserved.
    /// </summary>
    [Fact]
    public async Task FF1_Roundtrip_Digits_With_Vault_KeyProvider()
    {
        using var http = await BuildVaultHttpClientAsync();

        // Vault-based key provider: keys live under kv/data/tokenization/keys/<tenant>/<keyId>
        using var keys = new VaultHttpKeyProvider(http, "kv");

        // Vault-based token store: stores reversible tokens (included here for completeness)
        using var store = new VaultHttpTokenStore(http);

        // Real FF1 FPE engine (format-preserving encryption)
        var fpe = new BcFpeEngine();

        // Tokenization service with Vault backends
        var svc = new TokenizationServiceImpl(keys, store, fpe);

        var pt = "4111111111111111"; // 16-digit credit card number
        var tweak = Encoding.UTF8.GetBytes("order-42");

        // --- Tokenize ---
        var tok = await svc.Tokenize(new TokenizeRequest
        {
            TokenType = TokenType.Fpe,
            Context = MakeCtx(tweak),
            Items =
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

        // The payload portion of the token should contain digits only and preserve the length
        var payload = token.Split('.').Skip(3).First();
        Assert.True(payload.All(char.IsDigit));
        Assert.Equal(pt.Length, payload.Length);

        // --- Detokenize ---
        var det = await svc.Detokenize(new DetokenizeRequest
        {
            Context = MakeCtx(tweak),
            Items = { new TokenizedField { Field = "credit_card", Token = token } }
        }, null);

        Assert.Empty(det.Errors);
        Assert.Single(det.Items);
        Assert.Equal(pt, det.Items[0].Plaintext);
    }

    /// <summary>
    ///     Tests a full roundtrip with RANDOM tokens using both the Vault KeyProvider
    ///     and the Vault TokenStore.
    ///     Flow:
    ///     - A plaintext (email) is stored as a RANDOM token.
    ///     - The token is checked for its prefix ("v1.r.").
    ///     - Then the token is detokenized via the Vault-backed TokenStore
    ///     and the original plaintext is expected.
    ///     Purpose:
    ///     - Ensure non-deterministic RANDOM tokens are correctly persisted
    ///     and can be resolved again via Vault.
    /// </summary>
    [Fact]
    public async Task RANDOM_Roundtrip_With_Vault_KeyProvider_And_Vault_TokenStore()
    {
        using var http = await BuildVaultHttpClientAsync();

        // KeyProvider (Vault), even though RANDOM does not directly require the key
        using var keys = new VaultHttpKeyProvider(http, "kv");

        // TokenStore (Vault), required for later detokenization of RANDOM
        using var store = new VaultHttpTokenStore(http);

        // FPE engine (not used for RANDOM, but the service expects an instance)
        var fpe = new BcFpeEngine();

        // Service with option: also store non-reversible tokens (here: RANDOM)
        var svc = new TokenizationServiceImpl(keys, store, fpe, true);

        var pt = "alice@example.com";
        var tweak = Encoding.UTF8.GetBytes("demo");

        // --- Tokenize ---
        var tok = await svc.Tokenize(new TokenizeRequest
        {
            TokenType = TokenType.Random,
            Context = MakeCtx(tweak),
            Items =
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

        // --- Detokenize (loads plaintext from Vault store) ---
        var det = await svc.Detokenize(new DetokenizeRequest
        {
            Context = MakeCtx(tweak),
            Items = { new TokenizedField { Field = "email", Token = token } }
        }, null);

        Assert.Empty(det.Errors);
        Assert.Single(det.Items);
        Assert.Equal(pt, det.Items[0].Plaintext);
    }
}