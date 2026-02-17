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
///     Integration tests for the FPE (Format-Preserving Encryption) procedure
///     using BouncyCastle (FF1) and a Vault-backed key/token store.
///     Vault is accessed via mTLS in order to load or store real keys.
/// </summary>
public class FpeIntegrationTests
{
    /// <summary>
    ///     Helper function to resolve relative file paths (e.g., test certificates).
    /// </summary>
    private static string P(string rel)
    {
        return Path.Combine(AppContext.BaseDirectory, rel.Replace('/', Path.DirectorySeparatorChar));
    }

    /// <summary>
    ///     Builds a gRPC context object for tokenization/detokenization calls.
    /// </summary>
    private static Context MakeCtx(string tenant = "t-acme", string keyId = "k1", string purpose = "tests",
        byte[] tweak = null)
    {
        return new Context
        {
            TenantId = tenant,
            KeyId = keyId,
            Purpose = purpose,
            Tweak = tweak != null ? ByteString.CopyFrom(tweak) : ByteString.Empty
        };
    }

    /// <summary>
    ///     Creates an HttpClient for Vault using mTLS:
    ///     - Loads the CA
    ///     - Loads client certificate and key
    ///     - Sets the X-Vault-Token header
    /// </summary>
    private static async Task<HttpClient> BuildVaultHttpClientAsync()
    {
        // ---- TLS trust anchor (server CA) ----
        var serverCaPem = await File.ReadAllTextAsync(P("tests/Certs/ca.pem"));
        var serverCa = X509Certificate2.CreateFromPem(serverCaPem);
        var anchors = new X509Certificate2Collection { serverCa };

        // ---- Client certificate (PEM pair -> PFX) ----

        var flags =
            OperatingSystem.IsWindows()
                ? X509KeyStorageFlags.MachineKeySet // or UserKeySet for non-service apps
                  | X509KeyStorageFlags.PersistKeySet
                  | X509KeyStorageFlags.Exportable
                : X509KeyStorageFlags.EphemeralKeySet // fine on Linux/macOS
                  | X509KeyStorageFlags.Exportable;

        var client = new X509Certificate2("tests/Certs/client.p12", "changeit", flags);

        // ---- Build HttpClient using your handler factory (mTLS) ----
        var http = HttpClientFactory.Build(
            anchors,
            SslProtocols.Tls12 | SslProtocols.Tls13,
            client);

        http.BaseAddress = new Uri("https://127.0.0.1:8200");
        http.DefaultRequestHeaders.Add("X-Vault-Token",
            Environment.GetEnvironmentVariable("VAULT_TOKEN") ?? "hvs.pb8h7f1TX7vDEMmLnbkpq9CA");

        return http;
    }

    // -------------------- Tests --------------------

    /// <summary>
    ///     Tests an FPE-FF1 roundtrip for credit card numbers:
    ///     - length stays the same
    ///     - alphabet (digits only) stays the same
    /// </summary>
    [Fact]
    public async Task FF1_Roundtrip_Digits_Preserve_Length_And_Domain()
    {
        using var http = await BuildVaultHttpClientAsync();
        using var keys = new VaultHttpKeyProvider(http, "kv");
        using var
            store = new VaultHttpTokenStore(http); // FPE doesn't require it, but we avoid in-memory per request
        var fpe = new BcFpeEngine();

        var svc = new TokenizationServiceImpl(keys, store, fpe);
        var pt = "4111111111111111"; // 16 digits
        var tweak = Encoding.UTF8.GetBytes("order-42");

        var tok = await svc.Tokenize(new TokenizeRequest
        {
            TokenType = TokenType.Fpe,
            Context = MakeCtx(tweak: tweak),
            Items =
            {
                new FieldPayload
                    { Field = "credit_card", Plaintext = pt, DataClass = DataClass.CreditCard, PreserveFormat = true }
            }
        }, null);

        Assert.Empty(tok.Errors);
        var token = tok.Items[0].Token;
        Assert.StartsWith("v1.f.", token);

        var payload = token.Split('.').Skip(3).First();
        Assert.True(payload.All(char.IsDigit));
        Assert.Equal(pt.Length, payload.Length);

        var det = await svc.Detokenize(new DetokenizeRequest
        {
            Context = MakeCtx(tweak: tweak),
            Items = { new TokenizedField { Field = "credit_card", Token = token } }
        }, null);

        Assert.Empty(det.Errors);
        Assert.Equal(pt, det.Items[0].Plaintext);
    }

    /// <summary>
    ///     Same roundtrip as above, but explicitly using Vault keys (persistence).
    /// </summary>
    [Fact]
    public async Task FF1_Roundtrip_Digits_Preserve_Length_And_Domain_With_VaultKeys()
    {
        using var http = await BuildVaultHttpClientAsync();
        using var keys = new VaultHttpKeyProvider(http, "kv");
        using var store = new VaultHttpTokenStore(http);
        var fpe = new BcFpeEngine();

        var svc = new TokenizationServiceImpl(keys, store, fpe);
        var pt = "4111111111111111";
        var tweak = Encoding.UTF8.GetBytes("order-42");

        var tok = await svc.Tokenize(new TokenizeRequest
        {
            TokenType = TokenType.Fpe,
            Context = MakeCtx(tweak: tweak),
            Items =
            {
                new FieldPayload
                    { Field = "credit_card", Plaintext = pt, DataClass = DataClass.CreditCard, PreserveFormat = true }
            }
        }, null);

        Assert.Empty(tok.Errors);
        var token = tok.Items[0].Token;
        Assert.StartsWith("v1.f.", token);

        var payload = token.Split('.').Skip(3).First();
        Assert.True(payload.All(char.IsDigit));
        Assert.Equal(pt.Length, payload.Length);

        var det = await svc.Detokenize(new DetokenizeRequest
        {
            Context = MakeCtx(tweak: tweak),
            Items = { new TokenizedField { Field = "credit_card", Token = token } }
        }, null);

        Assert.Empty(det.Errors);
        Assert.Equal(pt, det.Items[0].Plaintext);
    }

    /// <summary>
    ///     Tests RANDOM tokenization with Vault key and Vault store (reversible because it is persisted).
    /// </summary>
    [Fact]
    public async Task RANDOM_Roundtrip_With_Vault_Key_And_Store()
    {
        using var http = await BuildVaultHttpClientAsync();
        using var keys = new VaultHttpKeyProvider(http, "kv");
        using var store = new VaultHttpTokenStore(http);
        var fpe = new BcFpeEngine();

        var svc = new TokenizationServiceImpl(keys, store, fpe, true);
        var pt = "alice@example.com";
        var tweak = Encoding.UTF8.GetBytes("demo");

        var tok = await svc.Tokenize(new TokenizeRequest
        {
            TokenType = TokenType.Random,
            Context = MakeCtx(tweak: tweak, tenant: "devtenant"),
            Items = { new FieldPayload { Field = "email", Plaintext = pt, DataClass = DataClass.Email } }
        }, null);

        Assert.Empty(tok.Errors);
        var token = tok.Items[0].Token;
        Assert.StartsWith("v1.r.", token);

        var det = await svc.Detokenize(new DetokenizeRequest
        {
            Context = MakeCtx(tweak: tweak, tenant: "devtenant"),
            Items = { new TokenizedField { Field = "email", Token = token } }
        }, null);

        Assert.Empty(det.Errors);
        Assert.Equal(pt, det.Items[0].Plaintext);
    }

    /// <summary>
    ///     Tests an FPE-FF1 roundtrip for alphanumeric data.
    /// </summary>
    [Fact]
    public async Task FF1_Roundtrip_Alnum_Works()
    {
        using var http = await BuildVaultHttpClientAsync();
        using var keys = new VaultHttpKeyProvider(http, "kv");
        using var store = new VaultHttpTokenStore(http);
        var fpe = new BcFpeEngine();

        var svc = new TokenizationServiceImpl(keys, store, fpe);

        var pt = "Ab3dE7xYz"; // alnum
        var tweak = Encoding.UTF8.GetBytes("any-tweak");

        var tok = await svc.Tokenize(new TokenizeRequest
        {
            TokenType = TokenType.Fpe,
            Context = MakeCtx(tweak: tweak),
            Items =
            {
                new FieldPayload
                    { Field = "username", Plaintext = pt, DataClass = DataClass.Unspecified, PreserveFormat = true }
            }
        }, null);

        var token = tok.Items[0].Token;
        Assert.StartsWith("v1.f.", token);

        var det = await svc.Detokenize(new DetokenizeRequest
        {
            Context = MakeCtx(tweak: tweak),
            Items = { new TokenizedField { Field = "username", Token = token } }
        }, null);

        Assert.Equal(pt, det.Items[0].Plaintext);
    }

    /// <summary>
    ///     Ensures that FPE fails if no engine is configured.
    /// </summary>
    [Fact]
    public async Task Fpe_Fails_When_Engine_Not_Configured()
    {
        using var http = await BuildVaultHttpClientAsync();
        using var keys = new VaultHttpKeyProvider(http, "kv");
        using var store = new VaultHttpTokenStore(http);

        var svc = new TokenizationServiceImpl(keys, store, null);

        var resp = await svc.Tokenize(new TokenizeRequest
        {
            TokenType = TokenType.Fpe,
            Context = MakeCtx(tweak: Encoding.UTF8.GetBytes("t")),
            Items =
            {
                new FieldPayload
                    { Field = "iban", Plaintext = "1234567890", DataClass = DataClass.Iban, PreserveFormat = true }
            }
        }, null);

        Assert.Empty(resp.Items);
        Assert.Single(resp.Errors);
        Assert.Equal("iban", resp.Errors[0].Field);
        Assert.Contains("FPE", resp.Errors[0].Message, StringComparison.OrdinalIgnoreCase);
    }

    private static Context Ctx(byte[] tweak, string tenant = "t-acme", string keyId = "k1", string purpose = "tests")
    {
        return new Context
        {
            TenantId = tenant,
            KeyId = keyId,
            Purpose = purpose,
            Tweak = ByteString.CopyFrom(tweak ?? Array.Empty<byte>())
        };
    }

    /// <summary>
    ///     FPE produces different ciphertexts for the same inputs
    ///     when the tweak changes.
    /// </summary>
    [Fact]
    public async Task FF1_DifferentTweaks_ProduceDifferentCiphertexts_ForSameInputAndKey()
    {
        using var http = await BuildVaultHttpClientAsync();
        using var keys = new VaultHttpKeyProvider(http, "kv");
        using var store = new VaultHttpTokenStore(http);
        var fpe = new BcFpeEngine();

        var svc = new TokenizationServiceImpl(keys, store, fpe);
        var pt = "4111111111111111";
        var req = new FieldPayload
            { Field = "credit_card", Plaintext = pt, DataClass = DataClass.CreditCard, PreserveFormat = true };

        var tweakA = Encoding.UTF8.GetBytes("order-1001");
        var tweakB = Encoding.UTF8.GetBytes("order-1002");

        var tokA = await svc.Tokenize(
            new TokenizeRequest { TokenType = TokenType.Fpe, Context = Ctx(tweakA), Items = { req } }, null);
        var tokB = await svc.Tokenize(
            new TokenizeRequest { TokenType = TokenType.Fpe, Context = Ctx(tweakB), Items = { req } }, null);

        var payloadA = tokA.Items[0].Token.Split('.').Skip(3).First();
        var payloadB = tokB.Items[0].Token.Split('.').Skip(3).First();

        Assert.NotEqual(payloadA, payloadB);
        Assert.Equal(pt.Length, payloadA.Length);
        Assert.Equal(pt.Length, payloadB.Length);
        Assert.True(payloadA.All(char.IsDigit));
        Assert.True(payloadB.All(char.IsDigit));
    }

    /// <summary>
    ///     Verifies that decrypting with the wrong tweak does not return the original plaintext.
    /// </summary>
    [Fact]
    public async Task FF1_Detokenize_WithWrongTweak_DoesNotRecoverPlaintext()
    {
        using var http = await BuildVaultHttpClientAsync();
        using var keys = new VaultHttpKeyProvider(http, "kv");
        using var store = new VaultHttpTokenStore(http);
        var fpe = new BcFpeEngine();

        var svc = new TokenizationServiceImpl(keys, store, fpe);
        var plaintext = "9876543210987654";
        var correctTweak = Encoding.UTF8.GetBytes("tweak-correct");
        var wrongTweak = Encoding.UTF8.GetBytes("tweak-wrong!!");

        var tok = await svc.Tokenize(new TokenizeRequest
        {
            TokenType = TokenType.Fpe,
            Context = Ctx(correctTweak),
            Items =
            {
                new FieldPayload
                {
                    Field = "credit_card", Plaintext = plaintext, DataClass = DataClass.CreditCard,
                    PreserveFormat = true
                }
            }
        }, null);

        var token = tok.Items[0].Token;

        var detWrong = await svc.Detokenize(new DetokenizeRequest
        {
            Context = Ctx(wrongTweak),
            Items = { new TokenizedField { Field = "credit_card", Token = token } }
        }, null);

        var detCorrect = await svc.Detokenize(new DetokenizeRequest
        {
            Context = Ctx(correctTweak),
            Items = { new TokenizedField { Field = "credit_card", Token = token } }
        }, null);

        Assert.Single(detCorrect.Items);
        Assert.Equal(plaintext, detCorrect.Items[0].Plaintext);

        Assert.Single(detWrong.Items);
        Assert.NotEqual(plaintext, detWrong.Items[0].Plaintext);
        Assert.Equal(plaintext.Length, detWrong.Items[0].Plaintext.Length);
        Assert.True(detWrong.Items[0].Plaintext.All(char.IsDigit));
    }
}