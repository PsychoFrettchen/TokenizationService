using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using em.Tokenization.V1;
using Google.Protobuf;
using TokenizationService_Tests.tests.Utils;
using TokenizationService.CryptoImpl;
using TokenizationService.Factory;
using TokenizationService.KeyManagement;
using TokenizationService.KeyManagment;
using TokenizationService.Tokenization;

public sealed class TokenizationCoreTests_Vault
{
    // ---------- Helpers ----------

    /// <summary>
    ///     Helper function to build a path relative to the test execution directory.
    /// </summary>
    private static string P(string rel)
    {
        return Path.Combine(AppContext.BaseDirectory, rel.Replace('/', Path.DirectorySeparatorChar));
    }

    /// <summary>
    ///     Builds a default context with tenant, optional keyId, and purpose.
    /// </summary>
    private static Context DefaultCtx(string tenant = "t-acme", string keyId = null, string purpose = "tests")
    {
        return new Context { TenantId = tenant, KeyId = keyId ?? "", Purpose = purpose };
    }

    /// <summary>
    ///     Builds a context including tweak bytes (e.g., for FPE).
    /// </summary>
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
    ///     Creates an HttpClient with mTLS that is allowed to talk to Vault.
    ///     - Loads the CA root (ca.pem),
    ///     - binds the client certificate (client.pem + client.key),
    ///     - sets Vault address and the Vault token header.
    /// </summary>
    private static HttpClient BuildVaultHttpClient()
    {
        // ---- Load TLS trust anchor (CA) ----
        var caPem = File.ReadAllText(P("tests/Certs/ca.pem"));
        var caCert = X509Certificate2.CreateFromPem(caPem);
        var anchors = new X509Certificate2Collection { caCert };

        // ---- Client certificate (PEM pair -> PFX) ----
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

        http.BaseAddress = new Uri(Environment.GetEnvironmentVariable("VAULT_ADDR") ?? "https://127.0.0.1:8200");
        var vaultToken =
            Environment.GetEnvironmentVariable("VAULT_TOKEN") ?? "hvs.pb8h7f1TX7vDEMmLnbkpq9CA";
        http.DefaultRequestHeaders.Add("X-Vault-Token", vaultToken);
        return http;
    }

    /// <summary>
    ///     Builds a TokenizationServiceImpl instance that uses Vault as key provider and token store.
    ///     Optionally with an FPE engine (FF1) and configurable whether non-reversible tokens are persisted in the store.
    /// </summary>
    private static TokenizationServiceImpl BuildSvc(bool storeNonReversible, bool withFpe)
    {
        var kvMount = Environment.GetEnvironmentVariable("VAULT_KV_MOUNT") ?? "kv";
        var http = BuildVaultHttpClient();

        // Vault-backed IKeyProvider + ITokenStore
        var keys = new VaultHttpKeyProvider(http, kvMount);
        var store = new VaultHttpTokenStore(http, kvMount);

        var fpe = withFpe ? new BcFpeEngine() : null;
        return new TokenizationServiceImpl(keys, store, fpe, storeNonReversible);
    }

    // ---------- tests ----------

    /// <summary>
    ///     Tests the full roundtrip with random tokens:
    ///     Tokenize → Detokenize → Validate.
    ///     Expectation: the token can be correctly recovered and validated.
    /// </summary>
    [Fact]
    public async Task Random_Tokenize_And_Detokenize_Roundtrip()
    {
        var svc = BuildSvc(true, true);
        using var ts = new TestServer(svc); // insecure server is fine for core tests

        // Request with two fields (email + phone)
        var req = new TokenizeRequest
        {
            TokenType = TokenType.Random,
            Context = DefaultCtx(keyId: "k1")
        };
        req.Items.Add(
            new FieldPayload { Field = "email", Plaintext = "alice@example.com", DataClass = DataClass.Email });
        req.Items.Add(new FieldPayload { Field = "phone", Plaintext = "14155551234", DataClass = DataClass.Phone });

        // Tokenization
        var tokResp = await ts.Client.TokenizeAsync(req);
        Assert.Equal(2, tokResp.Items.Count);
        Assert.All(tokResp.Items, it => Assert.StartsWith("v1.r.", it.Token));
        Assert.Equal("k1", tokResp.KeyId);

        // Detokenization
        var detReq = new DetokenizeRequest { Context = DefaultCtx(keyId: "k1") };
        detReq.Items.AddRange(tokResp.Items.Select(t => new TokenizedField { Field = t.Field, Token = t.Token }));
        var detResp = await ts.Client.DetokenizeAsync(detReq);

        Assert.Equal(2, detResp.Items.Count);
        Assert.Contains(detResp.Items, x => x.Field == "email" && x.Plaintext == "alice@example.com");
        Assert.Contains(detResp.Items, x => x.Field == "phone" && x.Plaintext == "14155551234");

        // Validation
        var val = await ts.Client.ValidateTokenAsync(new ValidateTokenRequest
        {
            Token = tokResp.Items[0].Token,
            Context = DefaultCtx(keyId: "k1")
        });

        Assert.True(val.Valid);
        Assert.Equal(TokenType.Random, val.TokenType);
        Assert.Equal("email", val.Field); // pulled from Vault store
        Assert.Equal(DataClass.Email, val.DataClass);
    }

    /// <summary>
    ///     Tests HMAC tokenization without persisting non-reversible tokens.
    ///     Expectation: token can be validated, but contains no field information
    ///     and cannot be detokenized (404 error).
    /// </summary>
    [Fact]
    public async Task Hmac_Tokenize_Validate_NotDetokenizable_WhenNotStored()
    {
        // Tests HMAC tokenization without persistence: validation OK, detokenize not possible
        var svc = BuildSvc(false, false);
        using var ts = new TestServer(svc);

        var tok = await ts.Client.TokenizeAsync(new TokenizeRequest
        {
            TokenType = TokenType.Hmac,
            Context = DefaultCtx(keyId: "k-hc"),
            Items = { new FieldPayload { Field = "ssn", Plaintext = "123-45-6789", DataClass = DataClass.Ssn } }
        });

        Assert.Single(tok.Items);
        Assert.StartsWith("v1.hc.", tok.Items[0].Token);

        var v = await ts.Client.ValidateTokenAsync(new ValidateTokenRequest
        {
            Token = tok.Items[0].Token,
            Context = DefaultCtx(keyId: "k-hc")
        });
        Assert.True(v.Valid);
        Assert.Equal(TokenType.Hmac, v.TokenType);
        Assert.True(string.IsNullOrEmpty(v.Field)); // field unknown because it was not persisted

        var det = await ts.Client.DetokenizeAsync(new DetokenizeRequest
        {
            Context = DefaultCtx(keyId: "k-hc"),
            Items = { new TokenizedField { Field = "ssn", Token = tok.Items[0].Token } }
        });
        Assert.Empty(det.Items);
        Assert.Single(det.Errors);
        Assert.Equal(40404, det.Errors[0].Code); // "Token not found"
    }

    /// <summary>
    ///     Tests hash tokenization with a masked view.
    ///     Expectation: token contains the hash prefixes and appends a formatted (mask) view
    ///     as a suffix, e.g. 9999-9999-9999-9999.
    /// </summary>
    [Fact]
    public async Task Hash_Tokenize_WithMaskedView_PreservesMaskInSuffix()
    {
        // Tests hash tokenization with masked view: suffix matches format mask
        var svc = BuildSvc(false, false);
        using var ts = new TestServer(svc);

        var tok = await ts.Client.TokenizeAsync(new TokenizeRequest
        {
            TokenType = TokenType.Hash,
            Context = DefaultCtx(keyId: "k-hash"),
            Items =
            {
                new FieldPayload
                {
                    Field = "credit_card",
                    Plaintext = "4111111111111111",
                    DataClass = DataClass.CreditCard,
                    PreserveFormat = false,
                    FormatMode = FormatMode.Masked,
                    FormatMask = "9999-9999-9999-9999"
                }
            }
        });

        var token = tok.Items[0].Token;
        Assert.StartsWith("v1.hs.", token);
        Assert.Contains("~", token);

        var maskedPart = token.Split('~')[1];
        Assert.Matches(@"^\d{4}-\d{4}-\d{4}-\d{4}$", maskedPart);
    }

    /// <summary>
    ///     Tests FPE tokenization without a configured engine.
    ///     Expectation: the service either returns an error (strict mode)
    ///     or produces a "shim" token whose payload consists only of digits (lenient mode).
    /// </summary>
    [Fact]
    public async Task Fpe_Fallback_ShowsDigitPayload_WhenDigits_And_NoEngine()
    {
        // Tests behavior when FPE is requested but no engine exists:
        // depending on policy: error OR "shim" payload
        var svc = BuildSvc(false, false);
        using var ts = new TestServer(svc);

        var resp = await ts.Client.TokenizeAsync(new TokenizeRequest
        {
            TokenType = TokenType.Fpe,
            Context = DefaultCtx(keyId: "k-fpe"),
            Items =
            {
                new FieldPayload
                {
                    Field = "iban",
                    Plaintext = "123456789012",
                    DataClass = DataClass.Iban,
                    PreserveFormat = true
                }
            }
        });

        if (resp.Items.Count == 0)
        {
            // Strict mode → return error
            Assert.Single(resp.Errors);
            Assert.Equal("iban", resp.Errors[0].Field);
            Assert.Contains("FPE", resp.Errors[0].Message, StringComparison.OrdinalIgnoreCase);
            return;
        }

        // Lenient mode → shim token
        var token = resp.Items[0].Token;
        Assert.StartsWith("v1.f.", token);

        // Payload contains digits only
        var payload = token.Split('.').Skip(3).First();
        Assert.True(payload.All(char.IsDigit));
    }

    /// <summary>
    ///     Tests rotating the active key for a tenant.
    ///     Expectation: initially "default" is active.
    ///     After rotation to "kid-2", that key is used,
    ///     and tokenization without keyId falls back to "kid-2".
    /// </summary>
    [Fact]
    public async Task RotateKey_SwitchesActiveKey()
    {
        // Tests that RotateKey switches the active key for a tenant
        var tenant = "tenant-rotate-" + Guid.NewGuid().ToString("N").Substring(0, 6);

        var svc = BuildSvc(true, true);
        using var ts = new TestServer(svc);

        // Before rotation: "default"
        var before = await ts.Client.RotateKeyAsync(new RotateKeyRequest
        {
            Context = DefaultCtx(tenant)
        });
        Assert.Equal("default", before.ActiveKeyId);

        // After rotation → "kid-2"
        var after = await ts.Client.RotateKeyAsync(new RotateKeyRequest
        {
            Context = DefaultCtx(tenant),
            NewKeyId = "kid-2"
        });
        Assert.Equal("kid-2", after.ActiveKeyId);

        // Tokenize without explicit keyId → uses active key ("kid-2")
        var tok = await ts.Client.TokenizeAsync(new TokenizeRequest
        {
            TokenType = TokenType.Random,
            Context = DefaultCtx(tenant),
            Items =
            {
                new FieldPayload
                {
                    Field = "email",
                    Plaintext = "alice@example.com",
                    DataClass = DataClass.Email
                }
            }
        });

        Assert.Equal("kid-2", tok.KeyId);
        Assert.Single(tok.Items);
        Assert.StartsWith("v1.r.", tok.Items[0].Token);
    }

    /// <summary>
    ///     Tests the streaming tokenization API.
    ///     Expectation: each input item (f1, f2) produces its own token
    ///     and is returned immediately via the stream.
    /// </summary>
    [Fact]
    public async Task StreamTokenize_EmitsItemPerInput()
    {
        // Tests streaming API: each input immediately produces a token item
        var svc = BuildSvc(true, true);
        using var ts = new TestServer(svc);

        using var call = ts.Client.StreamTokenize();

        // Send init
        await call.RequestStream.WriteAsync(new StreamTokenizeIn
        {
            Init = new StreamTokenizeInit
            {
                TokenType = TokenType.Random,
                Context = DefaultCtx(keyId: "k-stream")
            }
        });

        // Push two items
        await call.RequestStream.WriteAsync(new StreamTokenizeIn
            { Item = new FieldPayload { Field = "f1", Plaintext = "A" } });
        await call.RequestStream.WriteAsync(new StreamTokenizeIn
            { Item = new FieldPayload { Field = "f2", Plaintext = "B" } });
        await call.RequestStream.CompleteAsync();

        // Verify: 2 items returned
        var seen = 0;
        while (await call.ResponseStream.MoveNext(CancellationToken.None))
        {
            var msg = call.ResponseStream.Current;
            Assert.NotNull(msg?.Item);
            Assert.StartsWith("v1.r.", msg.Item.Token);
            seen++;
        }

        Assert.Equal(2, seen);
    }
}