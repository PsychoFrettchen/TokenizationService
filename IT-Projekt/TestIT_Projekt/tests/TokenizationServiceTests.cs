using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using em.Tokenization.V1;
using Google.Protobuf;
using IT_Projekt;
using IT_Projekt.CryptoImpl;
using IT_Projekt.Factory;
using IT_Projekt.KeyManagement;
using IT_Projekt.KeyManagment;

public sealed class TokenizationCoreTests_Vault
{
    // ---------- Helfer ----------

    /// <summary>
    /// Hilfsfunktion zum Bauen eines Pfades relativ zum Test-Ausführungsverzeichnis.
    /// </summary>
    private static string P(string rel) =>
        Path.Combine(AppContext.BaseDirectory, rel.Replace('/', Path.DirectorySeparatorChar));

    /// <summary>
    /// Baut einen Standard-Kontext mit Tenant, optionalem KeyId und Purpose.
    /// </summary>
    private static Context DefaultCtx(string tenant = "t-acme", string keyId = null, string purpose = "tests")
        => new Context { TenantId = tenant, KeyId = keyId ?? "", Purpose = purpose };

    /// <summary>
    /// Baut einen Kontext inkl. Tweak-Bytes (z. B. für FPE).
    /// </summary>
    private static Context Ctx(byte[] tweak, string tenant = "t-acme", string keyId = "k1", string purpose = "tests")
        => new Context
        {
            TenantId = tenant,
            KeyId = keyId,
            Purpose = purpose,
            Tweak = ByteString.CopyFrom(tweak ?? Array.Empty<byte>())
        };

    
    /// <summary>
    /// Erstellt einen HttpClient mit mTLS, der gegen Vault sprechen darf.
    /// - Lädt CA-Root (ca.pem),
    /// - bindet das Client-Zertifikat (client.pem + client.key),
    /// - setzt Vault-Adresse und Vault-Token Header.
    /// </summary>
    private static HttpClient BuildVaultHttpClient()
    {
        // ---- TLS Trust Anchor (CA) laden ----
        var caPem = File.ReadAllText(P("tests/Certs/ca.pem"));
        var caCert = X509Certificate2.CreateFromPem(caPem);
        var anchors = new X509Certificate2Collection { caCert };

        // ---- Client certificate (PEM pair -> PFX) ----
        var flags =
            OperatingSystem.IsWindows()
                ? X509KeyStorageFlags.MachineKeySet   // or UserKeySet for non-service apps
                  | X509KeyStorageFlags.PersistKeySet
                  | X509KeyStorageFlags.Exportable
                : X509KeyStorageFlags.EphemeralKeySet // fine on Linux/macOS
                  | X509KeyStorageFlags.Exportable;

        var client = new X509Certificate2("tests/Certs/client.p12", "changeit", flags);

        // ---- HttpClient mit mTLS bauen ----
        var http = HttpClientFactory.Build(
            trustAnchors: anchors,
            protocols: SslProtocols.Tls12 | SslProtocols.Tls13,
            clientCertificate: client);

        http.BaseAddress = new Uri(Environment.GetEnvironmentVariable("VAULT_ADDR") ?? "https://127.0.0.1:8200");
        var vaultToken =
            Environment.GetEnvironmentVariable("VAULT_TOKEN") ?? "hvs.pb8h7f1TX7vDEMmLnbkpq9CA";
        http.DefaultRequestHeaders.Add("X-Vault-Token", vaultToken);
        return http;
    }

    /// <summary>
    /// Baut eine TokenizationServiceImpl-Instanz, die Vault als KeyProvider und TokenStore verwendet.
    /// Optional mit FPE-Engine (FF1) und konfigurierbar, ob nicht-reversible Tokens im Store persistiert werden.
    /// </summary>
    private static TokenizationServiceImpl BuildSvc(bool storeNonReversible, bool withFpe)
    {
        var kvMount = Environment.GetEnvironmentVariable("VAULT_KV_MOUNT") ?? "kv";
        var http = BuildVaultHttpClient();

        // Vault-backed IKeyProvider + ITokenStore
        var keys = new VaultHttpKeyProvider(http, kvMount);
        var store = new VaultHttpTokenStore(http, kvMount);

        var fpe = withFpe ? new BcFpeEngine(BcFpeEngine.Mode.FF1) : null;
        return new TokenizationServiceImpl(keys, store, fpe, storeNonReversible);
    }

    // ---------- tests ----------

    /// <summary>
    /// Testet den vollständigen Roundtrip mit zufälligen Tokens:
    /// Tokenize → Detokenize → Validate. 
    /// Erwartung: Token lässt sich korrekt zurückführen und validieren.
    /// </summary>
    [Fact]
    public async Task Random_Tokenize_And_Detokenize_Roundtrip()
    {
        var svc = BuildSvc(storeNonReversible: true, withFpe: true);
        using var ts = new TestServer(svc); // insecure server is fine for core tests
        
        // Anfrage mit zwei Feldern (Email + Phone)
        var req = new TokenizeRequest
        {
            TokenType = TokenType.Random,
            Context = DefaultCtx(keyId: "k1")
        };
        req.Items.Add(
            new FieldPayload { Field = "email", Plaintext = "alice@example.com", DataClass = DataClass.Email });
        req.Items.Add(new FieldPayload { Field = "phone", Plaintext = "14155551234", DataClass = DataClass.Phone });

        // Tokenisierung
        var tokResp = await ts.Client.TokenizeAsync(req);
        Assert.Equal(2, tokResp.Items.Count);
        Assert.All(tokResp.Items, it => Assert.StartsWith("v1.r.", it.Token));
        Assert.Equal("k1", tokResp.KeyId);
        // Detokenisierung
        var detReq = new DetokenizeRequest { Context = DefaultCtx(keyId: "k1") };
        detReq.Items.AddRange(tokResp.Items.Select(t => new TokenizedField { Field = t.Field, Token = t.Token }));
        var detResp = await ts.Client.DetokenizeAsync(detReq);

        Assert.Equal(2, detResp.Items.Count);
        Assert.Contains(detResp.Items, x => x.Field == "email" && x.Plaintext == "alice@example.com");
        Assert.Contains(detResp.Items, x => x.Field == "phone" && x.Plaintext == "14155551234");
        
        // Validierung
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
    /// Testet HMAC-Tokenisierung ohne Speicherung von nicht-reversiblen Tokens.
    /// Erwartung: Token kann validiert werden, enthält aber keine Feldinformationen
    /// und lässt sich nicht detokenisieren (404-Fehler).
    /// </summary>
    [Fact]
    public async Task Hmac_Tokenize_Validate_NotDetokenizable_WhenNotStored()
    {
        // Testet HMAC-Tokenisierung ohne Persistenz: Validierung ok, Detokenize nicht möglich
        var svc = BuildSvc(storeNonReversible: false, withFpe: false);
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
        Assert.True(string.IsNullOrEmpty(v.Field)); // Feld unbekannt, da nicht persistiert

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
    /// Testet Hash-Tokenisierung mit Masked-View.
    /// Erwartung: Token enthält die Hash-Präfixe und hängt eine 
    /// formatierte (Mask) Sicht als Suffix an, z. B. 9999-9999-9999-9999.
    /// </summary>
    [Fact]
    public async Task Hash_Tokenize_WithMaskedView_PreservesMaskInSuffix()
    {
        // Testet Hash-Tokenisierung mit Masked-View: Suffix entspricht FormatMaske
        var svc = BuildSvc(storeNonReversible: false, withFpe: false);
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
    /// Testet FPE-Tokenisierung ohne konfigurierte Engine.
    /// Erwartung: Service gibt entweder einen Fehler (strict mode)
    /// oder erzeugt einen "Shim"-Token, dessen Payload nur aus Ziffern besteht (lenient mode).
    /// </summary>
    [Fact]
    public async Task Fpe_Fallback_ShowsDigitPayload_WhenDigits_And_NoEngine()
    {
        // Testet Verhalten wenn FPE angefragt, aber keine Engine vorhanden:
        // // je nach Policy Fehler ODER "Shim"-Payload
        var svc = BuildSvc(storeNonReversible: false, withFpe: false);
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
            // Strict mode → Fehler zurück
            Assert.Single(resp.Errors);
            Assert.Equal("iban", resp.Errors[0].Field);
            Assert.Contains("FPE", resp.Errors[0].Message, StringComparison.OrdinalIgnoreCase);
            return;
        }

        // Lenient mode → Shim-Token
        var token = resp.Items[0].Token;
        Assert.StartsWith("v1.f.", token);

        // Payload enthält nur Ziffern
        var payload = token.Split('.').Skip(3).First();
        Assert.True(payload.All(char.IsDigit));
    }

    /// <summary>
    /// Testet das Rotieren des aktiven Schlüssels für einen Tenant.
    /// Erwartung: Anfangs ist "default" aktiv. 
    /// Nach Rotation auf "kid-2" wird dieser Key verwendet,
    /// und Tokenize ohne KeyId greift auf "kid-2" zurück.
    /// </summary>
    [Fact]
    public async Task RotateKey_SwitchesActiveKey()
    {
        // Testet, dass RotateKey den aktiven Key für einen Tenant umstellt
        var tenant = "tenant-rotate-" + Guid.NewGuid().ToString("N").Substring(0, 6);

        var svc = BuildSvc(storeNonReversible: true, withFpe: true);
        using var ts = new TestServer(svc);

        // Vor Rotation: "default"
        var before = await ts.Client.RotateKeyAsync(new RotateKeyRequest
        {
            Context = DefaultCtx(tenant: tenant)
        });
        Assert.Equal("default", before.ActiveKeyId);

        // Nach Rotation → "kid-2"
        var after = await ts.Client.RotateKeyAsync(new RotateKeyRequest
        {
            Context = DefaultCtx(tenant: tenant),
            NewKeyId = "kid-2"
        });
        Assert.Equal("kid-2", after.ActiveKeyId);

        // Tokenize ohne explizite KeyId → verwendet aktiven Key ("kid-2")
        var tok = await ts.Client.TokenizeAsync(new TokenizeRequest
        {
            TokenType = TokenType.Random,
            Context   = DefaultCtx(tenant: tenant), 
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
    /// Testet die Streaming-API für Tokenisierung.
    /// Erwartung: Jeder Input-Item (f1, f2) erzeugt ein eigenes Token 
    /// und wird sofort über den Stream zurückgegeben.
    /// </summary>
    [Fact]
    public async Task StreamTokenize_EmitsItemPerInput()
    {
        // Testet Streaming-API: jeder Input erzeugt sofort ein Token-Item
        var svc = BuildSvc(storeNonReversible: true, withFpe: true);
        using var ts = new TestServer(svc);

        using var call = ts.Client.StreamTokenize();

        // Init senden
        await call.RequestStream.WriteAsync(new StreamTokenizeIn
        {
            Init = new StreamTokenizeInit
            {
                TokenType = TokenType.Random,
                Context = DefaultCtx(keyId: "k-stream")
            }
        });

        // Zwei Items nachschieben
        await call.RequestStream.WriteAsync(new StreamTokenizeIn
            { Item = new FieldPayload { Field = "f1", Plaintext = "A" } });
        await call.RequestStream.WriteAsync(new StreamTokenizeIn
            { Item = new FieldPayload { Field = "f2", Plaintext = "B" } });
        await call.RequestStream.CompleteAsync();
        
        // Prüfen: 2 Items zurück
        int seen = 0;
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