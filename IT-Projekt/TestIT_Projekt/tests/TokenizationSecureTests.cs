using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Grpc.Core;
using em.Tokenization.V1;
using Google.Protobuf;
using IT_Projekt;                               // TokenizationServiceImpl
using IT_Projekt.Authorization;               // AuthorizationInterceptor, KeycloakAccessTokenValidator
using IT_Projekt.CryptoImpl;                  // BcFpeEngine
using IT_Projekt.Factory;                     // HttpClientFactory (mTLS-HttpClient)
using IT_Projekt.KeyManagement;               // VaultHttpTokenStore
using IT_Projekt.KeyManagment;                // VaultHttpKeyProvider

/// <summary>
/// End-to-End-Tests für den Tokenization-Service mit:
/// - mTLS-geschütztem gRPC-Testserver (eigene PEMs)
/// - OAuth2/JWT via Keycloak (Scopes "tokenize"/"detokenize")
/// - Schlüsselspeicher & Token-Store in HashiCorp Vault (KV v2)
/// </summary>
public sealed class TokenizationSecureTests : IDisposable
{
    private TestServer server; // Hilfsserver (bindet Service + Zertifikate + Interceptor)

    /// <summary>
    /// Hilfsfunktion: Pfade relativ zum Test-Binärverzeichnis auflösen.
    /// </summary>
    private static string P(string rel) =>
        Path.Combine(AppContext.BaseDirectory, rel.Replace('/', Path.DirectorySeparatorChar));

    // ---------- Helpers: Keycloak ----------

    /// <summary>
    /// Baut einen HttpClient für Keycloak mit mTLS:
    /// - Server-CA wird als Trust Anchor gesetzt
    /// - Client-Zertifikat (PEM+Key) wird als ClientAuth-Zertifikat präsentiert
    /// </summary>
    private static HttpClient BuildMtlsClientForKeycloak()
    {
        // CA einlesen und als Trust Anchor verwenden
        var caPem     = File.ReadAllText(P("tests/Certs/ca.pem"));
        var serverCa  = X509Certificate2.CreateFromPem(caPem);
        var anchors   = new X509Certificate2Collection { serverCa };

        // Clientcert (PEM) + Key laden, in PFX überführen (für HttpClientHandler)
        var flags =
            OperatingSystem.IsWindows()
                ? X509KeyStorageFlags.MachineKeySet   // or UserKeySet for non-service apps
                  | X509KeyStorageFlags.PersistKeySet
                  | X509KeyStorageFlags.Exportable
                : X509KeyStorageFlags.EphemeralKeySet // fine on Linux/macOS
                  | X509KeyStorageFlags.Exportable;

        var client = new X509Certificate2("tests/Certs/client.p12", "changeit", flags);

        // HttpClient mit mTLS bauen (TLS 1.2 + 1.3 wenn verfügbar)
        var http = HttpClientFactory.Build(
            trustAnchors: anchors,
            protocols: SslProtocols.Tls12 | SslProtocols.Tls13,
            clientCertificate: client);
        return http;
    }

    /// <summary>
    /// Holt via Client-Credentials-Flow ein Access Token von Keycloak.
    /// Scopes werden im Request mitgegeben (z. B. "tokenize detokenize").
    /// </summary>
    private static async Task<string> GetKeycloakTokenAsync(
        HttpClient http,
        string baseUrl,
        string realm,
        string clientId,
        string clientSecretOrNull,
        string scopes = "tokenize detokenize")
    {
        var tokenEndpoint = $"{baseUrl.TrimEnd('/')}/realms/{realm}/protocol/openid-connect/token";

        using var req = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
        {
            Content = new FormUrlEncodedContent(new []
            {
                new KeyValuePair<string,string>("grant_type", "client_credentials"),
                new KeyValuePair<string,string>("client_id", clientId),
                new KeyValuePair<string,string>("scope", scopes),
            }
            // Client Secret ist optional (bei mTLS Client-Auth ggf. nicht notwendig)
            .Concat(string.IsNullOrEmpty(clientSecretOrNull)
                ? Array.Empty<KeyValuePair<string,string>>()
                : new [] { new KeyValuePair<string,string>("client_secret", clientSecretOrNull) }))
        };

        var resp = await http.SendAsync(req);
        resp.EnsureSuccessStatusCode();
        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        // Access Token extrahieren
        return doc.RootElement.GetProperty("access_token").GetString();
    }

    // ---------- Helpers: Vault (mTLS) ----------

    /// <summary>
    /// Baut einen HttpClient für Vault mit mTLS:
    /// - Server-CA wird gepinnt
    /// - Client-Zertifikat wird präsentiert
    /// - BaseAddress und Vault-Token werden gesetzt
    /// </summary>
    private static async Task<HttpClient> BuildVaultHttpClientAsync()
    {
        // Trust Anchor (Server-CA)
        var serverCaPem = await File.ReadAllTextAsync(P("tests/Certs/ca.pem"));
        var serverCa    = X509Certificate2.CreateFromPem(serverCaPem);
        var anchors     = new X509Certificate2Collection { serverCa };

        // mTLS Client-Zertifikat (PEM+Key → PFX)
        var clientCertPem = await File.ReadAllTextAsync(P("tests/Certs/client.pem"));
        var clientKeyPem  = await File.ReadAllTextAsync(P("tests/Certs/client.key"));
        var client = X509Certificate2.CreateFromPem(clientCertPem, clientKeyPem);
        client = new X509Certificate2(
            client.Export(X509ContentType.Pfx), (string?)null,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);

        // HttpClient mit mTLS bauen
        var http = HttpClientFactory.Build(
            trustAnchors: anchors,
            protocols: SslProtocols.Tls12 | SslProtocols.Tls13,
            clientCertificate: client);

        // Vault-Basisadresse + Zugriffstoken setzen
        http.BaseAddress = new Uri(Environment.GetEnvironmentVariable("VAULT_ADDR") ?? "https://127.0.0.1:8200");
        http.DefaultRequestHeaders.Add("X-Vault-Token",
            Environment.GetEnvironmentVariable("VAULT_TOKEN") ?? "hvs.pb8h7f1TX7vDEMmLnbkpq9CA");

        return http;
    }

    /// <summary>
    /// Baut ein Context-Objekt (Mandant/KeyId/Purpose/Tweak) für Tokenize/Detokenize.
    /// </summary>
    private static Context Ctx(byte[] tweak, string tenant = "devtenant", string keyId = "k1", string purpose = "tests")
        => new Context
        {
            TenantId = tenant,
            KeyId = keyId,
            Purpose = purpose,
            Tweak = ByteString.CopyFrom(tweak ?? Array.Empty<byte>())
        };

    // ---------- Tests ----------

    /// <summary>
    /// Happy Path:
    /// - Holt ein JWT mit Scopes "tokenize detokenize"
    /// - Startet gRPC-Testserver mit mTLS und AuthorizationInterceptor (Keycloak-JWKS)
    /// - Tokenize(FPE) + Detokenize Roundtrip mit Vault-Keys und Vault-TokenStore
    /// </summary>
    [Fact]
    public async Task Succeeds_With_KeycloakJWT_mTLS_And_Vault_Providers()
    {
        // ---- Keycloak-Konfiguration (aus ENV oder Defaults) ----
        var kcBase   = Environment.GetEnvironmentVariable("KC_BASE")   ?? "https://127.0.0.1:8443";
        var kcRealm  = Environment.GetEnvironmentVariable("KC_REALM")  ?? "itprojekt";
        var kcClient = Environment.GetEnvironmentVariable("KC_CLIENT_ID") ?? "tokenization-api";
        var kcSecret = Environment.GetEnvironmentVariable("KC_CLIENT_SECRET")?? "7A9gVWVmzLuHcDrPGURheMaHEiQotX0l";

        // mTLS-HttpClient für Keycloak
        using var httpKc = BuildMtlsClientForKeycloak();
        httpKc.BaseAddress = new Uri(kcBase);

        // ---- Vault: KeyProvider + TokenStore über mTLS ----
        using var httpVault  = await BuildVaultHttpClientAsync();
        var kvMount          = Environment.GetEnvironmentVariable("VAULT_KV_MOUNT") ?? "kv";
        using var keyProvider = new VaultHttpKeyProvider(httpVault, kvMount);
        using var tokenStore  = new VaultHttpTokenStore(httpVault, kvMount);

        // ---- Service mit echter FPE-Engine (FF1) ----
        var fpe = new BcFpeEngine(BcFpeEngine.Mode.FF1);
        var svc = new TokenizationServiceImpl(keyProvider, tokenStore, fpe, storeNonReversible: true);

        // ---- Authorization-Interceptor: Keycloak JWKS-Validator ----
        // Wichtig: issuer muss exakt mit "iss" im JWT übereinstimmen (hier Keycloak-URL für den Realm).
        var issuer   = "https://localhost:8443/realms/itprojekt";
        var audience = kcClient;
        using var validator = new KeycloakAccessTokenValidator(httpKc, issuer, audience);
        var interceptor = new AuthorizationInterceptor(validator);

        // ---- gRPC-Testserver mit mTLS und echten PEMs starten ----
        server = new TestServer(
            svc,
            host: "localhost", // muss zu SAN in server.pem passen
            interceptor: interceptor,
            mtls: true,
            caPemPath: P("tests/Certs/ca.pem"),
            serverCertPemPath: P("tests/Certs/server.pem"),
            serverKeyPemPath: P("tests/Certs/server.key"),
            clientCertPemPath: P("tests/Certs/client.pem"),
            clientKeyPemPath: P("tests/Certs/client.key"));
        {
            // ---- Access Token (mit beiden Scopes) holen ----
            httpKc.BaseAddress = new Uri(kcBase);
            var accessToken = await GetKeycloakTokenAsync(
                httpKc, kcBase, kcRealm, kcClient, kcSecret, scopes: "tokenize detokenize");

            // Authorization-Header an gRPC-Calls anhängen
            var headers = new Metadata { { "authorization", $"Bearer {accessToken}" } };
            var client  = server.Client;

            // Roundtrip mit FPE (numerische Domain; Formatpreserving)
            var pt    = "4111111111111111";
            var tweak = Encoding.UTF8.GetBytes("order-42");

            var tok = await client.TokenizeAsync(new TokenizeRequest
            {
                TokenType = TokenType.Fpe,
                Context   = Ctx(tweak, tenant: "devtenant", keyId: "k1"),
                Items     = { new FieldPayload { Field = "credit_card", Plaintext = pt, DataClass = DataClass.CreditCard, PreserveFormat = true } }
            }, headers);

            // Erwartung: keine Fehler, 1 Token, Prefix "v1.f."
            Assert.Empty(tok.Errors);
            Assert.Single(tok.Items);
            Assert.StartsWith("v1.f.", tok.Items[0].Token);

            // Detokenize → sollte Original wiederherstellen
            var det = await client.DetokenizeAsync(new DetokenizeRequest
            {
                Context = Ctx(tweak, tenant: "devtenant", keyId: "k1"),
                Items   = { new TokenizedField { Field = "credit_card", Token = tok.Items[0].Token } }
            }, headers);

            Assert.Empty(det.Errors);
            Assert.Single(det.Items);
            Assert.Equal(pt, det.Items[0].Plaintext);
        }
    }

    /// <summary>
    /// Negativtest:
    /// - Startet den mTLS-Server mit Auth-Interceptor
    /// - Ruft OHNE Bearer-Token auf → Erwartet StatusCode.Unauthenticated
    /// </summary>
    [Fact]
    public async Task Fails_Without_Bearer_Token()
    {
        // Minimaler Server (aber mTLS) für Unauthenticated-Check
        using var httpVault  = await BuildVaultHttpClientAsync();
        var kvMount          = Environment.GetEnvironmentVariable("VAULT_KV_MOUNT") ?? "kv";
        using var keyProvider = new VaultHttpKeyProvider(httpVault, kvMount);
        using var tokenStore  = new VaultHttpTokenStore(httpVault, kvMount);
        var fpe = new BcFpeEngine(BcFpeEngine.Mode.FF1);

        // Validator ist vorhanden, aber wir senden KEIN Bearer → Interceptor soll 401 liefern
        var kcBase   = Environment.GetEnvironmentVariable("KC_BASE")  ?? "https://127.0.0.1:8443";
        var kcRealm  = Environment.GetEnvironmentVariable("KC_REALM") ?? "itprojekt";
        var issuer   = $"{kcBase.TrimEnd('/')}/realms/{kcRealm}";
        var audience = Environment.GetEnvironmentVariable("KC_CLIENT_ID") ?? "tokenization-api";
        using var httpKc = BuildMtlsClientForKeycloak();
        using var validator = new KeycloakAccessTokenValidator(httpKc, issuer, audience);
        var interceptor = new AuthorizationInterceptor(validator);

        // Testserver mit mTLS & Interceptor; anschließend gRPC-Aufruf ohne Authorization
        server = new TestServer(
            new TokenizationServiceImpl(keyProvider, tokenStore, fpe, storeNonReversible: true),
            host: "localhost",
            interceptor: interceptor,
            mtls: true,
            caPemPath:        P("tests/Certs/ca.pem"),
            serverCertPemPath:P("tests/Certs/server.pem"),
            serverKeyPemPath: P("tests/Certs/server.key"),
            clientCertPemPath:P("tests/Certs/client.pem"),
            clientKeyPemPath: P("tests/Certs/client.key"));
        {
            var client = server.Client;

            // Erwartet RpcException(StatusCode.Unauthenticated) wegen fehlendem Bearer
            var ex = await Assert.ThrowsAsync<RpcException>(async () =>
                await client.TokenizeAsync(new TokenizeRequest
                {
                    TokenType = TokenType.Random,
                    Context = new Context { TenantId = "t", KeyId = "k" },
                    Items = { new FieldPayload { Field = "email", Plaintext = "x@y", DataClass = DataClass.Email } }
                }).ResponseAsync);

            Assert.Equal(StatusCode.Unauthenticated, ex.StatusCode);
        }
    }

    /// <summary>
    /// Aufräumen: Test-Server stoppen.
    /// </summary>
    public void Dispose() => server?.Dispose();
}
