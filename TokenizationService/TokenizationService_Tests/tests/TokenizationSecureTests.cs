using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using em.Tokenization.V1;
using Google.Protobuf;
using Grpc.Core;
using TokenizationService_Tests.tests.Utils;
using TokenizationService.Authorization;
using TokenizationService.CryptoImpl;
using TokenizationService.Factory;
using TokenizationService.KeyManagement;
using TokenizationService.KeyManagment;
using TokenizationService.Tokenization;
// TokenizationServiceImpl
// AuthorizationInterceptor, KeycloakAccessTokenValidator
// BcFpeEngine
// HttpClientFactory (mTLS HttpClient)
// VaultHttpTokenStore

// VaultHttpKeyProvider

/// <summary>
///     End-to-end tests for the Tokenization service with:
///     - an mTLS-protected gRPC test server (custom PEMs)
///     - OAuth2/JWT via Keycloak (scopes "tokenize"/"detokenize")
///     - key store & token store in HashiCorp Vault (KV v2)
/// </summary>
public sealed class TokenizationSecureTests : IDisposable
{
    private TestServer server; // helper server (binds service + certificates + interceptor)

    /// <summary>
    ///     Cleanup: stop the test server.
    /// </summary>
    public void Dispose()
    {
        server?.Dispose();
    }

    /// <summary>
    ///     Helper: resolve paths relative to the test binary directory.
    /// </summary>
    private static string P(string rel)
    {
        return Path.Combine(AppContext.BaseDirectory, rel.Replace('/', Path.DirectorySeparatorChar));
    }

    // ---------- Helpers: Keycloak ----------

    /// <summary>
    ///     Builds an HttpClient for Keycloak with mTLS:
    ///     - server CA is set as trust anchor
    ///     - client certificate (PEM + key) is presented as client-auth certificate
    /// </summary>
    private static HttpClient BuildMtlsClientForKeycloak()
    {
        // Read CA and use as trust anchor
        var caPem = File.ReadAllText(P("tests/Certs/ca.pem"));
        var serverCa = X509Certificate2.CreateFromPem(caPem);
        var anchors = new X509Certificate2Collection { serverCa };

        // Load client cert (PEM) + key and convert to PFX (for HttpClientHandler)
        var flags =
            OperatingSystem.IsWindows()
                ? X509KeyStorageFlags.MachineKeySet // or UserKeySet for non-service apps
                  | X509KeyStorageFlags.PersistKeySet
                  | X509KeyStorageFlags.Exportable
                : X509KeyStorageFlags.EphemeralKeySet // fine on Linux/macOS
                  | X509KeyStorageFlags.Exportable;

        var client = new X509Certificate2("tests/Certs/client.p12", "changeit", flags);

        // Build HttpClient with mTLS (TLS 1.2 + 1.3 if available)
        var http = HttpClientFactory.Build(
            anchors,
            SslProtocols.Tls12 | SslProtocols.Tls13,
            client);
        return http;
    }

    /// <summary>
    ///     Obtains an access token from Keycloak via the client credentials flow.
    ///     Scopes are included in the request (e.g., "tokenize detokenize").
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
            Content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "client_credentials"),
                    new KeyValuePair<string, string>("client_id", clientId),
                    new KeyValuePair<string, string>("scope", scopes)
                }
                // Client secret is optional (with mTLS client auth it may not be required)
                .Concat(string.IsNullOrEmpty(clientSecretOrNull)
                    ? Array.Empty<KeyValuePair<string, string>>()
                    : new[] { new KeyValuePair<string, string>("client_secret", clientSecretOrNull) }))
        };

        var resp = await http.SendAsync(req);
        resp.EnsureSuccessStatusCode();
        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        // Extract access token
        return doc.RootElement.GetProperty("access_token").GetString();
    }

    // ---------- Helpers: Vault (mTLS) ----------

    /// <summary>
    ///     Builds an HttpClient for Vault with mTLS:
    ///     - server CA is pinned
    ///     - client certificate is presented
    ///     - BaseAddress and Vault token are set
    /// </summary>
    private static async Task<HttpClient> BuildVaultHttpClientAsync()
    {
        // Trust anchor (server CA)
        var serverCaPem = await File.ReadAllTextAsync(P("tests/Certs/ca.pem"));
        var serverCa = X509Certificate2.CreateFromPem(serverCaPem);
        var anchors = new X509Certificate2Collection { serverCa };

        // mTLS client certificate (PEM + key → PFX)
        var clientCertPem = await File.ReadAllTextAsync(P("tests/Certs/client.pem"));
        var clientKeyPem = await File.ReadAllTextAsync(P("tests/Certs/client.key"));
        var client = X509Certificate2.CreateFromPem(clientCertPem, clientKeyPem);
        client = new X509Certificate2(
            client.Export(X509ContentType.Pfx), (string?)null,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);

        // Build HttpClient with mTLS
        var http = HttpClientFactory.Build(
            anchors,
            SslProtocols.Tls12 | SslProtocols.Tls13,
            client);

        // Set Vault base address + access token
        http.BaseAddress = new Uri(Environment.GetEnvironmentVariable("VAULT_ADDR") ?? "https://127.0.0.1:8200");
        http.DefaultRequestHeaders.Add("X-Vault-Token",
            Environment.GetEnvironmentVariable("VAULT_TOKEN") ?? "hvs.pb8h7f1TX7vDEMmLnbkpq9CA");

        return http;
    }

    /// <summary>
    ///     Builds a Context object (tenant/keyId/purpose/tweak) for Tokenize/Detokenize.
    /// </summary>
    private static Context Ctx(byte[] tweak, string tenant = "devtenant", string keyId = "k1", string purpose = "tests")
    {
        return new Context
        {
            TenantId = tenant,
            KeyId = keyId,
            Purpose = purpose,
            Tweak = ByteString.CopyFrom(tweak ?? Array.Empty<byte>())
        };
    }

    // ---------- Tests ----------

    /// <summary>
    ///     Happy path:
    ///     - obtains a JWT with scopes "tokenize detokenize"
    ///     - starts an mTLS gRPC test server with AuthorizationInterceptor (Keycloak JWKS)
    ///     - Tokenize(FPE) + Detokenize roundtrip using Vault keys and Vault token store
    /// </summary>
    [Fact]
    public async Task Succeeds_With_KeycloakJWT_mTLS_And_Vault_Providers()
    {
        // ---- Keycloak configuration (from ENV or defaults) ----
        var kcBase = Environment.GetEnvironmentVariable("KC_BASE") ?? "https://127.0.0.1:8443";
        var kcRealm = Environment.GetEnvironmentVariable("KC_REALM") ?? "tokenizationservice";
        var kcClient = Environment.GetEnvironmentVariable("KC_CLIENT_ID") ?? "tokenization-api";
        var kcSecret = Environment.GetEnvironmentVariable("KC_CLIENT_SECRET") ?? "7A9gVWVmzLuHcDrPGURheMaHEiQotX0l";

        // mTLS HttpClient for Keycloak
        using var httpKc = BuildMtlsClientForKeycloak();
        httpKc.BaseAddress = new Uri(kcBase);

        // ---- Vault: key provider + token store over mTLS ----
        using var httpVault = await BuildVaultHttpClientAsync();
        var kvMount = Environment.GetEnvironmentVariable("VAULT_KV_MOUNT") ?? "kv";
        using var keyProvider = new VaultHttpKeyProvider(httpVault, kvMount);
        using var tokenStore = new VaultHttpTokenStore(httpVault, kvMount);

        // ---- Service with real FPE engine (FF1) ----
        var fpe = new BcFpeEngine();
        var svc = new TokenizationServiceImpl(keyProvider, tokenStore, fpe, true);

        // ---- Authorization interceptor: Keycloak JWKS validator ----
        // Important: issuer must match the "iss" claim in the JWT exactly (Keycloak realm URL).
        var issuer = "https://localhost:8443/realms/tokenizationservice";
        var audience = kcClient;
        using var validator = new KeycloakAccessTokenValidator(httpKc, issuer, audience);
        var interceptor = new AuthorizationInterceptor(validator);

        // ---- Start mTLS gRPC test server with real PEMs ----
        server = new TestServer(
            svc,
            "localhost", // must match SAN in server.pem
            interceptor,
            true,
            P("tests/Certs/ca.pem"),
            P("tests/Certs/server.pem"),
            P("tests/Certs/server.key"),
            P("tests/Certs/client.pem"),
            P("tests/Certs/client.key"));
        {
            // ---- Obtain access token (with both scopes) ----
            httpKc.BaseAddress = new Uri(kcBase);
            var accessToken = await GetKeycloakTokenAsync(
                httpKc, kcBase, kcRealm, kcClient, kcSecret);

            // Attach Authorization header to gRPC calls
            var headers = new Metadata { { "authorization", $"Bearer {accessToken}" } };
            var client = server.Client;

            // Roundtrip using FPE (numeric domain; format-preserving)
            var pt = "4111111111111111";
            var tweak = Encoding.UTF8.GetBytes("order-42");

            var tok = await client.TokenizeAsync(new TokenizeRequest
            {
                TokenType = TokenType.Fpe,
                Context = Ctx(tweak),
                Items =
                {
                    new FieldPayload
                    {
                        Field = "credit_card", Plaintext = pt, DataClass = DataClass.CreditCard, PreserveFormat = true
                    }
                }
            }, headers);

            // Expectation: no errors, 1 token, prefix "v1.f."
            Assert.Empty(tok.Errors);
            Assert.Single(tok.Items);
            Assert.StartsWith("v1.f.", tok.Items[0].Token);

            // Detokenize → should restore the original
            var det = await client.DetokenizeAsync(new DetokenizeRequest
            {
                Context = Ctx(tweak),
                Items = { new TokenizedField { Field = "credit_card", Token = tok.Items[0].Token } }
            }, headers);

            Assert.Empty(det.Errors);
            Assert.Single(det.Items);
            Assert.Equal(pt, det.Items[0].Plaintext);
        }
    }

    /// <summary>
    ///     Negative test:
    ///     - starts the mTLS server with auth interceptor
    ///     - calls WITHOUT a bearer token → expects StatusCode.Unauthenticated
    /// </summary>
    [Fact]
    public async Task Fails_Without_Bearer_Token()
    {
        // Minimal server (still mTLS) for unauthenticated check
        using var httpVault = await BuildVaultHttpClientAsync();
        var kvMount = Environment.GetEnvironmentVariable("VAULT_KV_MOUNT") ?? "kv";
        using var keyProvider = new VaultHttpKeyProvider(httpVault, kvMount);
        using var tokenStore = new VaultHttpTokenStore(httpVault, kvMount);
        var fpe = new BcFpeEngine();

        // Validator exists, but we send NO bearer → interceptor should return 401
        var kcBase = Environment.GetEnvironmentVariable("KC_BASE") ?? "https://127.0.0.1:8443";
        var kcRealm = Environment.GetEnvironmentVariable("KC_REALM") ?? "tokenizationservice";
        var issuer = $"{kcBase.TrimEnd('/')}/realms/{kcRealm}";
        var audience = Environment.GetEnvironmentVariable("KC_CLIENT_ID") ?? "tokenization-api";
        using var httpKc = BuildMtlsClientForKeycloak();
        using var validator = new KeycloakAccessTokenValidator(httpKc, issuer, audience);
        var interceptor = new AuthorizationInterceptor(validator);

        // Test server with mTLS & interceptor; then gRPC call without Authorization
        server = new TestServer(
            new TokenizationServiceImpl(keyProvider, tokenStore, fpe, true),
            "localhost",
            interceptor,
            true,
            P("tests/Certs/ca.pem"),
            P("tests/Certs/server.pem"),
            P("tests/Certs/server.key"),
            P("tests/Certs/client.pem"),
            P("tests/Certs/client.key"));
        {
            var client = server.Client;

            // Expect RpcException(StatusCode.Unauthenticated) due to missing bearer token
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
}