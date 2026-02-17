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

/// <summary>
///     End-to-end test: Keycloak (JWT over mTLS) + Vault (keys/tokens) + gRPC service.
///     Tests whether tokenization and detokenization work across the entire stack.
/// </summary>
public class Tokenization_E2E_Keycloak_Vault_Tests : IDisposable
{
    private TestServer server;

    public void Dispose()
    {
        server?.Dispose();
    }

    /// <summary>
    ///     Helper: converts a relative path into the test certificate directory.
    /// </summary>
    private static string P(string rel)
    {
        return Path.Combine(AppContext.BaseDirectory, rel.Replace('/', Path.DirectorySeparatorChar));
    }

    // -------- Keycloak helpers --------

    /// <summary>
    ///     Requests an access token from Keycloak (client credentials flow).
    /// </summary>
    private static async Task<string> GetKeycloakTokenAsync(HttpClient http, string baseUrl, string realm,
        string clientId, string clientSecretOrNull, string scopes = "tokenize detokenize")
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
                .Concat(string.IsNullOrEmpty(clientSecretOrNull)
                    ? Array.Empty<KeyValuePair<string, string>>()
                    : new[]
                    {
                        new KeyValuePair<string, string>("client_secret", clientSecretOrNull)
                    }))
        };

        var resp = await http.SendAsync(req);
        resp.EnsureSuccessStatusCode();
        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("access_token").GetString();
    }

    /// <summary>
    ///     Builds an HttpClient for Keycloak, including mTLS (client certificate + CA trust).
    /// </summary>
    private static HttpClient BuildMtlsClientForKeycloak()
    {
        // mTLS for Keycloak: trust server CA + present client cert
        var caPem = File.ReadAllText(P("tests/Certs/ca.pem"));
        var serverCa = X509Certificate2.CreateFromPem(caPem);
        var anchors = new X509Certificate2Collection { serverCa };
        var flags =
            OperatingSystem.IsWindows()
                ? X509KeyStorageFlags.MachineKeySet
                  | X509KeyStorageFlags.PersistKeySet
                  | X509KeyStorageFlags.Exportable
                : X509KeyStorageFlags.EphemeralKeySet // Linux/macOS
                  | X509KeyStorageFlags.Exportable;

        var client = new X509Certificate2("tests/Certs/client.p12", "changeit", flags);

        var http = HttpClientFactory.Build(
            anchors,
            SslProtocols.Tls12 | SslProtocols.Tls13,
            client);
        return http;
    }

    // -------- Vault helpers --------

    /// <summary>
    ///     Builds an HttpClient for Vault over mTLS and sets BaseAddress + token.
    /// </summary>
    private static async Task<HttpClient> BuildVaultHttpClientAsync()
    {
        // Load CA
        var serverCaPem = await File.ReadAllTextAsync(P("tests/Certs/ca.pem"));
        var serverCa = X509Certificate2.CreateFromPem(serverCaPem);
        var anchors = new X509Certificate2Collection { serverCa };

        // Load client certificate
        var clientCertPem = await File.ReadAllTextAsync(P("tests/Certs/client.pem"));
        var clientKeyPem = await File.ReadAllTextAsync(P("tests/Certs/client.key"));
        var client = X509Certificate2.CreateFromPem(clientCertPem, clientKeyPem);
        client = new X509Certificate2(
            client.Export(X509ContentType.Pfx), (string)null,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);

        // Build HttpClient
        var http = HttpClientFactory.Build(
            anchors,
            SslProtocols.Tls12 | SslProtocols.Tls13,
            client);

        http.BaseAddress = new Uri("https://127.0.0.1:8200");
        http.DefaultRequestHeaders.Add("X-Vault-Token",
            Environment.GetEnvironmentVariable("VAULT_TOKEN") ?? "hvs.pb8h7f1TX7vDEMmLnbkpq9CA");

        return http;
    }

    /// <summary>
    ///     Builds a gRPC context for tokenization.
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

    [Fact]
    public async Task EndToEnd_Keycloak_mTLS_JWT_Vault_FPE_Roundtrip()
    {
        // ---------- Keycloak configuration ----------
        var kcBase = Environment.GetEnvironmentVariable("KC_BASE") ?? "https://127.0.0.1:8443";
        var kcRealm = Environment.GetEnvironmentVariable("KC_REALM") ?? "tokenizationservice";
        var kcClient = Environment.GetEnvironmentVariable("KC_CLIENT_ID") ?? "tokenization-api";
        var kcSecret = Environment.GetEnvironmentVariable("KC_CLIENT_SECRET") ?? "7A9gVWVmzLuHcDrPGURheMaHEiQotX0l";

        using var httpKeycloak = BuildMtlsClientForKeycloak();

        // ---------- Vault provider/store ----------
        using var http = await BuildVaultHttpClientAsync();
        var kvMount = Environment.GetEnvironmentVariable("VAULT_KV_MOUNT") ?? "kv";
        using var keyProvider = new VaultHttpKeyProvider(http, kvMount);
        using var tokenStore = new VaultHttpTokenStore(http, kvMount);

        // ---------- Service with FPE engine ----------
        var fpe = new BcFpeEngine();
        var svc = new TokenizationServiceImpl(keyProvider, tokenStore, fpe, true);

        // ---------- Authorization via Keycloak JWKS and mTLS ----------
        var issuer = "https://localhost:8443/realms/tokenizationservice";
        var audience = kcClient;
        using var validator = new KeycloakAccessTokenValidator(httpKeycloak, issuer, audience);
        var interceptor = new AuthorizationInterceptor(validator);

        // ---------- TestServer with PEMs (mTLS) ----------
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
            // ---------- Fetch JWT ----------
            httpKeycloak.BaseAddress = new Uri(kcBase);
            var token = await GetKeycloakTokenAsync(httpKeycloak, kcBase, kcRealm, kcClient, kcSecret);

            // ---------- gRPC call with Bearer ----------
            var client = server.Client;
            var headers = new Metadata { { "authorization", $"Bearer {token}" } };

            // Test data
            var pt = "4111111111111111";
            var tweak = Encoding.UTF8.GetBytes("order-42");

            var tok = await client.TokenizeAsync(new TokenizeRequest
            {
                TokenType = TokenType.Fpe,
                Context = Ctx(tweak, "devtenant"),
                Items =
                {
                    new FieldPayload
                    {
                        Field = "credit_card", Plaintext = pt, DataClass = DataClass.CreditCard, PreserveFormat = true
                    }
                }
            }, headers);

            Assert.Empty(tok.Errors);
            Assert.Single(tok.Items);
            Assert.StartsWith("v1.f.", tok.Items[0].Token);

            // --- Detokenize ---
            var det = await client.DetokenizeAsync(new DetokenizeRequest
            {
                Context = Ctx(tweak, "devtenant"),
                Items = { new TokenizedField { Field = "credit_card", Token = tok.Items[0].Token } }
            }, headers);

            Assert.Empty(det.Errors);
            Assert.Single(det.Items);
            Assert.Equal(pt, det.Items[0].Plaintext);
        }
    }

    [Fact]
    public async Task Rejects_Fake_Keycloak_Token_With_Wrong_Issuer_And_Signature()
    {
        // ---------- Keycloak/Vault/Service setup as in the success test ----------
        var kcClient = Environment.GetEnvironmentVariable("KC_CLIENT_ID") ?? "tokenization-api";

        using var httpKeycloak = BuildMtlsClientForKeycloak();

        using var http = await BuildVaultHttpClientAsync();
        var kvMount = Environment.GetEnvironmentVariable("VAULT_KV_MOUNT") ?? "kv";
        using var keyProvider = new VaultHttpKeyProvider(http, kvMount);
        using var tokenStore = new VaultHttpTokenStore(http, kvMount);

        var fpe = new BcFpeEngine();
        var svc = new TokenizationServiceImpl(keyProvider, tokenStore, fpe, true);

        // Validator expects tokens from the real issuer + audience = kcClient
        var issuer = "https://localhost:8443/realms/tokenizationservice";
        var audience = kcClient;
        using var validator = new KeycloakAccessTokenValidator(httpKeycloak, issuer, audience);
        var interceptor = new AuthorizationInterceptor(validator);

        server = new TestServer(
            svc,
            "localhost",
            interceptor,
            true,
            P("tests/Certs/ca.pem"),
            P("tests/Certs/server.pem"),
            P("tests/Certs/server.key"),
            P("tests/Certs/client.pem"),
            P("tests/Certs/client.key"));

        // ---------- Build a fake JWT ----------
        // Header indicates RS256, payload intentionally has the wrong issuer/audience (does NOT match validator),
        // and the "signature" is broken. That is enough to make signature/issuer validation fail.
        // Base64URL parts are hard-coded to avoid needing a helper.
        var fakeHeader = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"; // {"alg":"RS256","typ":"JWT"}
        var fakePayload =
            "eyJpc3MiOiJodHRwczovL21hbGljaW91cy9yZWFsbXMvZXZpbCIsImF1ZCI6Indyb25nIiwic2NvcGUiOiJ0b2tlbml6ZSIsImV4cCI6MjUzNDA5ODQwMH0";
        var fakeSig = "invalid_signature";
        var fakeJwt = $"{fakeHeader}.{fakePayload}.{fakeSig}";

        var client = server.Client;
        var headers = new Metadata { { "authorization", $"Bearer {fakeJwt}" } };

        // ---------- Call that MUST fail ----------
        var pt = "4111111111111111";
        var tweak = Encoding.UTF8.GetBytes("order-42");

        var ex = await Assert.ThrowsAsync<RpcException>(async () =>
            await client.TokenizeAsync(new TokenizeRequest
            {
                TokenType = TokenType.Fpe,
                Context = Ctx(tweak, "devtenant"),
                Items =
                {
                    new FieldPayload
                    {
                        Field = "credit_card", Plaintext = pt, DataClass = DataClass.CreditCard, PreserveFormat = true
                    }
                }
            }, headers));

        // Expectation: auth fails before the service does any work.
        Assert.Equal(StatusCode.Unauthenticated, ex.Status.StatusCode);
    }
}