using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Grpc.Core;
using em.Tokenization.V1;
using Google.Protobuf;
using IT_Projekt;
using IT_Projekt.Authorization;
using IT_Projekt.CryptoImpl;
using IT_Projekt.Factory;
using IT_Projekt.KeyManagement;
using IT_Projekt.KeyManagment;


/// <summary>
/// End-to-End Test: Keycloak (JWT über mTLS) + Vault (Keys/Tokens) + gRPC Service.
/// Testet, ob Tokenisierung und Detokenisierung über den gesamten Stack funktioniert.
/// </summary>
public class Tokenization_E2E_Keycloak_Vault_Tests : IDisposable
{
    private TestServer server;

    /// <summary>
    /// Hilfsfunktion: Konvertiert einen relativen Pfad ins Test-Zertifikatsverzeichnis.
    /// </summary>
    private static string P(string rel) =>
        Path.Combine(AppContext.BaseDirectory, rel.Replace('/', Path.DirectorySeparatorChar));

    // -------- Keycloak helpers --------

    /// <summary>
    /// Fordert ein Access Token bei Keycloak an (Client-Credentials-Flow).
    /// </summary>
    private static async Task<string> GetKeycloakTokenAsync(HttpClient http, string baseUrl, string realm,
        string clientId, string clientSecretOrNull, string scopes = "tokenize detokenize")
    {
        var tokenEndpoint = $"{baseUrl.TrimEnd('/')}/realms/{realm}/protocol/openid-connect/token";
        using var req = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
        {
            Content = new FormUrlEncodedContent(new[]
                {
                    new System.Collections.Generic.KeyValuePair<string, string>("grant_type", "client_credentials"),
                    new System.Collections.Generic.KeyValuePair<string, string>("client_id", clientId),
                    new System.Collections.Generic.KeyValuePair<string, string>("scope", scopes),
                }
                .Concat(string.IsNullOrEmpty(clientSecretOrNull)
                    ? Array.Empty<System.Collections.Generic.KeyValuePair<string, string>>()
                    : new[]
                    {
                        new System.Collections.Generic.KeyValuePair<string, string>("client_secret", clientSecretOrNull)
                    }))
        };

        var resp = await http.SendAsync(req);
        resp.EnsureSuccessStatusCode();
        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("access_token").GetString();
    }

    /// <summary>
    /// Baut einen HttpClient für Keycloak, inkl. mTLS (Client-Zertifikat + CA Trust).
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
            trustAnchors: anchors,
            protocols: SslProtocols.Tls12 | SslProtocols.Tls13,
            clientCertificate: client);
        return http;
    }

    // -------- Vault helpers --------

    /// <summary>
    /// Baut einen HttpClient für Vault über mTLS, setzt BaseAddress + Token.
    /// </summary>
    private static async Task<HttpClient> BuildVaultHttpClientAsync()
    {
        // CA laden
        var serverCaPem = await File.ReadAllTextAsync(P("tests/Certs/ca.pem"));
        var serverCa = X509Certificate2.CreateFromPem(serverCaPem);
        var anchors = new X509Certificate2Collection { serverCa };

        // Client-Zertifikat laden
        var clientCertPem = await File.ReadAllTextAsync(P("tests/Certs/client.pem"));
        var clientKeyPem = await File.ReadAllTextAsync(P("tests/Certs/client.key"));
        var client = X509Certificate2.CreateFromPem(clientCertPem, clientKeyPem);
        client = new X509Certificate2(
            client.Export(X509ContentType.Pfx), (string)null,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);

        // Client-Zertifikat laden
        var http = IT_Projekt.Factory.HttpClientFactory.Build(
            trustAnchors: anchors,
            protocols: SslProtocols.Tls12 | SslProtocols.Tls13,
            clientCertificate: client);

        http.BaseAddress = new Uri("https://127.0.0.1:8200");
        http.DefaultRequestHeaders.Add("X-Vault-Token",
            Environment.GetEnvironmentVariable("VAULT_TOKEN") ?? "hvs.pb8h7f1TX7vDEMmLnbkpq9CA");

        return http;
    }

    /// <summary>
    /// Baut einen gRPC-Context für Tokenisierung.
    /// </summary>
    private static Context Ctx(byte[] tweak, string tenant = "t-acme", string keyId = "k1", string purpose = "tests")
        => new Context
        {
            TenantId = tenant,
            KeyId = keyId,
            Purpose = purpose,
            Tweak = ByteString.CopyFrom(tweak ?? Array.Empty<byte>())
        };

    [Fact]
    public async Task EndToEnd_Keycloak_mTLS_JWT_Vault_FPE_Roundtrip()
    {
        // ---------- Keycloak-Konfiguration ----------
        var kcBase = Environment.GetEnvironmentVariable("KC_BASE") ?? "https://127.0.0.1:8443";
        var kcRealm = Environment.GetEnvironmentVariable("KC_REALM") ?? "itprojekt";
        var kcClient = Environment.GetEnvironmentVariable("KC_CLIENT_ID") ?? "tokenization-api";
        var kcSecret = Environment.GetEnvironmentVariable("KC_CLIENT_SECRET") ?? "7A9gVWVmzLuHcDrPGURheMaHEiQotX0l";

        using var httpKeycloak = BuildMtlsClientForKeycloak();

        // ---------- Vault-Provider/Store ----------
        using var http = await BuildVaultHttpClientAsync();
        var kvMount = Environment.GetEnvironmentVariable("VAULT_KV_MOUNT") ?? "kv";
        using var keyProvider = new VaultHttpKeyProvider(http, kvMount);
        using var tokenStore = new VaultHttpTokenStore(http, kvMount);

        // ---------- Service mit FPE Engine ----------
        var fpe = new BcFpeEngine(BcFpeEngine.Mode.FF1);
        var svc = new TokenizationServiceImpl(keyProvider, tokenStore, fpe, storeNonReversible: true);

        // ---------- Authorization via Keycloak JWKS und mTLS ----------
        var issuer = $"https://localhost:8443/realms/itprojekt";
        var audience = kcClient;
        using var validator = new KeycloakAccessTokenValidator(httpKeycloak, issuer, audience);
        var interceptor = new AuthorizationInterceptor(validator);

        // ---------- TestServer mit PEMs (mTLS) ----------
        server = new TestServer(
            svc,
            host: "localhost", // must match SAN in server.pem
            interceptor: interceptor,
            mtls: true,
            caPemPath: P("tests/Certs/ca.pem"),
            serverCertPemPath: P("tests/Certs/server.pem"),
            serverKeyPemPath: P("tests/Certs/server.key"),
            clientCertPemPath: P("tests/Certs/client.pem"),
            clientKeyPemPath: P("tests/Certs/client.key"));
        {
            // ---------- JWT holen ----------
            httpKeycloak.BaseAddress = new Uri(kcBase);
            var token = await GetKeycloakTokenAsync(httpKeycloak, kcBase, kcRealm, kcClient, kcSecret,
                scopes: "tokenize detokenize");

            // ---------- gRPC Call mit Bearer ----------
            var client = server.Client;
            var headers = new Metadata { { "authorization", $"Bearer {token}" } };

            // Test-Daten
            var pt = "4111111111111111";
            var tweak = Encoding.UTF8.GetBytes("order-42");

            var tok = await client.TokenizeAsync(new TokenizeRequest
            {
                TokenType = TokenType.Fpe,
                Context = Ctx(tweak, tenant: "devtenant", keyId: "k1"),
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
                Context = Ctx(tweak, tenant: "devtenant", keyId: "k1"),
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
        // ---------- Keycloak/Vault/Service Setup wie im Erfolgstest ----------
        var kcClient = Environment.GetEnvironmentVariable("KC_CLIENT_ID") ?? "tokenization-api";

        using var httpKeycloak = BuildMtlsClientForKeycloak();

        using var http = await BuildVaultHttpClientAsync();
        var kvMount = Environment.GetEnvironmentVariable("VAULT_KV_MOUNT") ?? "kv";
        using var keyProvider = new VaultHttpKeyProvider(http, kvMount);
        using var tokenStore = new VaultHttpTokenStore(http, kvMount);

        var fpe = new BcFpeEngine(BcFpeEngine.Mode.FF1);
        var svc = new TokenizationServiceImpl(keyProvider, tokenStore, fpe, storeNonReversible: true);

        // Der Validator erwartet Tokens vom realen Issuer + Audience = kcClient
        var issuer = $"https://localhost:8443/realms/itprojekt";
        var audience = kcClient;
        using var validator = new KeycloakAccessTokenValidator(httpKeycloak, issuer, audience);
        var interceptor = new AuthorizationInterceptor(validator);

        server = new TestServer(
            svc,
            host: "localhost",
            interceptor: interceptor,
            mtls: true,
            caPemPath: P("tests/Certs/ca.pem"),
            serverCertPemPath: P("tests/Certs/server.pem"),
            serverKeyPemPath: P("tests/Certs/server.key"),
            clientCertPemPath: P("tests/Certs/client.pem"),
            clientKeyPemPath: P("tests/Certs/client.key"));

        // ---------- Gefälschten JWT bauen ----------
        // Header gibt RS256 an, Payload hat absichtlich falschen Issuer/Audience (passt NICHT zu validator),
        // und die "Signatur" ist kaputt. Das reicht, damit die Signaturprüfung/Issuer-Prüfung scheitert.
        // Base64URL-Teile sind fest codiert, damit kein Helper nötig ist.
        var fakeHeader = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"; // {"alg":"RS256","typ":"JWT"}
        var fakePayload =
            "eyJpc3MiOiJodHRwczovL21hbGljaW91cy9yZWFsbXMvZXZpbCIsImF1ZCI6Indyb25nIiwic2NvcGUiOiJ0b2tlbml6ZSIsImV4cCI6MjUzNDA5ODQwMH0";
        var fakeSig = "invalid_signature";
        var fakeJwt = $"{fakeHeader}.{fakePayload}.{fakeSig}";

        var client = server.Client;
        var headers = new Metadata { { "authorization", $"Bearer {fakeJwt}" } };

        // ---------- Aufruf, der scheitern MUSS ----------
        var pt = "4111111111111111";
        var tweak = Encoding.UTF8.GetBytes("order-42");

        var ex = await Assert.ThrowsAsync<RpcException>(async () =>
            await client.TokenizeAsync(new TokenizeRequest
            {
                TokenType = TokenType.Fpe,
                Context = Ctx(tweak, tenant: "devtenant", keyId: "k1"),
                Items =
                {
                    new FieldPayload
                    {
                        Field = "credit_card", Plaintext = pt, DataClass = DataClass.CreditCard, PreserveFormat = true
                    }
                }
            }, headers));

        // Erwartung: Auth schlägt fehl, bevor der Service überhaupt arbeitet.
        Assert.Equal(StatusCode.Unauthenticated, ex.Status.StatusCode);
    }
    
    public void Dispose()
    {
        server?.Dispose();
    }
}