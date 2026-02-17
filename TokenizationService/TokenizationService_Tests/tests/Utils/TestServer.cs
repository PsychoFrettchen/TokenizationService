using em.Tokenization.V1;
using Grpc.Core;
using Grpc.Core.Interceptors;
using TokenizationService.Tokenization;

namespace TokenizationService_Tests.tests.Utils;

public sealed class TestServer : IDisposable
{
    /// <param name="svc">Already configured service instance (e.g., with Vault providers).</param>
    /// <param name="host">
    ///     Hostname/address the server binds to. Note: If TLS is enabled, the name used here must match
    ///     the SAN (Subject Alternative Name) of the server certificate, if the client connects by name
    ///     (not by IP).
    /// </param>
    /// <param name="interceptor">Optional interceptor (e.g., <c>AuthorizationInterceptor</c>).</param>
    /// <param name="mtls">
    ///     true = mTLS (server requires client certificates).
    ///     false = TLS without a client certificate (or insecure if no server PEMs are provided).
    /// </param>
    /// <param name="caPemPath">PEM with trusted CA(s) (server validates client; client trusts server).</param>
    /// <param name="serverCertPemPath">PEM of the server certificate.</param>
    /// <param name="serverKeyPemPath">PEM of the corresponding private key (PKCS#8/PKCS#1, unencrypted).</param>
    /// <param name="clientCertPemPath">PEM of the client certificate (only required for mTLS).</param>
    /// <param name="clientKeyPemPath">PEM of the client private key (only required for mTLS).</param>
    public TestServer(
        TokenizationServiceImpl svc,
        string host = "127.0.0.1",
        Interceptor interceptor = null,
        bool mtls = true,
        string caPemPath = "tests/Certs/ca.pem",
        string serverCertPemPath = "tests/Certs/server.pem",
        string serverKeyPemPath = "tests/Certs/server.key",
        string clientCertPemPath = "tests/Certs/client.pem",
        string clientKeyPemPath = "tests/Certs/client.key")
    {
        if (svc == null) throw new ArgumentNullException(nameof(svc));

        // Bind service (+ optional interceptor)
        var def = em.Tokenization.V1.TokenizationService.BindService(svc);
        if (interceptor != null) def = def.Intercept(interceptor);

        // Insecure – only if TLS/mTLS is explicitly off AND no server PEMs were provided.
        if (!mtls && string.IsNullOrWhiteSpace(serverCertPemPath))
        {
            Server = new Server
            {
                Services = { def },
                Ports = { new ServerPort(host, 0, ServerCredentials.Insecure) }
            };
            Server.Start();

            Port = Server.Ports.Single().BoundPort;
            Channel = new Channel(host, Port, ChannelCredentials.Insecure);
            Client = new em.Tokenization.V1.TokenizationService.TokenizationServiceClient(Channel);
            return;
        }

        // ---- Load PEMs (throws IO exception if missing; desired in tests) ----
        var caPem = !string.IsNullOrEmpty(caPemPath) ? File.ReadAllText(caPemPath) : null;
        var serverCertPem =
            !string.IsNullOrEmpty(serverCertPemPath) ? File.ReadAllText(serverCertPemPath) : null;
        var serverKeyPem = !string.IsNullOrEmpty(serverKeyPemPath) ? File.ReadAllText(serverKeyPemPath) : null;
        var clientCertPem =
            !string.IsNullOrEmpty(clientCertPemPath) ? File.ReadAllText(clientCertPemPath) : null;
        var clientKeyPem = !string.IsNullOrEmpty(clientKeyPemPath) ? File.ReadAllText(clientKeyPemPath) : null;

        // ---- Create server credentials ----
        ServerCredentials serverCreds;
        if (mtls)
        {
            if (string.IsNullOrEmpty(caPem) || string.IsNullOrEmpty(serverCertPem) ||
                string.IsNullOrEmpty(serverKeyPem))
                throw new ArgumentException("For mTLS, caPem, serverCertPem, and serverKeyPem must be set.");

            serverCreds = new SslServerCredentials(
                new[] { new KeyCertificatePair(serverCertPem, serverKeyPem) },
                caPem,
                true); // enforce mTLS
        }
        else
        {
            if (string.IsNullOrEmpty(serverCertPem) || string.IsNullOrEmpty(serverKeyPem))
                throw new ArgumentException("For TLS (without mTLS), serverCertPem and serverKeyPem must be set.");

            // TLS without client auth
            serverCreds = new SslServerCredentials(
                new[] { new KeyCertificatePair(serverCertPem, serverKeyPem) },
                null,
                false);
        }

        // Start server (port 0 = let the OS choose)
        Server = new Server { Services = { def }, Ports = { new ServerPort(host, 0, serverCreds) } };
        Server.Start();
        Port = Server.Ports.Single().BoundPort;

        // ---- Create client credentials ----
        ChannelCredentials clientCreds;
        if (mtls)
        {
            if (string.IsNullOrEmpty(caPem) || string.IsNullOrEmpty(clientCertPem) ||
                string.IsNullOrEmpty(clientKeyPem))
                throw new ArgumentException(
                    "For an mTLS client, caPem, clientCertPem, and clientKeyPem must be set.");

            clientCreds = new SslCredentials(
                caPem, // trust the server CA
                new KeyCertificatePair(clientCertPem, clientKeyPem)); // send client cert
        }
        else
        {
            // TLS without client certificate – client only needs to trust the server CA
            if (string.IsNullOrEmpty(caPem))
                throw new ArgumentException("For TLS, a trusted CA (caPem) should be provided.");
            clientCreds = new SslCredentials(caPem);
        }

        // Channel + client
        Channel = new Channel(host, Port, clientCreds);
        Client = new em.Tokenization.V1.TokenizationService.TokenizationServiceClient(Channel);
    }

    /// <summary>The started gRPC server.</summary>
    public Server Server { get; }

    /// <summary>The client channel to the local server (incl. TLS/mTLS depending on configuration).</summary>
    public Channel Channel { get; }

    /// <summary>Convenient, already-bound gRPC client for <see cref="TokenizationService" />.</summary>
    public em.Tokenization.V1.TokenizationService.TokenizationServiceClient Client { get; }

    /// <summary>The port actually bound by the server (0 = ephemeral → this is the assigned one).</summary>
    public int Port { get; }

    /// <summary>
    ///     Shuts down channel and server cleanly.
    /// </summary>
    public void Dispose()
    {
        try
        {
            Channel?.ShutdownAsync().Wait();
        }
        catch
        {
            /* tests: best effort */
        }

        try
        {
            Server?.ShutdownAsync().Wait();
        }
        catch
        {
            /* tests: best effort */
        }
    }
}