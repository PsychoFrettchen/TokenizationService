using Grpc.Core;
using Grpc.Core.Interceptors;
using em.Tokenization.V1;
using IT_Projekt;

public sealed class TestServer : IDisposable
{
    /// <summary>Der gestartete gRPC-Server.</summary>
    public Server Server { get; }

    /// <summary>Der Client-Channel zum lokalen Server (inkl. TLS/mTLS je nach Konfiguration).</summary>
    public Channel Channel { get; }

    /// <summary>Bequemer, bereits gebundener gRPC-Client für <see cref="TokenizationService"/>.</summary>
    public TokenizationService.TokenizationServiceClient Client { get; }

    /// <summary>Vom Server tatsächlich belegter Port (0 = Ephemeral → hier der zugewiesene).</summary>
    public int Port { get; }

    /// <param name="svc">Bereits konfigurierte Service-Instanz (z. B. mit Vault-Providern).</param>
    /// <param name="host">
    /// Hostname/Adresse, auf der der Server bindet. Achtung: Wenn TLS aktiv ist, muss der hier
    /// verwendete Name zum SAN (Subject Alternative Name) des Server-Zertifikats passen, sofern
    /// der Client per Namen (nicht IP) verbindet.
    /// </param>
    /// <param name="interceptor">Optionaler Interceptor (z. B. <c>AuthorizationInterceptor</c>).</param>
    /// <param name="mtls">
    /// true = mTLS (Server verlangt Client-Zertifikate).  
    /// false = TLS ohne Client-Zertifikat (oder Insecure, wenn keine Server-PEMs übergeben werden).
    /// </param>
    /// <param name="caPemPath">PEM mit vertrauenswürdiger(n) CA(s) (Server prüft Client; Client vertraut Server).</param>
    /// <param name="serverCertPemPath">PEM des Server-Zertifikats.</param>
    /// <param name="serverKeyPemPath">PEM des zugehörigen privaten Schlüssels (PKCS#8/PKCS#1, unverschlüsselt).</param>
    /// <param name="clientCertPemPath">PEM des Client-Zertifikats (nur bei mTLS benötigt).</param>
    /// <param name="clientKeyPemPath">PEM des Client-Private-Keys (nur bei mTLS benötigt).</param>
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

        // Service binden (+ optional Interceptor)
        var def = TokenizationService.BindService(svc);
        if (interceptor != null) def = def.Intercept(interceptor);

        // Insecure – nur wenn ausdrücklich TLS/mTLS „aus“ und KEINE Server-PEMs übergeben wurden.
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
            Client = new TokenizationService.TokenizationServiceClient(Channel);
            return;
        }

        // ---- PEMs laden (wirft beim Fehlen eine IO-Exception; in Tests gewünscht) ----
        string caPem            = !string.IsNullOrEmpty(caPemPath)            ? File.ReadAllText(caPemPath)            : null;
        string serverCertPem    = !string.IsNullOrEmpty(serverCertPemPath)    ? File.ReadAllText(serverCertPemPath)    : null;
        string serverKeyPem     = !string.IsNullOrEmpty(serverKeyPemPath)     ? File.ReadAllText(serverKeyPemPath)     : null;
        string clientCertPem    = !string.IsNullOrEmpty(clientCertPemPath)    ? File.ReadAllText(clientCertPemPath)    : null;
        string clientKeyPem     = !string.IsNullOrEmpty(clientKeyPemPath)     ? File.ReadAllText(clientKeyPemPath)     : null;

        // ---- Server-Credentials erstellen ----
        ServerCredentials serverCreds;
        if (mtls)
        {
            if (string.IsNullOrEmpty(caPem) || string.IsNullOrEmpty(serverCertPem) || string.IsNullOrEmpty(serverKeyPem))
                throw new ArgumentException("Für mTLS müssen caPem, serverCertPem und serverKeyPem gesetzt sein.");

            serverCreds = new SslServerCredentials(
                new[] { new KeyCertificatePair(serverCertPem, serverKeyPem) },
                rootCertificates: caPem,
                forceClientAuth: true); // mTLS erzwingen
        }
        else
        {
            if (string.IsNullOrEmpty(serverCertPem) || string.IsNullOrEmpty(serverKeyPem))
                throw new ArgumentException("Für TLS (ohne mTLS) müssen serverCertPem und serverKeyPem gesetzt sein.");

            // TLS ohne Client-Auth
            serverCreds = new SslServerCredentials(
                new[] { new KeyCertificatePair(serverCertPem, serverKeyPem) },
                rootCertificates: null,
                forceClientAuth: false);
        }

        // Server starten (Port 0 = vom OS wählen lassen)
        Server = new Server { Services = { def }, Ports = { new ServerPort(host, 0, serverCreds) } };
        Server.Start();
        Port = Server.Ports.Single().BoundPort;

        // ---- Client-Credentials erstellen ----
        ChannelCredentials clientCreds;
        if (mtls)
        {
            if (string.IsNullOrEmpty(caPem) || string.IsNullOrEmpty(clientCertPem) || string.IsNullOrEmpty(clientKeyPem))
                throw new ArgumentException("Für mTLS-Client müssen caPem, clientCertPem und clientKeyPem gesetzt sein.");

            clientCreds = new SslCredentials(
                rootCertificates: caPem, // Server-CA vertrauen
                keyCertificatePair: new KeyCertificatePair(clientCertPem, clientKeyPem)); // Client-Zertifikat senden
        }
        else
        {
            // TLS ohne Client-Zertifikat – Client muss nur der Server-CA vertrauen
            if (string.IsNullOrEmpty(caPem))
                throw new ArgumentException("Für TLS sollte eine vertrauenswürdige CA (caPem) angegeben werden.");
            clientCreds = new SslCredentials(rootCertificates: caPem);
        }

        // Channel + Client
        Channel = new Channel(host, Port, clientCreds);
        Client  = new TokenizationService.TokenizationServiceClient(Channel);
    }

    /// <summary>
    /// Fährt Channel und Server geordnet herunter.
    /// </summary>
    public void Dispose()
    {
        try { Channel?.ShutdownAsync().Wait(); } catch { /* Tests: best effort */ }
        try { Server?.ShutdownAsync().Wait(); } catch { /* Tests: best effort */ }
    }
}
