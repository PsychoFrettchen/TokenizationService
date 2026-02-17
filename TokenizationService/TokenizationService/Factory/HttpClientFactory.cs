using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.X509;

namespace TokenizationService.Factory
{
    /// <summary>
    ///     Factory for <see cref="HttpClient" /> with optional mTLS and strict server validation:
    ///     - TLS 1.2 (+ 1.3 if available)
    ///     - Hostname validation (no NameMismatch allowed)
    ///     - Chain building with AllowUnknownCA and subsequent SPKI pinning against the provided trust anchors
    ///     - Optional client certificate (mTLS)
    /// </summary>
    public static class HttpClientFactory
    {
        private static readonly ConcurrentDictionary<string, byte[]> SpkiCache =
            new ConcurrentDictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        ///     Creates an <see cref="HttpClient" /> with custom TLS validation.
        /// </summary>
        /// <param name="trustAnchors">
        ///     Trust anchors (Root/Intermediate/Leaf) against which the SPKI of chain elements is pinned.
        ///     If <c>null</c> or empty, OS trust applies (standard .NET validation).
        /// </param>
        /// <param name="protocols">TLS protocols. Default: TLS 1.2 (+ 1.3 if supported by the runtime enum).</param>
        /// <param name="clientCertificate">Optional: client certificate for mTLS.</param>
        public static HttpClient Build(
            X509Certificate2Collection trustAnchors,
            SslProtocols protocols = default,
            X509Certificate2 clientCertificate = null)
        {
            if (protocols == default) protocols = ChooseBestProtocols();

            var handler = new HttpClientHandler
            {
                SslProtocols = protocols
            };

            // Switch to Manual only if we attach client certificates ourselves.
            if (clientCertificate != null)
            {
                handler.CheckCertificateRevocationList = true;
                handler.ClientCertificateOptions = ClientCertificateOption.Manual;
                handler.ClientCertificates.Add(clientCertificate);
            }

            handler.ServerCertificateCustomValidationCallback = (req, cert, chain, errors) =>
                ValidateServer(cert, trustAnchors, chain, errors);

            // Optional (Prod): enable CRL/OCSP (consider custom timeouts if necessary)
            // handler.CheckCertificateRevocationList = true;

            return new HttpClient(handler, true);
        }

        /// <summary>
        ///     Selects TLS 1.2 and – if available in the current runtime enum – also TLS 1.3.
        /// </summary>
        private static SslProtocols ChooseBestProtocols()
        {
            var p = SslProtocols.Tls12;
            if (TryGetTls13(out var tls13)) p |= tls13;
            return p;
        }

        /// <summary>
        ///     Determines at runtime whether <see cref="SslProtocols.Tls13" /> is available
        ///     (no hard target-framework dependency).
        /// </summary>
        private static bool TryGetTls13(out SslProtocols tls13)
        {
            tls13 = default;
            var hasName = Enum.GetNames(typeof(SslProtocols))
                .Any(n => string.Equals(n, "Tls13", StringComparison.Ordinal));
            if (!hasName) return false;

            tls13 = (SslProtocols)Enum.Parse(typeof(SslProtocols), "Tls13");
            return true;
        }

        /// <summary>
        ///     Strict server validation:
        ///     1) Hostname must match (NameMismatch → false)
        ///     2) Chain is built with AllowUnknownCertificateAuthority
        ///     3) If trust anchors are provided, only UntrustedRoot is tolerable AND
        ///     at least one chain element must match the SPKI of an anchor
        ///     4) If no anchors are provided, full OS validation must succeed
        /// </summary>
        public static bool ValidateServer(
            X509Certificate2 serverCert,
            X509Certificate2Collection anchors,
            X509Chain _ /*unused*/,
            SslPolicyErrors errors)
        {
            // 0) Basic guards
            if (serverCert == null) return false;

            // 1) Check hostname (SAN/CN vs. request host). If .NET reports NameMismatch → reject immediately.
            if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
                return false;

            using (var chain = new X509Chain())
            {
                // 2) Build chain: allow unknown CA, configure revocation as appropriate
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // in Prod: Online/Offline recommended
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

                // Leaf must contain "Server Authentication" EKU
                chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));

                var haveAnchors = anchors != null && anchors.Count > 0;
                if (haveAnchors)
                    foreach (var a in anchors)
                        chain.ChainPolicy.ExtraStore.Add(a);

                var built = chain.Build(serverCert);
                var statuses = chain.ChainStatus.Select(s => s.Status).ToArray();

                if (haveAnchors)
                {
                    // 3) With custom anchors: Only UntrustedRoot is tolerable
                    // (since we manually pin), all other errors → reject
                    if (!built && statuses.Any(s => s != X509ChainStatusFlags.UntrustedRoot))
                        return false;

                    // Precompute SPKI hashes of anchors
                    var anchorSpkis = anchors.Cast<X509Certificate2>()
                        .Select(GetSpkiSha256)
                        .ToArray();

                    // At least one chain element must match an anchor SPKI
                    foreach (var element in chain.ChainElements.Cast<X509ChainElement>())
                    {
                        var elSpki = GetSpkiSha256(element.Certificate);
                        if (anchorSpkis.Any(a => a.SequenceEqual(elSpki)))
                            return true;
                    }

                    return false; // no match found
                }

                // 4) Without custom anchors → full OS validation (no errors)
                return built && statuses.Length == 0;
            }
        }

        /// <summary>
        ///     SHA-256 over the DER-encoded SubjectPublicKeyInfo (SPKI) of the certificate.
        ///     Result is cached (key = thumbprint).
        /// </summary>
        private static byte[] GetSpkiSha256(X509Certificate2 cert)
        {
            if (cert == null) return Array.Empty<byte>();

            return SpkiCache.GetOrAdd(cert.Thumbprint ?? Convert.ToBase64String(cert.RawData), _ =>
            {
                var parser = new X509CertificateParser();
                var bcCert = parser.ReadCertificate(cert.RawData);
                var spkiDer = bcCert.CertificateStructure.SubjectPublicKeyInfo.GetDerEncoded();

                using (var sha = SHA256.Create())
                {
                    return sha.ComputeHash(spkiDer);
                }
            });
        }
    }
}