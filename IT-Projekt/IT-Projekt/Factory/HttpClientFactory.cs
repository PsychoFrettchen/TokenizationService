using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.X509;

namespace IT_Projekt.Factory
{
    /// <summary>
    /// Fabrik für <see cref="HttpClient"/> mit optionalem mTLS und strenger Servervalidierung:
    /// - TLS 1.2 (+ 1.3 wenn verfügbar)
    /// - Hostnamenprüfung (kein NameMismatch erlaubt)
    /// - Kettenaufbau mit AllowUnknownCA und anschließendes SPKI-Pinning gegen die angegebenen Trust-Anchors
    /// - Optionales Client-Zertifikat (mTLS)
    /// </summary>
    public static class HttpClientFactory
    {
        private static readonly ConcurrentDictionary<string, byte[]> SpkiCache =
            new ConcurrentDictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Erstellt einen <see cref="HttpClient"/> mit benutzerdefinierter TLS-Validierung.
        /// </summary>
        /// <param name="trustAnchors">
        /// Trust-Anchors (Root/Intermediate/Leaf), gegen die die SPKI von Kettenelementen gepinnt wird.
        /// Wenn <c>null</c> oder leer, gilt OS-Trust (normale .NET-Validierung).
        /// </param>
        /// <param name="protocols">TLS-Protokolle. Standard: TLS 1.2 (+ 1.3 wenn vom Runtime-Enum unterstützt).</param>
        /// <param name="clientCertificate">Optional: Client-Zertifikat für mTLS.</param>
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

            // Nur auf Manual umschalten, wenn wir selbst Client-Certs beifügen.
            if (clientCertificate != null)
            {
                handler.CheckCertificateRevocationList = true;
                handler.ClientCertificateOptions = ClientCertificateOption.Manual;
                handler.ClientCertificates.Add(clientCertificate);
            }

            handler.ServerCertificateCustomValidationCallback = (req, cert, chain, errors) =>
                ValidateServer(cert, trustAnchors, chain, errors);

            // Optional (Prod): CRL/OCSP einschalten (ggf. CustomTimeOuts beachten)
            // handler.CheckCertificateRevocationList = true;

            return new HttpClient(handler, disposeHandler: true);
        }

        /// <summary>
        /// Wählt TLS 1.2 und – wenn im aktuellen Runtime-Enum vorhanden – zusätzlich TLS 1.3.
        /// </summary>
        private static SslProtocols ChooseBestProtocols()
        {
            var p = SslProtocols.Tls12;
            if (TryGetTls13(out var tls13)) p |= tls13;
            return p;
        }

        /// <summary>
        /// Ermittelt zur Laufzeit, ob <see cref="SslProtocols.Tls13"/> verfügbar ist (kein harter Target-Framework-Dependency).
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
        /// Strenge Servervalidierung:
        /// 1) Hostname muss passen (NameMismatch → false)
        /// 2) Kette wird mit AllowUnknownCertificateAuthority gebaut
        /// 3) Sind Trust-Anchors gegeben, ist nur UntrustedRoot tolerierbar UND mind. ein Kettenelement muss auf SPKI eines Anchors matchen
        /// 4) Sind keine Anchors gegeben, muss die OS-Validierung vollständig bestehen
        /// </summary>
        public static bool ValidateServer(
            X509Certificate2 serverCert,
            X509Certificate2Collection anchors,
            X509Chain _ /*unused*/,
            SslPolicyErrors errors)
        {
            // 0) Grundlegende Guards
            if (serverCert == null) return false;

            // 1) Hostname prüfen (SAN/CN vs. Request-Host). Wenn .NET NameMismatch meldet → sofort ablehnen.
            if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
                return false;
            using (var chain = new X509Chain())
            {
                // 2) Kette aufbauen: Unbekannte CA zulassen, Revocation je nach Umgebung
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // in Prod: Online/Offline sinnvoll
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

                // Leaf muss "Server Authentication" EKU besitzen
                chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));

                bool haveAnchors = anchors != null && anchors.Count > 0;
                if (haveAnchors)
                {
                    foreach (var a in anchors) chain.ChainPolicy.ExtraStore.Add(a);
                }

                bool built = chain.Build(serverCert);
                var statuses = chain.ChainStatus.Select(s => s.Status).ToArray();

                if (haveAnchors)
                {
                    // 3) Mit Custom-Anchors: Nur UntrustedRoot tolerieren (weil wir manuell pinnen),
                    // alle anderen Fehler → ablehnen
                    if (!built && statuses.Any(s => s != X509ChainStatusFlags.UntrustedRoot))
                        return false;

                    // SPKI-Hashes der Anchors vorberechnen
                    var anchorSpkis = anchors.Cast<X509Certificate2>()
                        .Select(GetSpkiSha256)
                        .ToArray();

                    // Mind. ein Element der gebauten Kette muss auf einen Anchor-SPKI matchen
                    foreach (var element in chain.ChainElements.Cast<X509ChainElement>())
                    {
                        var elSpki = GetSpkiSha256(element.Certificate);
                        if (anchorSpkis.Any(a => a.SequenceEqual(elSpki)))
                            return true;
                    }
                    return false; // keine Übereinstimmung gefunden
                }

                // 4) Ohne Custom-Anchors → vollständige OS-Validierung (keine Fehler)
                return built && statuses.Length == 0;
            }
        }

        /// <summary>
        /// SHA-256 über das DER-kodierte SubjectPublicKeyInfo (SPKI) des Zertifikats.
        /// Ergebnis wird gecached (Key = Thumbprint).
        /// </summary>
        private static byte[] GetSpkiSha256(X509Certificate2 cert)
        {
            if (cert == null) return Array.Empty<byte>();

            return SpkiCache.GetOrAdd(cert.Thumbprint ?? Convert.ToBase64String(cert.RawData), _ =>
            {
                var parser = new X509CertificateParser();
                var bcCert = parser.ReadCertificate(cert.RawData);
                byte[] spkiDer = bcCert.CertificateStructure.SubjectPublicKeyInfo.GetDerEncoded();

                using (var sha = SHA256.Create())
                    return sha.ComputeHash(spkiDer);
            });
        }
    }
}
