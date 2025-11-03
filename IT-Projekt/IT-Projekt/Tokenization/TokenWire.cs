using System;
using System.Security.Cryptography;
using System.Text;
using IT_Projekt.CryptoImpl;

namespace IT_Projekt
{
    /// <summary>
    /// Hilfsklasse für die Serialisierung und Deserialisierung von Token-Strings.  
    /// Tokens haben das Format:
    ///   v1.{typeTag}.{kid8}.{payload}
    /// 
    /// - <c>v1</c>: Versionspräfix (ermöglicht zukünftige Änderungen am Format).  
    /// - <c>typeTag</c>: Kennzeichnet den Token-Typ (z. B. "r" = Random, "f" = FPE, "hc" = HMAC etc.).  
    /// - <c>kid8</c>: 8-Zeichen-Präfix des SHA-256-Hashes des Key-IDs (Base64URL-kodiert).  
    /// - <c>payload</c>: eigentlicher Tokeninhalt (z. B. zufällige Daten oder FPE-Ausgabe).
    /// </summary>
    internal static class TokenWire
    {
        /// <summary>
        /// Baut einen Token-String der Form <c>v1.{typeTag}.{kid8}.{payload}</c>.
        /// </summary>
        /// <param name="typeTag">Kurzes Kürzel für den Token-Typ (z. B. "r", "f", "hc").</param>
        /// <param name="keyId">Der vollständige Schlüssel-Id-String. 
        /// Wird zu einem 8-Zeichen-Präfix (<see cref="Kid8"/>) reduziert.</param>
        /// <param name="payload">Der eigentliche Inhalt (z. B. Zufallsstring oder FPE-ciphertext).</param>
        /// <returns>Den zusammengesetzten Token-String.</returns>
        public static string Build(string typeTag, string keyId, string payload)
            => $"v1.{typeTag}.{Kid8(keyId)}.{payload}";

        /// <summary>
        /// Versucht, einen Token-String in seine Bestandteile zu zerlegen.
        /// </summary>
        /// <param name="token">Der Eingabe-Token.</param>
        /// <param name="typeTag">Ausgabe: Token-Typ-Kürzel.</param>
        /// <param name="kid8">Ausgabe: 8-Zeichen-KeyId-Präfix.</param>
        /// <param name="payload">Ausgabe: Payload-Teil des Tokens.</param>
        /// <returns><c>true</c>, wenn erfolgreich geparst werden konnte, sonst <c>false</c>.</returns>
        public static bool TryParse(string token, out string typeTag, out string kid8, out string payload)
        {
            typeTag = kid8 = payload = null;
            if (string.IsNullOrEmpty(token)) return false;

            var parts = token.Split('.');
            if (parts.Length < 4 || !string.Equals(parts[0], "v1", StringComparison.Ordinal))
                return false;

            typeTag = parts[1];
            kid8    = parts[2];
            payload = string.Join(".", parts, 3, parts.Length - 3);
            return true;
        }

        /// <summary>
        /// Berechnet den Key-Identifier-Präfix ("kid8"):  
        /// SHA-256(KeyId) → Base64URL → die ersten 8 Zeichen.
        /// </summary>
        /// <param name="keyId">Eindeutige Key-Id (kann null sein → behandelt als leerer String).</param>
        /// <returns>8 Zeichen langer Präfix-String.</returns>
        public static string Kid8(string keyId)
        {
            using (var sha = SHA256.Create())
            {
                var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(keyId ?? ""));
                return Crypto.Base64Url(bytes).Substring(0, 8);
            }
        }
    }
}
