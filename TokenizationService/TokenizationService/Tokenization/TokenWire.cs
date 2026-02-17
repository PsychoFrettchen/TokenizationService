using System;
using System.Security.Cryptography;
using System.Text;
using TokenizationService.CryptoImpl;

namespace TokenizationService
{
    /// <summary>
    ///     Helper class for serializing and deserializing token strings.
    ///     Tokens use the following format:
    ///     v1.{typeTag}.{kid8}.{payload}
    ///     - <c>v1</c>: Version prefix (allows future format changes).
    ///     - <c>typeTag</c>: Identifies the token type (e.g., "r" = Random, "f" = FPE, "hc" = HMAC, etc.).
    ///     - <c>kid8</c>: 8-character prefix of the SHA-256 hash of the Key ID (Base64URL-encoded).
    ///     - <c>payload</c>: The actual token content (e.g., random data or FPE output).
    /// </summary>
    internal static class TokenWire
    {
        /// <summary>
        ///     Builds a token string of the form <c>v1.{typeTag}.{kid8}.{payload}</c>.
        /// </summary>
        /// <param name="typeTag">Short identifier for the token type (e.g., "r", "f", "hc").</param>
        /// <param name="keyId">
        ///     The full key ID string.
        ///     It is reduced to an 8-character prefix via <see cref="Kid8" />.
        /// </param>
        /// <param name="payload">The actual content (e.g., random string or FPE ciphertext).</param>
        /// <returns>The assembled token string.</returns>
        public static string Build(string typeTag, string keyId, string payload)
        {
            return $"v1.{typeTag}.{Kid8(keyId)}.{payload}";
        }

        /// <summary>
        ///     Attempts to split a token string into its components.
        /// </summary>
        /// <param name="token">The input token.</param>
        /// <param name="typeTag">Output: token type identifier.</param>
        /// <param name="kid8">Output: 8-character KeyId prefix.</param>
        /// <param name="payload">Output: payload portion of the token.</param>
        /// <returns><c>true</c> if parsing was successful; otherwise <c>false</c>.</returns>
        public static bool TryParse(string token, out string typeTag, out string kid8, out string payload)
        {
            typeTag = kid8 = payload = null;
            if (string.IsNullOrEmpty(token)) return false;

            var parts = token.Split('.');
            if (parts.Length < 4 || !string.Equals(parts[0], "v1", StringComparison.Ordinal))
                return false;

            typeTag = parts[1];
            kid8 = parts[2];
            payload = string.Join(".", parts, 3, parts.Length - 3);
            return true;
        }

        /// <summary>
        ///     Computes the key identifier prefix ("kid8"):
        ///     SHA-256(KeyId) → Base64URL → first 8 characters.
        /// </summary>
        /// <param name="keyId">Unique key ID (may be null → treated as empty string).</param>
        /// <returns>8-character prefix string.</returns>
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