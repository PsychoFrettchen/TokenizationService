using System;
using System.Security.Cryptography;
using System.Text;

namespace TokenizationService.CryptoImpl
{
    internal static class Crypto
    {
        /// <summary>
        ///     Encodes a byte array into Base64URL format.
        ///     Standard Base64 encoding is used,
        ///     trailing padding ('=') is removed and '+' → '-' as well as '/' → '_'
        ///     are replaced so that the string is URL- and filename-safe.
        /// </summary>
        /// <param name="bytes">The byte array to encode. <c>null</c> is treated as empty.</param>
        /// <returns>Base64URL-encoded string without padding.</returns>
        public static string Base64Url(byte[] bytes)
        {
            var s = Convert.ToBase64String(bytes ?? Array.Empty<byte>())
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            return s;
        }

        /// <summary>
        ///     Decodes a Base64URL string into bytes.
        ///     Missing padding is restored and URL-safe characters are converted
        ///     back to the standard Base64 alphabet.
        /// </summary>
        /// <param name="s">The Base64URL-encoded input string. <c>null</c>/empty returns an empty byte array.</param>
        /// <returns>The decoded byte array.</returns>
        /// <exception cref="FormatException">Thrown if the input is not a valid Base64/Base64URL sequence.</exception>
        public static byte[] FromBase64Url(string s)
        {
            if (string.IsNullOrEmpty(s)) return Array.Empty<byte>();
            var p = s.Replace('-', '+').Replace('_', '/');
            // Base64 requires length % 4 == 0 → add missing padding
            switch (p.Length % 4)
            {
                case 2: p += "=="; break;
                case 3: p += "="; break;
            }

            return Convert.FromBase64String(p);
        }

        /// <summary>
        ///     Computes the SHA-256 hash of the UTF-8 encoded <paramref name="text" />
        ///     and returns it as a 64-character lowercase hexadecimal string.
        /// </summary>
        /// <param name="text">The input text. <c>null</c> is treated as an empty string.</param>
        /// <returns>Hexadecimal representation of the 32-byte digest (lowercase).</returns>
        public static string Sha256Hex(string text)
        {
            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(text ?? ""));
                var sb = new StringBuilder(hash.Length * 2);
                foreach (var b in hash) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        }

        /// <summary>
        ///     Computes HMAC-SHA-256 over the UTF-8 encoded <paramref name="text" />
        ///     using the specified <paramref name="key" />
        ///     and returns the MAC as a lowercase hexadecimal string.
        /// </summary>
        /// <param name="text">The input text. <c>null</c> is treated as an empty string.</param>
        /// <param name="key">Secret key. Must not be <c>null</c>.</param>
        /// <returns>Hexadecimal representation of the 32-byte HMAC (lowercase).</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="key" /> is <c>null</c>.</exception>
        public static string HmacSha256Hex(string text, byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            using (var h = new HMACSHA256(key))
            {
                var mac = h.ComputeHash(Encoding.UTF8.GetBytes(text ?? ""));
                var sb = new StringBuilder(mac.Length * 2);
                foreach (var b in mac) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        }

        /// <summary>
        ///     Generates a cryptographically secure random byte array of the specified length.
        /// </summary>
        /// <param name="len">Number of random bytes to generate (≥ 0).</param>
        /// <returns>A byte array of length <paramref name="len" />.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="len" /> &lt; 0.</exception>
        public static byte[] RandomBytes(int len)
        {
            if (len < 0) throw new ArgumentOutOfRangeException(nameof(len));
            var b = new byte[len];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(b);
            }

            return b;
        }

        /// <summary>
        ///     HKDF (RFC 5869) with SHA-256: Extract-and-Expand to derive
        ///     context-bound key material of length <paramref name="len" />.
        /// </summary>
        /// <param name="ikm">Input key material (IKM). <c>null</c> is treated as empty.</param>
        /// <param name="salt">
        ///     Optional salt (not secret). If <c>null</c>, a zero-salt of hash length
        ///     (32 bytes for SHA-256) is used according to RFC 5869.
        /// </param>
        /// <param name="info">Optional context-specific info (label). <c>null</c> is treated as empty.</param>
        /// <param name="len">Length of the output key material (OKM) in bytes (&gt; 0).</param>
        /// <returns>Derived key bytes (OKM) of length <paramref name="len" />.</returns>
        /// <remarks>
        ///     Steps:
        ///     1) Extract: PRK = HMAC_SHA256(salt, ikm).<br />
        ///     2) Expand: T(1) = HMAC(PRK, info || 0x01),
        ///     T(2) = HMAC(PRK, T(1) || info || 0x02), …<br />
        ///     OKM = T(1) || T(2) || … until <paramref name="len" /> is reached.
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="len" /> ≤ 0.</exception>
        public static byte[] Hkdf(byte[] ikm, byte[] salt, byte[] info, int len)
        {
            if (len <= 0) throw new ArgumentOutOfRangeException(nameof(len));

            // Extract
            using (var hmac = new HMACSHA256(salt ?? new byte[32]))
            {
                var prk = hmac.ComputeHash(ikm ?? Array.Empty<byte>());

                // Expand
                var okm = new byte[len];
                var t = Array.Empty<byte>();
                var offset = 0;
                byte counter = 1;

                while (offset < len)
                {
                    using (var hm = new HMACSHA256(prk))
                    {
                        var infoLen = info?.Length ?? 0;
                        var input = new byte[t.Length + infoLen + 1];
                        Buffer.BlockCopy(t, 0, input, 0, t.Length);
                        if (infoLen > 0) Buffer.BlockCopy(info, 0, input, t.Length, infoLen);
                        input[input.Length - 1] = counter++;

                        t = hm.ComputeHash(input);
                    }

                    var toCopy = Math.Min(t.Length, len - offset);
                    Buffer.BlockCopy(t, 0, okm, offset, toCopy);
                    offset += toCopy;
                }

                return okm;
            }
        }
    }
}