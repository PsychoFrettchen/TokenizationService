using System;
using System.Security.Cryptography;
using System.Text;

namespace IT_Projekt.CryptoImpl
{
    internal static class Crypto
    {
        /// <summary>
        /// Kodiert ein Byte-Array in das Base64URL-Format.
        /// Dabei wird die Standard-Base64-Kodierung verwendet,
        /// abschließendes Padding ('=') entfernt und '+' → '-' sowie '/' → '_' ersetzt,
        /// sodass der String URL- und dateinamen-sicher ist.
        /// </summary>
        /// <param name="bytes">Das zu kodierende Byte-Array. <c>null</c> wird als leer behandelt.</param>
        /// <returns>Base64URL-kodierter String ohne Padding.</returns>
        public static string Base64Url(byte[] bytes)
        {
            var s = Convert.ToBase64String(bytes ?? Array.Empty<byte>())
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            return s;
        }

        /// <summary>
        /// Dekodiert einen Base64URL-String in Bytes.
        /// Fehlendes Padding wird ergänzt und URL-sichere Zeichen werden in das Standard-Base64-Alphabet zurückgeführt.
        /// </summary>
        /// <param name="s">Der Base64URL-kodierte Eingabestring. <c>null</c>/leer ergibt ein leeres Byte-Array.</param>
        /// <returns>Das dekodierte Byte-Array.</returns>
        /// <exception cref="FormatException">Wenn die Eingabe keine gültige Base64-/Base64URL-Sequenz ist.</exception>
        public static byte[] FromBase64Url(string s)
        {
            if (string.IsNullOrEmpty(s)) return Array.Empty<byte>();
            var p = s.Replace('-', '+').Replace('_', '/');
            // Base64 benötigt Länge % 4 == 0 → fehlendes Padding ergänzen
            switch (p.Length % 4) { case 2: p += "=="; break; case 3: p += "="; break; }
            return Convert.FromBase64String(p);
        }

        /// <summary>
        /// Berechnet den SHA-256-Hashwert des UTF-8-kodierten <paramref name="text"/> und gibt ihn als
        /// 64-stellige Hexadezimal-Zeichenkette in Kleinbuchstaben zurück.
        /// </summary>
        /// <param name="text">Der Eingabetext. <c>null</c> wird als leere Zeichenfolge behandelt.</param>
        /// <returns>Hexadezimaldarstellung des 32-Byte-Digests (Kleinbuchstaben).</returns>
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
        /// Berechnet HMAC-SHA-256 über den UTF-8-kodierten <paramref name="text"/> mit dem angegebenen <paramref name="key"/>
        /// und gibt den MAC als Hexadezimal-Zeichenkette in Kleinbuchstaben zurück.
        /// </summary>
        /// <param name="text">Der Eingabetext. <c>null</c> wird als leere Zeichenfolge behandelt.</param>
        /// <param name="key">Geheimer Schlüssel. Darf nicht <c>null</c> sein.</param>
        /// <returns>Hexadezimaldarstellung des 32-Byte-HMAC (Kleinbuchstaben).</returns>
        /// <exception cref="ArgumentNullException">Wenn <paramref name="key"/> <c>null</c> ist.</exception>
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
        /// Erzeugt ein kryptographisch sicheres, zufälliges Byte-Array der angegebenen Länge.
        /// </summary>
        /// <param name="len">Anzahl der zu generierenden Zufallsbytes (≥ 0).</param>
        /// <returns>Ein Byte-Array der Länge <paramref name="len"/>.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Wenn <paramref name="len"/> &lt; 0 ist.</exception>
        public static byte[] RandomBytes(int len)
        {
            if (len < 0) throw new ArgumentOutOfRangeException(nameof(len));
            var b = new byte[len];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(b);
            return b;
        }

        /// <summary>
        /// HKDF (RFC 5869) mit SHA-256: Extract-and-Expand zur Ableitung
        /// von kontextgebundenem Schlüsselmaterial der Länge <paramref name="len"/>.
        /// </summary>
        /// <param name="ikm">Eingabe-Schlüsselmaterial (IKM). <c>null</c> wird als leer behandelt.</param>
        /// <param name="salt">
        /// Optionales Salt (nicht geheim). Ist es <c>null</c>, wird gemäß RFC 5869 ein
        /// Null-Salt in Hashlänge (32 Bytes für SHA-256) verwendet.
        /// </param>
        /// <param name="info">Optionale kontextspezifische Info (Label). <c>null</c> wird als leer behandelt.</param>
        /// <param name="len">Länge des auszugebenden Schlüsselmaterials (OKM) in Bytes (&gt; 0).</param>
        /// <returns>Abgeleitete Schlüsselbytes (OKM) der Länge <paramref name="len"/>.</returns>
        /// <remarks>
        /// Schritte:
        /// 1) Extract: PRK = HMAC_SHA256(salt, ikm).<br/>
        /// 2) Expand: T(1) = HMAC(PRK, info || 0x01), T(2) = HMAC(PRK, T(1) || info || 0x02), …<br/>
        /// OKM = T(1) || T(2) || … bis <paramref name="len"/> erreicht ist.
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">Wenn <paramref name="len"/> ≤ 0 ist.</exception>
        public static byte[] Hkdf(byte[] ikm, byte[] salt, byte[] info, int len)
        {
            if (len <= 0) throw new ArgumentOutOfRangeException(nameof(len));

            // Extract
            using (var hmac = new HMACSHA256(salt ?? new byte[32]))
            {
                var prk = hmac.ComputeHash(ikm ?? Array.Empty<byte>());

                // Expand
                var okm = new byte[len];
                byte[] t = Array.Empty<byte>();
                int offset = 0;
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

                    int toCopy = Math.Min(t.Length, len - offset);
                    Buffer.BlockCopy(t, 0, okm, offset, toCopy);
                    offset += toCopy;
                }

                return okm;
            }
        }
    }
}
