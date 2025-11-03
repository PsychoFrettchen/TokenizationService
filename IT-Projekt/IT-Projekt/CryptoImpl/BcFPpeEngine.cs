using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Fpe;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;

namespace IT_Projekt.CryptoImpl
{
    /// <summary>
    ///     Format-Preserving Encryption (FPE)-Engine-Adapter, der die FF1- oder FF3-1-Implementierung von BouncyCastle
    ///     (NIST SP 800-38G) verwendet, um Zeichenfolgen über ein bestimmtes Alphabet zu verschlüsseln oder zu entschlüsseln.
    ///
    ///     Adapter um sensible Daten zu schützen , aber deren Form und zulässige Zeichen beizubehalten –
    ///     beispielsweise bei der Tokenisierung von Kreditkartennummern, IBANs oder anderen Identifikatoren mit festem Format.
    /// </summary>
    public sealed class BcFpeEngine : IFpeEngine
    {
        /// <summary>
        ///  Der zu verwendende FPE-Modus. FF1 ist am flexibelsten (beliebige Tweak-Länge),
        ///  während FF3-1 strenger ist (erfordert einen 7-Byte-Tweak).
        /// </summary>
        /// <param name="mode">FF1 oder FF3</param>
        public enum Mode { FF1, FF3_1 }
        private readonly Mode mode;
        
        /// <summary>
        ///  Erstellt eine neue <see cref="BcFpeEngine"/> unter Verwendung des angegebenen FPE-Modus.
        /// </summary>
        /// <param name="mode">Der zu verwendende FPE-Modus. Standardmäßig ist Mode.FF1/></param>
        public BcFpeEngine(Mode mode = Mode.FF1) => this.mode = mode;

        /// <summary>
        /// Verschlüsselt den angegebene Plaintext unter Beibehaltung des Formats.
        /// </summary>
        /// <param name="plaintext">Die zu verschlüsselnde Klartextzeichenfolge. Darf nur Zeichen aus dem Alphabet</param>
        /// <param name="key">AES key (16, 24, or 32 bytes)</param>
        /// <param name="tweak">Optionale Optimierung (wie eine Nonce oder eine Kontextbindung). FF1 akzeptiert jede Länge;
        ///     FF3-1 erfordert genau 7 Bytes.</param>
        /// <param name="alphabet">Das Alphabet (Menge der zulässigen Zeichen). Legt die Radix (Länge des Alphabets) fest.
        ///     Beispiel: <c>„0123456789”</c> für numerische FPE, <c>„ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789”</c> für alphanumerische.</param>
        /// <exception cref="ArgumentException">Wirft eine Exception, wenn Plaintext null ist </exception>
        /// <exception cref="ArgumentException">Wirft eine Exception, wenn die Schlüsselgröße, das Alphabet oder die Eingabelänge ungültig sind.</exception>
        /// <returns></returns>
        public string Encrypt(string plaintext, byte[] key, byte[] tweak, string alphabet)
            => Transform(encrypt: true, s: plaintext, key: key, tweak: tweak, alphabet: alphabet);
        /// <summary>
        ///   Entschlüsselt die angegebene Chiffretext unter Verwendung einer formatbewahrenden Verschlüsselung.        /// </summary>
        /// <param name="ciphertext">Der zu entschlüsselnde Chiffretext. Muss von <see cref="Encrypt"/> mit denselben Parametern erstellt worden sein.</param>
        /// <param name="key">AES key (16, 24, or 32 bytes)</param>
        /// <param name="tweak">
        ///  Die gleiche Optimierung wie bei der Verschlüsselung; die Entschlüsselung schlägt fehl oder erzeugt Datenmüll, wenn diese nicht übereinstimmt.
        /// </param>
        /// <param name="alphabet">Das bei der Verschlüsselung verwendete Alphabet. Muss exakt übereinstimmen.</param>
        /// <returns>Den Plaintext</returns>
        /// <exception cref="ArgumentNullException">Wirft eine Exception wenn, <paramref name="ciphertext"/> null ist.</exception>
        /// <exception cref="ArgumentException">Wirft eine exception, wenn key size, alphabet oder input length invalide ist.</exception>
        public string Decrypt(string ciphertext, byte[] key, byte[] tweak, string alphabet)
            => Transform(encrypt: false, s: ciphertext, key: key, tweak: tweak, alphabet: alphabet);
        
        private string Transform(bool encrypt, string s, byte[] key, byte[] tweak, string alphabet)
        {
            //Sicherheitsvorkehrungen:
            // Nicht-Null-Eingabe,
            // definiertes Alphabet,
            // gültige AES-Schlüssellänge,
            // Länge ≥ 2 (38G empfiehlt, kleine Domänen zu vermeiden).
            if (s == null) throw new ArgumentNullException(nameof(s));
            if (string.IsNullOrEmpty(alphabet)) throw new ArgumentException("Alphabet required.", nameof(alphabet));
            if (key == null || (key.Length != 16 && key.Length != 24 && key.Length != 32))
                throw new ArgumentException("Key must be 16/24/32 bytes.", nameof(key));
            if (s.Length < 2) throw new ArgumentException("FPE requires length >= 2.", nameof(s));

            //BasicAlphabetMapper konvertiert Zeichen ↔︎ Basisziffern basierend auf dem angegebenen Alphabet (eindeutige Zeichen erforderlich).
            // AesEngine ist die zugrunde liegende Blockverschlüsselung für FF1/FF3-1.
            var mapper = new BasicAlphabetMapper(alphabet.ToCharArray());
            var aes = new AesEngine();

            //FF1: Der Tweak kann leer sein oder eine beliebige Länge haben.
            // FF3-1: Der Tweak muss genau 7 Byte lang sein → wird durch RequireFf3_1Tweak erzwungen.
            // FpeParameters bündelt AES-Schlüssel, Radix und Tweak.
            // Radix ist die Anzahl der Zeichen im Alphabet
            var normalizedTweak = mode == Mode.FF1 ? (tweak ?? Array.Empty<byte>()) : RequireFf3_1Tweak(tweak);
            var p = new FpeParameters(new KeyParameter(key), mapper.Radix, normalizedTweak);

            //Konvertiert die Eingabezeichenfolge in Ziffern (Indizes im Alphabet). Der Ausgabepuffer hat dieselbe Länge.
            //alphabet ist z.B "0123456789" Radix =10; BasicAlphabetMapper kennt Alphabet und bildet jedes Zicher der Eingabe s auf den Index ab:
            //"407" = [4,0,7]
            //x ist die Ziffernfolge in einer bestimmten Basus der Radix. y ist der Ausgabepuffer gleicher Länge
            byte[] x = mapper.ConvertToIndexes(s.ToCharArray());
            byte[] y = new byte[x.Length];

            //Erstellen der richtigen Engine (FF1 oder FF3-1), initialisiert für die Ver-/Entschlüsselung
            // Die Ausgabe y ist die transformierte Ziffernfolge (gleiche Länge, gleiche Basis).
            if (mode == Mode.FF1)
            {
                var ff1 = new FpeFf1Engine(aes);
                ff1.Init(encrypt, p);
                ff1.ProcessBlock(x, 0, x.Length, y, 0);
            }
            else
            {
                var ff31 = new FpeFf3_1Engine(aes);
                ff31.Init(encrypt, p);
                ff31.ProcessBlock(x, 0, x.Length, y, 0);
            }
            //Ordnet die Ziffern wieder den Zeichen des Alphabets zu → Format bleibt erhalten (gleicher Zeichensatz, gleiche Länge).
            return new string(mapper.ConvertToChars(y));
        }

        //FF3-1 Spezifikationsanforderung: Tweak ist 56 Bit (7 Byte). Wird frühzeitig durchgesetzt, um eindeutige Fehler zu erkennen.
        private static byte[] RequireFf3_1Tweak(byte[] tweak)
        {
            if (tweak == null || tweak.Length != 7)
                throw new ArgumentException("FF3-1 requires a 7-byte tweak (56 bits).", nameof(tweak));
            return tweak;
        }
    }
}
