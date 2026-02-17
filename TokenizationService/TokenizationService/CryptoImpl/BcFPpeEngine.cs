using System;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Fpe;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;

namespace TokenizationService.CryptoImpl
{
    /// <summary>
    ///     Format-Preserving Encryption (FPE) engine adapter that uses the FF1 or FF3-1 implementation from BouncyCastle
    ///     (NIST SP 800-38G) to encrypt or decrypt strings over a given alphabet.
    ///     Adapter to protect sensitive data while preserving its format and allowed characters –
    ///     for example when tokenizing credit card numbers, IBANs, or other identifiers with a fixed format.
    /// </summary>
    public sealed class BcFpeEngine : IFpeEngine
    {
        /// <summary>
        ///     The FPE mode to use. FF1 is the most flexible (arbitrary tweak length),
        ///     while FF3-1 is stricter (requires a 7-byte tweak).
        /// </summary>
        /// <param name="mode">FF1 or FF3_1</param>
        public enum Mode
        {
            FF1,
            FF3_1
        }

        private readonly Mode mode;

        /// <summary>
        ///     Creates a new <see cref="BcFpeEngine" /> using the specified FPE mode.
        /// </summary>
        /// <param name="mode">The FPE mode to use. Default is Mode.FF1.</param>
        public BcFpeEngine(Mode mode = Mode.FF1)
        {
            this.mode = mode;
        }

        /// <summary>
        ///     Encrypts the specified plaintext while preserving its format.
        /// </summary>
        /// <param name="plaintext">The plaintext string to encrypt. Must only contain characters from the alphabet.</param>
        /// <param name="key">AES key (16, 24, or 32 bytes).</param>
        /// <param name="tweak">
        ///     Optional tweak (like a nonce or context binding). FF1 accepts any length;
        ///     FF3-1 requires exactly 7 bytes.
        /// </param>
        /// <param name="alphabet">
        ///     The alphabet (set of allowed characters). Defines the radix (alphabet length).
        ///     Example: <c>"0123456789"</c> for numeric FPE,
        ///     <c>"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"</c> for alphanumeric.
        /// </param>
        /// <exception cref="ArgumentException">Thrown if plaintext is null.</exception>
        /// <exception cref="ArgumentException">Thrown if key size, alphabet, or input length is invalid.</exception>
        public string Encrypt(string plaintext, byte[] key, byte[] tweak, string alphabet)
        {
            return Transform(true, plaintext, key, tweak, alphabet);
        }

        /// <summary>
        ///     Decrypts the specified ciphertext using format-preserving encryption.
        /// </summary>
        /// <param name="ciphertext">
        ///     The ciphertext to decrypt. Must have been created by <see cref="Encrypt" /> with the same parameters.
        /// </param>
        /// <param name="key">AES key (16, 24, or 32 bytes).</param>
        /// <param name="tweak">
        ///     The same tweak used for encryption; decryption will fail or produce garbage if it does not match.
        /// </param>
        /// <param name="alphabet">The alphabet used during encryption. Must match exactly.</param>
        /// <returns>The plaintext.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="ciphertext" /> is null.</exception>
        /// <exception cref="ArgumentException">Thrown if key size, alphabet, or input length is invalid.</exception>
        public string Decrypt(string ciphertext, byte[] key, byte[] tweak, string alphabet)
        {
            return Transform(false, ciphertext, key, tweak, alphabet);
        }

        private string Transform(bool encrypt, string s, byte[] key, byte[] tweak, string alphabet)
        {
            // Security checks:
            // Non-null input,
            // defined alphabet,
            // valid AES key length,
            // length ≥ 2 (38G recommends avoiding small domains).
            if (s == null) throw new ArgumentNullException(nameof(s));
            if (string.IsNullOrEmpty(alphabet)) throw new ArgumentException("Alphabet required.", nameof(alphabet));
            if (key == null || (key.Length != 16 && key.Length != 24 && key.Length != 32))
                throw new ArgumentException("Key must be 16/24/32 bytes.", nameof(key));
            if (s.Length < 2) throw new ArgumentException("FPE requires length >= 2.", nameof(s));

            // BasicAlphabetMapper converts characters ↔ base digits based on the specified alphabet (unique characters required).
            // AesEngine is the underlying block cipher for FF1/FF3-1.
            var mapper = new BasicAlphabetMapper(alphabet.ToCharArray());
            var aes = new AesEngine();

            // FF1: Tweak may be empty or any length.
            // FF3-1: Tweak must be exactly 7 bytes → enforced by RequireFf3_1Tweak.
            // FpeParameters bundles AES key, radix, and tweak.
            // Radix is the number of characters in the alphabet.
            var normalizedTweak = mode == Mode.FF1 ? tweak ?? Array.Empty<byte>() : RequireFf3_1Tweak(tweak);
            var p = new FpeParameters(new KeyParameter(key), mapper.Radix, normalizedTweak);

            // Converts the input string into digits (indexes in the alphabet).
            // The output buffer has the same length.
            // Example:
            // alphabet = "0123456789" → Radix = 10
            // "407" = [4, 0, 7]
            // x is the digit sequence in base radix; y is the output buffer of the same length.
            var x = mapper.ConvertToIndexes(s.ToCharArray());
            var y = new byte[x.Length];

            // Create the appropriate engine (FF1 or FF3-1), initialize for encryption/decryption.
            // The output y is the transformed digit sequence (same length, same base).
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

            // Maps the digits back to characters of the alphabet → format is preserved
            // (same character set, same length).
            return new string(mapper.ConvertToChars(y));
        }

        // FF3-1 specification requirement: Tweak must be 56 bits (7 bytes).
        // Enforced early to provide clear error handling.
        private static byte[] RequireFf3_1Tweak(byte[] tweak)
        {
            if (tweak == null || tweak.Length != 7)
                throw new ArgumentException("FF3-1 requires a 7-byte tweak (56 bits).", nameof(tweak));
            return tweak;
        }
    }
}