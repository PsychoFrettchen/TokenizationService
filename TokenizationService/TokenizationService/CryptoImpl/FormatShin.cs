using System;
using System.Security.Cryptography;
using System.Text;

namespace TokenizationService.CryptoImpl
{
    /// <summary>
    ///     Helper class (“shim”) for generating deterministic, masked views.
    ///     This class implements a simplified format-preserving approach:
    ///     - Input: a mask (e.g., "9999-9999-9999-9999")
    ///     - Output: deterministically generated characters that conform to the mask format.
    ///     Example:
    ///     Mask = "9999-9999", Seed = {Key}
    ///     Output = "4831-9027"
    /// </summary>
    internal static class FormatShim
    {
        // Allowed character sets (alphabets) for mask placeholders
        private static readonly char[] Digits = "0123456789".ToCharArray(); // for '9'

        private static readonly char[]
            Letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".ToCharArray(); // for 'A'

        private static readonly char[] Alnum =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray(); // for 'X'

        /// <summary>
        ///     Generates a new pseudorandom block using HMAC-SHA256.
        ///     - Seed: key for deterministic random generation
        ///     - Counter: incremented to generate new blocks
        ///     - Produces a 32-byte block
        ///     - HMAC acts here as a deterministic random bit source
        /// </summary>
        private static byte[] DrbgBlock(byte[] seed, ulong counter)
        {
            // Represent counter in big-endian format (for HMAC input)
            var ctrBytes = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian) Array.Reverse(ctrBytes);

            // HMAC-SHA256 with seed as key
            using (var h = new HMACSHA256(seed ?? Array.Empty<byte>()))
            {
                return h.ComputeHash(ctrBytes);
            }
        }

        /// <summary>
        ///     Returns the next character from the current block.
        ///     If the block is exhausted, a new one is generated via DrbgBlock().
        /// </summary>
        private static char NextFrom(ref byte[] block, ref int idx, byte[] seed, ref ulong ctr, char[] alphabet)
        {
            // If current block is exhausted → generate new block
            if (idx >= block.Length)
            {
                block = DrbgBlock(seed, ++ctr);
                idx = 0;
            }

            // Byte value mod alphabet length = index in alphabet
            var c = alphabet[block[idx++] % alphabet.Length];
            return c;
        }

        /// <summary>
        ///     Generates a deterministic output from a mask (e.g., "9999-AAAA")
        ///     and a seed while preserving the mask format.
        ///     Mask symbols:
        ///     - '9' = digit (0–9)
        ///     - 'A' = letter (A–Z, a–z)
        ///     - 'X' = alphanumeric (A–Z, a–z, 0–9)
        ///     All other characters are copied unchanged (e.g., '-').
        ///     Important: Since HMAC-SHA256 with a seed is used,
        ///     the output is deterministic.
        /// </summary>
        public static string DeterministicMaskedView(string mask, byte[] seed)
        {
            if (string.IsNullOrEmpty(mask)) return string.Empty;

            var sb = new StringBuilder(mask.Length);
            ulong ctr = 0; // Counter for new blocks
            var block = DrbgBlock(seed, ctr); // Initial block
            var idx = 0; // Index within current block

            foreach (var m in mask)
                switch (m)
                {
                    case '9': sb.Append(NextFrom(ref block, ref idx, seed, ref ctr, Digits)); break;
                    case 'A': sb.Append(NextFrom(ref block, ref idx, seed, ref ctr, Letters)); break;
                    case 'X': sb.Append(NextFrom(ref block, ref idx, seed, ref ctr, Alnum)); break;
                    default:
                        sb.Append(m); // Copy unchanged (e.g., hyphen)
                        break;
                }

            return sb.ToString();
        }
    }
}