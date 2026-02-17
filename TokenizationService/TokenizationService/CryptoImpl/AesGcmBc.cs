using System;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace TokenizationService.CryptoImpl
{
    internal static class AesGcmBc
    {
        // Standard GCM tag length: 16 bytes (128 bits)
        private const int TagLenBytes = 16;

        // Common GCM nonce/IV length: 12 bytes
        private const int NonceLenBytes = 12;

        /// <summary>
        ///     Encrypts plaintext using AES-256-GCM (BouncyCastle).
        ///     Important: a nonce/IV must never be reused with the same key!
        /// </summary>
        /// <param name="key">AES key (32 bytes for AES-256).</param>
        /// <param name="plaintext">Bytes to encrypt (may be empty).</param>
        /// <param name="aad">Additional authenticated data (not encrypted, optional).</param>
        /// <param name="nonce">12-byte GCM nonce/IV; if null, a new random nonce is generated.</param>
        /// <returns>Nonce, ciphertext, and tag.</returns>
        /// <exception cref="ArgumentException">Thrown if key or parameter lengths are invalid.</exception>
        public static CipherResult Encrypt(byte[] key, byte[] plaintext, byte[] aad = null, byte[] nonce = null)
        {
            // AES-256-GCM only: 32-byte key
            if (key == null || key.Length != 32) throw new ArgumentException("AES-GCM requires 32-byte key");

            // Generate nonce (not the key!); 12-byte nonce is standard for GCM
            nonce = nonce ?? Crypto.RandomBytes(NonceLenBytes);

            // Build AES in GCM mode
            var cipher = new GcmBlockCipher(new AesEngine());

            // AeadParameters:
            // - KeyParameter(key): symmetric key
            // - TagLenBytes * 8  : tag length in bits (128 bits)
            // - nonce            : IV/nonce
            // - aad              : additional authenticated data
            var parameters = new AeadParameters(new KeyParameter(key), TagLenBytes * 8, nonce, aad);

            // true = encryption mode
            cipher.Init(true, parameters);

            // Determine output length for the given input length
            var outBuf = new byte[cipher.GetOutputSize(plaintext?.Length ?? 0)];

            // Process plaintext
            var len = cipher.ProcessBytes(plaintext ?? Array.Empty<byte>(), 0, plaintext?.Length ?? 0, outBuf, 0);

            // DoFinal appends the tag and finalizes
            len += cipher.DoFinal(outBuf, len);

            // Split: ciphertext first, tag last (16 bytes)
            var ctLen = outBuf.Length - TagLenBytes;

            var result = new CipherResult
            {
                Nonce = nonce,
                Ciphertext = new byte[ctLen],
                Tag = new byte[TagLenBytes]
            };

            Buffer.BlockCopy(outBuf, 0, result.Ciphertext, 0, ctLen);
            Buffer.BlockCopy(outBuf, ctLen, result.Tag, 0, TagLenBytes);
            return result;
        }

        /// <summary>
        ///     Decrypts AES-256-GCM and verifies the authentication tag.
        ///     If the tag does not match, BouncyCastle throws an InvalidCipherTextException.
        /// </summary>
        /// <param name="key">32-byte key (AES-256).</param>
        /// <param name="nonce">12-byte nonce/IV (must match the value used for encryption).</param>
        /// <param name="ciphertext">Encrypted data.</param>
        /// <param name="tag">16-byte authentication tag.</param>
        /// <param name="aad">Optional AAD (must be identical to Encrypt).</param>
        /// <returns>Plaintext bytes.</returns>
        /// <exception cref="ArgumentException">Thrown if key/nonce/tag lengths are invalid.</exception>
        /// <remarks>
        ///     Security: If an incorrect nonce, incorrect AAD, or an incorrect tag is provided,
        ///     DoFinal fails with InvalidCipherTextException (integrity protection).
        /// </remarks>
        public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag, byte[] aad = null)
        {
            // Parameter validation
            if (key == null || key.Length != 32) throw new ArgumentException("AES-GCM requires 32-byte key");
            if (nonce == null || nonce.Length != NonceLenBytes)
                throw new ArgumentException("AES-GCM requires 12-byte nonce");
            if (tag == null || tag.Length != TagLenBytes) throw new ArgumentException("AES-GCM requires 16-byte tag");

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), TagLenBytes * 8, nonce, aad);

            // false = decryption mode
            cipher.Init(false, parameters);

            // GCM expects input as (ciphertext || tag)
            var inBuf = new byte[(ciphertext?.Length ?? 0) + tag.Length];
            if (ciphertext != null && ciphertext.Length > 0)
                Buffer.BlockCopy(ciphertext, 0, inBuf, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, inBuf, ciphertext?.Length ?? 0, tag.Length);

            var outBuf = new byte[cipher.GetOutputSize(inBuf.Length)];
            var len = cipher.ProcessBytes(inBuf, 0, inBuf.Length, outBuf, 0);

            // DoFinal validates the tag (near-constant time in the library) and throws on failure.
            len += cipher.DoFinal(outBuf, len);

            var pt = new byte[len];
            Buffer.BlockCopy(outBuf, 0, pt, 0, len);
            return pt;
        }

        /// <summary>
        ///     Packs Nonce (12) || Tag (16) || Ciphertext into a single byte array.
        ///     Useful for storage/transport.
        /// </summary>
        public static byte[] Pack(CipherResult r)
        {
            if (r.Nonce == null || r.Nonce.Length != NonceLenBytes)
                throw new ArgumentException("Nonce must be 12 bytes.", nameof(r));
            if (r.Tag == null || r.Tag.Length != TagLenBytes)
                throw new ArgumentException("Tag must be 16 bytes.", nameof(r));

            var buf = new byte[r.Nonce.Length + r.Tag.Length + (r.Ciphertext?.Length ?? 0)];
            Buffer.BlockCopy(r.Nonce, 0, buf, 0, r.Nonce.Length);
            Buffer.BlockCopy(r.Tag, 0, buf, r.Nonce.Length, r.Tag.Length);
            if (r.Ciphertext != null && r.Ciphertext.Length > 0)
                Buffer.BlockCopy(r.Ciphertext, 0, buf, r.Nonce.Length + r.Tag.Length, r.Ciphertext.Length);
            return buf;
        }

        /// <summary>
        ///     Unpacks a blob of the form Nonce(12) || Tag(16) || Ciphertext.
        /// </summary>
        public static void Unpack(byte[] blob, out byte[] nonce, out byte[] tag, out byte[] ciphertext)
        {
            if (blob == null || blob.Length < NonceLenBytes + TagLenBytes)
                throw new ArgumentException("Invalid AES-GCM blob");

            nonce = new byte[NonceLenBytes];
            tag = new byte[TagLenBytes];

            Buffer.BlockCopy(blob, 0, nonce, 0, NonceLenBytes);
            Buffer.BlockCopy(blob, NonceLenBytes, tag, 0, TagLenBytes);

            var ctLen = blob.Length - (NonceLenBytes + TagLenBytes);
            ciphertext = new byte[ctLen];
            if (ctLen > 0) Buffer.BlockCopy(blob, NonceLenBytes + TagLenBytes, ciphertext, 0, ctLen);
        }

        public struct CipherResult
        {
            public byte[] Nonce; // 12 bytes (IV)
            public byte[] Ciphertext; // Length equals the plaintext length
            public byte[] Tag; // 16 bytes (authentication tag)
        }
    }
}