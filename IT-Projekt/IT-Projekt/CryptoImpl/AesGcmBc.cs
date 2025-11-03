using System;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace IT_Projekt.CryptoImpl
{
    internal static class AesGcmBc
    {
        // Standard-Tag-Länge bei GCM: 16 Bytes (128 Bit)
        private const int TagLenBytes = 16;
        // Übliche Nonce-/IV-Länge bei GCM: 12 Bytes
        private const int NonceLenBytes = 12;

        public struct CipherResult
        {
            public byte[] Nonce;      // 12 Bytes (IV)
            public byte[] Ciphertext; // Länge entspricht der Klartextlänge
            public byte[] Tag;        // 16 Bytes (Authentifizierungs-Tag)
        }

        /// <summary>
        /// Verschlüsselt einen Klartext mit AES-256-GCM (BouncyCastle).
        /// Wichtiger Hinweis: Nonce/IV darf unter demselben Schlüssel niemals wiederverwendet werden!
        /// </summary>
        /// <param name="key">AES-Schlüssel (32 Bytes für AES-256).</param>
        /// <param name="plaintext">Zu verschlüsselnde Bytes (darf leer sein).</param>
        /// <param name="aad">Zusätzliche authentifizierte Daten (werden nicht verschlüsselt, optional).</param>
        /// <param name="nonce">12-Byte GCM-Nonce/IV; falls null, wird eine neue zufällige Nonce erzeugt.</param>
        /// <returns>Nonce, Ciphertext und Tag.</returns>
        /// <exception cref="ArgumentException">Wenn Schlüssel- oder Parameterlängen nicht passen.</exception>
        public static CipherResult Encrypt(byte[] key, byte[] plaintext, byte[] aad = null, byte[] nonce = null)
        {
            // Nur AES-256-GCM: 32-Byte-Schlüssel
            if (key == null || key.Length != 32) throw new ArgumentException("AES-GCM requires 32-byte key");

            // Nonce erzeugen (nicht den Schlüssel!); 12-Byte-Nonce ist Standard für GCM
            nonce = nonce ?? Crypto.RandomBytes(NonceLenBytes);

            // AES im GCM-Modus aufbauen
            var cipher = new GcmBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine());

            // AeadParameters:
            // - KeyParameter(key): symmetrischer Schlüssel
            // - TagLenBytes * 8  : Tag-Länge in Bits (128 Bit)
            // - nonce            : IV/Nonce
            // - aad              : Additional Authenticated Data
            var parameters = new AeadParameters(new KeyParameter(key), TagLenBytes * 8, nonce, aad);

            // true = Verschlüsselungsmodus
            cipher.Init(true, parameters);

            // Ausgabelänge für angegebene Input-Länge bestimmen
            var outBuf = new byte[cipher.GetOutputSize(plaintext?.Length ?? 0)];

            // Klartext verarbeiten
            int len = cipher.ProcessBytes(plaintext ?? Array.Empty<byte>(), 0, plaintext?.Length ?? 0, outBuf, 0);

            // DoFinal hängt den Tag an und schließt ab
            len += cipher.DoFinal(outBuf, len);

            // Split: vorne Ciphertext, hinten Tag (16 Bytes)
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
        /// Entschlüsselt AES-256-GCM und verifiziert den Authentifizierungs-Tag.
        /// Bei Tag-Mismatch wirft BouncyCastle eine InvalidCipherTextException.
        /// </summary>
        /// <param name="key">32-Byte-Schlüssel (AES-256).</param>
        /// <param name="nonce">12-Byte Nonce/IV (muss der Verschlüsselung entsprechen).</param>
        /// <param name="ciphertext">Verschlüsselte Daten.</param>
        /// <param name="tag">16-Byte Authentifizierungs-Tag.</param>
        /// <param name="aad">Optionale AAD (muss identisch zu Encrypt sein).</param>
        /// <returns>Klartext-Bytes.</returns>
        /// <exception cref="ArgumentException">Wenn Schlüssel-/Nonce-/Tag-Längen falsch sind.</exception>
        /// <remarks>
        /// Sicherheit: Wird eine falsche Nonce, falsches AAD oder ein falscher Tag übergeben,
        /// schlägt DoFinal mit InvalidCipherTextException fehl (Integritätsschutz).
        /// </remarks>
        public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag, byte[] aad = null)
        {
            // Parameterprüfungen
            if (key == null || key.Length != 32) throw new ArgumentException("AES-GCM requires 32-byte key");
            if (nonce == null || nonce.Length != NonceLenBytes) throw new ArgumentException("AES-GCM requires 12-byte nonce");
            if (tag == null || tag.Length != TagLenBytes) throw new ArgumentException("AES-GCM requires 16-byte tag");

            var cipher = new GcmBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), TagLenBytes * 8, nonce, aad);

            // false = Entschlüsselungsmodus
            cipher.Init(false, parameters);

            // GCM erwartet Input als (Ciphertext || Tag)
            var inBuf = new byte[(ciphertext?.Length ?? 0) + tag.Length];
            if (ciphertext != null && ciphertext.Length > 0)
                Buffer.BlockCopy(ciphertext, 0, inBuf, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, inBuf, ciphertext?.Length ?? 0, tag.Length);

            var outBuf = new byte[cipher.GetOutputSize(inBuf.Length)];
            int len = cipher.ProcessBytes(inBuf, 0, inBuf.Length, outBuf, 0);

            // DoFinal prüft den Tag (konstantzeitnah in der Lib) und wirft bei Fehler.
            len += cipher.DoFinal(outBuf, len);

            var pt = new byte[len];
            Buffer.BlockCopy(outBuf, 0, pt, 0, len);
            return pt;
        }

        /// <summary>
        /// Packt Nonce (12) || Tag (16) || Ciphertext in ein einzelnes Byte-Array.
        /// Praktisch zum Speichern/Transport.
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
        /// Entpackt ein Blob der Form Nonce(12) || Tag(16) || Ciphertext.
        /// </summary>
        public static void Unpack(byte[] blob, out byte[] nonce, out byte[] tag, out byte[] ciphertext)
        {
            if (blob == null || blob.Length < NonceLenBytes + TagLenBytes)
                throw new ArgumentException("Invalid AES-GCM blob");

            nonce = new byte[NonceLenBytes];
            tag   = new byte[TagLenBytes];

            Buffer.BlockCopy(blob, 0, nonce, 0, NonceLenBytes);
            Buffer.BlockCopy(blob, NonceLenBytes, tag, 0, TagLenBytes);

            var ctLen = blob.Length - (NonceLenBytes + TagLenBytes);
            ciphertext = new byte[ctLen];
            if (ctLen > 0) Buffer.BlockCopy(blob, NonceLenBytes + TagLenBytes, ciphertext, 0, ctLen);
        }
    }
}
