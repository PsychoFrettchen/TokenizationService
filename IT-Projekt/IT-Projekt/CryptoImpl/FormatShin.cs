using System;
using System.Security.Cryptography;
using System.Text;

namespace IT_Projekt.CryptoImpl
{
    /// <summary>
    /// Hilfsklasse („Shim“) zur Erzeugung von deterministischen, maskierten Views.
    /// Diese Klasse implementiert ein vereinfachtes Format-Preserving-Verfahren:
    /// - Eingabe: eine Maske (z. B. "9999-9999-9999-9999")
    /// - Ausgabe: deterministisch generierte Zeichen, die das Maskenformat einhalten.
    /// 
    /// Beispiel: 
    /// Maske = "9999-9999", Seed = {Key}
    /// Ausgabe = "4831-9027"
    /// </summary>
    internal static class FormatShim
    {
        // Erlaubte Zeichensätze (Alphabete) für Maskenplatzhalter
        private static readonly char[] Digits  = "0123456789".ToCharArray();                       // für '9'
        private static readonly char[] Letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".ToCharArray(); // für 'A'
        private static readonly char[] Alnum   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray(); // für 'X'

        /// <summary>
        /// Erzeugt einen neuen Pseudozufalls-Block mithilfe von HMAC-SHA256.
        /// - Seed: Schlüssel für die deterministische Zufallsgenerierung
        /// - Counter: wird hochgezählt, um neue Blöcke zu generieren
        /// - Erzeugt 32-Byte Block
        /// - HMAC dient hier als deterministische Zufallsbitquelle
        /// </summary>
        private static byte[] DrbgBlock(byte[] seed, ulong counter)
        {
            // Counter in Big-Endian darstellen (für HMAC-Eingabe)
            var ctrBytes = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian) Array.Reverse(ctrBytes);

            // HMAC-SHA256 mit Seed als Schlüssel
            using (var h = new HMACSHA256(seed ?? Array.Empty<byte>()))
                return h.ComputeHash(ctrBytes);
        }

        /// <summary>
        /// Liefert das nächste Zeichen aus dem aktuellen Block.
        /// Falls der Block verbraucht ist, wird ein neuer über DrbgBlock() generiert.
        /// </summary>
        private static char NextFrom(ref byte[] block, ref int idx, byte[] seed, ref ulong ctr, char[] alphabet)
        {
            // Falls aktueller Block erschöpft → neuen Block erzeugen
            if (idx >= block.Length) 
            { 
                block = DrbgBlock(seed, ++ctr); 
                idx = 0; 
            }

            // Byte-Wert mod Alphabet-Länge = Index im Alphabet
            var c = alphabet[block[idx++] % alphabet.Length];
            return c;
        }

        /// <summary>
        /// Erzeugt aus einer Maske (z. B. "9999-AAAA") und einem Seed
        /// eine deterministische Ausgabe, die das Maskenformat beibehält.
        /// 
        /// Maskensymbole:
        /// - '9' = Ziffer (0–9)
        /// - 'A' = Buchstabe (A–Z, a–z)
        /// - 'X' = alphanumerisch (A–Z, a–z, 0–9)
        /// Alle anderen Zeichen werden unverändert übernommen (z. B. '-').
        /// 
        /// Wichtig: Da HMAC-SHA256 mit Seed verwendet wird, ist die Ausgabe deterministisch.
        /// </summary>
        public static string DeterministicMaskedView(string mask, byte[] seed)
        {
            if (string.IsNullOrEmpty(mask)) return string.Empty;

            var sb = new StringBuilder(mask.Length);
            ulong ctr = 0;                              // Zähler für neue Blöcke
            var block = DrbgBlock(seed, ctr);           // Initialer Block
            int idx = 0;                                // Index im aktuellen Block

            foreach (var m in mask)
            {
                switch (m)
                {
                    case '9': sb.Append(NextFrom(ref block, ref idx, seed, ref ctr, Digits)); break;
                    case 'A': sb.Append(NextFrom(ref block, ref idx, seed, ref ctr, Letters)); break;
                    case 'X': sb.Append(NextFrom(ref block, ref idx, seed, ref ctr, Alnum));   break;
                    default:  sb.Append(m); // Unveränderte Übernahme z. B. Bindestrich
                        break;
                }
            }

            return sb.ToString();
        }
    }
}
