namespace IT_Projekt.CryptoImpl
{
    /// <summary>
    /// Schnittstelle für eine Format Preserving Encryption (FPE) Engine.
    /// 
    /// FPE bedeutet: die verschlüsselte Ausgabe (Ciphertext) hat dasselbe Format
    /// wie die Eingabe (Plaintext). Beispiel: 
    ///   - Plaintext:  "4111111111111111"  (Kreditkartennummer, nur Ziffern)
    ///   - Ciphertext: "9834720192837465"  (gleiche Länge, nur Ziffern)
    /// 
    /// Dieses Interface definiert zwei Hauptoperationen:
    /// - Encrypt:  Verschlüsselung von Klartext → Ciphertext
    /// - Decrypt:  Entschlüsselung von Ciphertext → Klartext
    /// 
    /// Parameter:
    /// - plaintext / ciphertext: die Eingabedaten als String
    /// - key:      Byte-Array mit dem geheimen Schlüssel
    /// - tweak:    Zusätzlicher Wert (Nonce / Salt), beeinflusst das Ergebnis,
    ///             ohne dass ein neuer Schlüssel benötigt wird
    /// - alphabet: Zeichenmenge (z. B. "0123456789" für Ziffern, oder alphanumerisch)
    /// 
    /// Implementierungen könnten z. B. auf FF1 oder FF3 (NIST SP 800-38G) basieren.
    /// </summary>
    public interface IFpeEngine
    {
        /// <summary>
        /// Verschlüsselt den gegebenen Klartext formatbewahrend.
        /// </summary>
        string Encrypt(string plaintext, byte[] key, byte[] tweak, string alphabet);

        /// <summary>
        /// Entschlüsselt den gegebenen Ciphertext zurück in den Klartext.
        /// </summary>
        string Decrypt(string ciphertext, byte[] key, byte[] tweak, string alphabet);
    }
}