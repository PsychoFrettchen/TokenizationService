namespace IT_Projekt.Provider
{
    /// <summary>
    /// Schnittstelle für einen Schlüssel-Provider, der kryptografische Schlüssel
    /// tenant-spezifisch aus einer zugrundeliegenden Key-Management-Lösung
    /// (z. B. Vault KV, HSM, Cloud KMS) bereitstellt.
    /// 
    /// Diese Abstraktion ermöglicht es dem Tokenization-Service, unabhängig von der
    /// konkreten Schlüsselquelle zu arbeiten.
    /// </summary>
    public interface IKeyProvider
    {
        /// <summary>
        /// Gibt den aktuellen Schlüssel für einen bestimmten Tenant und Key-Id zurück.
        /// Falls der Schlüssel noch nicht existiert, sollte er erzeugt und persistiert werden.
        /// </summary>
        /// <param name="tenantId">Tenant-Identifikator (Mandant).</param>
        /// <param name="keyId">Schlüssel-Identifikator (z. B. "k1", "default").</param>
        /// <returns>Ein 32-Byte AES-Schlüssel oder anderes Keymaterial.</returns>
        byte[] GetKey(string tenantId, string keyId);

        /// <summary>
        /// Rotiert den aktiven Schlüssel für einen Tenant, indem eine neue Key-Id gesetzt wird.
        /// Implementierungen müssen sicherstellen, dass nachfolgende Tokenisierungen den neuen Key verwenden.
        /// </summary>
        /// <param name="tenantId">Tenant-Identifikator.</param>
        /// <param name="newKeyId">Neue Key-Id, die als aktiv markiert wird.</param>
        void Rotate(string tenantId, string newKeyId);

        /// <summary>
        /// Gibt die aktuell aktive Key-Id für einen Tenant zurück.
        /// Dies wird genutzt, wenn kein explizites <c>keyId</c> angegeben wird.
        /// </summary>
        /// <param name="tenantId">Tenant-Identifikator.</param>
        /// <returns>Die aktive Key-Id oder ein Fallback (z. B. "default").</returns>
        string GetActiveKeyId(string tenantId);
    }
}