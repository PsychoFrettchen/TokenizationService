namespace IT_Projekt
{
    /// <summary>
    /// Abstraktion für einen Speicher, in dem Token-Informationen persistiert werden.  
    /// Wird vor allem für:
    /// <list type="bullet">
    ///   <item><description><b>Reversible Tokenisierung</b> – z. B. bei zufälligen Tokens (RANDOM), die später wieder aufgelöst (detokenized) werden müssen.</description></item>
    ///   <item><description><b>Auditing / Logging</b> – Nachvollziehbarkeit, wer welchen Klarwert zu welchem Token gespeichert hat.</description></item>
    /// </list>
    ///
    /// Implementierungen können z. B. auf Vault (KV v2), Datenbanken oder In-Memory-Stores basieren.
    /// </summary>
    public interface ITokenStore
    {
        /// <summary>
        /// Persistiert einen TokenRecord (enthält u. a. Token, Klartext, TenantId, KeyId, Feldname).
        /// Bei reversiblen Tokens ist dies notwendig, um später wieder detokenisieren zu können.
        /// </summary>
        void Save(TokenRecord record);

        /// <summary>
        /// Versucht, einen gespeicherten <see cref="TokenRecord"/> anhand des Tokens abzurufen.
        /// </summary>
        /// <param name="token">Der Tokenwert (muss nicht null/leer sein).</param>
        /// <param name="record">Ausgabe: gefundener Datensatz oder null, falls nicht gefunden.</param>
        /// <returns><c>true</c>, wenn ein Eintrag gefunden wurde, andernfalls <c>false</c>.</returns>
        bool TryGet(string token, out TokenRecord record);

        /// <summary>
        /// Entfernt einen gespeicherten TokenRecord (z. B. im Rahmen von Aufbewahrungsfristen oder Datenlöschung).
        /// </summary>
        /// <param name="token">Der zu löschende Token. Falls null/leer, passiert nichts.</param>
        void Delete(string token);
    }
}