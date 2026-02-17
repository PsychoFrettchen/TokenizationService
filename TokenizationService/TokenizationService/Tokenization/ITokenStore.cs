namespace TokenizationService
{
    /// <summary>
    ///     Abstraction for a store in which token information is persisted.
    ///     Mainly used for:
    ///     <list type="bullet">
    ///         <item>
    ///             <description>
    ///                 <b>Reversible tokenization</b> – e.g., for random tokens (RANDOM)
    ///                 that must later be resolved (detokenized).
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <description>
    ///                 <b>Auditing / Logging</b> – traceability of which plaintext value
    ///                 was stored under which token.
    ///             </description>
    ///         </item>
    ///     </list>
    ///     Implementations may be based on Vault (KV v2), databases, or in-memory stores.
    /// </summary>
    public interface ITokenStore
    {
        /// <summary>
        ///     Persists a TokenRecord (containing, among other things,
        ///     token, plaintext, TenantId, KeyId, and field name).
        ///     For reversible tokens, this is required to enable later detokenization.
        /// </summary>
        void Save(TokenRecord record);

        /// <summary>
        ///     Attempts to retrieve a stored <see cref="TokenRecord" /> by its token.
        /// </summary>
        /// <param name="token">The token value (must not be null/empty).</param>
        /// <param name="record">Output: the found record or null if not found.</param>
        /// <returns><c>true</c> if an entry was found; otherwise <c>false</c>.</returns>
        bool TryGet(string token, out TokenRecord record);

        /// <summary>
        ///     Removes a stored TokenRecord
        ///     (e.g., due to retention policies or data deletion requests).
        /// </summary>
        /// <param name="token">The token to delete. If null/empty, nothing happens.</param>
        void Delete(string token);
    }
}