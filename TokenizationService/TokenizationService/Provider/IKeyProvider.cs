namespace TokenizationService.Provider
{
    /// <summary>
    ///     Interface for a key provider that supplies cryptographic keys
    ///     per tenant from an underlying key management solution
    ///     (e.g., Vault KV, HSM, Cloud KMS).
    ///     This abstraction allows the Tokenization service to operate
    ///     independently of the concrete key source.
    /// </summary>
    public interface IKeyProvider
    {
        /// <summary>
        ///     Returns the current key for a specific tenant and key ID.
        ///     If the key does not yet exist, it should be created and persisted.
        /// </summary>
        /// <param name="tenantId">Tenant identifier.</param>
        /// <param name="keyId">Key identifier (e.g., "k1", "default").</param>
        /// <returns>A 32-byte AES key or other key material.</returns>
        byte[] GetKey(string tenantId, string keyId);

        /// <summary>
        ///     Rotates the active key for a tenant by setting a new key ID.
        ///     Implementations must ensure that subsequent tokenizations use the new key.
        /// </summary>
        /// <param name="tenantId">Tenant identifier.</param>
        /// <param name="newKeyId">New key ID to mark as active.</param>
        void Rotate(string tenantId, string newKeyId);

        /// <summary>
        ///     Returns the currently active key ID for a tenant.
        ///     This is used when no explicit <c>keyId</c> is specified.
        /// </summary>
        /// <param name="tenantId">Tenant identifier.</param>
        /// <returns>The active key ID or a fallback (e.g., "default").</returns>
        string GetActiveKeyId(string tenantId);
    }
}