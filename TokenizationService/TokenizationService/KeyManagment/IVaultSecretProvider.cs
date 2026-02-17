using System.Threading.Tasks;

namespace TokenizationService.KeyManagment
{
    /// <summary>
    ///     Abstraction for retrieving secrets (such as PFX passwords) from HashiCorp Vault.
    /// </summary>
    public interface IVaultSecretProvider
    {
        /// <summary>
        ///     Retrieves a single field value (by default <c>"password"</c>)
        ///     from a KV v2 secret in Vault.
        /// </summary>
        /// <param name="mount">
        ///     The name of the KV v2 mount point (e.g., <c>"kv"</c>).
        /// </param>
        /// <param name="secretPath">
        ///     The path to the secret relative to the mount
        ///     (e.g., <c>"tokenization/certs/client-admin"</c>).
        /// </param>
        /// <param name="field">
        ///     The specific field within the <c>data</c> object of the secret
        ///     to return (default is <c>"password"</c>).
        /// </param>
        /// <returns>
        ///     The field value as a string.
        /// </returns>
        /// <exception cref="System.Exception">
        ///     Thrown if the secret or field cannot be found.
        /// </exception>
        Task<string> GetPfxPasswordAsync(string mount, string secretPath, string field = "password");
    }
}