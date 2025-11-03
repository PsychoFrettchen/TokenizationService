using System.Threading.Tasks;

namespace IT_Projekt.KeyManagment
{
    /// <summary>
    /// Abstraktion zum Abrufen von Geheimnissen (wie PFX-Passwörtern) aus HashiCorp Vault.
    /// </summary>
    public interface IVaultSecretProvider
    {
        
        /// <summary>
        /// Ruft einen einzelnen Feldwert (standardmäßig <c>„password“</c>) aus einem KV v2-Geheimnis in Vault ab.
        /// </summary>
        /// <param name="mount">
        /// Der Name des KV v2-Einhängepunkts (z. B. <c>„kv“</c>).
        /// </param>
        /// <param name="secretPath">
        /// Der Pfad zum geheimen Verzeichnis relativ zum Mount (z. B. <c>„tokenization/certs/client-admin“</c>).
        /// </param>
        /// <param name="field">
        /// Das spezifische Feld innerhalb des <c>data</c>-Objekts des Geheimnisses, das zurückgegeben werden soll (Standardwert ist <c>„password“</c>).
        /// </param>
        /// <returns>
        /// Der Feldwert als string.
        /// </returns>
        /// <exception cref="System.Exception">
        /// Wird ausgelöst, wenn das Geheimnis oder Feld nicht gefunden werden kann.
        /// </exception>
        Task<string> GetPfxPasswordAsync(string mount, string secretPath, string field = "password");
    }
}