namespace TokenizationService.CryptoImpl
{
    /// <summary>
    ///     Interface for a Format-Preserving Encryption (FPE) engine.
    ///     FPE means: the encrypted output (ciphertext) has the same format
    ///     as the input (plaintext). Example:
    ///     - Plaintext:  "4111111111111111"  (credit card number, digits only)
    ///     - Ciphertext: "9834720192837465"  (same length, digits only)
    ///     This interface defines two main operations:
    ///     - Encrypt:  encrypt plaintext → ciphertext
    ///     - Decrypt:  decrypt ciphertext → plaintext
    ///     Parameters:
    ///     - plaintext / ciphertext: input data as a string
    ///     - key:      byte array containing the secret key
    ///     - tweak:    additional value (nonce / salt) that influences the result
    ///     without requiring a new key
    ///     - alphabet: set of allowed characters (e.g. "0123456789" for digits, or alphanumeric)
    ///     Implementations could, for example, be based on FF1 or FF3 (NIST SP 800-38G).
    /// </summary>
    public interface IFpeEngine
    {
        /// <summary>
        ///     Encrypts the given plaintext while preserving the format.
        /// </summary>
        string Encrypt(string plaintext, byte[] key, byte[] tweak, string alphabet);

        /// <summary>
        ///     Decrypts the given ciphertext back into plaintext.
        /// </summary>
        string Decrypt(string ciphertext, byte[] key, byte[] tweak, string alphabet);
    }
}