using System;
using System.Collections.Generic;
using em.Tokenization.V1;

namespace TokenizationService
{
    /// <summary>
    ///     Represents a persisted record for a token.
    ///     Stored in the <see cref="ITokenStore" /> and used both
    ///     for detokenization (mapping token → plaintext)
    ///     and for auditing/administration purposes.
    /// </summary>
    public sealed class TokenRecord
    {
        /// <summary>
        ///     The generated token value (e.g., v1.r.... or v1.f....).
        ///     Serves as the key for detokenization.
        /// </summary>
        public string Token { get; set; }

        /// <summary>
        ///     Tenant ID for which this token was created.
        /// </summary>
        public string TenantId { get; set; }

        /// <summary>
        ///     Field name this token refers to (e.g., "email", "credit_card").
        /// </summary>
        public string Field { get; set; }

        /// <summary>
        ///     The original plaintext value.
        ///     Note: This is only stored for reversible tokenization.
        ///     For non-reversible methods (e.g., Hash/HMAC without a store),
        ///     this field remains empty.
        /// </summary>
        public string Plaintext { get; set; }

        /// <summary>
        ///     Token type (Random, FPE, HMAC, Hash, …).
        /// </summary>
        public TokenType Type { get; set; }

        /// <summary>
        ///     Key ID (KeyId) that was used to create the token.
        ///     Used for versioning during key rotation.
        /// </summary>
        public string KeyId { get; set; }

        /// <summary>
        ///     Data class describing the content (e.g., Email, phone number, credit card).
        ///     Useful for validations and masking.
        /// </summary>
        public DataClass DataClass { get; set; }

        /// <summary>
        ///     Timestamp (UTC) when the token was created and stored.
        /// </summary>
        public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        ///     Additional attributes (freely defined).
        ///     Can contain metadata for auditing or classification.
        /// </summary>
        public IReadOnlyDictionary<string, string> Attributes { get; set; }
            = new Dictionary<string, string>();
    }
}