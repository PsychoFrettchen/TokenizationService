namespace TokenizationService.CryptoImpl
{
    /// <summary>
    ///     Provides predefined character sets (alphabets)
    ///     used for cryptographic operations (e.g., FPE, tokenization, randomization).
    /// </summary>
    internal static class Alphabets
    {
        /// <summary>
        ///     Digits 0–9.
        ///     Used when only numeric values are allowed (e.g., credit cards, IBAN check digits).
        /// </summary>
        public const string Digits = "0123456789";

        /// <summary>
        ///     Alphanumeric alphabet (uppercase and lowercase letters A–Z, a–z, plus digits 0–9).
        ///     Used when a broader alphabet is required for tokens or FPE.
        /// </summary>
        public const string Alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        /// <summary>
        ///     Pre-converted character array version of digits (0–9).
        ///     Advantage: does not need to be recreated using <c>ToCharArray()</c>
        ///     each time individual characters are selected randomly or deterministically.
        /// </summary>
        public static readonly char[] DigitsChars = Digits.ToCharArray();

        /// <summary>
        ///     Pre-converted character array version of the alphanumeric alphabet.
        /// </summary>
        public static readonly char[] AlnumChars = Alnum.ToCharArray();
    }
}