namespace IT_Projekt.CryptoImpl
{
    /// <summary>
    /// Stellt vordefinierte Zeichensätze (Alphabete) zur Verfügung, 
    /// die für kryptographische Verfahren (z. B. FPE, Tokenisierung, Randomisierung) genutzt werden.
    /// </summary>
    internal static class Alphabets
    {
        /// <summary>
        /// Ziffern 0–9. 
        /// Wird verwendet, wenn nur numerische Werte erlaubt sind (z. B. Kreditkarten, IBAN-Prüfziffern).
        /// </summary>
        public const string Digits = "0123456789";

        /// <summary>
        /// Alphanumerisches Alphabet (Groß- und Kleinbuchstaben A–Z, a–z, plus Ziffern 0–9).
        /// Wird verwendet, wenn ein breiteres Alphabet für Token oder FPE benötigt wird.
        /// </summary>
        public const string Alnum  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        /// <summary>
        /// Vorkonvertierte Zeichenarray-Variante der Ziffern (0–9).
        /// Vorteil: muss nicht jedes Mal neu per <c>ToCharArray()</c> erzeugt werden,
        /// wenn einzelne Zeichen zufällig oder deterministisch gezogen werden.
        /// </summary>
        public static readonly char[] DigitsChars = Digits.ToCharArray();

        /// <summary>
        /// Vorkonvertierte Zeichenarray-Variante des alphanumerischen Alphabets.
        /// </summary>
        public static readonly char[] AlnumChars  = Alnum.ToCharArray();
    }
}